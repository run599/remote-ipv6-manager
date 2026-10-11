# -*- coding: utf-8 -*-
"""
发布工具：把本地仓库的 MCP 插件与已构建的受管端 exe 上传到服务端 filestore。

为什么需要它（用户的需求原话："把 python 解释器还有那些脚本打包到服务器上，
有人触发受管端 EXE 的时候自动下发"）：
  受管端启动后会从服务端拉取运行时与插件，所以**服务端才是分发源**。
  但服务端 filestore 里的东西是手工放上去的，与仓库源码会漂移 ——
  实测就撞到：服务端上的 screen_capture.py 还是旧版（没有 PNG 编码），
  即使同步链路完全正常，受管端拿到的插件也不支持实时看屏。

上传策略：只覆盖本地存在的插件目录，**不删除服务端上本地没有的插件**
（服务端现有 11 个插件、仓库只有 3 个，其余 8 个是服务端特有的，删了就是真丢东西）。
"""
import hashlib
import os
import sys
import io

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")
import paramiko

# 用法: python publish_filestore.py
# 可用环境变量覆盖（换服务器/换路径时不必改代码）
HOST = os.environ.get("R6M_FS_HOST", "192.168.1.10")
USER = os.environ.get("R6M_FS_USER", "root")
PWD  = os.environ.get("R6M_FS_PASS", "CHANGE_ME")        # 口令不入库，走环境变量
REMOTE = os.environ.get("R6M_FS_DIR", "/mnt/mmc0-4/r6m-server/filestore")
REPO = os.environ.get("R6M_REPO", os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

c = paramiko.SSHClient()
c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
c.connect(HOST, username=USER, password=PWD, timeout=25, look_for_keys=False, allow_agent=False)
sftp = c.open_sftp()


def run(cmd):
    _i, o, e = c.exec_command(cmd, timeout=60)
    out = o.read().decode("utf-8", "replace")
    err = e.read().decode("utf-8", "replace")
    return out + err


def ensure_dir(p):
    try:
        sftp.stat(p)
    except IOError:
        sftp.mkdir(p)


ensure_dir(REMOTE)
ensure_dir(REMOTE + "/plugins")

# ── 1) 上传插件（只覆盖本地有的，不删服务端特有的）──
local_plugins = os.path.join(REPO, "plugins")
names = sorted(d for d in os.listdir(local_plugins) if os.path.isdir(os.path.join(local_plugins, d)))
uploaded = 0
for name in names:
    ldir = os.path.join(local_plugins, name)
    rdir = REMOTE + "/plugins/" + name
    ensure_dir(rdir)
    for fn in sorted(os.listdir(ldir)):
        lp = os.path.join(ldir, fn)
        if not os.path.isfile(lp):
            continue
        # 跳过 *.bak / *.orig 之类的本地备份：服务端下发的文件清单是"目录里有什么就发什么"，
        # 备份文件会被一并下发给每个受管端（白耗带宽，还把本地命名暴露出去）
        if fn.endswith('.bak') or fn.endswith('.orig') or fn.endswith('.tmp'):
            print('  - 跳过本地备份: %s/%s' % (name, fn))
            continue
        rp = rdir + "/" + fn
        sftp.put(lp, rp)
        uploaded += 1
        local_sha = hashlib.sha256(open(lp, "rb").read()).hexdigest()
        remote_sha = run("sha256sum '%s' | cut -d' ' -f1" % rp).strip()
        flag = "" if remote_sha == local_sha else ""
        print("  %s %-22s %-22s %8d B  sha=%s" % (flag, name + "/" + fn, "", os.path.getsize(lp), local_sha[:16]))

print("插件文件上传 %d 个（本地 %d 个插件目录）" % (uploaded, len(names)))

# ── 2) 上传受管端 exe（分发用的副本，供 deploy_file / 手工取用）──
exe = os.path.join(REPO, "client", "build", "RemoteClient.exe")
if os.path.isfile(exe):
    sftp.put(exe, REMOTE + "/RemoteClient.exe")
    local_sha = hashlib.sha256(open(exe, "rb").read()).hexdigest()
    remote_sha = run("sha256sum " + REMOTE + "/RemoteClient.exe | cut -d' ' -f1").strip()
    print("  %s RemoteClient.exe %d B sha=%s" % ("" if remote_sha == local_sha else "",
                                                 os.path.getsize(exe), local_sha[:16]))
else:
    print("  ! 未找到 %s，跳过 exe 上传" % exe)

# 注意：sftp 要在**所有** SFTP 操作之后才关。原实现在汇报前就 close()，
# 后面的 exec_command 复用同一条已失效的 channel，报 'Channel closed'。

# ── 3) 汇报服务端最终状态（含解释器）──
print("\n=== 服务端 filestore 现状 ===")
print(run("ls -la " + REMOTE + " | head -8").rstrip())
print("\n=== 插件与文件数 ===")
print(run("for d in " + REMOTE + "/plugins/*/; do printf '  %-16s %s files\\n' \"$(basename $d)\" \"$(ls -1 $d | wc -l)\"; done").rstrip())
print("\n=== 解释器 ===")
print(run("ls -la " + REMOTE + "/python-*.zip 2>/dev/null || echo '  !! 没有解释器 zip'").rstrip())
print("\n=== screen_capture 是否为 PNG 版（查 encode_png 标记）===")
print(run("grep -c 'def encode_png' " + REMOTE + "/plugins/screen_capture/screen_capture.py || echo 0").rstrip())
sftp.close()
c.close()
