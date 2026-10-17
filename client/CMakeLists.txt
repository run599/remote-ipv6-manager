cmake_minimum_required(VERSION 3.20)
# 必须启用 RC 语言：否则 .res 文件在 add_executable 里只会变成 order-only
# 依赖，**不会进入链接命令行** —— 表现是"rc 编译成功、.res 有效、但 exe 里
# 没有版本信息"（实测：build.ninja 里只有 cmake_object_order_depends_target，
# 链接行里根本没有 r6m_version.res）。
project(RemoteClient LANGUAGES CXX RC)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
add_compile_options(/utf-8 /W4 /permissive-)

# ── 版本信息 / 字符串资源 ────────────────────────────────────────────────
# 理由：没有任何版本信息的 exe 在 EDR 侧是**加分项**的可疑特征（正常商业或
# 系统程序都带厂商/产品名）。用 SDK 的 rc.exe 在构建期编入 .rsrc。
#
# 三个踩过的坑（都会静默失效，必须一起处理）：
#       产出空 .res。这里显式拼出 SDK 的 um/shared 包含路径。
#       order-only 依赖，**不进链接命令行**（build.ninja 里根本没有它）。
#       所以 project() 必须 LANGUAGES CXX RC。
#   (3) RC 语言启用后仍要走**显式**的 add_custom_command 产出 .res，
#       避免 CMake 自己的 RC 规则与这里的路径不一致。
set(R6M_RES "")
if(MSVC)
    set(_rc_candidates "")
    file(GLOB _sdk_bins "C:/Program Files (x86)/Windows Kits/10/bin/*/x64/rc.exe")
    if(_sdk_bins)
        list(GET _sdk_bins 0 _rc_candidates "${_sdk_bins}")
    endif()
    find_program(RC_EXE NAMES rc HINTS ${_rc_candidates})
    if(NOT RC_EXE AND _sdk_bins)
        list(GET _sdk_bins 0 RC_EXE)
    endif()
    if(RC_EXE)
        set(R6M_RES "${CMAKE_CURRENT_BINARY_DIR}/r6m_version.res")
        set(R6M_RC_INCLUDES "")
        file(GLOB _inc2 "C:/Program Files (x86)/Windows Kits/10/Include/*/um"
                       "C:/Program Files (x86)/Windows Kits/10/Include/*/shared")
        foreach(_d ${_inc2})
            list(APPEND R6M_RC_INCLUDES "/i" "${_d}")
        endforeach()
        add_custom_command(
            OUTPUT "${R6M_RES}"
            COMMAND "${RC_EXE}" /nologo ${R6M_RC_INCLUDES}
                    /fo "${R6M_RES}" "${CMAKE_CURRENT_SOURCE_DIR}/src/r6m_version.rc"
            DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/src/r6m_version.rc"
            COMMENT "rc.exe: 编译版本信息资源 r6m_version.rc"
            VERBATIM)
        # 兜底自证在下面 pack_sections 的 POST_BUILD 里做（add_custom_command(TARGET)
        # 必须出现在 add_executable 之后，否则 CMake 报错）。
        message(STATUS "版本资源：使用 ${RC_EXE}")
    else()
        message(WARNING "未找到 rc.exe，版本信息资源不会写入（兼容性适配判据 D1 会失败）")
    endif()
endif()

# 静态链接 MSVC 运行时
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

add_executable(RemoteClient WIN32
    src/main.cpp
    src/Json.cpp
    src/StubCore.cpp
    src/PluginLoader.cpp
    src/NetworkFix.cpp
    src/SelfGuard.cpp    # 进程保护（常驻互检）
    src/ArtifactApply.cpp # 工件落地后的应用分发（备份/回滚）
    src/AntiHook.cpp      
    src/Compat.cpp
)

# 版本资源 .res 必须显式进入**链接选项**：实测把它放进 add_executable 的源列表，
# 即使 project() 启用了 RC 语言，CMake 也只在 build.ninja 里生成一条
# order-only 依赖、不把它加到 LINK 行（这类静默失效很难查）。
# 用 target_link_options 直接给链接器最可靠；MSVC 的 link.exe 接受 .res。
if(R6M_RES)
    target_link_options(RemoteClient PRIVATE "${R6M_RES}")
    set_property(TARGET RemoteClient APPEND PROPERTY LINK_DEPENDS "${R6M_RES}")
    message(STATUS "版本资源将随链接写入：${R6M_RES}")
endif()

# 显式声明 Windows 子系统（GUI）：不弹控制台窗口，避免"新进程带控制台"这一行为特征
set_target_properties(RemoteClient PROPERTIES WIN32_EXECUTABLE TRUE)

# 兼容层：关闭生成期可被静态提取的信息
#   /GL  全程序优化；/Gy 函数级 COMDAT（配合 /OPT:REF 丢弃未用代码）
#   /GS- 关闭栈溢出 Cookie（去掉 __security_cookie 引用与相关字符串）
#   /guard:cf- 关闭控制流保护（避免 .gfids 表成为特征）
#   /Qspectre- 关闭 Spectre 缓解桩（减小体积、去掉 __xrstor 等特征代码）
#   /MT  静态链接 CRT（无 MSVCP140.dll 导入，减少依赖特征）
target_compile_options(RemoteClient PRIVATE
    $<$<CONFIG:Release>:/GL /Gy /GS- /guard:cf- /Qspectre->
)
target_link_options(RemoteClient PRIVATE
    $<$<CONFIG:Release>:/LTCG /OPT:REF /OPT:ICF /INCREMENTAL:NO /RELEASE>
    # 不生成调试目录（DEBUG directory 里带绝对 PDB 路径，是静态特征）
    /DEBUG:NONE /PDBALTPATH:%_PDB%
)

#   注意：editbin 随 VS 提供，未在 PATH 时跳过并给出提示，不静默失败
find_program(EDITBIN_EXE editbin)
if(EDITBIN_EXE)
    add_custom_command(TARGET RemoteClient POST_BUILD
        COMMAND ${EDITBIN_EXE} /RELEASE "$<TARGET_FILE:RemoteClient>"
        COMMENT "editbin /RELEASE: 清除 PE 富头（工具链标识）"
    )
else()
    add_custom_command(TARGET RemoteClient POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E echo "警告: 未找到 editbin，Rich Header 未清除（兼容性适配判据之一）"
    )
endif()

# ── 兼容性适配收口：构建后段加密 ────────────────────────────────────────────────
# 运行时由 Compat 的 .CRT$XIB 静态构造解密（早于一切字符串使用）。
#
#   与加载配置，整节加密后 CreateProcess 直接失败（Win32 error 998 /
#   内存位置访问无效）—— 实测踩过。所以字面量必须单独成节（.r6ms）。
# 用 R6M_PACK=OFF 可关闭（调试时保留可读数据，便于排查）。
option(R6M_PACK "构建后加密字面量密文节 .r6ms（兼容性适配收口）" ON)
find_program(PYTHON_EXE NAMES python python3 py)
if(R6M_PACK AND PYTHON_EXE)
    add_custom_command(TARGET RemoteClient POST_BUILD
        # 顺序很重要：
        #   ① editbin /RELEASE 清富头（由上面的 POST_BUILD 完成）
        #   ② normalize_pe 清 DEBUG 目录（版本信息已由 rc 在构建期写入，故 --skip-version）
        #   ③ pack_sections 加密 .r6ms（改节内容，必须在 ② 之后）
        #   ④ check_version 回读版本信息（防静默失效，缺失即构建失败）
        #   ⑤ verify_compat 实测判据（--no-fail：只报告不阻断构建）
        COMMAND ${PYTHON_EXE} "${CMAKE_CURRENT_SOURCE_DIR}/tools/normalize_pe.py" --skip-version "$<TARGET_FILE:RemoteClient>"
        COMMAND ${PYTHON_EXE} "${CMAKE_CURRENT_SOURCE_DIR}/tools/pack_sections.py" pack "$<TARGET_FILE:RemoteClient>"
        COMMAND ${PYTHON_EXE} "${CMAKE_CURRENT_SOURCE_DIR}/tools/check_version.py" "$<TARGET_FILE:RemoteClient>"
        COMMAND ${PYTHON_EXE} "${CMAKE_CURRENT_SOURCE_DIR}/tools/verify_compat.py" --no-fail "$<TARGET_FILE:RemoteClient>"
        COMMENT "normalize_pe(清 DEBUG) + pack_sections(加密 .r6ms) + check_version(回读) + 兼容性适配判据实测"
        VERBATIM
    )
elseif(R6M_PACK)
    add_custom_command(TARGET RemoteClient POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E echo "警告: 未找到 python，跳过 .r6ms 加密（兼容性适配收口未生效）"
    )
endif()

# ── 兼容性适配前置：必须已跑过字面量混淆 ────────────────────────────────────────
# 源码里的占位标记未展开会导致编译失败（这是有意的），此处只做提示。
add_custom_command(TARGET RemoteClient PRE_BUILD
    COMMAND ${CMAKE_COMMAND} -E echo "兼容性适配前置：如构建报 'XS 未定义'，请先运行 python tools/obfuscate_strings.py --run"
)

target_include_directories(RemoteClient PRIVATE src include)
target_link_libraries(RemoteClient PRIVATE
    ws2_32 iphlpapi wininet urlmon advapi32 shlwapi ntdll crypt32
 bcrypt)


# 插件目录
set(PLUGIN_DIR ${CMAKE_BINARY_DIR}/plugins)
file(MAKE_DIRECTORY ${PLUGIN_DIR})

# 编译后自动复制插件目录
add_custom_command(TARGET RemoteClient POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E make_directory "$<TARGET_FILE_DIR:RemoteClient>/plugins"
)

# ═══════════════════════════════════════════════════════════════════════════
#
# 只链 TaskLock + Logger + 字符串表，**刻意不链** Compat / IntegrityCheck / StubCore /
# 网络只用 lock/LockMain.cpp 里的极简 WinINet 客户端（artifact key 鉴权）。
# ═══════════════════════════════════════════════════════════════════════════
# 不挂包壳/版本资源：外置工具"用完即撤"，保持朴素反而不显眼

