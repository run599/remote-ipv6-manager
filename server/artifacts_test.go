package main

// artifacts_test.go —— 验证"密钥不会投反"。
//
// 这些用例针对的是**真实的错配路径**，不是摆设：

import (
	"testing"
)

func newHub(t *testing.T) *ArtifactHub {
	t.Helper()
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	return NewArtifactHub(t.TempDir(), key)
}

// 两个都需要的密钥的工具：各拿各的钥匙，各查各的文件，互不串门。
func TestTwoArtifactsDoNotCross(t *testing.T) {
	h := newHub(t)
	a := &Artifact{HWID: "hw1", Name: "sample.exe", SHA256: "aaaa111122223333", Key: "key-sample-0001"}
	b := &Artifact{HWID: "hw1", Name: "R6Screen.exe", SHA256: "bbbb111122223333", Key: "key-screen-01"}
	if _, err := h.Register(a); err != nil {
		t.Fatalf("登记 A 失败: %v", err)
	}
	if _, err := h.Register(b); err != nil {
		t.Fatalf("登记 B 失败: %v", err)
	}
	ra, ok := h.Resolve("hw1", "sample.exe")
	if !ok || ra.Key != "key-sample-0001" {
		t.Fatalf("按文件名查 A 拿到错钥匙: %+v ok=%v", ra, ok)
	}
	rb, ok := h.Resolve("hw1", "R6Screen.exe")
	if !ok || rb.Key != "key-screen-01" {
		t.Fatalf("按文件名查 B 拿到错钥匙: %+v ok=%v", rb, ok)
	}
	// 两把钥匙各自只能解到自己的工件
	if n, _, ok := h.Identity("key-sample-0001"); !ok || n != "sample.exe" {
		t.Fatalf("key-sample-0001 的身份错了: %s ok=%v", n, ok)
	}
	if n, _, ok := h.Identity("key-screen-01"); !ok || n != "R6Screen.exe" {
		t.Fatalf("key-screen-01 的身份错了: %s ok=%v", n, ok)
	}
}

// 核心保障：一把钥匙不许改嫁。这是"投反"的唯一根源，必须硬拒。
func TestKeyCannotBeReassigned(t *testing.T) {
	h := newHub(t)
	if _, err := h.Register(&Artifact{HWID: "hw1", Name: "sample.exe", SHA256: "aaaa1111", Key: "k1"}); err != nil {
		t.Fatalf("首次登记失败: %v", err)
	}
	if _, err := h.Register(&Artifact{HWID: "hw1", Name: "R6Other.exe", SHA256: "cccc2222", Key: "k1"}); err == nil {
		t.Fatal("同一把钥匙被改指派给别的文件名，居然通过了 —— 这正是投反的成因")
	}
	if _, err := h.Register(&Artifact{HWID: "hw1", Name: "sample.exe", SHA256: "dddd3333", Key: "k1"}); err == nil {
		t.Fatal("同一把钥匙绑到了不同内容的同名文件，居然通过了")
	}
	// 拒绝之后原记录必须完好无损
	a, ok := h.Resolve("hw1", "sample.exe")
	if !ok || a.SHA256 != "aaaa1111" {
		t.Fatalf("拒绝登记后原记录被破坏: %+v", a)
	}
	first, _ := h.Resolve("hw1", "sample.exe")
	d0 := first.DeployedMs
	if _, err := h.Register(&Artifact{HWID: "hw1", Name: "sample.exe", SHA256: "aaaa1111", Key: "k1"}); err != nil {
		t.Fatalf("原样重投应幂等，却报错: %v", err)
	}
	again, _ := h.Resolve("hw1", "sample.exe")
	if again.DeployedMs != d0 {
		t.Fatalf("续投应保留首次投放时间: %d -> %d", d0, again.DeployedMs)
	}
}

func TestSameNameNewKeyReplacesOld(t *testing.T) {
	h := newHub(t)
	if _, err := h.Register(&Artifact{HWID: "hw1", Name: "sample.exe", SHA256: "aaaa1111", Key: "old"}); err != nil {
		t.Fatalf("登记失败: %v", err)
	}
	replaced, err := h.Register(&Artifact{HWID: "hw1", Name: "sample.exe", SHA256: "aaaa1111", Key: "new"})
	if err != nil {
		t.Fatalf("同名换钥匙应被接受（并作废旧记录），却报错: %v", err)
	}
	if replaced == nil || replaced.Key != "old" {
		t.Fatalf("没有回报被作废的旧钥匙: %+v", replaced)
	}
	if _, _, ok := h.Identity("old"); ok {
		t.Fatal("旧钥匙仍能鉴权 —— 说明旧记录没被作废，会出现两条记录抢同一身份")
	}
	if n, _, ok := h.Identity("new"); !ok || n != "sample.exe" {
		t.Fatalf("新钥匙身份不对: %s ok=%v", n, ok)
	}
	// 同名只应剩一条
	cnt := 0
	for _, a := range h.items {
		if a.HWID == "hw1" && a.Name == "sample.exe" {
			cnt++
		}
	}
	if cnt != 1 {
		t.Fatalf("同名工件记录数应为 1，实际 %d", cnt)
	}
}

// 同一把钥匙不许跨机器复用：A 机的钥匙拿到 B 机就是无效的。
func TestKeyIsScopedToHWID(t *testing.T) {
	h := newHub(t)
	if _, err := h.Register(&Artifact{HWID: "hwA", Name: "sample.exe", SHA256: "aaaa", Key: "kA"}); err != nil {
		t.Fatalf("登记失败: %v", err)
	}
	if h.AuthByKey("kA", "hwB") {
		t.Fatal("A 机的钥匙在 B 机上通过了鉴权 —— 跨机复用会让映射彻底失效")
	}
	if !h.AuthByKey("kA", "hwA") {
		t.Fatal("本机钥匙鉴权失败")
	}
	if _, err := h.Register(&Artifact{HWID: "hwB", Name: "sample.exe", SHA256: "aaaa", Key: "kB"}); err != nil {
		t.Fatalf("B 机登记同名文件失败: %v", err)
	}
	if rb, _ := h.Resolve("hwB", "sample.exe"); rb.Key != "kB" {
		t.Fatalf("B 机应拿到自己的钥匙，实际 %s", rb.Key)
	}
}
