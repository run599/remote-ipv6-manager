package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

// ═══════════════════════════════════════════════
// TLS 自签证书管理
//
// 首次启动生成 ECDSA P-256 自签证书（10 年有效期），
// 持久化在可执行文件同级目录，后续启动复用同一证书，
// 保证证书指纹稳定，供客户端做 pinning 校验。
// ═══════════════════════════════════════════════

// ensureCert 确保存在自签 TLS 证书，返回 (证书路径, 私钥路径, SHA-256 指纹 hex)
func ensureCert(dir string) (string, string, string, error) {
	certFile := filepath.Join(dir, "server.crt")
	keyFile := filepath.Join(dir, "server.key")

	// 已有证书则直接复用（指纹必须稳定，否则客户端 pinning 失效）
	if _, err := os.Stat(certFile); err == nil {
		if _, err := os.Stat(keyFile); err == nil {
			fp, err := certFingerprint(certFile)
			if err != nil {
				return "", "", "", fmt.Errorf("读取现有证书失败: %w", err)
			}
			return certFile, keyFile, fp, nil
		}
	}

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", "", fmt.Errorf("生成私钥失败: %w", err)
	}

	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return "", "", "", fmt.Errorf("生成序列号失败: %w", err)
	}

	tmpl := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "r6m-server", Organization: []string{"RemoteIPv6Manager"}},
		NotBefore:    time.Now().Add(-time.Hour), // 容忍时钟偏差
		NotAfter:     time.Now().AddDate(10, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("::1"), net.ParseIP("127.0.0.1")},
	}

	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		return "", "", "", fmt.Errorf("签发证书失败: %w", err)
	}

	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0644); err != nil {
		return "", "", "", fmt.Errorf("写入证书失败: %w", err)
	}
	keyBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return "", "", "", fmt.Errorf("编码私钥失败: %w", err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes}), 0600); err != nil {
		return "", "", "", fmt.Errorf("写入私钥失败: %w", err)
	}

	fp := sha256.Sum256(der)
	return certFile, keyFile, hex.EncodeToString(fp[:]), nil
}

// certFingerprint 计算证书文件的 SHA-256 指纹
func certFingerprint(certFile string) (string, error) {
	data, err := os.ReadFile(certFile)
	if err != nil {
		return "", err
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" {
		return "", fmt.Errorf("无效的证书文件")
	}
	fp := sha256.Sum256(block.Bytes)
	return hex.EncodeToString(fp[:]), nil
}
