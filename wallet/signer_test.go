package wallet

import (
	"crypto/ed25519"
	"encoding/hex"
	"testing"

	"github.com/caigou-xyz/aegis/test_utils"
	"github.com/stretchr/testify/require"

	"github.com/caigou-xyz/aegis/client"
	"github.com/stretchr/testify/assert"
)

func TestPrivateKeySigner(t *testing.T) {
	privateKey, err := hex.DecodeString(test_utils.TONPrivateKeys[0])
	require.NoError(t, err)
	privKey := ed25519.PrivateKey(privateKey)
	pubKey := privKey.Public().(ed25519.PublicKey)

	// 创建 PrivateKeySigner
	signer := NewPrivateKeySigner(privKey)

	// 测试 PublicKey 方法
	assert.Equal(t, pubKey, signer.PublicKey())

	// 测试签名功能
	testData := []byte("test message")
	signature, err := signer.Sign(testData)
	assert.NoError(t, err)

	// 验证签名
	valid := ed25519.Verify(pubKey, testData, signature)
	assert.True(t, valid)
}

func TestRemoteSigner(t *testing.T) {
	userPrivateKey, err := hex.DecodeString(test_utils.UserPrivateKey)
	require.NoError(t, err)

	// 创建 RemoteSigner
	signer, err := NewRemoteSigner(client.NewClient(userPrivateKey, "http://127.0.0.1:49152"), test_utils.TONV4R2Addresses[0], nil)
	assert.NoError(t, err)

	// 使用原始 PrivateKey
	TONPrivateKey, err := hex.DecodeString(test_utils.TONPrivateKeys[0])
	require.NoError(t, err)
	key := ed25519.PrivateKey(TONPrivateKey)
	// 测试 PublicKey 方法
	pubKey := key.Public().(ed25519.PublicKey)

	assert.Equal(t, pubKey, signer.PublicKey())

	testData := []byte("test message")

	// 测试签名功能
	resultSignature, err := signer.Sign(testData)
	assert.NoError(t, err)

	// 验证签名
	valid := ed25519.Verify(pubKey, testData, resultSignature)
	assert.True(t, valid)
}

func TestSignerConsistency(t *testing.T) {
	// 生成一个新的密钥对
	privateKey, err := hex.DecodeString(test_utils.TONPrivateKeys[0])
	require.NoError(t, err)
	privKey := ed25519.PrivateKey(privateKey)
	pubKey := privKey.Public().(ed25519.PublicKey)

	testAddress := test_utils.TONV4R2Addresses[0]
	testData := []byte("test message")

	// 创建 PrivateKeySigner
	privateSigner := NewPrivateKeySigner(privKey)

	// 创建 RemoteSigner
	userPrivateKey, err := hex.DecodeString(test_utils.UserPrivateKey)
	require.NoError(t, err)
	remoteSigner, err := NewRemoteSigner(client.NewClient(userPrivateKey, "http://127.0.0.1:49152"), testAddress, nil)
	assert.NoError(t, err)

	// 获取两种签名器的签名结果
	sig1, err := privateSigner.Sign(testData)
	assert.NoError(t, err)

	sig2, err := remoteSigner.Sign(testData)
	assert.NoError(t, err)

	// 验证两个签名是否一致
	assert.Equal(t, sig1, sig2)

	// 验证两个签名都是有效的
	valid1 := ed25519.Verify(pubKey, testData, sig1)
	valid2 := ed25519.Verify(pubKey, testData, sig2)
	assert.True(t, valid1)
	assert.True(t, valid2)
}
