package utils

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
)

var (
	AesKey = "vH1q!fRBr&tVR~8En$5v5?1pJdV#vn)_"
)

const DefaultAesKey = "vH1q!fRBr&tVR~8En$5v5?1pJdV#vn)_"

func InitAes(aesKey string) {
	if len(aesKey) == 0 {
		AesKey = DefaultAesKey
	} else {
		AesKey = aesKey
	}
}

func PKCS7Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

func PKCS7UnPadding(origData []byte) []byte {
	length := len(origData)
	unpadding := int(origData[length-1])
	return origData[:(length - unpadding)]
}

// AES加密,CBC
func AesEncrypt(data string, optional ...bool) (string, error) {
	useDefault := false
	aesKey := ""
	if len(optional) > 0 {
		useDefault = optional[0]
	}
	if useDefault {
		aesKey = DefaultAesKey
	} else {
		aesKey = AesKey
	}
	block, err := aes.NewCipher([]byte(aesKey))
	if err != nil {
		return "", err
	}
	blockSize := block.BlockSize()
	origData := PKCS7Padding([]byte(data), blockSize)
	blockMode := cipher.NewCBCEncrypter(block, []byte(aesKey)[:blockSize])
	crypted := make([]byte, len(origData))
	blockMode.CryptBlocks(crypted, origData)
	return base64.StdEncoding.EncodeToString(crypted), nil
}

// AES解密
func AesDecrypt(data string, optional ...bool) (string, error) {
	aesKey := DefaultAesKey
	crypted, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher([]byte(aesKey))
	if err != nil {
		return "", err
	}
	blockSize := block.BlockSize()
	blockMode := cipher.NewCBCDecrypter(block, []byte(aesKey)[:blockSize])
	origData := make([]byte, len(crypted))
	blockMode.CryptBlocks(origData, crypted)
	origData = PKCS7UnPadding(origData)
	return string(origData), nil
}

func AesEncryptByKey(data, key string) (string, error) {
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return "", err
	}
	blockSize := block.BlockSize()
	origData := PKCS7Padding([]byte(data), blockSize)
	blockMode := cipher.NewCBCEncrypter(block, []byte(key)[:blockSize])
	crypted := make([]byte, len(origData))
	blockMode.CryptBlocks(crypted, origData)
	return base64.StdEncoding.EncodeToString(crypted), nil
}

func AesDecryptByKey(data, key string) (string, error) {
	crypted, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return "", err
	}
	blockSize := block.BlockSize()
	blockMode := cipher.NewCBCDecrypter(block, []byte(key)[:blockSize])
	origData := make([]byte, len(crypted))
	blockMode.CryptBlocks(origData, crypted)
	origData = PKCS7UnPadding(origData)
	return string(origData), nil
}
