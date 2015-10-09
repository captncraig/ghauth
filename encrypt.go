package ghauth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"io"
)

func (a *authManager) encrypt(plaintext []byte) string {
	//encrypt then sign
	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return ""
	}
	stream := cipher.NewCFBEncrypter(a.aes, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], plaintext)
	hash := a.hash(ciphertext)
	a.hash(ciphertext)
	return base64.StdEncoding.EncodeToString(append(hash, ciphertext...))
}
func (a *authManager) hash(ciphertext []byte) []byte {
	h := hmac.New(sha256.New, a.hmac_key)
	_, err := h.Write(ciphertext)
	if err != nil {
		return []byte{}
	}
	m := h.Sum(nil)
	return m
}
func (a *authManager) decrypt(cookieData string) string {
	ciphertext, err := base64.StdEncoding.DecodeString(cookieData)
	if err != nil {
		return ""
	}
	if len(ciphertext) < sha256.Size+aes.BlockSize { //at least room for iv and hmac
		return ""
	}
	//first validate hmac
	msgMac := ciphertext[:sha256.Size]
	ciphertext = ciphertext[sha256.Size:]
	actualMac := a.hash(ciphertext)
	if !hmac.Equal(msgMac, actualMac) {
		return ""
	}
	// pull out iv and decrypt
	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(a.aes, iv)
	stream.XORKeyStream(ciphertext, ciphertext)
	return string(ciphertext)
}
