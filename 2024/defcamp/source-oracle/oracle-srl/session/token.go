package session

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"time"

	"github.com/pkg/errors"
)

type UserData struct {
	Username  string `json:"username"`
	Password  string `json:"password"`
	Timestamp string `json:"timestamp"`
}

func GenerateSessionToken(username string, password string, key []byte) (string, error) {

	userData := UserData{
		Username:  username,
		Password:  password,
		Timestamp: time.Now().Format(time.RFC3339),
	}

	jsonData, err := json.Marshal(userData)
	if err != nil {
		return "", err
	}

	jsonData = pad(jsonData)
	if len(jsonData)%aes.BlockSize != 0 {
		return "", errors.New("Padding error")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	ciphertext := make([]byte, aes.BlockSize+len(jsonData))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext[aes.BlockSize:], jsonData)

	return hex.EncodeToString(ciphertext), nil
}

func ValidateSessionToken(token string, key []byte) (string, error) {

	cipherText, err := hex.DecodeString(token)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	if len(cipherText) < aes.BlockSize {
		return "", errors.New("ciphertext too short")
	}
	iv := cipherText[:aes.BlockSize]
	cipherText = cipherText[aes.BlockSize:]

	if len(cipherText)%aes.BlockSize != 0 {
		return "", errors.New("ciphertext is not a multiple of the block size")
	}

	mode := cipher.NewCBCDecrypter(block, iv)

	mode.CryptBlocks(cipherText, cipherText)

	cipherData, err := stripPadding(cipherText)
	if err != nil {
		return "", err
	}

	var userData UserData
	if err := json.Unmarshal(cipherData, &userData); err != nil {
		return "", err
	}

	timestamp, err := time.Parse(time.RFC3339, userData.Timestamp)
	if err != nil {
		return "", err
	}

	if time.Since(timestamp) > 5*time.Minute {
		return "", errors.New("session token expired")
	}

	return userData.Username, nil
}

func pad(plaintext []byte) []byte {
	if len(plaintext)%aes.BlockSize == 0 {
		for i := 0; i < aes.BlockSize; i++ {
			plaintext = append(plaintext, byte(aes.BlockSize))
		}
		return plaintext
	}

	var padding int
	if len(plaintext) < aes.BlockSize {
		padding = aes.BlockSize - len(plaintext)
	} else {
		padding = aes.BlockSize - (len(plaintext) % aes.BlockSize)
	}
	for i := 0; i < padding; i++ {
		plaintext = append(plaintext, byte(padding))
	}

	return plaintext
}

func stripPadding(plaintext []byte) ([]byte, error) {

	paddingError := errors.New("invalid padding")
	lastByte := len(plaintext) - 1

	if int(plaintext[lastByte]) > aes.BlockSize {
		return []byte(""), paddingError
	}

	paddingValue := int(plaintext[lastByte])

	if paddingValue == 0 {
		return []byte(""), paddingError
	}

	if paddingValue > len(plaintext) {
		return []byte(""), paddingError
	}

	for checked := 0; checked < paddingValue; checked++ {
		if int(plaintext[len(plaintext)-1]) != paddingValue {
			return []byte(""), paddingError
		}
		plaintext = plaintext[:len(plaintext)-1]
	}
	return plaintext, nil
}
