package auth

import (
    "crypto/rand"
    "encoding/base64"
)

// GenerateRefreshToken генерирует случайный refresh-токен
func GenerateRefreshToken() (string, error) {
    b := make([]byte, 32) // 32 байта = 256 бит
    _, err := rand.Read(b)
    if err != nil {
        return "", err
    }
    return base64.URLEncoding.EncodeToString(b), nil
}