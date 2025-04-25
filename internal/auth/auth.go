package auth

import (
    "errors"
    "golang.org/x/crypto/bcrypt"
)

func ValidateUserInput(login, email, password string) error {
    if len(login) < 3 {
        return errors.New("login must be at least 3 characters long")
    }
    if len(password) < 8 {
        return errors.New("password must be at least 8 characters long")
    }
    return nil
}

func HashPassword(password string) (string, error) {
    hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
    if err != nil {
        return "", err
    }
    return string(hashedPassword), nil
}

// ComparePassword сравнивает хэшированный пароль с исходным паролем
func ComparePassword(hashedPassword, password string) error {
    return bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
}