package middleware

import (
    "context"
    "errors"
    "log"
    "net/http"

    "github.com/golang-jwt/jwt/v5"
)

type ContextKey string

const UserIDKey ContextKey = "user_id"

var (
    ErrUnauthorized = errors.New("unauthorized")
)

func AuthMiddleware(secretKey []byte) func(next http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            authHeader := r.Header.Get("Authorization")
            if authHeader == "" || len(authHeader) < 7 || authHeader[:7] != "Bearer " {
                http.Error(w, ErrUnauthorized.Error(), http.StatusUnauthorized)
                return
            }

            tokenString := authHeader[len("Bearer "):]

            token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
                if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
                    log.Println("Unexpected signing method:", token.Method)
                    return nil, ErrUnauthorized
                }
                return secretKey, nil
            })

            if err != nil || !token.Valid {
                log.Println("Token parsing error:", err)
                http.Error(w, ErrUnauthorized.Error(), http.StatusUnauthorized)
                return
            }

            claims, ok := token.Claims.(jwt.MapClaims)
            if !ok {
                log.Println("Invalid claims type")
                http.Error(w, ErrUnauthorized.Error(), http.StatusUnauthorized)
                return
            }

            userID, ok := claims["user_id"].(float64)
            if !ok {
                log.Println("user_id not found in token claims")
                http.Error(w, ErrUnauthorized.Error(), http.StatusUnauthorized)
                return
            }

            // Логируем user_id для отладки
            log.Println("Token is valid. Adding user_id to context:", int(userID))

            // Передаем user_id через контекст
            ctx := context.WithValue(r.Context(), UserIDKey, int(userID))
            r = r.WithContext(ctx)

            next.ServeHTTP(w, r)
        })
    }
}
