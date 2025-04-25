package handlers

import (
    "encoding/json"
    "fmt"
    "log"
    "net/http"
    "strings"
    "time"

    "auth-service/internal/auth"
    "auth-service/internal/db"
    "auth-service/internal/middleware"

    "github.com/golang-jwt/jwt/v5"
)

func ProfileHandlers(mux *http.ServeMux) {
    mux.HandleFunc("GET /api/v1/profile", func(w http.ResponseWriter, r *http.Request) {
        // Извлекаем user_id из контекста
        userID, ok := r.Context().Value(middleware.UserIDKey).(int)
        if !ok || userID == 0 {
            http.Error(w, "Unauthorized", http.StatusUnauthorized)
            return
        }

        // Логируем user_id для отладки
        log.Println("User ID extracted from context:", userID)

        // Возвращаем успешный ответ
        fmt.Fprintf(w, "Welcome! Your user ID is %v", userID)
    })
}

func LoginHandlers(mux *http.ServeMux, dbInstance *db.Database, secretKey []byte) {
    mux.HandleFunc("POST /api/v1/login", func(w http.ResponseWriter, r *http.Request) {
        // Структура для входных данных
        var userInput struct {
            Login    string `json:"login"`
            Password string `json:"password"`
        }

        // Проверка Content-Type
        if r.Header.Get("Content-Type") != "application/json" {
            http.Error(w, "Content-Type must be application/json", http.StatusBadRequest)
            return
        }

        // Декодирование JSON
        if err := json.NewDecoder(r.Body).Decode(&userInput); err != nil {
            http.Error(w, "Invalid input", http.StatusBadRequest)
            return
        }

        // Поиск пользователя в базе данных
        var storedUser struct {
            ID           int
            PasswordHash string
        }
        err := dbInstance.Pool.QueryRow(
            r.Context(),
            "SELECT id, password_hash FROM users WHERE login = $1",
            userInput.Login,
        ).Scan(&storedUser.ID, &storedUser.PasswordHash)
        if err != nil {
            log.Println("Failed to find user:", err)
            http.Error(w, "Invalid login or password", http.StatusUnauthorized)
            return
        }

        // Проверка пароля
        if err := auth.ComparePassword(storedUser.PasswordHash, userInput.Password); err != nil {
            log.Println("Invalid password:", err)
            http.Error(w, "Invalid login or password", http.StatusUnauthorized)
            return
        }

        // Генерация JWT-токена
        jwtToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
            "user_id": storedUser.ID,
            "exp":     time.Now().Add(time.Hour * 24).Unix(), // Токен действителен 24 часа
        })

        jwtTokenString, err := jwtToken.SignedString(secretKey)
        if err != nil {
            log.Println("Failed to generate JWT token:", err)
            http.Error(w, "Failed to generate token", http.StatusInternalServerError)
            return
        }

        // Генерация refresh-токена
        refreshToken, err := auth.GenerateRefreshToken()
        if err != nil {
            log.Println("Failed to generate refresh token:", err)
            http.Error(w, "Failed to generate refresh token", http.StatusInternalServerError)
            return
        }

        // Сохранение refresh-токена в базу данных
        if err := dbInstance.SaveRefreshToken(storedUser.ID, refreshToken, 7*24*time.Hour); err != nil {
            log.Println("Failed to save refresh token:", err)
            http.Error(w, "Failed to save refresh token", http.StatusInternalServerError)
            return
        }

        // Успешный ответ
        w.WriteHeader(http.StatusOK)
        json.NewEncoder(w).Encode(map[string]string{
            "token":         jwtTokenString,
            "refresh_token": refreshToken,
        })
    })
}

func RegisterHandlers(mux *http.ServeMux, dbInstance *db.Database) {
    mux.HandleFunc("POST /api/v1/register", func(w http.ResponseWriter, r *http.Request) {
        var userInput struct {
            Login    string `json:"login"`
            Email    string `json:"email"`
            Password string `json:"password"`
        }

        // Декодирование JSON
        if err := json.NewDecoder(r.Body).Decode(&userInput); err != nil {
            http.Error(w, "Invalid input", http.StatusBadRequest)
            return
        }

        // Валидация входных данных
        if err := auth.ValidateUserInput(userInput.Login, userInput.Email, userInput.Password); err != nil {
            http.Error(w, err.Error(), http.StatusBadRequest)
            return
        }

        // Хэширование пароля
        passwordHash, err := auth.HashPassword(userInput.Password)
        if err != nil {
            http.Error(w, "Failed to hash password", http.StatusInternalServerError)
            return
        }

        // Сохранение пользователя в базу данных
        var userID int
        err = dbInstance.Pool.QueryRow(
            r.Context(),
            "INSERT INTO users (login, email, password_hash) VALUES ($1, $2, $3) RETURNING id",
            userInput.Login, userInput.Email, passwordHash,
        ).Scan(&userID)
        if err != nil {
            if strings.Contains(err.Error(), "duplicate key") {
                http.Error(w, "User with this login or email already exists", http.StatusConflict)
                return
            }
            http.Error(w, "Failed to register user", http.StatusInternalServerError)
            return
        }

        // Успешный ответ
        w.WriteHeader(http.StatusCreated)
        json.NewEncoder(w).Encode(map[string]string{"message": "User registered successfully"})
    })
}

func RefreshTokenHandlers(mux *http.ServeMux, dbInstance *db.Database, secretKey []byte) {
    mux.HandleFunc("POST /api/v1/refresh-token", func(w http.ResponseWriter, r *http.Request) {
        var input struct {
            RefreshToken string `json:"refresh_token"`
        }

        // Декодирование JSON
        if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
            http.Error(w, "Invalid input", http.StatusBadRequest)
            return
        }

        // Поиск refresh-токена в базе данных
        var storedToken struct {
            UserID   int
            ExpiresAt time.Time
        }
        err := dbInstance.Pool.QueryRow(
            r.Context(),
            "SELECT user_id, expires_at FROM refresh_tokens WHERE token = $1",
            input.RefreshToken,
        ).Scan(&storedToken.UserID, &storedToken.ExpiresAt)
        if err != nil {
            log.Println("Failed to find refresh token:", err)
            http.Error(w, "Invalid or expired refresh token", http.StatusUnauthorized)
            return
        }

        // Проверка времени истечения
        if time.Now().After(storedToken.ExpiresAt) {
            http.Error(w, "Refresh token has expired", http.StatusUnauthorized)
            return
        }

        // Генерация нового JWT-токена
        newToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
            "user_id": storedToken.UserID,
            "exp":     time.Now().Add(time.Hour * 24).Unix(),
        })
        tokenString, err := newToken.SignedString(secretKey)
        if err != nil {
            log.Println("Failed to generate JWT token:", err)
            http.Error(w, "Failed to generate token", http.StatusInternalServerError)
            return
        }

        // Возвращаем новый токен
        w.WriteHeader(http.StatusOK)
        json.NewEncoder(w).Encode(map[string]string{"token": tokenString})
    })
}
