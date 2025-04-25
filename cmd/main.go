package main

import (
    "log"
    "net/http"
    "os"
    "github.com/joho/godotenv"
    "auth-service/internal/db"
    "auth-service/internal/handlers"
    "auth-service/internal/middleware"
)

func main() {
    // Загружаем переменные окружения
    err := godotenv.Load()
    if err != nil {
        log.Fatal("Error loading .env file")
    }

    secretKey := []byte(os.Getenv("SECRET_KEY")) 

    // Подключение к базе данных
    dsn := "postgres://auth_user:new_password@localhost:5432/auth_service?sslmode=disable"
    dbInstance, err := db.NewDatabase(dsn)
    if err != nil {
        log.Fatalf("Failed to connect to the database: %v", err)
    }
    defer dbInstance.Pool.Close()

    // Инициализация маршрутизатора
    mux := http.NewServeMux()

    // Регистрация обработчиков
    handlers.RegisterHandlers(mux, dbInstance)
    handlers.LoginHandlers(mux, dbInstance, secretKey) 
    handlers.RefreshTokenHandlers(mux, dbInstance, secretKey)
    handlers.ProfileHandlers(mux)
   

  // Middleware с авторизацией для маршрута профиля
mux.Handle("/api/v1/profile", middleware.AuthMiddleware(secretKey)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
    userID, ok := r.Context().Value(middleware.UserIDKey).(int)
    if !ok || userID == 0 {
        http.Error(w, "Unauthorized", http.StatusUnauthorized)
        return
    }
    log.Println("User ID extracted from context:", userID)
    w.Write([]byte("Welcome to your profile!"))
})))

    // Запуск сервера
    log.Println("Starting server on :8080")
    if err := http.ListenAndServe(":8080", mux); err != nil {
        log.Fatalf("Failed to start server: %v", err)
    }
}
