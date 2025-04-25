package db

import (
    "context"
    "fmt"
    "log"
    "time"

    "github.com/jackc/pgx/v5/pgxpool"
)

type Database struct {
    Pool *pgxpool.Pool
}

func NewDatabase(dsn string) (*Database, error) {
    pool, err := pgxpool.New(context.Background(), dsn)
    if err != nil {
        return nil, fmt.Errorf("failed to create connection pool: %w", err)
    }

    // Проверка соединения
    if err := pool.Ping(context.Background()); err != nil {
        return nil, fmt.Errorf("failed to ping database: %w", err)
    }

    log.Println("Successfully connected to the database")
    return &Database{Pool: pool}, nil
}

// SaveRefreshToken сохраняет refresh-токен в базу данных
func (db *Database) SaveRefreshToken(userID int, token string, expiresIn time.Duration) error {
    expiresAt := time.Now().Add(expiresIn)
    _, err := db.Pool.Exec(
        context.Background(),
        "INSERT INTO refresh_tokens (user_id, token, expires_at) VALUES ($1, $2, $3)",
        userID, token, expiresAt,
    )
    return err
}