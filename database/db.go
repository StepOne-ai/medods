package database

import (
    "context"
    "fmt"
    "os"
    "time"

    "github.com/jackc/pgx/v5/pgxpool"
    "go.uber.org/zap"
)

var DB *pgxpool.Pool
var logger *zap.Logger

func InitLogger() {
    var err error
    logger, err = zap.NewProduction()
    if err != nil {
        panic(err)
    }
}

func InitDB() (*pgxpool.Pool, error) {
    InitLogger()

    connString := os.Getenv("DATABASE_URL")
    if connString == "" {
        connString = "postgres://postgres:stepan2005@localhost:5432/medods"
        fmt.Println("Switching to default connection string:", connString)
    }

    logger.Info("Initializing database connection", zap.String("connection_string", connString))

    config, err := pgxpool.ParseConfig(connString)
    if err != nil {
        return nil, fmt.Errorf("failed to parse connection string: %w", err)
    }

    config.MaxConns = 20
    config.MinConns = 5
    config.HealthCheckPeriod = 1 * time.Minute

    DB, err = pgxpool.NewWithConfig(context.Background(), config)
    if err != nil {
        return nil, fmt.Errorf("failed to create connection pool: %w", err)
    }

    if err := DB.Ping(context.Background()); err != nil {
        return nil, fmt.Errorf("failed to ping database: %w", err)
    }

    createTableUserSQL := `
    CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        guid TEXT UNIQUE NOT NULL,
        hashed_refresh_token TEXT NOT NULL
    );
    `

    _, err = DB.Exec(context.Background(), createTableUserSQL)
    if err != nil {
        return nil, fmt.Errorf("failed to create table: %w", err)
    }

    createTableUserAgentSQL := `
    CREATE TABLE IF NOT EXISTS user_agents (
        id SERIAL PRIMARY KEY,
        user_guid TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        user_agent TEXT,
        last_ip TEXT
    );`
    
    _, err = DB.Exec(context.Background(), createTableUserAgentSQL)
    if err != nil {
        return nil, fmt.Errorf("failed to create table: %w", err)
    }

    logger.Info("Database connected and table created")
    return DB, nil
}

func CloseDB() {
    if DB == nil {
        logger.Info("Database connection is already closed or was never opened")
        return
    }
    DB.Close()
    logger.Info("Database disconnected")
}
