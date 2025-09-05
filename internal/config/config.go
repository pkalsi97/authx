package config

import (
	"log"
	"os"

	"github.com/joho/godotenv"
)

type Config struct {
	Port      string
	DbUrl     string
	JwtSecret string
	RedisAddr string
	RedisDb   string
}

func LoadConfig() *Config {
	_ = godotenv.Load()

	cfg := &Config{
		Port:      getEnv("PORT"),
		DbUrl:     getEnv("DB_URL"),
		JwtSecret: getEnv("JWT_SECRET"),
		RedisAddr: getEnv("REDIS_ADDR"),
		RedisDb:   getEnv("REDIS_DB"),
	}
	return cfg
}

func getEnv(key string) string {
	val := os.Getenv(key)
	if val == "" {
		log.Fatalf("Error: Required Environment Variable %s, not set!", key)
	}
	return val
}
