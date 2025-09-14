package config

import (
	"log"
	"os"

	"github.com/joho/godotenv"
)

type Config struct {
	Port           string
	DbUrl          string
	RedisAddr      string
	RedisDb        string
	Retries        string
	PrivateKeyPath string
	PublicKeyPath  string
}

func LoadConfig() *Config {
	_ = godotenv.Load()

	cfg := &Config{
		Port:           getEnv("PORT"),
		DbUrl:          getEnv("DB_URL"),
		RedisAddr:      getEnv("REDIS_ADDR"),
		RedisDb:        getEnv("REDIS_DB"),
		Retries:        getEnv("RETRIES"),
		PrivateKeyPath: getEnv("PRIVATE_KEY_PATH"),
		PublicKeyPath:  getEnv("PUBLIC_KEY_PATH"),
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
