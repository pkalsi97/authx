package db

import (
	"context"
	"log"
	"strconv"

	"github.com/redis/go-redis/v9"
)

var (
	ctx    = context.Background()
	client *redis.Client
)

func StartRedis(addr string, dbStr string) {
	db, err := strconv.Atoi(dbStr)
	if err != nil {
		db = 0
	}

	client := redis.NewClient(&redis.Options{
		Addr: addr,
		DB:   db,
	})

	if err := client.Ping(ctx).Err(); err != nil {
		log.Fatalf("Could not connect to Redis: %v", err)
	}
	log.Println("Redis connected:", addr)
}

func StopRedis() {
	if client != nil {
		_ = client.Close()
	}
	log.Println("Redis connection closed")
}

func GetRedis() *redis.Client {
	if client == nil {
		log.Fatal("Redis client is not initialized. Call StartRedis first.")
	}
	return client
}
