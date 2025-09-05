package db

import (
	"context"
	"encoding/json"
	"log"
	"strconv"

	"github.com/pkalsi97/authx/internal/models"
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

	client = redis.NewClient(&redis.Options{
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

func RedisSet(ctx context.Context, Id string, input *models.UserSignupData) error {
	key := "user" + Id
	data, err := json.Marshal(input)
	if err != nil {
		return err
	}

	return client.Set(ctx, key, data, 0).Err()
}

func RedisGet(ctx context.Context, Id string) (*models.UserSignupData, error) {
	key := "user" + Id
	var output models.UserSignupData

	val, err := client.Get(ctx, key).Result()
	if err != nil {
		return nil, err
	}

	if err := json.Unmarshal([]byte(val), &output); err != nil {
		return nil, err
	}
	return &output, nil
}
