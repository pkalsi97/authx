package db

import (
	"context"
	"encoding/json"
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

func RedisSet[T any](ctx context.Context, Id string, input T) error {
	key := "user" + Id
	data, err := json.Marshal(input)
	if err != nil {
		return err
	}

	return client.Set(ctx, key, data, 0).Err()
}

func RedisGet[T any](ctx context.Context, Id string) (*T, error) {
	key := "user" + Id
	val, err := client.Get(ctx, key).Result()
	if err == redis.Nil {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	var output T
	if err := json.Unmarshal([]byte(val), &output); err != nil {
		return nil, err
	}
	return &output, nil
}

func RedisDel(ctx context.Context, id string) error {
	key := "user" + id
	return client.Del(ctx, key).Err()
}
