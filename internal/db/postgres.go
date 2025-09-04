package db

import (
	"context"
	"log"

	"github.com/jackc/pgx/v5/pgxpool"
)

var pool *pgxpool.Pool

func StartDb(url string) {
	var err error
	pool, err = pgxpool.New(context.Background(), url)
	if err != nil {
		log.Fatal("Unable to connect to Database:", err)
	}
	log.Printf("Database Connected")
}

func GetDb() *pgxpool.Pool {
	return pool
}

func CloseDB() {
	if pool != nil {
		pool.Close()
		log.Println("Database Connection closed")
	}
}
