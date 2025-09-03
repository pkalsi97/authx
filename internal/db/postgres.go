package db

import (
	"context"
	"log"

	"github.com/jackc/pgx/v5"
)

var db *pgx.Conn

func StartDb(url string) {
	var err error
	db, err = pgx.Connect(context.Background(), url)
	if err != nil {
		log.Fatal("Unable to connect to Database:", err)
	}
	log.Printf("Database Connected")
}

func CloseDB() {
	if db != nil {
		_ = db.Close(context.Background())
		log.Println("Database Connection closed")
	}
}
