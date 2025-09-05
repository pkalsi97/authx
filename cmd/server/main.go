package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/pkalsi97/authx/internal/config"
	"github.com/pkalsi97/authx/internal/db"
	"github.com/pkalsi97/authx/internal/server"
)

func main() {
	cfg := config.LoadConfig()
	port := cfg.Port
	dbUrl := cfg.DbUrl
	redisAddr := cfg.RedisAddr
	redisDb := cfg.RedisDb

	db.StartDb(dbUrl)
	db.StartRedis(redisAddr, redisDb)

	mux := server.SetUpRoutes()
	server := &http.Server{
		Addr:    ":" + port,
		Handler: mux,
	}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM, syscall.SIGTSTP)

	go func() {
		log.Printf(" Server running at :%s\n", port)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Server Failed: %v", err)
		}
	}()

	sig := <-sigChan
	log.Printf("Shutdown signal received: %s", sig.String())

	ctxShutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := server.Shutdown(ctxShutdown); err != nil {
		log.Fatalf("Server forced to shutdown: %v", err)
	} else {
		log.Println("Server exited gracefully")
	}

	db.CloseDB()
	db.StopRedis()
}
