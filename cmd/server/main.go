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
	"github.com/pkalsi97/authx/internal/core"
	"github.com/pkalsi97/authx/internal/db"
	"github.com/pkalsi97/authx/internal/server"
	"github.com/pkalsi97/authx/internal/utils"
)

// @title AuthX API
// @version 1.0
// @description Authentication and credential management APIs.
// @host localhost:3000
// @BasePath /
// @schemes http https
// @securityDefinitions.apikey BearerAuth
// @in header
// @name Authorization
// @description JWT access token. Format: Bearer {token}

func main() {
	cfg := config.LoadConfig()
	port := cfg.Port
	dbUrl := cfg.DbUrl
	redisAddr := cfg.RedisAddr
	redisDb := cfg.RedisDb
	privateKeyPath := cfg.PrivateKeyPath
	publicKeyPath := cfg.PublicKeyPath

	keys, err := config.LoadKeys(privateKeyPath, publicKeyPath)
	if err != nil {
		log.Fatalf("Unable to load keys: %v", err)
	}

	utils.InitialiseTokenGen(keys.Private, keys.Public)
	if err := utils.InitialiseJWKS(); err != nil {
		log.Fatalf("Unable to Initialise JWKS: %v", err)
	}

	utils.InitaliseValidator()

	db.StartDb(dbUrl)
	db.StartRedis(redisAddr, redisDb)

	mux := server.SetUpRoutes(utils.JWKS)
	server := &http.Server{
		Addr:    ":" + port,
		Handler: core.LoggingMiddleware(mux),
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
