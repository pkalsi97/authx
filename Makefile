MIGRATE_SCRIPT = ./scripts/migrate.sh
GO_CMD = go run ./cmd/server/main.go

.PHONY: all

all:
	@echo "Running migrations..."
	$(MIGRATE_SCRIPT) up
	@echo "Starting Go server..."
	$(GO_CMD)
