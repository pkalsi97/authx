MIGRATE_SCRIPT = ./scripts/migrate.sh
GO_CMD = go run ./cmd/server/main.go

.PHONY: all migrate run

all: migrate run

migrate:
	@echo ""
	@output=$$($(MIGRATE_SCRIPT) up 2>&1); \
	if echo "$$output" | grep -q "no change"; then \
		echo "┌─────────────────────────────┐"; \
		echo "│    Database up-to-date      │"; \
		echo "└─────────────────────────────┘"; \
	elif echo "$$output" | grep -q "success"; then \
		echo "┌─────────────────────────────┐"; \
		echo "│    Migrations applied       │"; \
		echo "└─────────────────────────────┘"; \
	else \
		echo "$$output"; \
	fi

run:
	@echo "┌─────────────────────────────┐"
	@echo "│            AUTHX            │"
	@echo "└─────────────────────────────┘"
	@$(GO_CMD) || true
