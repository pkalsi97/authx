MIGRATE_SCRIPT = ./scripts/migrate.sh
GO_CMD = ./authx

.PHONY: all keys migrate run

all: banner keys run

banner:
	@printf "\n\033[1;31m"
	@printf "░█████╗░██╗░░░██╗████████╗██╗░░██╗██╗░░██╗\n"
	@printf "██╔══██╗██║░░░██║╚══██╔══╝██║░░██║╚██╗██╔╝\n"
	@printf "███████║██║░░░██║░░░██║░░░███████║░╚███╔╝░\n"
	@printf "██╔══██║██║░░░██║░░░██║░░░██╔══██║░██╔██╗░\n"
	@printf "██║░░██║╚██████╔╝░░░██║░░░██║░░██║██╔╝╚██╗\n"
	@printf "╚═╝░░╚═╝░╚═════╝░░░░╚═╝░░░╚═╝░░╚═╝╚═╝░░╚═╝\n"
	@printf "\033[0m\n"
keys:
	@printf "\n\033[1;36m=KEYS CHECK =============================\033[0m\n"
	@if [ ! -d ./keys ]; then \
		echo "Creating ./keys directory..."; \
		mkdir ./keys; \
	fi
	@if [ ! -f ./keys/private.pem ] || [ ! -f ./keys/public.pem ]; then \
		printf "Generating RSA key pair... "; \
		spin='|/-\'; \
		for i in $$(seq 1 20); do \
			printf "\b$${spin:$$((i%4)):1}"; \
			sleep 0.05; \
		done; \
		openssl genrsa -out ./keys/private.pem 2048 >/dev/null 2>&1; \
		openssl rsa -in ./keys/private.pem -pubout -out ./keys/public.pem >/dev/null 2>&1; \
		printf "Done\n"; \
	else \
		echo "Keys already exist, skipping generation."; \
	fi
	
run:
	@printf "\n\033[1;32m=AUTHX SERVER ===========================\033[0m\n"
	@printf "Launching server "; \
	spin='|/-\'; \
	for i in $$(seq 1 10); do \
		printf "\b$${spin:$$((i%4)):1}"; \
		sleep 0.05; \
	done; \
	echo "Done"; \
	./authx

