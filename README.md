# AuthX

AuthX is a **scalable authentication and authorization service** written in Go.
It provides APIs and gRPC services for user authentication, authorization, session management, and RBAC.

## ✨ Features

* Password & OTP login
* Signup with email/phone OTP verification
* JWT-based sessions (refresh & logout)
* Password reset flows
* Role-Based Access Control (RBAC)
* Admin APIs for owners & user pools
* Swagger API documentation
* gRPC service for token introspection

---

## 📖 API Documentation

Swagger UI →

```
http://localhost:3000/api/v1/docs/
```

---

## 🔌 gRPC Service

Exposed on **port 50051**.

```proto
service AuthService {
  rpc IntrospectToken(IntrospectRequest) returns (IntrospectResponse);
}
```

### Test with `grpcurl`

Example token introspection:

```sh
grpcurl -plaintext \
  -d '{"token":"<JWT_ACCESS_TOKEN>"}' \
  localhost:50051 \
  authx.AuthService/IntrospectToken
```

---

## ⚙️ Setup & Installation

### 1. Clone the repo

```sh
git clone https://github.com/pkalsi97/authx.git
cd authx
```

### 2. Post-Clone Setup Commands

Run these commands to get your environment ready:

```sh
# Copy example environment files
cp .env.example .env                # For local development
cp .env.docker.example .env.docker  # For Docker/production

# Initialize Go modules
go mod tidy

# Start server locally
make local

# Or, run using Docker Compose
docker compose up -d --build
docker compose logs -f authx
```

---

### 3. Environment Variables

#### `.env` (Local Development)

```ini
# Server
PORT=3000

# Database (local)
DB_URL=postgres://authx:<DB_PASSWORD>@localhost:5432/authx_db?sslmode=disable

# Redis (local)
REDIS_DB=0
REDIS_ADDR=localhost:6379

# Retry Config
RETRIES=3

# JWT Keys
PRIVATE_KEY_PATH=./keys/private.pem
PUBLIC_KEY_PATH=./keys/public.pem
```

#### `.env.docker` (Docker / Production)

```ini
# Server
PORT=3000

# Database (docker)
DB_URL=postgres://authx:<DB_PASSWORD>@postgres:5432/authx_db?sslmode=disable

# Redis (docker)
REDIS_DB=0
REDIS_ADDR=redis:6379

# Retry Config
RETRIES=3

# JWT Keys
PRIVATE_KEY_PATH=./keys/private.pem
PUBLIC_KEY_PATH=./keys/public.pem
```

> **Note:** Replace `<DB_PASSWORD>` with your actual database password.

---

### 4. Running Locally

```sh
make local
```

This will:

* Generate RSA keys if missing
* Start the server on `http://localhost:3000`
* Serve Swagger docs at `/api/v1/docs/`

---

### 5. Running with Docker Compose

Build and run services in the background:

```sh
docker compose up -d --build
docker compose logs -f authx
```

Services started:

* `authx` → `3000` (HTTP), `50051` (gRPC)
* `postgres` → `5432`
* `redis` → `6379`

---

## 📂 Project Structure

```
/cmd/server/       → main entrypoint
/internal/handlers → API handlers
/proto/            → gRPC service definitions
/migrations/       → database migrations
/keys/             → RSA keys (auto-generated if missing)
Makefile           → build & run commands
Dockerfile         → container build
docker-compose.yml → service orchestration
```

---

## 🧪 Example Workflow

1. Start services with Docker:

```sh
docker compose up -d --build
docker compose logs -f authx
```

2. Open Swagger API docs:

```
http://localhost:3000/api/v1/docs/
```

3. Test gRPC introspection:

```sh
grpcurl -plaintext \
  -d '{"token":"<JWT_ACCESS_TOKEN>"}' \
  localhost:50051 \
  authx.AuthService/IntrospectToken
```

---

## 🔄 Updating to Latest Code

If your `main` branch is behind the remote:

```sh
git checkout main
git fetch origin
git reset --hard origin/main
```

Rebuild or restart Docker services:

```sh
docker compose down
docker compose up -d --build
```

