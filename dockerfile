FROM golang:1.24-alpine AS build
RUN apk add --no-cache bash openssl make
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go build -o authx ./cmd/server/main.go

FROM golang:1.24-alpine
WORKDIR /app
RUN apk add --no-cache bash openssl make

COPY --from=build /app/authx .
COPY --from=build /app/Makefile .

COPY ./keys ./keys
COPY ./migrations ./migrations
COPY .env .env
RUN chmod +x ./authx

EXPOSE 3000
CMD ["make", "all"]
