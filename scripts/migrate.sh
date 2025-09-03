if [ -f .env ]; then
    export $(grep -v '^#' .env | xargs)
else
    echo ".env file not found. Please create one with DATABASE_URL."
    exit 1
fi


if [ -z "$DB_URL" ]; then
    echo "DATABASE_URL not set in .env"
    exit 1
fi

DB_URL=$DB_URL

MIGRATIONS_DIR="$(pwd)/migrations"

if ! command -v migrate &> /dev/null
then
    echo "golang-migrate CLI not found. Install it first: https://github.com/golang-migrate/migrate"
    exit 1
fi

ACTION=${1:-up}
STEPS=$2

case "$ACTION" in
    up)
        echo "Applying all pending migrations..."
        migrate -path "$MIGRATIONS_DIR" -database "$DB_URL" up
        ;;
    down)
        if [ -z "$STEPS" ]; then
            echo "Please specify number of steps to rollback, e.g., ./migrate.sh down 1"
            exit 1
        fi
        echo "Rolling back $STEPS migration(s)..."
        migrate -path "$MIGRATIONS_DIR" -database "$DB_URL" down "$STEPS"
        ;;
    force)
        if [ -z "$STEPS" ]; then
            echo "Please specify version to force, e.g., ./migrate.sh force 2"
            exit 1
        fi
        echo "Forcing database version to $STEPS..."
        migrate -path "$MIGRATIONS_DIR" -database "$DB_URL" force "$STEPS"
        ;;
    version)
        echo "Current migration version:"
        migrate -path "$MIGRATIONS_DIR" -database "$DB_URL" version
        ;;
    *)
        echo "Usage: $0 {up|down|force|version}"
        exit 1
        ;;
esac
