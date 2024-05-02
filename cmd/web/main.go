package main

import (
	"context"
	"database/sql"
	"flag"
	"log"
	"os"

	jwt "github.com/evgeniiburdin/gin_postgres_jwt_practice_1/middlewares/auth"
	"github.com/evgeniiburdin/gin_postgres_jwt_practice_1/pkg/models/postgres"
	appCache "github.com/evgeniiburdin/gin_postgres_jwt_practice_1/pkg/models/redis"
	"github.com/go-redis/redis/v8"
	_ "github.com/lib/pq"
)

type Application struct {
	errorLog *log.Logger
	infoLog  *log.Logger
	storage  postgres.Storage
	cache    appCache.Cache
	auth     jwt.AuthMiddleware
}

func main() {
	dbConnStr := flag.String("dsn", `host=localhost port=5432 user=postgres 
	password=superuser dbname=snippetbox3 sslmode=disable`, "data source name")

	flag.Parse()

	infoLog := log.New(os.Stdout, "INFO\t", log.Ldate|log.Ltime)
	errorLog := log.New(os.Stdout, "ERROR\t", log.Ldate|log.Ltime|log.Lshortfile)

	db, err := DBconnect(*dbConnStr)
	if err != nil {
		errorLog.Fatal(err)
	}
	defer db.Close()

	redisInstance, redisContext, err := RedisConnect()
	if err != nil {
		errorLog.Fatal(err)
	}
	defer redisInstance.Close()

	app := &Application{
		errorLog: errorLog,
		infoLog:  infoLog,
		storage:  &postgres.PostgresStorage{DB: db},
		cache:    &appCache.RedisCache{RedisI: redisInstance, RedisC: redisContext},
		auth:     &jwt.JWTAuthMiddleware{},
	}

	errorLog.Fatal(app.runServer())
}

func DBconnect(dbConnStr string) (*sql.DB, error) {
	db, err := sql.Open("postgres", dbConnStr)
	if err != nil {
		return nil, err
	}
	if err = db.Ping(); err != nil {
		return nil, err
	}
	return db, nil
}

func RedisConnect() (*redis.Client, *context.Context, error) {
	ctx := context.Background()
	rdb := redis.NewClient(&redis.Options{
		Addr:     "localhost:6379",
		Password: "",
		DB:       0,
	})
	_, err := rdb.Ping(ctx).Result()
	if err != nil {
		return nil, nil, err
	}
	return rdb, &ctx, nil
}
