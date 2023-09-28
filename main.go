package main

import (
	"log"

	"github.com/glebpepega/auth/internal/server"
	"github.com/joho/godotenv"
)

func loadEnv() {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}
}

func main() {
	loadEnv()
	server.New().Start()
}
