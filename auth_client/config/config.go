package config

import (
	"fmt"
	"os"

	"github.com/joho/godotenv"
)

type Config struct {
	HttpPort string
	AuthPort string
	AuthHost string
	BaseApi  string
}

func New(envPath string) (*Config, error) {
	if err := godotenv.Load(envPath); err != nil {
		return &Config{}, fmt.Errorf("no %s file found, err: %v", envPath, err)
	}

	config := &Config{
		HttpPort: getEnv("HTTP_PORT", "8082"),
		AuthPort: getEnv("AUTH_PORT", "8081"),
		AuthHost: getEnv("AUTH_HOST", "localhost"),
		BaseApi:  getEnv("BASE_API", "/api/v1"),
	}
	return config, nil
}

func getEnv(key string, defaultVal string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return defaultVal
}
