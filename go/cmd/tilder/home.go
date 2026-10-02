package main

import (
	"os"
	"path/filepath"
)

func homeDir() (string, error) {
	if dir := os.Getenv("TILDER_HOME"); dir != "" {
		return dir, nil
	}
	user, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(user, ".tilder"), nil
}

func envOr(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}
