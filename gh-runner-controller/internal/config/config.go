package config

import (
	"fmt"
	"os"
	"time"
)

type Config struct {
	GitHub   GitHubConfig
	Runner   RunnerConfig
	LogLevel string
}

type GitHubConfig struct {
	Token        string
	Organization string
	Repository   string
}

type RunnerConfig struct {
	MinRunners         int
	MaxRunners         int
	ScaleUpThreshold   int
	ScaleDownThreshold int
	CheckInterval      time.Duration
}

func Load() (*Config, error) {
	cfg := &Config{
		GitHub: GitHubConfig{
			Token:        getEnv("GITHUB_TOKEN", ""),
			Organization: getEnv("GITHUB_ORG", ""),
			Repository:   getEnv("GITHUB_REPO", ""),
		},
		Runner: RunnerConfig{
			MinRunners:         getEnvInt("MIN_RUNNERS", 1),
			MaxRunners:         getEnvInt("MAX_RUNNERS", 10),
			ScaleUpThreshold:   getEnvInt("SCALE_UP_THRESHOLD", 5),
			ScaleDownThreshold: getEnvInt("SCALE_DOWN_THRESHOLD", 0),
			CheckInterval:      time.Duration(getEnvInt("CHECK_INTERVAL_SEC", 30)) * time.Second,
		},
		LogLevel: getEnv("LOG_LEVEL", "info"),
	}

	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	return cfg, nil
}

func (c *Config) Validate() error {
	if c.GitHub.Token == "" {
		return fmt.Errorf("GITHUB_TOKEN is required")
	}
	if c.GitHub.Organization == "" && c.GitHub.Repository == "" {
		return fmt.Errorf("either GITHUB_ORG or GITHUB_REPO must be set")
	}
	if c.Runner.MinRunners < 0 {
		return fmt.Errorf("MIN_RUNNERS must be >= 0")
	}
	if c.Runner.MaxRunners < c.Runner.MinRunners {
		return fmt.Errorf("MAX_RUNNERS must be >= MIN_RUNNERS")
	}
	return nil
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvInt(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		var result int
		fmt.Sscanf(value, "%d", &result)
		return result
	}
	return defaultValue
}
