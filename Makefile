# Makefile
.PHONY: build docker-build docker-run help

# Binary name
BINARY_NAME=mcp-link

help: ## Show available commands
	@echo "Available commands:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-15s\033[0m %s\n", $$1, $$2}'

build: ## Build Go binary
	go build -o $(BINARY_NAME) .

docker-build: ## Build Docker image
	docker build -t mcp-link .

docker-run: ## Run Docker container
	docker run -d --name mcp-link -p 8080:8080 mcp-link
