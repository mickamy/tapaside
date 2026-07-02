APP_NAME  = tapaside
BUILD_DIR = bin

.PHONY: all build install uninstall clean test lint

all: build

build:
	@mkdir -p $(BUILD_DIR)
	go build -o $(BUILD_DIR)/$(APP_NAME) .

install:
	@bin_dir=$$(go env GOBIN); \
	if [ -z "$$bin_dir" ]; then \
		bin_dir=$$(go env GOPATH)/bin; \
	fi; \
	mkdir -p "$$bin_dir"; \
	go build -o "$$bin_dir/$(APP_NAME)" .

uninstall:
	@bin_dir=$$(go env GOBIN); \
	if [ -z "$$bin_dir" ]; then \
		bin_dir=$$(go env GOPATH)/bin; \
	fi; \
	rm -f "$$bin_dir/$(APP_NAME)"

clean:
	rm -rf $(BUILD_DIR)

test:
	go test ./... -race

lint:
	@command -v golangci-lint >/dev/null 2>&1 || { \
		echo "golangci-lint is not installed"; \
		exit 1; \
	}
	golangci-lint run
