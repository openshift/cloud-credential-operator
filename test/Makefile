# Include bindata targets
include bindata.mk

# Build test dependencies
.PHONY: deps
deps:
	cd e2e && go mod download && go mod tidy

# Run tests
.PHONY: test
test: bindata
	cd e2e && go test ./...

.PHONY: help
help:
	@echo "Available targets:"
	@echo "  bindata     - Generate bindata.go from testdata"
	@echo "  deps        - Download and tidy test dependencies"
	@echo "  test        - Run Go tests"
	@echo "  clean       - Remove generated files"
