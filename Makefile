BINARY_NAME = eth-send

# Build the Go application
build:
	go build -o $(BINARY_NAME) main.go

# Run the Go application
run:
	./$(BINARY_NAME)

# Clean build artifacts
clean:
	rm -f $(BINARY_NAME)