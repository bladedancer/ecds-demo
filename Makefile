BINARY_NAME=ecdsdemo

build:
	GOARCH=amd64 GOOS=linux go build -o bin/${BINARY_NAME} main.go

run:
	./${BINARY_NAME}

build_and_run: build run

clean:
	go clean
	rm bin/${BINARY_NAME}

test:
	go test ./...

test_coverage:
	go test ./... -coverprofile=coverage.out

dep:
	go mod tidy

vet:
	go vet

lint:
	golangci-lint run --enable-all