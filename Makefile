build:
	go generate ./...
	go build -o bin/flowlat cmd/flowlat.go
