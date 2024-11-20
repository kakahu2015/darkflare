.PHONY: all client server clean

all: client server

client:
	go build -o bin/darkflare-client client/main.go

server:
	go build -o bin/darkflare-server server/main.go

clean:
	rm -rf bin/
