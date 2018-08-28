BINARY_NAME = thales9000_tool

build:
	cd ./tools && go build -o $(BINARY_NAME) -v

run: 
	cd ./tools && go build -o $(BINARY_NAME) -v 
	./tools/$(BINARY_NAME)

test:
	go test -v .

linux-build:
	cd ./tools && GOOS=linux GOARCH=amd64 go build -o $(BINARY_NAME) -v

darwin-build:
	cd ./tools && GOOS=darwin GOARCH=amd64 go build -o $(BINARY_NAME) -v

windows-build:
	cd ./tools && GOOS=windows GOARCH=amd64 go build -o $(BINARY_NAME).exe -v

docker:
	docker build -t $(BINARY_NAME) .

clean:
	go clean
	rm -f ./tools/$(BINARY_NAME)*

.PHONY: build run test linux-build darwin-build windows-build docker clean
