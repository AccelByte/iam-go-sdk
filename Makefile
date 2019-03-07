clean:
	rm coverage.out

test:
	GO111MODULE=on go test -cover ./...

coverage:
	GO111MODULE=on go test -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out
