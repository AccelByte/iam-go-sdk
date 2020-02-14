clean:
	rm coverage.out

test:
	docker-compose -f docker-compose-test.yml up -d
	sleep 30
	GO111MODULE=on go test -cover ./...
	docker-compose -f docker-compose-test.yml down

coverage:
	GO111MODULE=on go test -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out
