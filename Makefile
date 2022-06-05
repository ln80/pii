DOCKER_NETWORK = lambda-local

DYNAMODB_PORT  = 8070
DYNAMODB_VOLUME = dynamodb-local-v2.0

KMS_PORT  = 8090

start-dynamodb:
	docker run -p $(DYNAMODB_PORT):8000 amazon/dynamodb-local -jar DynamoDBLocal.jar -inMemory

test/dynamodb: export DYNAMODB_ENDPOINT = http://localhost:$(DYNAMODB_PORT)
test/dynamodb:
	gotest -race -v -cover ./dynamodb/...


start-kms:
	docker run -p $(KMS_PORT):8080 nsmithuk/local-kms

test/kms: export KMS_ENDPOINT = http://localhost:$(KMS_PORT)
test/kms:
	gotest -race -v -cover ./kms/...

test:
	go test -race -cover ./...
