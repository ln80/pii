DOCKER_NETWORK = dev-local
DYNAMODB_PORT  = 8070
DYNAMODB_VOLUME = dynamodb-local-v2.0

start-dynamodb:
	docker run -p $(DYNAMODB_PORT):8000 amazon/dynamodb-local -jar DynamoDBLocal.jar -inMemory


test/dynamodb: export DYNAMODB_ENDPOINT = http://localhost:$(DYNAMODB_PORT)
test/dynamodb:
	gotest -race -v -cover ./dynamodb/...