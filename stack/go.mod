module github.com/ln80/pii/stack

go 1.17

require (
	github.com/aws/aws-lambda-go v1.32.0
	github.com/aws/aws-sdk-go-v2/config v1.15.8
	github.com/aws/aws-sdk-go-v2/service/dynamodb v1.15.6
	github.com/ln80/pii v0.2.1
)

require (
	github.com/aws/aws-sdk-go-v2 v1.16.5
	github.com/aws/aws-sdk-go-v2/credentials v1.12.3 // indirect
	github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue v1.9.2 // indirect
	github.com/aws/aws-sdk-go-v2/feature/dynamodb/expression v1.4.8 // indirect
	github.com/aws/aws-sdk-go-v2/feature/ec2/imds v1.12.5 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.1.12 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.4.6 // indirect
	github.com/aws/aws-sdk-go-v2/internal/ini v1.3.12 // indirect
	github.com/aws/aws-sdk-go-v2/service/dynamodbstreams v1.13.5 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding v1.9.2 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/endpoint-discovery v1.7.6 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.9.5 // indirect
	github.com/aws/aws-sdk-go-v2/service/kms v1.17.1 // indirect
	github.com/aws/aws-sdk-go-v2/service/lambda v1.23.2
	github.com/aws/aws-sdk-go-v2/service/sso v1.11.6 // indirect
	github.com/aws/aws-sdk-go-v2/service/sts v1.16.6 // indirect
	github.com/aws/smithy-go v1.11.3 // indirect
	github.com/jmespath/go-jmespath v0.4.0 // indirect
)

// replace github.com/ln80/pii v0.2.1 => ../
