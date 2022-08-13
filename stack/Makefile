

TEST_ENV = test
REGION = eu-west-1

# stack name may be defined by CI
ifndef STACK_NAME
override STACK_NAME = pii-stack-test
endif

NAME = $(STACK_NAME)

export GRACE_PERIOD=1
export CRON_FUNC=$(NAME)-CronFunction
export AWS_REGION=$(REGION)
export DYNAMODB_TABLE=$(NAME)-table

TEST_PARAMS = Name=$(NAME) GracePeriod=$(GRACE_PERIOD)

stackname:
	echo $(STACK_NAME)

validate:
	sam validate

build:
	sam build --cached

package:
	sam package --output-template-file packaged.yaml --s3-bucket ln80-sam-pkgs

publish:
	sam publish --template packaged.yaml --region eu-west-1

unit/test:
	go test --tags=unit -race -cover ./...

integ/deploy:
	sam deploy \
		--no-confirm-changeset \
		--no-fail-on-empty-changeset \
		--stack-name $(STACK_NAME) \
		--config-env $(TEST_ENV) \
		--capabilities CAPABILITY_IAM\
		--region $(REGION) \
		--parameter-overrides $(TEST_PARAMS)

integ/clear:
	sam delete --no-prompts --stack-name $(STACK_NAME) --region $(REGION)

integ/test:
	go test --tags=integ -race -v