## ----------------------------------------------------------------------
## This makefile can be used to execute common functions to interact with
## the source code, these functions ease local development and can also be
## used in CI/CD pipelines.
## ----------------------------------------------------------------------

golangcilint_version=v1.44.2
certstrap_version=v1.3.0

# REFERENCE: https://stackoverflow.com/questions/16931770/makefile4-missing-separator-stop
help: ## - Show this help.
	@sed -ne '/@sed/!s/## //p' $(MAKEFILE_LIST)

check-lint: ## - validate/install golangci-lint installation
	@which golangci-lint || (go install github.com/golangci/golangci-lint/cmd/golangci-lint@${golangcilint_version})

lint: check-lint ## - lint the source with verbose output
	@golangci-lint run --verbose

build: ## - build the source (latest)
	@docker compose build --build-arg GIT_COMMIT=`git rev-parse HEAD` \
	--build-arg GIT_BRANCH=`git rev-parse --abbrev-ref HEAD`
	@docker image prune -f

run: ## - run the service and its dependencies (docker) detached
	@docker compose up -d

stop:
	@docker compose down

clean:
	@rm -f ./certs/*.*
	@rm -f /usr/local/share/ca-certificates/ca.crt

check-certstrap:
	@which certstrap || go install github.com/sqaure/certstrap@${certstrap_version}

gen-certificates: check-certstrap ## Generate public/private certificates using certstrap
	@certstrap --depot-path ./certs init --common-name "ca" --passphrase=""
	@certstrap --depot-path ./certs request-cert --domain "localhost" --passphrase="" -key ./certs/server.key -csr ./certs/server.csr
	@certstrap --depot-path ./certs request-cert --domain "client" --passphrase="" -key ./certs/client.key -csr ./certs/client.csr
	@certstrap --depot-path ./certs sign localhost --passphrase="" --CA "ca" --csr ./certs/server.csr --cert ./certs/server.crt
	@certstrap --depot-path ./certs sign client --passphrase="" --CA "ca" --csr ./certs/client.csr --cert ./certs/client.crt

install-ca-cert:
	@sudo cp ./certs/ca.crt /usr/local/share/ca-certificates/ca.crt
	@sudo update-ca-certificates