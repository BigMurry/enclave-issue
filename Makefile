.PHONY: build-eif run log stop all

build-eif:
	docker build -t enclave-issue -f container/enclave.Dockerfile .
	nitro-cli build-enclave --docker-uri enclave-issue --output-file enclave-issue.eif

run:
	nitro-cli run-enclave --cpu-count 2 --memory 512 --enclave-cid 16 --eif-path enclave-issue.eif --debug-mode
	nitro-cli console --enclave-id `nitro-cli describe-enclaves | jq -r ".[0].EnclaveID"` | while IFS= read -r line; do printf '%s %s\n' "$$(date --rfc-3339=ns)" "$$line"; done >> enclave-issue.log 2>&1 &
stop:
	nitro-cli terminate-enclave --enclave-id `nitro-cli describe-enclaves | jq -r ".[0].EnclaveID"`
log:
	nitro-cli console --enclave-id `nitro-cli describe-enclaves | jq -r ".[0].EnclaveID"`

all: build-eif run
