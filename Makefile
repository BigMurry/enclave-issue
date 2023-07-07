.PHONY: build-eif run

build-eif:
	docker build -t enclave-issue -f container/enclave.Dockerfile .
	nitro-cli build-enclave --docuer-uri enclave-issue --output-file enclave-issue.eif

run: build-eif
	nitro-cli run-enclave --cpu-count 1 --memory 256 --enclave-cid 16 --eif-path enclave-issue.eif --debug-mode
	nitro-cli console --enclave-id $(nitro-cli describe-enclaves | jq -r ".[0].EnclaveID") >> enclave-issue.log 2>&1 &
