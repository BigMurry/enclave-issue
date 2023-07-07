# test enclave attestation certificate

# steps

1. prepare nitro enclave host machine
  - install docker and enclave cli (https://docs.aws.amazon.com/enclaves/latest/user/nitro-enclave-cli-install.html)
    - in `/etc/nitro_enclaves/allocator.yaml` file, `cpu_count: 2`, `memory_mib: 1024`

2. run enclave

```shell
cd <project>

# this will create the eif file and start the enclave and save log to file "enclave-issue.log"
make all
```

3. check the logs
log file sit at project root directory `enclave-issue.log`
