# Device Attestation CLI aliases
# Source this file: . ./da-env.sh
#
# Provides shell functions that mirror the Makefile targets:
#   da-fingerprint              - Display TPM EK fingerprint
#   da-init [SPKI=<pin>] [--manual] - Bootstrap device trust (--force without SPKI)
#   da-lak                      - Provision LAK certificate
#   da-agent                    - Provision agent certificate
#   da-gen USAGE=<name> [OUTPUT=<dir>] - Generate usage certificate

_da_ensure_infra() {
    docker compose up -d openbao init server tpm1 2>&1 | grep -v "^[ ]*Container\|^[ ]*Network\|^time=\|Running\|Created\|Started\|Waiting\|Healthy\|Exited\|warning"
    sleep 3
}

_da_run() {
    docker compose run --rm --no-deps -T client "$@" 2>&1 | grep -v "^[ ]*Container\|^[ ]*Network\|^time=\|Running\|Created\|Started\|Waiting\|Healthy\|Exited\|warning\|^Starting client\|^=\+$\|^ACME Client\|^Setting up socat\|socat proxy ready\|^$"
}

da-fingerprint() {
    docker compose up -d tpm1 2>&1 | grep -v "^[ ]*Container\|^[ ]*Network\|^time=\|Running\|Created\|Started\|Waiting\|Healthy\|Exited\|warning"
    sleep 2
    _da_run /bin/da-fingerprint
}

da-init() {
    _da_ensure_infra
    local spki="sha256//MoFvQ5ANhYPj0mvZIxi0yHruRLj81X51E+prcLrDzQY="
    local manual=""
    for arg in "$@"; do
        case "$arg" in
            SPKI=*) spki="${arg#SPKI=}" ;;
            --manual) manual="--manual" ;;
        esac
    done
    if [ -n "$spki" ]; then
        _da_run /bin/da-init $manual server:50051 "$spki"
    else
        _da_run /bin/da-init $manual --force server:50051
    fi
}

da-lak() {
    _da_ensure_infra
    _da_run /bin/da-lak
}

da-agent() {
    _da_ensure_infra
    _da_run /bin/da-agent
}

da-gen() {
    local usage=""
    local output="./certs"
    for arg in "$@"; do
        case "$arg" in
            USAGE=*) usage="${arg#USAGE=}" ;;
            OUTPUT=*) output="${arg#OUTPUT=}" ;;
        esac
    done
    if [ -z "$usage" ]; then
        echo "USAGE is required. Example: da-gen USAGE=vpn" >&2
        return 1
    fi
    mkdir -p "$output"
    _da_ensure_infra
    docker compose run --rm -v "$(cd "$output" && pwd):/output" client /bin/da-gen --usage "$usage" --output /output 2>&1 | grep -v "^[ ]*Container\|^[ ]*Network\|^time=\|Running\|Created\|Started\|Waiting\|Healthy\|Exited\|warning\|^Starting client\|^=\+$\|^ACME Client\|^Setting up socat\|socat proxy ready\|^$"
}

echo "Device attestation aliases loaded: da-fingerprint, da-init, da-lak, da-agent, da-gen"
