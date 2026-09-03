#!/bin/sh
set -eu

IFS= read -r request
remaining=$(cat)
if [ -n "$remaining" ]; then
    exit 90
fi

request_id=$(printf '%s\n' "$request" | /usr/bin/sed -n 's/.*"request_id":"\([0-9a-f]\{64\}\)".*/\1/p')
if [ ${#request_id} -ne 64 ]; then
    exit 91
fi

case "$request" in
    *'"proof":["0x72656c656173652d6f62736572766174696f6e2d70726f6f662d7631"]'*'"schema":"umi-substrate-proof/1"'*'"state_root":"0x2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a"'*'"state_version":1'*)
        printf '{"schema":"umi-substrate-proof-result/1","request_id":"%s","ok":true}\n' "$request_id"
        ;;
    *)
        printf '{"schema":"umi-substrate-proof-result/1","request_id":"%s","ok":false,"error_code":"invalid_proof"}\n' "$request_id"
        ;;
esac
