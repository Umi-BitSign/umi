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
    *'"expected_root":"0x2222222222222222222222222222222222222222222222222222222222222222"'*'"extrinsics":["0x6669727374","0x7365636f6e64"]'*'"schema":"umi-substrate-extrinsics-root/1"'*'"state_version":1'*)
        printf '{"schema":"umi-substrate-proof-result/1","request_id":"%s","ok":true}\n' "$request_id"
        ;;
    *'"extrinsics":["0x696e76616c69642d726f6f74"]'*'"schema":"umi-substrate-extrinsics-root/1"'*)
        printf '{"schema":"umi-substrate-proof-result/1","request_id":"%s","ok":false,"error_code":"invalid_extrinsics_root"}\n' "$request_id"
        ;;
    *'"items":[{"key":"0x61","value":null},{"key":"0x62","value":"0x"}]'*'"proof":["0x6e6f64652d31","0x6e6f64652d32"]'*)
        case "$request" in
            *'"items":[{"key":"0x61","value":null},{"key":"0x62","value":"0x"}]'*'"proof":["0x6e6f64652d31","0x6e6f64652d32"]'*'"schema":"umi-substrate-proof/1"'*'"state_root":"0x1111111111111111111111111111111111111111111111111111111111111111"'*'"state_version":1'*) ;;
            *) exit 92 ;;
        esac
        printf '{"schema":"umi-substrate-proof-result/1","request_id":"%s","ok":true}\n' "$request_id"
        ;;
    *'"items":[{"key":"0x6b6579","value":"0x76616c7565"}]'*'"proof":["0x70726f6f66"]'*)
        case "$request" in
            *'"items":[{"key":"0x6b6579","value":"0x76616c7565"}]'*) ;;
            *) exit 93 ;;
        esac
        printf '{"schema":"umi-substrate-proof-result/1","request_id":"%s","ok":true}\n' "$request_id"
        ;;
    *'"proof":["0x6572726f722d696e76616c69645f696e707574"]'*)
        printf '{"schema":"umi-substrate-proof-result/1","request_id":"%s","ok":false,"error_code":"invalid_input"}\n' "$request_id"
        ;;
    *'"proof":["0x6572726f722d756e737570706f727465645f73746174655f76657273696f6e"]'*)
        printf '{"schema":"umi-substrate-proof-result/1","request_id":"%s","ok":false,"error_code":"unsupported_state_version"}\n' "$request_id"
        ;;
    *'"proof":["0x6572726f722d6475706c69636174655f6e6f6465"]'*)
        printf '{"schema":"umi-substrate-proof-result/1","request_id":"%s","ok":false,"error_code":"duplicate_node"}\n' "$request_id"
        ;;
    *'"proof":["0x6572726f722d696e76616c69645f70726f6f66"]'*)
        printf '{"schema":"umi-substrate-proof-result/1","request_id":"%s","ok":false,"error_code":"invalid_proof"}\n' "$request_id"
        ;;
    *'"proof":["0x6d616c666f726d65642d6e6f742d6a736f6e"]'*)
        printf 'not-json\n'
        ;;
    *'"proof":["0x6d616c666f726d65642d656d7074792d6f626a656374"]'*)
        printf '{}\n'
        ;;
    *'"proof":["0x6d616c666f726d65642d77726f6e672d6964"]'*)
        printf '{"schema":"umi-substrate-proof-result/1","request_id":"wrong","ok":true}\n'
        ;;
    *'"proof":["0x6d616c666f726d65642d6578747261"]'*)
        printf '{"schema":"umi-substrate-proof-result/1","request_id":"wrong","ok":true}\nextra\n'
        ;;
    *'"proof":["0x74696d656f7574"]'*)
        /bin/sleep 10
        ;;
    *'"proof":["0x6e6f6e7a65726f"]'*)
        printf 'sensitive diagnostic\n' >&2
        exit 7
        ;;
    *'"proof":["0x756e75736564"]'*)
        printf 'unused\n'
        ;;
    *)
        exit 99
        ;;
esac
