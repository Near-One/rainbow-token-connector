#!/usr/bin/env bash

# Exit script as soon as a command fails.
set -e

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

docker run \
     --mount type=bind,source=$DIR/..,target=/host \
     --cap-add=SYS_PTRACE --security-opt seccomp=unconfined \
     -w /host/bridge-token-factory \
     -e RUSTFLAGS='-C link-arg=-s' \
     nearprotocol/contract-builder \
     cargo +stable build --target wasm32-unknown-unknown --release

mkdir -p res
cp $DIR/target/wasm32-unknown-unknown/release/bridge_token_factory.wasm $DIR/../res/
