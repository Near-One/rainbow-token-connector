#!/usr/bin/env bash

# Exit script as soon as a command fails.
set -e

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

arch=`uname -m`
if [ "$arch" == "arm64" ]
then
    tag=":latest-arm64"
else
    tag=""
fi

docker run \
     --rm \
     --mount type=bind,source=$DIR/..,target=/host \
     --cap-add=SYS_PTRACE --security-opt seccomp=unconfined \
     -w /host/bridge-token-factory \
     -e RUSTFLAGS='-C link-arg=-s' \
     -e BRIDGE_TOKEN=/host/res/bridge_token.wasm \
     nearprotocol/contract-builder$tag \
     /bin/bash -c "rustup target add wasm32-unknown-unknown; cargo build --target wasm32-unknown-unknown --release"

mkdir -p res
cp $DIR/target/wasm32-unknown-unknown/release/bridge_token_factory.wasm $DIR/../res/
