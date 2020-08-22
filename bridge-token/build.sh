#!/bin/bash

RUSTFLAGS='-C link-arg=-s' cargo +stable build -p bridge-token --target wasm32-unknown-unknown --release || exit 1
mkdir -p res
cp target/wasm32-unknown-unknown/release/bridge_token.wasm ../res/
