#!/bin/bash

RUSTFLAGS='-C link-arg=-s' cargo +stable build -p bridge-token-factory --target wasm32-unknown-unknown --release || exit 1
mkdir -p res
cp target/wasm32-unknown-unknown/release/bridge_token_factory.wasm ../res/
