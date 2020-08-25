#!/bin/bash

RUSTFLAGS='-C link-arg=-s' cargo +stable build -p mock-prover --target wasm32-unknown-unknown --release || exit 1
mkdir -p res
cp target/wasm32-unknown-unknown/release/mock_prover.wasm ../res/
