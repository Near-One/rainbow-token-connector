#!/usr/bin/env bash

# Exit script as soon as a command fails.
set -e

yarn

# Remove existing files.
rm -f dist/*.sol

# Build contracts
yarn build

function flatten_contracts_and_prepare_res_files () {
    contract_files=$1

    for contract_path in ${contract_files}
    do
        filename=$(basename -- "$contract_path")у
        # Get contract name without extension and without directories.
        contract_name="${filename%.*}"
        echo ${contract_path}
        yarn hardhat flatten "${contract_path}" > "dist/${contract_name}.full.sol"
        # Remove two first redundant lines containing command info from the previous command
        # and the last line containing command execution time
        sed --in-place '1,2d;$d' "dist/${contract_name}.full.sol" | tee
        # Fix for https://github.com/nomiclabs/truffle-flattener/issues/55
        sed --in-place '/^\/\/ SPDX-License-Identifier:/d' "dist/${contract_name}.full.sol"
        cp build/contracts/${contract_name}.sol/${contract_name}.json ../res/.
    done
}

flatten_contracts_and_prepare_res_files "./contracts/*.sol"
