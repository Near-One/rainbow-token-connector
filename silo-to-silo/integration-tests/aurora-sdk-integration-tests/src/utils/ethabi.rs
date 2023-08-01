use aurora_engine_types::types::Address;
use std::path::Path;

#[derive(Debug, Clone, PartialEq)]
pub struct ContractConstructor {
    pub code: Vec<u8>,
    pub abi: ethabi::Contract,
}

impl ContractConstructor {
    pub fn from_extended_json<P>(contract_path: P) -> Self
    where
        P: AsRef<Path>,
    {
        let reader = std::fs::File::open(contract_path).unwrap();
        let contract: ExtendedJsonSolidityArtifact = serde_json::from_reader(reader).unwrap();

        Self {
            abi: contract.abi,
            code: hex::decode(&contract.bytecode[2..]).unwrap(),
        }
    }

    pub fn deployed_at(self, address: Address) -> DeployedContract {
        DeployedContract {
            abi: self.abi,
            address,
        }
    }

    /// Creates the bytes that are used as the input to an EVM transaction for deploying
    /// the Solidity contract (without invoking any constructor). This function does not
    /// interact with any EVM itself, it only produces the bytes needed to pass to an EVM.
    pub fn create_deploy_bytes_without_constructor(&self) -> Vec<u8> {
        self.code.clone()
    }

    /// Creates the bytes that are used as the input to an EVM transaction for deploying
    /// the Solidity contract (includes invoking the constructor that takes no arguments).
    /// This function does not interact with any EVM itself, it only produces the bytes
    /// needed to pass to an EVM.
    pub fn create_deploy_bytes_without_args(&self) -> Vec<u8> {
        self.create_deploy_bytes_with_args(&[])
    }

    /// Creates the bytes that are used as the input to an EVM transaction for deploying
    /// the Solidity contract (includes invoking the constructor with the given arguments).
    /// This function does not interact with any EVM itself, it only produces the bytes
    /// needed to pass to an EVM.
    pub fn create_deploy_bytes_with_args(&self, args: &[ethabi::Token]) -> Vec<u8> {
        self.abi
            .constructor()
            .unwrap()
            .encode_input(self.code.clone(), args)
            .unwrap()
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct DeployedContract {
    pub abi: ethabi::Contract,
    pub address: Address,
}

impl DeployedContract {
    /// Creates the bytes that are used as the input to an EVM transaction for calling the
    /// given function of the Solidity contract. The function must not take any arguments.
    /// This function does not interact with any EVM itself, it only produces the bytes needed
    /// to pass to an EVM.
    pub fn create_call_method_bytes_without_args(&self, method_name: &str) -> Vec<u8> {
        self.create_call_method_bytes_with_args(method_name, &[])
    }

    /// Creates the bytes that are used as the input to an EVM transaction for calling the
    /// given function of the Solidity contract (including passing in the given arguments).
    /// This function does not interact with any EVM itself, it only produces the bytes needed
    /// to pass to an EVM.
    pub fn create_call_method_bytes_with_args(
        &self,
        method_name: &str,
        args: &[ethabi::Token],
    ) -> Vec<u8> {
        self.abi
            .function(method_name)
            .unwrap()
            .encode_input(args)
            .unwrap()
    }
}

#[derive(serde::Deserialize)]
struct ExtendedJsonSolidityArtifact {
    abi: ethabi::Contract,
    bytecode: String,
}
