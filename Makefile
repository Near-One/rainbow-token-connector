CARGO = cargo

.PHONY = res/bridge_token.wasm res/bridge_token_factory.wasm res/bridge_token_no_icon.wasm res/bridge_token_factory_no_icon.wasm res/ERC20MetadataLogger.json

all: res/bridge_token.wasm res/bridge_token_factory.wasm res/ERC20MetadataLogger.json

prepare:
	rustup target add wasm32-unknown-unknown

res/bridge_token.wasm: $(shell find bridge-token/src -name "*.rs")
	cd bridge-token && \
	export RUSTFLAGS='-C link-arg=-s' && \
	$(CARGO) build --target wasm32-unknown-unknown --release && \
	cp target/wasm32-unknown-unknown/release/bridge_token.wasm ../res/ && \
	ls -l ../res/bridge_token.wasm

res/bridge_token_factory.wasm: export BRIDGE_TOKEN = $(realpath res/bridge_token.wasm)
res/bridge_token_factory.wasm: res/bridge_token.wasm $(shell find bridge-token-factory/src -name "*.rs")
	cd bridge-token-factory && \
	export RUSTFLAGS='-C link-arg=-s' && \
	$(CARGO) build --target wasm32-unknown-unknown --release && \
	cp target/wasm32-unknown-unknown/release/bridge_token_factory.wasm ../res/ && \
	ls -l ../res/bridge_token_factory.wasm

res/bridge_aurora_token_factory.wasm: export BRIDGE_TOKEN = $(realpath res/bridge_token.wasm)
res/bridge_aurora_token_factory.wasm: res/bridge_token.wasm $(shell find bridge-aurora-token-factory/src -name "*.rs")
	cd bridge-aurora-token-factory && \
	export RUSTFLAGS='-C link-arg=-s' && \
	$(CARGO) build --target wasm32-unknown-unknown --release && \
	cp target/wasm32-unknown-unknown/release/bridge_aurora_token_factory.wasm ../res/ && \
	ls -l ../res/bridge_aurora_token_factory.wasm

res/ERC20MetadataLogger.json: metadata-connector/contracts/ERC20MetadataLogger.sol
	cd metadata-connector && \
	yarn && \
	yarn compile && \
	cp artifacts/contracts/ERC20MetadataLogger.sol/ERC20MetadataLogger.json ../res/ && \
	ls -l ../res/ERC20MetadataLogger.json

test: export BRIDGE_TOKEN = $(realpath res/bridge_token.wasm)
test:
	cd bridge-token-factory && \
	cargo test --all

# <--
# For testing purposes only (can be removed at any moment)
no_icon: res/bridge_token_no_icon.wasm res/bridge_token_factory_no_icon.wasm

res/bridge_token_no_icon.wasm: $(shell find bridge-token/src -name "*.rs")
	cd bridge-token && \
	export RUSTFLAGS='-C link-arg=-s' && \
	BRIDGE_TOKEN=$(realpath ../res/bridge_token.wasm) $(CARGO) build --target wasm32-unknown-unknown --no-default-features --release && \
	cp target/wasm32-unknown-unknown/release/bridge_token.wasm ../res/bridge_token_no_icon.wasm && \
	ls -l ../res/bridge_token_no_icon.wasm

res/bridge_token_factory_no_icon.wasm: export BRIDGE_TOKEN=$(realpath res/bridge_token_no_icon.wasm)
res/bridge_token_factory_no_icon.wasm: res/bridge_token_no_icon.wasm $(shell find bridge-token-factory/src -name "*.rs")
	cd bridge-token-factory && \
	export RUSTFLAGS='-C link-arg=-s' && \
    $(CARGO) build --target wasm32-unknown-unknown --release && \
	cp target/wasm32-unknown-unknown/release/bridge_token_factory.wasm ../res/bridge_token_factory_no_icon.wasm && \
	ls -l ../res/bridge_token_factory_no_icon.wasm
# -->

