CARGO = cargo

all: res/bridge_token.wasm res/bridge_token_factory.wasm

res/bridge_token.wasm:
	cd bridge-token && \
	RUSTFLAGS='-C link-arg=-s' $(CARGO) build --target wasm32-unknown-unknown --release && \
	cp target/wasm32-unknown-unknown/release/bridge_token.wasm ../res/ && \
	ls -l ../res/bridge_token.wasm

res/bridge_token_factory.wasm: res/bridge_token.wasm
	cd bridge-token-factory && \
	RUSTFLAGS='-C link-arg=-s' $(CARGO) build --target wasm32-unknown-unknown --release && \
	cp target/wasm32-unknown-unknown/release/bridge_token_factory.wasm ../res/ && \
	ls -l ../res/bridge_token_factory.wasm

# <--
# For testing purposes only (can be removed at any moment)
res/bridge_token_no_icon.wasm:
	cd bridge-token && \
	RUSTFLAGS='-C link-arg=-s' $(CARGO) build --target wasm32-unknown-unknown --no-default-features --release && \
	cp target/wasm32-unknown-unknown/release/bridge_token.wasm ../res/bridge_token_no_icon.wasm && \
	ls -l ../res/bridge_token_no_icon.wasm

res/bridge_token_factory_no_icon.wasm: res/bridge_token_no_icon.wasm
	cd bridge-token-factory && \
	RUSTFLAGS='-C link-arg=-s' $(CARGO) build --target wasm32-unknown-unknown --release && \
	cp target/wasm32-unknown-unknown/release/bridge_token_factory.wasm ../res/bridge_token_factory_no_icon.wasm && \
	ls -l ../res/bridge_token_factory_no_icon.wasm
# -->

