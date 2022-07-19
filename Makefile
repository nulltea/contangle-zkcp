HACKED_CIRCOM_PATH=~/repos/circom/Cargo.toml

build-circom:
	cargo run --manifest-path $HACKED_CIRCOM_PATH -- $CIRCUIT.circom --r1cs --wasm --sym -o build
