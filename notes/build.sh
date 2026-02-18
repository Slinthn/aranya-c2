pushd aranya-core/crates/aranya-policy-compiler
cargo build
popd

pushd aranya-core/crates/aranya-policy-ifgen
cargo build
popd

aranya-core/target/debug/policy-compiler src/policy.md
