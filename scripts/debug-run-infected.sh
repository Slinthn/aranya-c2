trap "trap - SIGTERM && kill -- -$$" SIGTERM SIGINT EXIT

cargo run --bin infected -- 127.0.1.1:4445 &
cargo run --bin infected -- 127.0.1.2:4445 &
cargo run --bin infected -- 127.0.1.3:4445 &
cargo run --bin infected -- 127.0.1.4:4445 &
cargo run --bin infected -- 127.0.1.5:4445 &

read
