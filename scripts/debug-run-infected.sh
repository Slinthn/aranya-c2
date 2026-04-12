trap "trap - SIGTERM && kill -- -$$" SIGTERM SIGINT EXIT
cargo build --bin infected
for i in {1..10}; do
    ./target/debug/infected 127.0.1.$i:4445 &
done

read
