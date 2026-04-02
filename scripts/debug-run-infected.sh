trap "trap - SIGTERM && kill -- -$$" SIGTERM SIGINT EXIT

for i in {1..20}; do
    cargo run --bin infected -- 127.0.1.$i:4445 &
done

read
