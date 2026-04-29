# Run this script alongisde the infected network script
kill_everything() {
    trap - SIGTERM
    kill $$
}

trap "kill_everything" SIGTERM SIGINT EXIT

# Build the binary
cargo build --bin infected

# Run n infected nodes
for i in {1..1}; do
    oct4=$(( i % 256 ))
    oct3=$(( (i / 256) + 1 ))
    ./target/debug/infected 127.0.$oct3.$oct4:4445 &
done

read
