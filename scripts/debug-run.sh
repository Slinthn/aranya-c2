trap "trap - SIGTERM && kill -- -$$" SIGTERM SIGINT EXIT
cargo run --bin operator -- --config-dir /tmp/debugoperator --new-graph --new-rsa --set-callback 127.0.0.1:4447
./scripts/debug-run-infected.sh &
sleep 5
cargo run --bin operator -- --config-dir /tmp/debugoperator --command "cat hello" --start-afc 127.0.1.1:4445

read
