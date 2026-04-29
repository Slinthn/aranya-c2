# Run this script alongisde the infected network script
kill_everything() {
    trap - SIGTERM
    docker container rm -f $(docker container ls -aq --filter "name=aranyac2-infected*")
    kill $$
}

trap "kill_everything" SIGTERM SIGINT EXIT

# Create the network if it doesn't exist
docker network create --subnet=172.20.0.0/16 aranyanet

# Build the binary and docker container
cargo build --bin infected
docker build -t aranyac2-infected --build-arg TYPE=infected .

# Run n infected nodes
for i in {0..50}; do
    oct4=$(( i % 256 ))
    oct3=$(( (i / 256) + 1 ))
    docker run --name "aranyac2-infected-$i" -d --network=aranyanet --ip=172.20.$oct3.$oct4 aranyac2-infected &
done

read
