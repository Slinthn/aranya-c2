kill_everything() {
    trap - SIGTERM
    docker container rm -f $(docker container ls -aq)
    kill $$
}

if [ "$#" -ne 1 ]; then
    echo "Usage: $0 [DOCKER IMAGE]"
    echo
    echo "Docker images:"
    docker image ls -a
    exit
fi

trap "kill_everything" SIGTERM SIGINT EXIT

echo "Starting infected nodes with Docker..."

for i in {1..50}; do
    docker run --name "infected-$i" -d --network=aranyanet --ip=172.20.1.$i $1
done

# Singular exposed instance (i.e. like not behind firewall idea)
# docker run --name "infected-exposed" -d --network=aranyanet -p 4242:4445/udp --ip=172.20.0.42 $1

echo "Nodes set up, press Enter to exit all nodes"

read
