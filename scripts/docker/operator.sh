# Run this with the infected network. This will run the operator
kill_operator() {
    docker container rm -f $(docker container ls -aq --filter "name=aranyac2-operator*")
}

trap "kill_operator" SIGTERM SIGINT EXIT

# Create the network if it doesn't exist
docker network create --subnet=172.20.0.0/16 aranyanet

cargo build --bin operator
docker build -t aranyac2-operator --build-arg TYPE=operator .

docker run --name "aranyac2-operator" -it --network=aranyanet --ip=172.20.0.2 aranyac2-operator

# NOTE: Now, run commands like:
#   set callback 172.20.0.2:4447
#   addpeer 172.20.1.2:4445
