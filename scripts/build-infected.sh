cargo build --bin infected
docker build -t infected --build-arg TYPE=infected .
