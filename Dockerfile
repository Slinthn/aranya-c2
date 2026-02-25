
FROM ubuntu

ARG TYPE

WORKDIR /
COPY target/debug/${TYPE} /executable

USER root
CMD ["/executable"]
