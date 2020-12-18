ARG GO_VERSION
FROM golang:${GO_VERSION}
RUN apt update && apt install -y ruby ruby-dev rubygems build-essential rpm && \
    gem install --no-document fpm
WORKDIR /work
COPY . /work