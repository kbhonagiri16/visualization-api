FROM golang:alpine
MAINTAINER Kalyan Bhonagiri kbhonagiri@mirantis.com

RUN apk update && apk add --no-cache git \
    make g++
ADD . /go/src/visualization-api
WORKDIR /go/src/visualization-api
RUN make init
RUN mkdir -p /etc/platformvisibility/visualization-api && \
    mkdir -p /var/log/platformvisibility/
COPY etc/platformvisibility/visualization-api/visualization-api.toml \
    /etc/platformvisibility/visualization-api/visualization-api.toml
RUN go run pkg/cmd/visualizationapi/main.go
