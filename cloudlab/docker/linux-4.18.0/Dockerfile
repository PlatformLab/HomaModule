# Dockerfile for creating environment for building 4.18.0 kernels

FROM ubuntu:18.04

RUN apt-get update && apt-get install -y \
    build-essential \
    gcc-8 \
    g++-8 \
    libncurses-dev \
    bison \
    flex \
    libssl-dev \
    libelf-dev \
    bc \
    rsync \
    kmod \
    cpio \
    liblz4-tool \
    git \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /users/ouster /ouster

WORKDIR /users/ouster
