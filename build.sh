#!/usr/bin/env bash

# check for cmake as it's required
if ! command -v cmake &> /dev/null
then
    echo "cmake could not be found please install it"
    exit 1
fi

# check for make
if ! command -v make &> /dev/null
then
    echo "make could not be found please install it"
    exit 1
fi

# make build dir
mkdir -p build
# generate build files
cmake -S ./ -B ./build
# build executable
cmake --build ./build

echo "Executable built u can run it using ./build/packet-sniffer"
