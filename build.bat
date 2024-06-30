@echo off

cmake --build ./build -j12

start build/Debug/packet-sniffer.exe
