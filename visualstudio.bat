@echo off

echo:===============
echo:===============
echo Hi :3
echo:===============
echo:===============
echo make sure u installed CMake, NPcap
echo this will generate visual studio project
echo:===============
echo:===============

echo:
echo: -[hadz] creating build folder ...
if not exist "build" mkdir "build"

echo: -[hadz] creating project files ...
cmake -S . -B build -DPCAP_ROOT="libs\win-pcap"

echo: ===============
echo: ===============
echo: ===============
echo: ===============
echo: ===============

if %errorlevel% neq 0 (echo: -[hadz] error .. make sure that u have cmake and npcap .. also just msg me) else (echo: -[hadz] nice everything should work now try to open build folder and open packet-sniffer.sln)

start build\packet-sniffer.sln

pause
