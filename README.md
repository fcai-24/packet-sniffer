# Packet Sniffer

packet sniffer as graduation project using libpcap

## TODOs:
- Add Filters.
- More info when parsing packet layers.
- At 1 custum protocol parsing.
- a graph of connections.

## setup dev env

### make sure cmake is installed at least version 3.25

- ubuntu :
    
    ubuntu default version (installed by `sudo apt install cmake`) is old install it this way

    ```bash
    # uninstall any old version
    sudo apt-get purge --auto-remove cmake

    # go to /opt/cmake
    sudo mkdir -p /opt/cmake && cd /opt/cmake

    # download cmake (this is cmake 3.28)
    sudo wget https://github.com/Kitware/CMake/releases/download/v3.28.0-rc4/cmake-3.28.0-rc4-linux-x86_64.tar.gz

    # extract
    sudo tar -xf ./cmake-3.28.0-rc4-linux-x86_64.tar.gz

    # link to /usr/local/bin (make shortcut to use it from anywhere)
    sudo ln -s ./cmake-3.28.0-rc4-linux-x86_64/cmake /usr/local/bin/cmake

    # now check version
    cmake --version # it should say 3.28.0
    ```

- macos :

    ```bash
    # make sure u have homebrew if not google it

    # install it using howbrew
    brew install cmake
    ```

### run build script

```bash
# clone repo and go inside
git clone --recurse-submodules https://github.com/fcai-24/packet-sniffer.git && cd packet-sniffer

# run build script
./build.sh

# run app
./build/packet-sniffer
```

