## Mooncoin Core 0.18.1.L


* Hardfork to new codebase occurs at block 1,801,000, however Mooncoin 0.13 and 0.18 wallets will be compatible until this point.

* This new version comes with Likes and MoonWord.

* PoW algorithm is Scrypt.

## Cross-compilation
-------------------

These steps can be performed on, for example, an Ubuntu VM. The depends system
will also work on other Linux distributions, however the commands for
installing the toolchain will be different.

Make sure you install the build requirements mentioned in
[build-unix.md](/doc/build-unix.md).
Then, install the toolchains and curl:

    sudo apt-get install g++-mingw-w64-i686 mingw-w64-i686-dev g++-mingw-w64-x86-64 mingw-w64-x86-64-dev curl libevent-dev libboost-system-dev libboost-filesystem-dev libboost-chrono-dev libboost-program-options-dev libboost-test-dev libboost-thread-dev

To build executables for Windows 32-bit:

    cd depends
    make HOST=i686-w64-mingw32 -j4
    cd ..
    ./configure --prefix=`pwd`/depends/i686-w64-mingw32
    make

To build executables for Windows 64-bit:

    cd depends
    make HOST=x86_64-w64-mingw32 -j4
    cd ..
    ./configure --prefix=`pwd`/depends/x86_64-w64-mingw32
    make
    
To build executables for Linux:

    ./autogen.sh
    ./configure
    if is for server environment add parameters --disable-wallet --without-gui --without-miniupnpc
    make


### Usage

To build dependencies for the current arch+OS:

    make

To build for another arch/OS:

    make HOST=host-platform-triplet

For example:

    make HOST=x86_64-w64-mingw32 -j4

A prefix will be generated that's suitable for plugging into Mooncoin's
configure. In the above example, a dir named x86_64-w64-mingw32 will be
created. To use it for Mooncoin:

    ./configure --prefix=`pwd`/depends/x86_64-w64-mingw32

Common `host-platform-triplets` for cross compilation are:

- `i686-w64-mingw32` for Win32
- `x86_64-w64-mingw32` for Win64
- `x86_64-apple-darwin11` for MacOSX
- `arm-linux-gnueabihf` for Linux ARM 32 bit
- `aarch64-linux-gnu` for Linux ARM 64 bit
_____



### RPC PORT 44663 / P2P PORT 44664

#### Mooncoin started as an early Dogecoin fork (0.6), was upgraded over time to the Litecoin codebase (0.8), since progressing through to a much more modern Litecoin 0.10 codebase - and finally to current platform of Litecoin 0.18.1 with segwit. Built with tomorrow in mind.

