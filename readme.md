# A New Pairing-based Two-round Tightly-secure Multi-signature scheme with Key Aggregation

## What's that?

- This is a repository for the implementation of the new multi-signature.

## Requirements

- `$ sudo apt install libgmp-dev`
- `$ sudo apt install cmake`

## Setup mcl (for Windows)

```
$ git clone https://github.com/aroha3/mcl-with-katz-wang
$ cd mcl
$ make -j4 CXX=clang++
$ mkdir build
$ cd build
$ cmake .. -DCMAKE_CXX_COMPILER=clang++
$ make
$ cd ../bin
$ cmake .. -DBUILD_TESTING=ON
$ make -j4
```
## Run bls_katzwang_sig

(After any modification in `bls_katzwang_sig.cpp`)
```
$ g++ -c sample/SHA256.cpp -o lib/libsha256.a -I./include
$ make bin/bls_katzwang_sig.exe
```
## Reference

- BLS Signature: https://github.com/herumi/mcl
- SHA256: https://github.com/System-Glitch/SHA256
