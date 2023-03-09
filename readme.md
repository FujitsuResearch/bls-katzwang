# A New Pairing-based Two-round Tightly-secure Multi-signature scheme with Key Aggregation

## What's that?

- This is a repository for the implementation of the new multi-signature.

## Requirements

- `$ sudo apt install libgmp-dev`
- `$ sudo apt install cmake`
- `$ sudo apt install clang`


## Setup mcl (for WSL on Windows)

```
$ git clone https://github.com/FujitsuResearch/bls-katzwang
$ cd bls-katzwang
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

## License

- For sample/bls_katzwang_sig.cpp: BSD 3-Clause Clear
