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
$ g++ -c sample/SHA256.cpp -o lib/libsha256.s -I./include
$ make bin/bls_katzwang_sig.exe
$ ./bls/bls_katzwang_sig.exe
Type your message.
aaa
Type the number of signers.
10
KeyGen Time: 2 [ms]
Round1 Time (generate seed): 0 [ms]
Round2 Time (compute h): 0 [ms]
Compute Sigma Time (compute h): 0 [ms]
Individual Verification Time: 6 [ms]
Signature Aggregation Time: 0 [ms]
Key Check (PoPs) Time: 11 [ms]
Key Aggregation Time: 0 [ms]
Verification Time: 0 [ms]
verification result :Success
```
## Reference

- This repository is forked from [herumi/mcl](https://github.com/herumi/mcl).
- sample/SHA256.cpp and include/SHA256.h are included in [System-Glitch/SHA256](https://github.com/System-Glitch/SHA256).

## License

- For sample/bls_katzwang_sig.cpp: BSD 3-Clause Clear
