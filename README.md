# Benchmark of CKKS schema in Microsoft SEAL library 


## Structure of the benchmark

## Preliminary setup 

INSTALLING SEAL library locally (from SEAL-main folder)

cmake -S . -B build -DCMAKE_INSTALL_PREFIX=<path/to/local/install>

cmake --build build

cmake --install build


INSTALLING SEAL library with HEXL support locally (from SEAL-main folder)

cmake -S . -B build -DSEAL_USE_INTEL_HEXL=on -DCMAKE_INSTALL_PREFIX=<path/to/local/install>

cmake --build build

cmake --install build


## Building and running

COMPILING and running CKKSBenchmark with local SEAL library (from CKKSBenchmark-main folder)

cmake -S . -B build -DSEAL_ROOT=<path/to/local/install>

cmake --build build

build/CKKSBenchmark
