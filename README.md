# CKKS Benchmark for Microsoft SEAL library 


## Introduction

CKKSBenchmark is organized to calculate the expression -(A<sup>2</sup>+B\*C+coeff_d\*D+coeff_u), followed by a back-and-forth rotation of one position of the result. In particular, it ensures that all primitive functions of the library are used at least once, and that the entire computation consumes only one level in the modulus chain. In case of multiple uses of the same primitive, only the first occurrence is benchmarked (light blue node).

![CKKS_benchmark_structure](https://github.com/massidonati/CKKSBenchmark/assets/2460195/d750419a-a9c6-4a2b-a55d-283869e7d028)



## Requirements

CKKSBenchmark is built with CMake on X86_84 and aarch64 platforms. It requires the following dependencies on Linux systems:

|  Dependency  |  Version  |
|--------------|-----------|
| CMake        | >=3.13    |
| SEAL         | 4.1.1     |



> [!NOTE]
> For requirements to build the Microsoft SEAL library, please refer to [this link](https://github.com/microsoft/SEAL#requirements).

## Preliminary setup 

All the following commands are assumed to be executed in a directory `SEAL`, where the user has cloned the Microsoft SEAL library.

### Building Microsoft SEAL
```
cmake -S . -B build
cmake --build build
```
After the build completes, the output binaries can be found in `build/lib/` and `build/bin/` directories.

### Installing Microsoft SEAL globally
Microsoft SEAL can be installed globally as follows:
```
cmake -S . -B build
cmake --build build
cmake --install build
```
> [!NOTE]
> It requires root root privileges

### Installing Microsoft SEAL locally
The `CMAKE_INSTALL_PREFIX` option allows to install Microsoft SEAL locally. 
For example, the following commands install the library to `~/mylibs/`:
```
cmake -S . -B build -DCMAKE_INSTALL_PREFIX=~/mylibs/
cmake --build build
cmake --install build
```

### Building Microsoft SEAL with HE Acceleration Library (HEXL) 
The use of Microsoft HE Acceleration Library can be enabled at building time with the option `SEAL_USE_INTEL_HEXL` as follows:
```
cmake -S . -B build -DSEAL_USE_INTEL_HEXL=on
```


## Configuration, building and running

COMPILING and running CKKSBenchmark with local SEAL library (from CKKSBenchmark-main folder)

cmake -S . -B build -DSEAL_ROOT=<path/to/local/install>

cmake --build build

build/CKKSBenchmark
