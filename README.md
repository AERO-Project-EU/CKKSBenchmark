# CKKS Benchmark for Microsoft SEAL library 

[Microsoft SEAL](https://github.com/microsoft/SEAL/tree/main) is an open-source Homomorphic Encryption (HE) library developed at Microsoft. This C++ library is easy to compile and run in various environments, and allows additions and multiplications to be performed on encrypted integers (BFV and BGV) or real numbers (CKKS). On Intel processors with AVX-512 instruction set, Microsoft SEAL can exploit the [Intel HE Acceleration library](https://github.com/intel/hexl/tree/development), which is an open-source library that provides efficient implementations of low-level kernels and cryptographic primitives used in homomorphic encryption. 

The purpose of CKKSBenchmark is to provide a complete benchmark of the CKKS primitive functions available to the user on `X86_84` and `aarch64` platforms. 

## Introduction

CKKSBenchmark is organized to calculate the expression *-(A<sup>2</sup>+B\*C+coeff_d\*D+coeff_u)*, followed by a back-and-forth rotation of one position of the result. In particular, it ensures that all primitive functions of the library are used at least once, and that the entire computation consumes only one level in the modulus chain. In case of multiple uses of the same primitive, only the first occurrence is benchmarked (light blue node).

![CKKS_benchmark_structure](https://github.com/massidonati/CKKSBenchmark/assets/2460195/d750419a-a9c6-4a2b-a55d-283869e7d028)

## Requirements

CKKSBenchmark is built with CMake. It requires the following dependencies on Linux systems:

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
> [!NOTE]
> This option is only available on Intel CPUs with AVX-512 feature set. [More information](https://github.com/intel/hexl/blob/development/README.md)

## Configuration, building and running

### Configuation

CKKSBenchmark has some configuration parameters, which can be modified in the file `1_kernel_benchmak_expr.cpp`

|    Parameter    |    Default    |    Description                      |
|-----------------|---------------|-------------------------------------|
| BENCH_UNIT      | 0             | Select the measurement unit: 0 for us or 1 for clock_cycles | 
| run             | 10            | Number of benchmark repetitions per setting   |
| num_bin         | 10            | Number of elements in the input vectors. It must be <= poly_modulus_degree/2 for each setting |
| csv_output      | true          | Output files in csv format, one per setting |
| range_limit     | 100.0         | Random input interval bounds \[-range_limit, range_limit\] |
| benchmark_settings | | Vector of structs that define the benchmarking settings. See table below for details |

Each benchmark setting, and the related SEAL context, can be configured by adding an element to the `benchmark_settings` vector. The setting parameters are:

|    Parameter    |    Values    |    Description                      |
|-----------------|--------------|-------------------------------------|
| encryption_mode | symmetric / asymmetric | Using of symmetric key or public/private keys |
| sec_level       | seal::sec_level_type::tc128 / tc192 / tc256 | Security level in bits |
| poly_modulus_degree | 4096 / 8192 / 16384 / 32768 | Degree of a power-of-two cyclotomic polynomial. 
| modulus_bit_sizes | e.g. {60,40,40,60} | Bit-lenghts of distinct prime numbers multiplied for obtaining the coeff_modulus parameter. Max size of each factor is 60 bits |

> [!NOTE]
> + A larger value of poly_modulus_degree makes ciphertext sizes larger and all operations slower, but enables more complicated encrypted computations.
> + A larger coeff_modulus implies a larger noise budget, hence more encrypted computation capabilities. The sum of bit-lengths is limited for each poly_modulus_degree and security level as reported in [SEAL documentation](https://github.com/microsoft/SEAL/blob/88bbc51dd684b82a781312ff04abd235c060163e/native/examples/1_bfv_basics.cpp#L69)
> + As reported in [SEAL documentation](https://github.com/microsoft/SEAL/blob/88bbc51dd684b82a781312ff04abd235c060163e/native/examples/4_ckks_basics.cpp), a general strategy to choose modulus_bit_sizes is:
>   - Choose a large prime as the first element (`P_0`)
>   - Choose the intermediate primes to be close to each other (`P_1,...,P_i-2`)
>   - Choose the last prime to be as large as the largest of the other primes (`P_i-1`)
> + The benchmark will automatically use the first intermediate prime to calculate the scale factor `S` for scaling the input values (double) as 2^P_1  

### Building and running

All the following commands are assumed to be executed in a directory `CKKSBenchmark`, where the user has cloned the repository.
```
cmake -S . -B build -DSEAL_ROOT=<path/to/local/install>
cmake --build build
build/CKKSBenchmark
```
> [!NOTE]
> The option `SEAL_ROOT` is required only if a local installation of Microsoft SEAL library is used.

### Output

For each setting the benchmark output consists of the `Avg`, `S_dev`, `Max`, and `Min` execution time according to the configured unit. It also provides the `Run` value to indicate the number of iterations run without errors. 

In addition, it also provides `Avg_o`, `Outlier`, and `Outlier %`, which are respectively the average execution time after outliers removal, the number and the percentage of outliers extracted using the interquartile approach. 

When configured, a csv file is created for each benchmarked setting in the folder `output`.
