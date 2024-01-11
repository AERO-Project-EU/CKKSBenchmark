cmake_minimum_required(VERSION 3.10)

# Set some basic project attributes
project (CKKSBenchmark
	VERSION 1.0
	DESCRIPTION "Benchmark of Microsoft SEAL CKKS scheme")

# This project will output an executable file
add_executable(${PROJECT_NAME} CKKSBenchmark.cpp)

# Create a simple configuration header
configure_file(config.h.in config.h)

# Include the configuration header in the build
target_include_directories(${PROJECT_NAME} PUBLIC "${PROJECT_BINARY_DIR}")

target_sources(${PROJECT_NAME} PRIVATE 
	test_mul_depth.cpp
	test_misc.cpp
	1_test_mul_depth_4096_3_ABC.cpp
	2_test_mul_depth_4096_4_ABC.cpp
	3_test_mul_depth_8192_4_ABC.cpp
	4_test_mul_depth_8192_4_ABCD.cpp
	5_test_mul_depth_8192_4_ABCD_ok.cpp
	6_test_add_depth_4096_3_accA.cpp
	7_test_add_depth_4096_4_accA.cpp
	8_test_add_depth_8192_4_accA.cpp
	9_test_muladd_depth_4096_3_AB_plus_accC.cpp
	10_test_muladd_depth_4096_4_AB_plus_accC.cpp
	11_test_muladd_depth_8192_4_ABC_plus_accD.cpp
	12_test_square_depth_4096_3_A.cpp
	13_test_square_depth_4096_4_A.cpp
	14_test_square_depth_8192_4_A.cpp
	15_test_neg_depth_4096_3_A.cpp
	16_test_neg_depth_4096_4_A.cpp
	17_test_neg_depth_8192_4_A.cpp
	18_test_rotate_depth_4096_3_A.cpp
	19_test_rotate_depth_4096_4_A.cpp
	20_test_rotate_depth_8192_4_A.cpp
	21_test_mulplain_depth_4096_3_A.cpp
	22_test_mulplain_depth_4096_4_A.cpp
	23_test_mulplain_depth_8192_4_A.cpp
	24_test_discriminant_2_4096_4.cpp
	25_test_discriminant_2_8192_4.cpp
	26_test_add_different_size_4096_3_AB_plus_C.cpp
	27_test_add_different_size_8192_4_AB_plus_C.cpp
	28_test_add_vs_size_perf_4096_3_AB_plus_C.cpp
	1_kernel_benchmark_expr.cpp
	2_kernel_benchmark_seal.cpp
	8_performance.cpp)

# Microsoft SEAL
find_package(SEAL 4.1.1 REQUIRED)
target_link_libraries(CKKSBenchmark SEAL::seal)