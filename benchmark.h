/*
 * benckmark.h
 *
 *  Created on: 4 Jan 2024
 *      Author: massimiliano
 */

#ifndef BENCHMARK_H_
#define BENCHMARK_H_

#include "seal/seal.h"
#include <string>
#include <iostream>
#include <fstream>
#include <ctime>
#include "utils.h"


/*
 * Encryption mode
 */
typedef enum {symmetric, asymmetric} encryption_mode;


/*
 * Benchmark parameter
 */
typedef struct {
	encryption_mode enc_mode;
	seal::sec_level_type sec_level;
	size_t poly_modulus_degree;
	std::vector<int> modulus_bit_sizes;
} benchmark_parms;


/*
 * Benchmark return/outcome
 */
typedef struct {
	std::string setting;
	bool check = true;
	std::string text;
} benchmark_return;


/*
 * Kernel benchmark stats result
 */
typedef struct {
	std::string kernel;
	uint32_t run;
	uint32_t max;
	uint32_t min;
	double avg;
	double s_dev;
} kernel_stats;


/*
 * Benchmark stats result
 */
typedef struct {
	std::string setting;
	std::vector<kernel_stats> stats;
} benchmark_statistics;


inline std::string benchmark_parms_to_string(benchmark_parms benchmark){
	std::string mode = (benchmark.enc_mode==symmetric?"symmetric":"asymmetric");
	std::string modulus;
	for(auto prime : benchmark.modulus_bit_sizes){
		modulus += std::to_string(prime) + ";";
	}
	modulus.pop_back();
	return
			"Mode=" + mode +
			", Level=" + std::to_string((int)benchmark.sec_level) +
			", Degree=" + std::to_string(benchmark.poly_modulus_degree) +
			", Modulus={" + modulus + "}";
};


inline std::string benchmark_return_to_string(benchmark_return ret){
	return ret.setting + ", precision=" + std::to_string(ret.check) + (!ret.text.empty()? (", " + ret.text) : (""));
};


inline kernel_stats calculate_kernel_stats(std::string kernel, std::vector<uint32_t> execs){
	kernel_stats stats;
	stats.kernel = kernel;
	stats.run = positive_value(execs);
	stats.max = max_val(execs);
	stats.min = min_val(execs);
	stats.avg = average(execs);
	stats.s_dev = std_deviation(execs);
	return stats;
};


inline std::string kernel_stats_to_string(kernel_stats stats){
	return stats.kernel + "\t\t" +
			std::to_string(stats.avg) + "\t" +
			std::to_string(stats.s_dev) + "\t" +
			std::to_string(stats.max) + "\t" +
			std::to_string(stats.min) + "\t" +
			std::to_string(stats.run);
}


inline std::string benckmark_statistics_to_string(benchmark_statistics stats){
	std::string s = stats.setting + "\n";
	for(const auto &value : stats.stats){
		s+= kernel_stats_to_string(value) + "\n";
	}
	return s;
}

/*
 * benchmark function
 */

// calculate kernel computation times elaborated on expression -(A^2 + BC + 3D + coeff)
void ckks_kernel_benchmark_expr();

// calculate kernel computation times elaborated as example/8_performance.cpp
void ckks_kernel_benchmark_seal();

void example_ckks_performance_default();

#endif /* BENCHMARK_H_ */
