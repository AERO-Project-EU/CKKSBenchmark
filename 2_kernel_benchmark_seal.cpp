/*
 * kernel_benchmark_seal.cpp
 *
 *  Created on: 10 Jan 2024
 *      Author: massimiliano
 */

#include "benchmark.h"
#include "utils.h"

using namespace std;
using namespace seal;


/*
 * benchmark unit
 * 0 time (us)
 * 1 clock cycle
 */
#define BENCH_UNIT 0

/*
 * cvs output
 */
const bool csv_output = true;

/*
 * number of benchmark repetitions
 */
const int run = 10;

/*
 * number of input bins
 */
const int num_bin = 10;

/*
 * range limit for input number generation
 */
const double range_limit = 1.0;

/*
 * benchmarking settings
 */
const vector<benchmark_parms> benchmark_settings =
{
		{symmetric,sec_level_type::tc128,4096,{40,25,40}},
//		{symmetric,sec_level_type::tc128,8192,{60,40,40,60}},
//		{symmetric,sec_level_type::tc128,16384,{60,40,40,40,60}},
//		{symmetric,sec_level_type::tc128,32768,{60,40,40,40,40,60}},

//		{symmetric,sec_level_type::tc192,4096,{25,20,25}},
//		{symmetric,sec_level_type::tc192,8192,{55,40,55}},
//		{symmetric,sec_level_type::tc192,16384,{60,40,40,40,60}},
//		{symmetric,sec_level_type::tc192,32768,{60,40,40,40,40,60}},

//		{symmetric,sec_level_type::tc256,4096,{20,16,20}},
//		{symmetric,sec_level_type::tc256,8192,{40,30,40}},
//		{symmetric,sec_level_type::tc256,16384,{60,40,40,60}},
//		{symmetric,sec_level_type::tc256,32768,{60,40,40,40,40,60}},


		//{asymmetric,sec_level_type::tc128,4096,{35,25,35}},
		//{asymmetric,sec_level_type::tc128,8192,{60,40,40,60}}
};

/*
 * This benchmark calculates -(A^2 + BC + 3D + coeff)
 */

void ckks_kernel_benchmark_seal(){

	cout << endl;
	cout << "***********************************" << endl;
	cout << "ckks_kernel_benchmark_seal()" << endl;
	cout << "num. settings " << benchmark_settings.size() << endl;
	cout << "num. repetitions " << run << endl;
	cout << "input data range [" << -range_limit << ", " << range_limit << "]" << endl;
	cout << "***********************************" << endl << endl;

	// declare execution trace variables
	vector<benchmark_return> benchmark_outcome(benchmark_settings.size());

	// declare benchmark statistics variables
	vector<benchmark_statistics> benchmark_stats(benchmark_settings.size());

	// set the scheme for all benchmarks
	EncryptionParameters parms(scheme_type::ckks);

	/*
	 * loop on benchmark settings to execute each of them
	 */
	for(int bench_index=0;bench_index<benchmark_settings.size();bench_index++){

		// current benchmark setting
		benchmark_parms curr_bench = benchmark_settings[bench_index];

		// current benchmark outcome
		benchmark_return *curr_bench_outcome = &benchmark_outcome[bench_index];

		cout << "Setting " << bench_index << " - " << benchmark_parms_to_string(curr_bench) << endl;
		curr_bench_outcome->setting = benchmark_parms_to_string(curr_bench);

		/*
		 * setup encryption parms and context based on the current setting
		 */
		size_t poly_modulus_degree = curr_bench.poly_modulus_degree;
		parms.set_poly_modulus_degree(poly_modulus_degree);
		try{
			parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, curr_bench.modulus_bit_sizes));
		}
		// catch exception and continue to next benchmark setting
		catch (const std::exception &e) {
			cout << "Exception -----> " << e.what() << endl << endl;
			curr_bench_outcome->text += " EXCEPTION_COEFF_SETUP";
			continue;
		}
		// scale fixed to 2^inner_prime_size
		size_t scale_exp = curr_bench.modulus_bit_sizes[1];
		double scale = pow(2.0, scale_exp);

		SEALContext context(parms,true,curr_bench.sec_level);

		print_parameters(context);
		print_modulus_switching_chain(context);

		SecretKey secret_key;
		PublicKey public_key;
		RelinKeys relin_keys;
		GaloisKeys gal_keys;

		try {
			/*
			 * generate keys
			 */
			cout << "### Generating keys...";

			KeyGenerator keygen(context);
			secret_key = keygen.secret_key();

			keygen.create_public_key(public_key);

			keygen.create_relin_keys(relin_keys);

			keygen.create_galois_keys(gal_keys);

			cout << "Done!" << endl << endl;
		}
		// catch exception and continue to next benchmark setting
		catch (const std::exception &e) {
			cout << "Exception -----> " << e.what() << endl << endl;
			curr_bench_outcome->text += " EXCEPTION_KEY_SETUP";
			continue;
		}

	    cout << "Print the parameter IDs of generated keys." << endl;
	    cout << "    + secret_key:  " << secret_key.parms_id() << endl;
	    cout << "    + public_key:  " << public_key.parms_id() << endl;
	    cout << "    + galois_key:  " << gal_keys.parms_id() << endl;
	    cout << "    + relin_keys:  " << relin_keys.parms_id() << endl << endl;

		/*
		 * declare encryptor, decryptor, encoder and evaluator
		 */
	    Encryptor encryptor(context, public_key, secret_key);
	    Decryptor decryptor(context, secret_key);
	    Evaluator evaluator(context);
	    CKKSEncoder encoder(context);

		// declare current benchmark statistics variables
	    vector<uint32_t> encode_series(run,0);
	    vector<uint32_t> encrypt_series(run,0);
	    vector<uint32_t> mul_series(run,0);
	    vector<uint32_t> relin_series(run,0);
	    vector<uint32_t> rescale_series(run,0);
	    vector<uint32_t> mul_plain_series(run,0);
	    vector<uint32_t> square_series(run,0);
	    vector<uint32_t> add_series(run,0);
	    vector<uint32_t> add_plain_series(run,0);
	    vector<uint32_t> negate_series(run,0);
	    vector<uint32_t> rotate_series(run,0);
	    vector<uint32_t> decrypt_series(run,0);
	    vector<uint32_t> decode_series(run,0);

		chrono::high_resolution_clock::time_point time_start, time_end;
		chrono::microseconds time_diff;
		clock_t clk_begin, clk_end;

		/*
		 * loop to execute the current benchmark setting run times
		 */
		for(int run_index=0;run_index<run;run_index++){

			cout << "-------------- Run " << run_index << " --------------" << endl << endl;

			//*****************************************************
			// generate fresh input data
			//*****************************************************
			cout << "### Generating input vector and expected results...";

		    const vector<double> input = generate_random_data(num_bin, -range_limit, range_limit);

		    vector<double> expected(num_bin);

		    cout << "Done!" << endl << endl;

		    try {

				//*****************************************************
				// [ENCODE] encode input data
				//*****************************************************
				cout << "### Encoding input data...";

				Plaintext plain;

				#if(BENCH_UNIT == 0)
				time_start = chrono::high_resolution_clock::now();
				#else
				clk_begin = clock();
				#endif

				// benchmark target
				encoder.encode(input, scale, plain);

				#if(BENCH_UNIT == 0)
				time_end = chrono::high_resolution_clock::now();
				encode_series[run_index] = (chrono::duration_cast<chrono::microseconds>(time_end - time_start).count());
				#else
				clk_end = clock();
				encode_series[run_index] = (clk_end-clk_begin);
				#endif

				cout << "Done!" << endl << endl;

				//*****************************************************
				// [ENCRYPT] encrypt plaintext
				//*****************************************************
				cout << "### Encrypting input data...";

				Ciphertext encr;

				if(curr_bench.enc_mode == symmetric){
					#if(BENCH_UNIT == 0)
					time_start = chrono::high_resolution_clock::now();
					#else
					clk_begin = clock();
					#endif

					// benchmark target
					encryptor.encrypt_symmetric(plain, encr);

					#if(BENCH_UNIT == 0)
					time_end = chrono::high_resolution_clock::now();
					encrypt_series[run_index] = (chrono::duration_cast<chrono::microseconds>(time_end - time_start).count());
					#else
					clk_end = clock();
					encrypt_series[run_index] = (clk_end-clk_begin);
					#endif

				} else {

					#if(BENCH_UNIT == 0)
					time_start = chrono::high_resolution_clock::now();
					#else
					clk_begin = clock();
					#endif

					// benchmark target
					encryptor.encrypt(plain, encr);

					#if(BENCH_UNIT == 0)
					time_end = chrono::high_resolution_clock::now();
					encrypt_series[run_index] = (chrono::duration_cast<chrono::microseconds>(time_end - time_start).count());
					#else
					clk_end = clock();
					encrypt_series[run_index] = (clk_end-clk_begin);
					#endif

				}
				cout << "Done!" << endl << endl;


				/*
				 * prepare other operands as run_index+1
				 */
				Ciphertext encr1, encr2, encr3;
				Plaintext plain1, plain2, plain3;
				encoder.encode((double)run_index+1, scale, plain1);
				encoder.encode((double)run_index+1, scale, plain2);
				encoder.encode((double)run_index+1, scale, plain3);
				encryptor.encrypt(plain1, encr1);
				encryptor.encrypt(plain2, encr2);
				encryptor.encrypt(plain3, encr3);

				//*****************************************************
				// [ADD] add input + (run_index+1)
				//*****************************************************
				cout << "### Add input + (run_index+1)...";

				#if(BENCH_UNIT == 0)
				time_start = chrono::high_resolution_clock::now();
				#else
				clk_begin = clock();
				#endif

				// benchmark target
				evaluator.add_inplace(encr1, encr);

				#if(BENCH_UNIT == 0)
				time_end = chrono::high_resolution_clock::now();
				add_series[run_index] = (chrono::duration_cast<chrono::microseconds>(time_end - time_start).count());
				#else
				clk_end = clock();
				add_series[run_index] = (clk_end-clk_begin);
				#endif

				cout << "Done!" << endl << endl;

				// calculate expected result
				for(int k=0;k<num_bin;k++){
					expected[k] = input[k] + run_index + 1;
				}

				// print and check result
				print_ciphertext_info(encr1, context);
				if(!check_chiphertext(&decryptor, &encoder, encr1, expected)){
					curr_bench_outcome->check = false;
					curr_bench_outcome->text += " ADD_" + std::to_string(run_index);
				}

				/*
				 * Now encr1 = input + (run_index+1) and  encr2 = encr3 = (run_index+1)
				 * plain1, plain2 and plain3 contain (run_index+1)
				 */

				//*****************************************************
				// [MULTIPLY] multiply (input + (run_index+1)) * (run_index+1)
				//*****************************************************
				cout << "### Multiplying (input + (run_index+1)) * (run_index+1)...";

				#if(BENCH_UNIT == 0)
				time_start = chrono::high_resolution_clock::now();
				#else
				clk_begin = clock();
				#endif

				// benchmark target
				evaluator.multiply_inplace(encr1, encr2);

				#if(BENCH_UNIT == 0)
				time_end = chrono::high_resolution_clock::now();
				mul_series[run_index] = (chrono::duration_cast<chrono::microseconds>(time_end - time_start).count());
				#else
				clk_end = clock();
				mul_series[run_index] = (clk_end-clk_begin);
				#endif

				cout << "Done!" << endl << endl;

				// calculate expected result
				for(int k=0;k<num_bin;k++){
					expected[k] = expected[k] * (run_index + 1);
				}

				// print and check result
				print_ciphertext_info(encr1, context);
				if(!check_chiphertext(&decryptor, &encoder, encr1, expected)){
					curr_bench_outcome->check = false;
					curr_bench_outcome->text += " MUL_" + std::to_string(run_index);
				}

				/*
				 * Now encr1 = (input + (run_index+1)) * (run_index+1) and encr2 = encr3 = (run_index+1)
				 * plain1, plain2 and plain3 contain (run_index+1)
				 */

				//*****************************************************
				// [RELIN] relinearize (input + (run_index+1)) * (run_index+1)
				//*****************************************************
				cout << "### Relinearize (input + (run_index+1)) * (run_index+1)...";

				#if(BENCH_UNIT == 0)
				time_start = chrono::high_resolution_clock::now();
				#else
				clk_begin = clock();
				#endif

				// benchmark target
				evaluator.relinearize_inplace(encr1,relin_keys);

				#if(BENCH_UNIT == 0)
				time_end = chrono::high_resolution_clock::now();
				relin_series[run_index] = (chrono::duration_cast<chrono::microseconds>(time_end - time_start).count());
				#else
				clk_end = clock();
				relin_series[run_index] = (clk_end-clk_begin);
				#endif

				cout << "Done!" << endl << endl;

				// print and check result
				print_ciphertext_info(encr1, context);
				if(!check_chiphertext(&decryptor, &encoder, encr1, expected)){
					curr_bench_outcome->check = false;
					curr_bench_outcome->text += " MUL_RELIN_" + std::to_string(run_index);
				}

				//*****************************************************
				// [RESCALE] rescale (input + (run_index+1)) * (run_index+1)
				//*****************************************************
				cout << "### Rescale (input + (run_index+1)) * (run_index+1)...";

				#if(BENCH_UNIT == 0)
				time_start = chrono::high_resolution_clock::now();
				#else
				clk_begin = clock();
				#endif

				// benchmark target
				evaluator.rescale_to_next_inplace(encr1);

				#if(BENCH_UNIT == 0)
				time_end = chrono::high_resolution_clock::now();
				rescale_series[run_index] = (chrono::duration_cast<chrono::microseconds>(time_end - time_start).count());
				#else
				clk_end = clock();
				rescale_series[run_index] = (clk_end-clk_begin);
				#endif

				cout << "Done!" << endl << endl;

				// print and check result
				print_ciphertext_info(encr1, context);
				if(!check_chiphertext(&decryptor, &encoder, encr1, expected)){
					curr_bench_outcome->check = false;
					curr_bench_outcome->text += " MUL_RESCALE_" + std::to_string(run_index);
				}

				//*****************************************************
				// [ROTATE] rotate 1 and -1 step (input + (run_index+1)) * (run_index+1)
				//*****************************************************
				cout << "### Rotate (input + (run_index+1)) * (run_index+1) 1...";

				#if(BENCH_UNIT == 0)
				time_start = chrono::high_resolution_clock::now();
				#else
				clk_begin = clock();
				#endif

				// benchmark target
				evaluator.rotate_vector_inplace(encr1, 1, gal_keys);

				#if(BENCH_UNIT == 0)
				time_end = chrono::high_resolution_clock::now();
				rotate_series[run_index] = (chrono::duration_cast<chrono::microseconds>(time_end - time_start).count());
				#else
				clk_end = clock();
				rotate_series[run_index] = (clk_end-clk_begin);
				#endif

				cout << "Done!" << endl << endl;

				cout << "### Rotate result -1 [NOT BENCHMARKED]...";

				evaluator.rotate_vector_inplace(encr1, -1, gal_keys);

				cout << "Done!" << endl << endl;

				// print and check result
				print_ciphertext_info(encr1, context);
				if(!check_chiphertext(&decryptor, &encoder, encr1, expected)){
					curr_bench_outcome->check = false;
					curr_bench_outcome->text += " ROTATE_" + std::to_string(run_index);
				}

				/*
				 * Now encr1 = (input + (run_index+1)) * (run_index+1)
				 */

				//*****************************************************
				// [NEGATE] negate (input + (run_index+1)) * (run_index+1)
				//*****************************************************
				cout << "### Negate (input + (run_index+1)) * (run_index+1)...";

				#if(BENCH_UNIT == 0)
				time_start = chrono::high_resolution_clock::now();
				#else
				clk_begin = clock();
				#endif

				// benchmark target
				evaluator.negate_inplace(encr1);

				#if(BENCH_UNIT == 0)
				time_end = chrono::high_resolution_clock::now();
				negate_series[run_index] = (chrono::duration_cast<chrono::microseconds>(time_end - time_start).count());
				#else
				clk_end = clock();
				negate_series[run_index] = (clk_end-clk_begin);
				#endif

				cout << "Done!" << endl << endl;

				// calculate expected result
				for(int k=0;k<num_bin;k++){
					expected[k] = -expected[k];
				}

				// print and check result
				print_ciphertext_info(encr1, context);
				if(!check_chiphertext(&decryptor, &encoder, encr1, expected)){
					curr_bench_outcome->check = false;
					curr_bench_outcome->text += " NEGATE_" + std::to_string(run_index);
				}

				/*
				 * Now encr1 = - (input + (run_index+1)) * (run_index+1)
				 */

				//*****************************************************
				// [MULTIPLY_PLAIN] (run_index+1) * (run_index+1)
				//*****************************************************
				cout << "### Multiply_plain (run_index+1) * (run_index+1)...";

				#if(BENCH_UNIT == 0)
				time_start = chrono::high_resolution_clock::now();
				#else
				clk_begin = clock();
				#endif

				// benchmark target
				evaluator.multiply_plain_inplace(encr2, plain2);

				#if(BENCH_UNIT == 0)
				time_end = chrono::high_resolution_clock::now();
				mul_plain_series[run_index] = (chrono::duration_cast<chrono::microseconds>(time_end - time_start).count());
				#else
				clk_end = clock();
				mul_plain_series[run_index] = (clk_end-clk_begin);
				#endif

				cout << "Done!" << endl << endl;

				// calculate expected result
				for(int k=0;k<num_bin;k++){
					expected[k] = (run_index + 1) * (run_index + 1);
				}

				// print and check result
				print_ciphertext_info(encr2, context);
				if(!check_chiphertext(&decryptor, &encoder, encr2, expected)){
					curr_bench_outcome->check = false;
					curr_bench_outcome->text += " MULPLAIN_" + std::to_string(run_index);
				}

				/*
				 * Now encr2 = (run_index+1)^2
				 */

				//*****************************************************
				// [SQUARE] square (run_index+1)^2
				//*****************************************************
				cout << "### Square (run_index+1)^2...";

				#if(BENCH_UNIT == 0)
				time_start = chrono::high_resolution_clock::now();
				#else
				clk_begin = clock();
				#endif

				// benchmark target
				evaluator.square_inplace(encr3);

				#if(BENCH_UNIT == 0)
				time_end = chrono::high_resolution_clock::now();
				square_series[run_index] = (chrono::duration_cast<chrono::microseconds>(time_end - time_start).count());
				#else
				clk_end = clock();
				square_series[run_index] = (clk_end-clk_begin);
				#endif

				cout << "Done!" << endl << endl;

				// print and check result
				print_ciphertext_info(encr2, context);
				if(!check_chiphertext(&decryptor, &encoder, encr2, expected)){
					curr_bench_outcome->check = false;
					curr_bench_outcome->text += " SQUARE_" + std::to_string(run_index);
				}

				/*
				 *
				 * Now encr2 = encr3 = (run_index+1)^2 and encr1 = -(input + (run_index+1)) * (run_index+1)
				 */


				//*****************************************************
				// [DECRYPT] decrypt the encr3 result
				//*****************************************************
				cout << "### Decrypt encr3...";

				#if(BENCH_UNIT == 0)
				time_start = chrono::high_resolution_clock::now();
				#else
				clk_begin = clock();
				#endif

				// benchmark target
				decryptor.decrypt(encr3, plain3);

				#if(BENCH_UNIT == 0)
				time_end = chrono::high_resolution_clock::now();
				decrypt_series[run_index] = (chrono::duration_cast<chrono::microseconds>(time_end - time_start).count());
				#else
				clk_end = clock();
				decrypt_series[run_index] = (clk_end-clk_begin);
				#endif

				cout << "Done!" << endl << endl;

				// print and check result
				print_plaintext_info(plain3, context);
				if(!check_plaintext(&encoder, plain3, expected)){
					curr_bench_outcome->check = false;
					curr_bench_outcome->text += " DECRYPT_3_" + std::to_string(run_index);
				}

				//*****************************************************
				// [DECODE] decode the encr3 result
				//*****************************************************
				cout << "### Decode encr3...";

				vector<double> result;

				#if(BENCH_UNIT == 0)
				time_start = chrono::high_resolution_clock::now();
				#else
				clk_begin = clock();
				#endif

				// benchmark target
				encoder.decode(plain3, result);

				#if(BENCH_UNIT == 0)
				time_end = chrono::high_resolution_clock::now();
				decode_series[run_index] = (chrono::duration_cast<chrono::microseconds>(time_end - time_start).count());
				#else
				clk_end = clock();
				decode_series[run_index] = (clk_end-clk_begin);
				#endif

				cout << "Done!" << endl << endl;

				if(!check_cleartext(result, expected)){
					curr_bench_outcome->check = false;
					curr_bench_outcome->text += " DECODE_3_" + std::to_string(run_index);
				}

				//*****************************************************
				// [DECRYPT] and [DECODE] the encr1 and encr2 results [NOT BENCHMARKED]
				//*****************************************************
				cout << "### Decrypt encr2...";

				decryptor.decrypt(encr2, plain2);

				cout << "Done!" << endl << endl;

				// print and check result
				print_plaintext_info(plain2, context);
				if(!check_plaintext(&encoder, plain2, expected)){
					curr_bench_outcome->check = false;
					curr_bench_outcome->text += " DECRYPT_2_" + std::to_string(run_index);
				}

				cout << "### Decode encr2...";

				encoder.decode(plain2, result);

				cout << "Done!" << endl << endl;

				if(!check_cleartext(result, expected)){
					curr_bench_outcome->check = false;
					curr_bench_outcome->text += " DECODE_2_" + std::to_string(run_index);
				}

				// calculate expected result
				for(int k=0;k<num_bin;k++){
					expected[k] = -((input[k] + (run_index+1)) * (run_index+1));
				}

				cout << "### Decrypt encr1...";

				decryptor.decrypt(encr1, plain1);

				cout << "Done!" << endl << endl;

				// print and check result
				print_plaintext_info(plain1, context);
				if(!check_plaintext(&encoder, plain1, expected)){
					curr_bench_outcome->check = false;
					curr_bench_outcome->text += " DECRYPT_1_" + std::to_string(run_index);
				}

				cout << "### Decode encr1...";

				encoder.decode(plain1, result);

				cout << "Done!" << endl << endl;

				if(!check_cleartext(result, expected)){
					curr_bench_outcome->check = false;
					curr_bench_outcome->text += " DECODE_1_" + std::to_string(run_index);
				}

		    }
		    // catch exception and continue to next run
		    catch (const std::exception &e) {
				cout << "Exception -----> " << e.what() << endl << endl;
				curr_bench_outcome->text += " EXCEPTION_" + std::to_string(run_index);
				continue;
			}

		} // end of loop on run times execution of benchmark

		/*
		 * calculate statistics about the current benchmark setting
		 */

		// current benchmark stats
		benchmark_statistics *curr_bench_stats = &benchmark_stats[bench_index];

		curr_bench_stats->setting = benchmark_parms_to_string(curr_bench);
		curr_bench_stats->stats.push_back(calculate_kernel_stats("ENCODE",encode_series));
		curr_bench_stats->stats.push_back(calculate_kernel_stats("ENCRYPT",encrypt_series));
		curr_bench_stats->stats.push_back(calculate_kernel_stats("ADD",add_series));
		curr_bench_stats->stats.push_back(calculate_kernel_stats("ADD_PL",add_plain_series));
		curr_bench_stats->stats.push_back(calculate_kernel_stats("MUL",mul_series));
		curr_bench_stats->stats.push_back(calculate_kernel_stats("MUL_PL",mul_plain_series));
		curr_bench_stats->stats.push_back(calculate_kernel_stats("SQUARE",square_series));
		curr_bench_stats->stats.push_back(calculate_kernel_stats("NEGATE",negate_series));
		curr_bench_stats->stats.push_back(calculate_kernel_stats("ROTATE",rotate_series));
		curr_bench_stats->stats.push_back(calculate_kernel_stats("RELIN",relin_series));
		curr_bench_stats->stats.push_back(calculate_kernel_stats("RESCALE",rescale_series));
		curr_bench_stats->stats.push_back(calculate_kernel_stats("DECRYPT",decrypt_series));
		curr_bench_stats->stats.push_back(calculate_kernel_stats("DECODE",decode_series));

		/*
		 * csv file output
		 */
		if(csv_output){
			ofstream stats_file;
			string fname = "./output/1_kernel_bench_" +
								to_string(curr_bench.enc_mode) + "_" +
								to_string((int)curr_bench.sec_level) + "_" +
								to_string(curr_bench.poly_modulus_degree) + "_" +
								to_string((int)curr_bench.modulus_bit_sizes.size()) + ".csv";
			// create file
			stats_file.open(fname, ios::out);

			//header
//			string header = to_string((int)curr_bench.enc_mode) + ", " +
//							to_string((int)curr_bench.sec_level) + ", " +
//							to_string((int)curr_bench.poly_modulus_degree) + ", " +
//							to_string((int)curr_bench.modulus_bit_sizes.size());
//			stats_file << header << endl << endl;
			string unit = BENCH_UNIT==0?"us":"cycles";
			stats_file << benchmark_return_to_string(*curr_bench_outcome) << "," << unit << endl << endl;

			// summary
			stats_file << " ,Encode,Encrypt,Add,Add_pl,Mul,Mul_pl,Square,Negate,Rotate,Relin,Rescale,Decrypt,Decoded" << endl;
			stats_file << "Avg," << curr_bench_stats->stats[0].avg << "," << curr_bench_stats->stats[1].avg << "," <<
									curr_bench_stats->stats[2].avg << "," << curr_bench_stats->stats[3].avg << "," <<
									curr_bench_stats->stats[4].avg << "," << curr_bench_stats->stats[5].avg << "," <<
									curr_bench_stats->stats[6].avg << "," << curr_bench_stats->stats[7].avg << "," <<
									curr_bench_stats->stats[8].avg << "," << curr_bench_stats->stats[9].avg << "," <<
									curr_bench_stats->stats[10].avg << "," << curr_bench_stats->stats[11].avg << "," <<
									curr_bench_stats->stats[12].avg << endl;
			stats_file << "S_dev," << curr_bench_stats->stats[0].s_dev << "," << curr_bench_stats->stats[1].s_dev << "," <<
									curr_bench_stats->stats[2].s_dev << "," << curr_bench_stats->stats[3].s_dev << "," <<
									curr_bench_stats->stats[4].s_dev << "," << curr_bench_stats->stats[5].s_dev << "," <<
									curr_bench_stats->stats[6].s_dev << "," << curr_bench_stats->stats[7].s_dev << "," <<
									curr_bench_stats->stats[8].s_dev << "," << curr_bench_stats->stats[9].s_dev << "," <<
									curr_bench_stats->stats[10].s_dev << "," << curr_bench_stats->stats[11].s_dev << "," <<
									curr_bench_stats->stats[12].s_dev << endl;
			stats_file << "Max," << curr_bench_stats->stats[0].max << "," << curr_bench_stats->stats[1].max << "," <<
									curr_bench_stats->stats[2].max << "," << curr_bench_stats->stats[3].max << "," <<
									curr_bench_stats->stats[4].max << "," << curr_bench_stats->stats[5].max << "," <<
									curr_bench_stats->stats[6].max << "," << curr_bench_stats->stats[7].max << "," <<
									curr_bench_stats->stats[8].max << "," << curr_bench_stats->stats[9].max << "," <<
									curr_bench_stats->stats[10].max << "," << curr_bench_stats->stats[11].max << "," <<
									curr_bench_stats->stats[12].max << endl;
			stats_file << "Min," << curr_bench_stats->stats[0].min << "," << curr_bench_stats->stats[1].min << "," <<
									curr_bench_stats->stats[2].min << "," << curr_bench_stats->stats[3].min << "," <<
									curr_bench_stats->stats[4].min << "," << curr_bench_stats->stats[5].min << "," <<
									curr_bench_stats->stats[6].min << "," << curr_bench_stats->stats[7].min << "," <<
									curr_bench_stats->stats[8].min << "," << curr_bench_stats->stats[9].min << "," <<
									curr_bench_stats->stats[10].min << "," << curr_bench_stats->stats[11].min << "," <<
									curr_bench_stats->stats[12].min << endl;
			stats_file << "Run," << curr_bench_stats->stats[0].run << "," << curr_bench_stats->stats[1].run << "," <<
									curr_bench_stats->stats[2].run << "," << curr_bench_stats->stats[3].run << "," <<
									curr_bench_stats->stats[4].run << "," << curr_bench_stats->stats[5].run << "," <<
									curr_bench_stats->stats[6].run << "," << curr_bench_stats->stats[7].run << "," <<
									curr_bench_stats->stats[8].run << "," << curr_bench_stats->stats[9].run << "," <<
									curr_bench_stats->stats[10].run << "," << curr_bench_stats->stats[11].run << "," <<
									curr_bench_stats->stats[12].run << endl << endl;
			// run details
			for(int i=0;i<run;i++){
				stats_file << ",";
				stats_file << encode_series[i] << ",";
				stats_file << encrypt_series[i] << ",";
				stats_file << add_series[i] << ",";
				stats_file << add_plain_series[i] << ",";
				stats_file << mul_series[i] << ",";
				stats_file << mul_plain_series[i] << ",";
				stats_file << square_series[i] << ",";
				stats_file << negate_series[i] << ",";
				stats_file << rotate_series[i] << ",";
				stats_file << relin_series[i] << ",";
				stats_file << rescale_series[i] << ",";
				stats_file << decrypt_series[i] << ",";
				stats_file << decode_series[i] << ",";
				stats_file << endl;
			}

			// close file
			stats_file.close();
		}

	} // end of loop on benchmark settings


	cout << endl;
	cout << "**********************************" << endl;
	cout << "STATISTICS RESULT" << endl;
	cout << "**********************************" << endl;

	// print execution outcomes and stats
	for(int i=0;i<benchmark_settings.size();i++){
		cout << benchmark_return_to_string(benchmark_outcome[i]) << endl;
		cout << benckmark_statistics_to_string(benchmark_stats[i]) << endl;
	}

}

