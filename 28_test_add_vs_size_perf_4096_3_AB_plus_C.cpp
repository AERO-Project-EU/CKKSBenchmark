/*
 * test_add_vs_size_perf_4096_3_AB_plus_C.cpp
 *
 *  Created on: 29 Dec 2023
 *      Author: massimiliano
 */

#include <iostream>
#include "seal/seal.h"
#include "utils.h"

using namespace std;
using namespace seal;

/*
 * calculate (A * B) + C with AB size = 3 and C size = 2
 * and with both operands size = 2 to compare execution times
 */

void test_add_vs_size_perf_4096_3_AB_plus_C(double range_limit = 100.0){

	int num_run = 1000;

	cout << "test_add_vs_size_perf_4096_3_AB_plus_C()" << endl;
	cout << "input data range [" << -range_limit << ", " << range_limit << "]" << endl;

	EncryptionParameters parms(scheme_type::ckks);

	/*
	 * poly_modulus degree 4096
	 * primes coeff_modulus {35,25,35} max_coeff_modulus 109
	 * scale 2^25 precision before point 35-25 = 10 bit, precision after point 25-10 = 15 Bit
	 */
	size_t poly_modulus_degree = 4096;
	size_t scale_exp = 25;
	parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, {35,25,35}));
    double scale = pow(2.0, scale_exp);

    /*
     * SEAL context
     */
    SEALContext context(parms);
    print_parameters(context);
    cout << "context.using_keyswitching()? " << context.using_keyswitching() << endl;
    cout << endl;

    print_modulus_switching_chain(context);

    /*
     * key generation
     */
    KeyGenerator keygen(context);
    SecretKey secret_key = keygen.secret_key();
    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);
    GaloisKeys gal_keys;
    keygen.create_galois_keys(gal_keys);

    cout << "Print the parameter IDs of generated keys." << endl;
    cout << "    + secret_key:  " << secret_key.parms_id() << endl;
    cout << "    + relin_keys:  " << relin_keys.parms_id() << endl << endl;

    /*
     * encryptor, decryptor, evaluator and encoder
     */
    Encryptor encryptor(context, secret_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);

    CKKSEncoder encoder(context);
    size_t slot_count = encoder.slot_count();
    cout << "Encoder number of slots: " << slot_count << endl;
    cout << "Scale 2^" << scale_exp << endl << endl;


	chrono::high_resolution_clock::time_point time_start, time_end;
	vector<uint32_t> time_diff_add_diffsize(num_run);
	vector<uint32_t> time_diff_decrypt_diffsize(num_run);
	vector<uint32_t> time_diff_decode_diffsize(num_run);
	vector<uint32_t> time_diff_add_samesize(num_run);
	vector<uint32_t> time_diff_decrypt_samesize(num_run);
	vector<uint32_t> time_diff_decode_samesize(num_run);
	vector<uint32_t> time_diff_relin(num_run);
	clock_t begin, end;
	vector<uint32_t> clock_diff_add_diffsize(num_run);
	vector<uint32_t> clock_diff_decrypt_diffsize(num_run);
	vector<uint32_t> clock_diff_decode_diffsize(num_run);
	vector<uint32_t> clock_diff_add_samesize(num_run);
	vector<uint32_t> clock_diff_decrypt_samesize(num_run);
	vector<uint32_t> clock_diff_decode_samesize(num_run);
	vector<uint32_t> clock_diff_relin(num_run);


    for(int run=0;run<num_run;run++){

		/*
		 * random input data and expected result
		 */
		const vector<double> input_A = generate_random_data(10, -range_limit, range_limit);
		const vector<double> input_B = generate_random_data(10, -range_limit, range_limit);
		const vector<double> input_C = generate_random_data(10, -range_limit, range_limit);

		cout << "Input A vector size " << input_A.size() << endl;
		print_vector(input_A);
		cout << "Input B vector size " << input_B.size() << endl;
		print_vector(input_B);
		cout << "Input C vector size " << input_C.size() << endl;
		print_vector(input_C);

		vector<double> expected_AB;
		vector<double> expected_AB_plus_C;
		for(int i=0;i<input_A.size();i++){
			expected_AB.push_back(input_A[i]*input_B[i]);
			expected_AB_plus_C.push_back(expected_AB[i] + input_C[i]);
		}

		cout << "--------------------------" << endl << endl;

		/*
		 * encode input vector
		 */
		Plaintext plain_A, plain_B, plain_C;
		encoder.encode(input_A, scale, plain_A);
		encoder.encode(input_B, scale, plain_B);
		encoder.encode(input_C, scale, plain_C);

		cout << "Input A plaintext" << endl;
		print_plaintext_info(plain_A,context);
		cout << "Input B plaintext" << endl;
		print_plaintext_info(plain_B,context);
		cout << "Input C plaintext" << endl;
		print_plaintext_info(plain_C,context);

		cout << "--------------------------" << endl << endl;

		/*
		 * encrypt plaintext
		 */
		Ciphertext encrypted_A, encrypted_B, encrypted_C;
		encryptor.encrypt_symmetric(plain_A, encrypted_A);
		encryptor.encrypt_symmetric(plain_B, encrypted_B);
		encryptor.encrypt_symmetric(plain_C, encrypted_C);

		cout << "Input A ciphertext" << endl;
		print_ciphertext_info(encrypted_A,context);
		cout << "Input B ciphertext" << endl;
		print_ciphertext_info(encrypted_B,context);
		cout << "Input C ciphertext" << endl;
		print_ciphertext_info(encrypted_C,context);

		cout << "--------------------------" << endl << endl;

		/*
		 * perform multiplication A*B
		 */
		Ciphertext encrypted_AB;
		evaluator.multiply(encrypted_A, encrypted_B, encrypted_AB);

		cout << "Result AB" << endl;
		print_ciphertext_info(encrypted_AB,context);

		check_chiphertext(&decryptor, &encoder, encrypted_AB, expected_AB);

		cout << "--------------------------" << endl << endl;

		/*
		 * relinearize A*B to return to size = 2
		 */
	//    evaluator.relinearize_inplace(encrypted_AB,relin_keys);
	//
	//    cout << "Result AB relin" << endl;
	//    print_ciphertext_info(encrypted_AB,context);
	//
	//    check_chiphertext(&decryptor, &encoder, encrypted_AB, expected_AB);

		/*
		 * rescale A*B to next prime in the chain
		 */
		evaluator.rescale_to_next_inplace(encrypted_AB);

		cout << "Result AB rescale" << endl;
		print_ciphertext_info(encrypted_AB,context);

		check_chiphertext(&decryptor, &encoder, encrypted_AB, expected_AB);

		/*
		 * switch C to the same prime as A*B
		 */
		evaluator.mod_switch_to_inplace(encrypted_C, encrypted_AB.parms_id());

		cout << "Input C mod switch" << endl;
		print_ciphertext_info(encrypted_C,context);

		cout << "--------------------------" << endl << endl;

		/*
		 * check scale
		 */
		if(!check_operand_scale(encrypted_AB, encrypted_C)){
			/*
			 * fix the scale of A*B by forcing the expected value
			 */
			encrypted_AB.scale() = pow(2.0,scale_exp);

			cout << "Result AB fix scale" << endl;
			print_ciphertext_info(encrypted_AB,context);

			check_chiphertext(&decryptor, &encoder, encrypted_AB, expected_AB);
		}

		/*
		 * perform addition (A*B) + C on different size
		 */
		Ciphertext encrypted_AB_plus_C_diffsize;

		time_start = chrono::high_resolution_clock::now();
		begin = clock();

		evaluator.add(encrypted_AB, encrypted_C, encrypted_AB_plus_C_diffsize);

		end = clock();
		time_end = chrono::high_resolution_clock::now();
		time_diff_add_diffsize[run] = (chrono::duration_cast<chrono::microseconds>(time_end - time_start)).count();
		clock_diff_add_diffsize[run] = end - begin;

		cout << "Add AB + C performance (different size): " << time_diff_add_diffsize[run] << "us, " << clock_diff_add_diffsize[run] << "cycles" << endl;

		cout << "Result AB + C" << endl;
		print_ciphertext_info(encrypted_AB_plus_C_diffsize,context);

		check_chiphertext(&decryptor, &encoder, encrypted_AB_plus_C_diffsize, expected_AB_plus_C);

		/*
		 * decrypt and decode
		 */
		Plaintext plain_res_diffsize;
		vector<double> clear_res_diffsize;

		time_start = chrono::high_resolution_clock::now();
		begin = clock();

		decryptor.decrypt(encrypted_AB_plus_C_diffsize, plain_res_diffsize);

		end = clock();
		time_end = chrono::high_resolution_clock::now();
		time_diff_decrypt_diffsize[run] = (chrono::duration_cast<chrono::microseconds>(time_end - time_start)).count();
		clock_diff_decrypt_diffsize[run] = end - begin;

		cout << "Decrypt AB + C performance (different size): " << time_diff_decrypt_diffsize[run] << "us, " << clock_diff_decrypt_diffsize[run] << "cycles" << endl;

		time_start = chrono::high_resolution_clock::now();
		begin = clock();

		encoder.decode(plain_res_diffsize, clear_res_diffsize);

		end = clock();
		time_end = chrono::high_resolution_clock::now();
		time_diff_decode_diffsize[run] = (chrono::duration_cast<chrono::microseconds>(time_end - time_start)).count();
		clock_diff_decode_diffsize[run] = end - begin;

		cout << "Decode AB + C performance (different size): " << time_diff_decode_diffsize[run] << "us, " << clock_diff_decode_diffsize[run] << "cycles" << endl;

		cout << "--------------------------" << endl << endl;


		/*
		 * relinearize A*B to return to size = 2
		 */
		time_start = chrono::high_resolution_clock::now();
		begin = clock();

		evaluator.relinearize_inplace(encrypted_AB,relin_keys);

		end = clock();
		time_end = chrono::high_resolution_clock::now();
		time_diff_relin[run] = (chrono::duration_cast<chrono::microseconds>(time_end - time_start)).count();
		clock_diff_relin[run] = end - begin;

		cout << "Relin AB: " << time_diff_relin[run] << "us, " << clock_diff_relin[run] << "cycles" << endl;


		cout << "Result AB relin" << endl;
		print_ciphertext_info(encrypted_AB,context);

		check_chiphertext(&decryptor, &encoder, encrypted_AB, expected_AB);

		cout << "--------------------------" << endl << endl;

		/*
		 * perform addition (A*B) + C on the same size
		 */

		Ciphertext encrypted_AB_plus_C_samesize;

		time_start = chrono::high_resolution_clock::now();
		begin = clock();

		evaluator.add(encrypted_AB, encrypted_C, encrypted_AB_plus_C_samesize);

		end = clock();
		time_end = chrono::high_resolution_clock::now();
		time_diff_add_samesize[run] = (chrono::duration_cast<chrono::microseconds>(time_end - time_start)).count();
		clock_diff_add_samesize[run] = end - begin;

		cout << "Add AB + C performance (same size): " << time_diff_add_samesize[run] << "us, " << clock_diff_add_samesize[run] << "cycles" << endl;

		cout << "Result AB + C" << endl;
		print_ciphertext_info(encrypted_AB_plus_C_samesize,context);

		check_chiphertext(&decryptor, &encoder, encrypted_AB_plus_C_samesize, expected_AB_plus_C);

		/*
		 * decrypt and decode
		 */
		Plaintext plain_res_samesize;
		vector<double> clear_res_samesize;

		time_start = chrono::high_resolution_clock::now();
		begin = clock();

		decryptor.decrypt(encrypted_AB_plus_C_samesize, plain_res_samesize);

		end = clock();
		time_end = chrono::high_resolution_clock::now();
		time_diff_decrypt_samesize[run] = (chrono::duration_cast<chrono::microseconds>(time_end - time_start)).count();
		clock_diff_decrypt_samesize[run] = end - begin;

		cout << "Decrypt AB + C performance (same size): " << time_diff_decrypt_samesize[run] << "us, " << clock_diff_decrypt_samesize[run] << "cycles" << endl;

		time_start = chrono::high_resolution_clock::now();
		begin = clock();

		encoder.decode(plain_res_samesize, clear_res_samesize);

		end = clock();
		time_end = chrono::high_resolution_clock::now();
		time_diff_decode_samesize[run] = (chrono::duration_cast<chrono::microseconds>(time_end - time_start)).count();
		clock_diff_decode_samesize[run] = end - begin;

		cout << "Decode AB + C performance (same size): " << time_diff_decode_samesize[run] << "us, " << clock_diff_decode_samesize[run] << "cycles" << endl;

		cout << "--------------------------" << endl << endl;

		for(int i=0;i<input_A.size();i++){
			cout << expected_AB_plus_C[i] << "  " <<  clear_res_diffsize[i] << "  " << clear_res_samesize[i] << endl;
		}

    }

	cout << "--------------------------" << endl << endl;

	cout << time_diff_decode_samesize.size() << endl;

	cout << "\tdiffSize\tsameSize" << endl;
	cout << "Add\t" << average(time_diff_add_diffsize) << "\t\t" << average(time_diff_add_samesize) << endl;
	cout << "Decrypt\t" << average(time_diff_decrypt_diffsize) << "\t\t" << average(time_diff_decrypt_samesize) << endl;
	cout << "Decode\t" << average(time_diff_decode_diffsize) << "\t\t" << average(time_diff_decode_samesize) << endl;
	cout << "Relin\t\t\t" << average(time_diff_relin) << endl;




}

