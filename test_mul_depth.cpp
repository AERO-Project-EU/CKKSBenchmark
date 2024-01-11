/*
 * test_mul_depth.cpp
 *
 *  Created on: 18 Dec 2023
 *      Author: massimiliano
 */

#include <iostream>
#include "seal/seal.h"
#include "utils.h"

using namespace std;
using namespace seal;



void test_mul_depth(){

	cout << "test_mul_depth()" << endl;

	EncryptionParameters parms(scheme_type::ckks);

	/*
	 * Example 1
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
	 * Example 2
	 * poly_modulus degree 8192
	 * primes coeff_modulus {60,40,40,60} max_coeff_modulus 218
	 * scale 2^40 precision before point 60-40 = 20 bit, precision after point 40-12 = 20 Bit
	 */
//	size_t poly_modulus_degree = 8192;
//	size_t scale_exp = 40;
//	parms.set_poly_modulus_degree(poly_modulus_degree);
//    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, {60,40,40,60}));
//    double scale = pow(2.0, scale_exp);

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

    /*
     * random input data and expected result
     */
    const vector<double> input = generate_random_data(10, -10.0, 10.0);

    cout << "Input vector size " << input.size() << endl;
    print_vector(input);

    vector<double> expected_output_2x;
    vector<double> expected_output_4x;
    for(int i=0;i<input.size();i++){
    	expected_output_2x.push_back(input[i]*2.0);
    	expected_output_4x.push_back(expected_output_2x[i]*2.0);
    }

    /*
     * encode input vector
     */
    Plaintext plain;
    encoder.encode(input, scale, plain);

    cout << "Input plaintext" << endl;
    print_plaintext_info(plain,context);

    /*
     * encrypt plaintext
     */
    Ciphertext encrypted;
    encryptor.encrypt_symmetric(plain, encrypted);

    cout << "Input ciphertext" << endl;
    print_ciphertext_info(encrypted,context);

    /*
     * encode coeff
     */
    Plaintext coeff;
    encoder.encode(2.0, scale, coeff);

    cout << "Coeff plaintext" << endl;
    print_plaintext_info(coeff,context);

    /*
     * perform multiplication 2*A
     */
    Ciphertext encrypted_2A;
    evaluator.multiply_plain(encrypted, coeff, encrypted_2A);

    cout << "Result 2A" << endl;
    print_ciphertext_info(encrypted_2A,context);

    check_chiphertext(&decryptor, &encoder, encrypted_2A, expected_output_2x);

    cout << "--------------------------" << endl << endl;

    /*
     * no need to relinearize
     */

    /*
     * rescale 2*A to next prime in the chain
     */
    evaluator.rescale_to_next_inplace(encrypted_2A);

    cout << "Result 2A rescale" << endl;
    print_ciphertext_info(encrypted_2A,context);

    check_chiphertext(&decryptor, &encoder, encrypted_2A, expected_output_2x);

    /*
     * switch coeff to the same prime as 2A
     */
    evaluator.mod_switch_to_inplace(coeff, encrypted_2A.parms_id());

    cout << "Coeff mod switch" << endl;
    print_plaintext_info(coeff,context);

    cout << "--------------------------" << endl << endl;

    /*
     * check scale
     */
    if(!check_operand_scale(encrypted_2A, coeff)){

		/*
		 * fix the scale of 2A by forcing the expected value
		 */
		encrypted_2A.scale() = pow(2.0,scale_exp);

		cout << "Result 2A fix scale" << endl;
		print_ciphertext_info(encrypted_2A,context);

		check_chiphertext(&decryptor, &encoder, encrypted_2A, expected_output_2x);
    }


    /*
     * perform multiplication 2*(2*A)
     */
    Ciphertext encrypted_4A;
    evaluator.multiply_plain(encrypted_2A, coeff, encrypted_4A);

    cout << "Result 4A" << endl;
    print_ciphertext_info(encrypted_4A,context);

    check_chiphertext(&decryptor, &encoder, encrypted_4A, expected_output_4x);

    cout << "--------------------------" << endl << endl;


}
