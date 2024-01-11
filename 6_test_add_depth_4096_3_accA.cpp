/*
 * test_add_depth_4096_3_accA.cpp
 *
 *  Created on: 22 Dec 2023
 *      Author: massimiliano
 */

#include <iostream>
#include "seal/seal.h"
#include "utils.h"

using namespace std;
using namespace seal;

/*
 * calculate A + A + A ... to test add depth
 */

void test_add_depth_4096_3_accA(double range_limit = 100.0, int run = 10){

	cout << "test_add_depth_4096_3_accA(" << run << ")" << endl;
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

    /*
     * random input data and expected result
     */
    const vector<double> input_A = generate_random_data(10, -range_limit, range_limit);

    cout << "Input A vector size " << input_A.size() << endl;
    print_vector(input_A);

    vector<double> expected_accA;
    for(int i=0;i<input_A.size();i++){
    	expected_accA.push_back(input_A[i]+input_A[i]);
    }

    cout << "--------------------------" << endl << endl;

    /*
     * encode input vector
     */
    Plaintext plain_A;
    encoder.encode(input_A, scale, plain_A);

    cout << "Input A plaintext" << endl;
    print_plaintext_info(plain_A,context);

    cout << "--------------------------" << endl << endl;

    /*
     * encrypt plaintext
     */
    Ciphertext encrypted_A;
    encryptor.encrypt_symmetric(plain_A, encrypted_A);

    cout << "Input A ciphertext" << endl;
    print_ciphertext_info(encrypted_A,context);

    cout << "--------------------------" << endl << endl;

    /*
     * perform accA = A + A
     */
    Ciphertext encrypted_accA;
    evaluator.add(encrypted_A, encrypted_A, encrypted_accA);

    cout << "Result Acc 2A" << endl;
    print_ciphertext_info(encrypted_accA,context);

    check_chiphertext(&decryptor, &encoder, encrypted_accA, expected_accA);

    /*
     * perform run-2 times accA += A
     */
    for(int i=0; i<run-2;i++){

        /*
         * check scale
         */
        if(!check_operand_scale(encrypted_accA, encrypted_A)){

    		/*
    		 * fix the scale of accA by forcing the expected value
    		 */
    		encrypted_accA.scale() = pow(2.0,scale_exp);

    		cout << "Result accA fix scale" << endl;
    		print_ciphertext_info(encrypted_accA,context);

    		check_chiphertext(&decryptor, &encoder, encrypted_accA, expected_accA);
        }

    	evaluator.add_inplace(encrypted_accA, encrypted_A);

        for(int j=0;j<input_A.size();j++){
        	expected_accA[j] += input_A[j];
        }

        cout << "Result Acc " << i+3 << "A" << endl;
        print_ciphertext_info(encrypted_accA,context);

        check_chiphertext(&decryptor, &encoder, encrypted_accA, expected_accA);

    }

}
