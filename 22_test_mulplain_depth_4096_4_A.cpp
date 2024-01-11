/*
 * test_mulplain_depth_4096_4_A.cpp
 *
 *  Created on: 28 Dec 2023
 *      Author: massimiliano
 */

#include <iostream>
#include "seal/seal.h"
#include "utils.h"

using namespace std;
using namespace seal;

/*
 * calculate 2*(2*A) to test multiply plain depth
 */

void test_mulplain_depth_4096_4_A(double range_limit = 100.0){

	cout << "test_mulplain_depth_4096_4_A()" << endl;
	cout << "input data range [" << -range_limit << ", " << range_limit << "]" << endl;


	EncryptionParameters parms(scheme_type::ckks);

	/*
	 * poly_modulus degree 4096
	 * primes coeff_modulus {25,20,20,25} max_coeff_modulus 109
	 * scale 2^20 precision before point 25-20 = 5 bit, precision after point 20-5 = 15 Bit
	 */
	size_t poly_modulus_degree = 4096;
	size_t scale_exp = 20;
	parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, {25,20,20,25}));
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

    vector<double> expected_2A;
    vector<double> expected_4A;
    for(int i=0;i<input_A.size();i++){
    	expected_2A.push_back(input_A[i]*2.0);
    	expected_4A.push_back(expected_2A[i]*2.0);
    }

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

    /*
     * encode coeff
     */
    Plaintext plain_coeff;
    encoder.encode(2.0, scale, plain_coeff);

    cout << "Coeff plaintext" << endl;
    print_plaintext_info(plain_coeff,context);

    /*
     * perform multiplication 2*A
     */
    Ciphertext encrypted_2A;
    evaluator.multiply_plain(encrypted_A, plain_coeff, encrypted_2A);

    cout << "Result 2A" << endl;
    print_ciphertext_info(encrypted_2A,context);

    check_chiphertext(&decryptor, &encoder, encrypted_2A, expected_2A);

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

    check_chiphertext(&decryptor, &encoder, encrypted_2A, expected_2A);

    /*
     * switch coeff to the same prime as 2A
     */
    evaluator.mod_switch_to_inplace(plain_coeff, encrypted_2A.parms_id());

    cout << "Coeff mod switch" << endl;
    print_plaintext_info(plain_coeff,context);

    cout << "--------------------------" << endl << endl;

    /*
     * check scale
     */
    if(!check_operand_scale(encrypted_2A, plain_coeff)){

		/*
		 * fix the scale of 2A by forcing the expected value
		 */
		encrypted_2A.scale() = pow(2.0,scale_exp);

		cout << "Result 2A fix scale" << endl;
		print_ciphertext_info(encrypted_2A,context);

		check_chiphertext(&decryptor, &encoder, encrypted_2A, expected_2A);
    }

    /*
     * perform multiplication 2*(2*A)
     */
    Ciphertext encrypted_4A;
    evaluator.multiply_plain(encrypted_2A, plain_coeff, encrypted_4A);

    cout << "Result 4A" << endl;
    print_ciphertext_info(encrypted_4A,context);

    check_chiphertext(&decryptor, &encoder, encrypted_4A, expected_4A);

    cout << "--------------------------" << endl << endl;


}
