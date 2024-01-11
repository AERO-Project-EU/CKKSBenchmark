/*
 * test_rotate_depth_4096_3_A.cpp
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
 * calculate rotate(A,1) run times to test rotate depth
 */

void test_rotate_depth_4096_3_A(double range_limit = 100.0, int run = 10){

	cout << "test_rotate_depth_4096_3_A(" << run << ")" << endl;
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

    vector<double> expected_rotateA = input_A;
    rotate(expected_rotateA.begin(), expected_rotateA.begin()+1, expected_rotateA.end());

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
     * perform A = rotate(A,1)
     */
    Ciphertext encrypted_rotateA;
    evaluator.rotate_vector(encrypted_A, 1, gal_keys, encrypted_rotateA);

    cout << "Result Rotate 1A" << endl;
    print_ciphertext_info(encrypted_rotateA,context);

    check_chiphertext(&decryptor, &encoder, encrypted_rotateA, expected_rotateA);

    /*
     * perform run-1 times A =  rotate(A,1)
     */
    for(int i=0; i<run-1;i++){

        /*
         * check scale
         */
        if(!check_operand_scale(encrypted_rotateA, pow(2.0, scale_exp))){

    		/*
    		 * fix the scale of negA by forcing the expected value
    		 */
    		encrypted_rotateA.scale() = pow(2.0,scale_exp);

    		cout << "Result rotate A fix scale" << endl;
    		print_ciphertext_info(encrypted_rotateA,context);

    		check_chiphertext(&decryptor, &encoder, encrypted_rotateA, expected_rotateA);
        }

    	evaluator.rotate_vector_inplace(encrypted_rotateA, 1, gal_keys);

    	rotate(expected_rotateA.begin(), expected_rotateA.begin()+1, expected_rotateA.end());

        cout << "Result Rotate " << i+2 << "A" << endl;
        print_ciphertext_info(encrypted_rotateA,context);

        check_chiphertext(&decryptor, &encoder, encrypted_rotateA, expected_rotateA);

    }

}
