/*
 * test_discriminant_2_8192_4.cpp
 *
 *  Created on: 289 Dec 2023
 *      Author: massimiliano
 */

#include <iostream>
#include "seal/seal.h"
#include "utils.h"

using namespace std;
using namespace seal;

/*
 * calculate discriminant of degree 2 polynomial B^2 - 4AC
 */

void test_discriminant_2_8192_4(double range_limit = 100.0){

	cout << "test_discriminant_2_8192_4()" << endl;
	cout << "input data range [" << -range_limit << ", " << range_limit << "]" << endl;

	EncryptionParameters parms(scheme_type::ckks);

	/*
	 * poly_modulus degree 8192
	 * primes coeff_modulus {60,40,40,60} max_coeff_modulus 218
	 * scale 2^40 precision before point 60-40 = 20 bit, precision after point 40-20 = 20 Bit
	 */
	size_t poly_modulus_degree = 8192;
	size_t scale_exp = 40;
	parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, {60,40,40,60}));
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
    const vector<double> input_B = generate_random_data(10, -range_limit, range_limit);
    const vector<double> input_C = generate_random_data(10, -range_limit, range_limit);

    cout << "Input A vector size " << input_A.size() << endl;
    print_vector(input_A);
    cout << "Input B vector size " << input_B.size() << endl;
    print_vector(input_B);
    cout << "Input C vector size " << input_C.size() << endl;
    print_vector(input_C);

    vector<double> expected_BB;
    vector<double> expected_AC;
    vector<double> expected_4AC;
    vector<double> expected_BB_minus_4AC;
    for(int i=0;i<input_A.size();i++){
    	expected_BB.push_back(input_B[i]*input_B[i]);
    	expected_AC.push_back(input_A[i]*input_C[i]);
    	expected_4AC.push_back(expected_AC[i]*4.0);
    	expected_BB_minus_4AC.push_back(expected_BB[i]-expected_4AC[i]);
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
     * perform B^2
     */
    cout << endl << "********** calculate B^2" << endl;
    Ciphertext encrypted_BB;
    evaluator.square(encrypted_B, encrypted_BB);

    cout << "Result B^2" << endl;
    print_ciphertext_info(encrypted_BB,context);

    check_chiphertext(&decryptor, &encoder, encrypted_BB, expected_BB);

    cout << "--------------------------" << endl << endl;

    /*
     * relinearize B^2 to return to size = 2
     */
    evaluator.relinearize_inplace(encrypted_BB,relin_keys);

    cout << "Result B^2 relin" << endl;
    print_ciphertext_info(encrypted_BB,context);

    check_chiphertext(&decryptor, &encoder, encrypted_BB, expected_BB);

    /*
     * rescale B^2 to next prime in the chain
     */
    evaluator.rescale_to_next_inplace(encrypted_BB);

    cout << "Result B^2 rescale" << endl;
    print_ciphertext_info(encrypted_BB,context);

    check_chiphertext(&decryptor, &encoder, encrypted_BB, expected_BB);

    cout << "--------------------------" << endl << endl;

    /*
     * perform multiplication A*C
     */
    cout << endl << "********** calculate AC" << endl;

    Ciphertext encrypted_AC;
    evaluator.multiply(encrypted_A, encrypted_C, encrypted_AC);

    cout << "Result AC" << endl;
    print_ciphertext_info(encrypted_AC,context);

    check_chiphertext(&decryptor, &encoder, encrypted_AC, expected_AC);

    cout << "--------------------------" << endl << endl;

    /*
     * relinearize AC to return to size = 2
     */
    evaluator.relinearize_inplace(encrypted_AC,relin_keys);

    cout << "Result AC relin" << endl;
    print_ciphertext_info(encrypted_AC,context);

    check_chiphertext(&decryptor, &encoder, encrypted_AC, expected_AC);

    /*
     * rescale AC to next prime in the chain
     */
    evaluator.rescale_to_next_inplace(encrypted_AC);

    cout << "Result AC rescale" << endl;
    print_ciphertext_info(encrypted_AC,context);

    check_chiphertext(&decryptor, &encoder, encrypted_AC, expected_AC);

    cout << "--------------------------" << endl << endl;


    /*
     * encode coeff
     */
    Plaintext plain_coeff;
    encoder.encode(4.0, scale, plain_coeff);

    cout << "Coeff plaintext" << endl;
    print_plaintext_info(plain_coeff,context);

    /*
     * switch coeff to the same prime as AC
     */
    cout << endl << "********** adjust coeff prime" << endl;

    evaluator.mod_switch_to_inplace(plain_coeff, encrypted_AC.parms_id());

    cout << "Input coeff mod switch" << endl;
    print_plaintext_info(plain_coeff,context);

    cout << "--------------------------" << endl << endl;

    /*
     * perform multiplication 4*(AC)
     */
    cout << endl << "********** calculate 4AC" << endl;

    Ciphertext encrypted_4AC;
    evaluator.multiply_plain(encrypted_AC, plain_coeff, encrypted_4AC);

    cout << "Result 4AC" << endl;
    print_ciphertext_info(encrypted_4AC,context);

    check_chiphertext(&decryptor, &encoder, encrypted_4AC, expected_4AC);

    cout << "--------------------------" << endl << endl;

    /*
     * relinearize 4AC to return to size = 2
     */
//    evaluator.relinearize_inplace(encrypted_4AC,relin_keys);
//
//    cout << "Result 4AC relin" << endl;
//    print_ciphertext_info(encrypted_4AC,context);
//
//    check_chiphertext(&decryptor, &encoder, encrypted_4AC, expected_4AC);

    /*
     * rescale 4AC to next prime in the chain
     */
    evaluator.rescale_to_next_inplace(encrypted_4AC);

    cout << "Result 4AC rescale" << endl;
    print_ciphertext_info(encrypted_4AC,context);

    check_chiphertext(&decryptor, &encoder, encrypted_4AC, expected_4AC);

    cout << "--------------------------" << endl << endl;


    // Here B^2 is at level 1 and 4AC is at level 0.
    // B^2 operand must be switched to level 0 prime before subtraction.

    /*
     * switch B^2 to the same prime as 4AC
     */
    cout << endl << "********** adjust B^2 prime" << endl;

    evaluator.mod_switch_to_inplace(encrypted_BB, encrypted_4AC.parms_id());

    cout << "B^2 mod switch" << endl;
    print_ciphertext_info(encrypted_BB,context);

    cout << "--------------------------" << endl << endl;

    // Additionally, here the scale of B^2 and 4AC are different after rescale.
    // The scale of the two operands must be forced to the same value:
    // 1. Force B^2 to the scale value of 4AC
    // 2. Force scale of both terms to the original starting scale value

    /*
     * check B^2 scale
     */
    if(!check_operand_scale(encrypted_BB, encrypted_4AC)){

		/*
		 * fix the scale of B^2 by forcing the scale value of 4AC
		 */
		encrypted_BB.scale() = encrypted_4AC.scale();

		cout << "Result B^2 fix scale" << endl;
		print_ciphertext_info(encrypted_BB,context);

		check_chiphertext(&decryptor, &encoder, encrypted_BB, expected_BB);
    }


    /*
     * perform subtraction B^2 - 4AC
     */
    cout << endl << "********** calculate B^2 - 4AC" << endl;

    Ciphertext encrypted_BB_minus_4AC;
    evaluator.sub(encrypted_BB, encrypted_4AC, encrypted_BB_minus_4AC);

    cout << "Result B^2 - 4AC" << endl;
    print_ciphertext_info(encrypted_BB_minus_4AC,context);

    check_chiphertext(&decryptor, &encoder, encrypted_BB_minus_4AC, expected_BB_minus_4AC);


}

