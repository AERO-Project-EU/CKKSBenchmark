// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "benchmark.h"
#include "utils.h"

using namespace std;
using namespace seal;


void ckks_performance_test(SEALContext context)
{
    chrono::high_resolution_clock::time_point time_start, time_end;

    print_parameters(context);
    cout << endl;

    auto &parms = context.first_context_data()->parms();
    size_t poly_modulus_degree = parms.poly_modulus_degree();

    cout << "Generating secret/public keys: ";
    KeyGenerator keygen(context);
    cout << "Done" << endl;

    auto secret_key = keygen.secret_key();
    PublicKey public_key;
    keygen.create_public_key(public_key);

    RelinKeys relin_keys;
    GaloisKeys gal_keys;
    chrono::microseconds time_diff;
    if (context.using_keyswitching())
    {
        cout << "Generating relinearization keys: ";
        time_start = chrono::high_resolution_clock::now();
        keygen.create_relin_keys(relin_keys);
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        cout << "Done [" << time_diff.count() << " microseconds]" << endl;

        if (!context.first_context_data()->qualifiers().using_batching)
        {
            cout << "Given encryption parameters do not support batching." << endl;
            return;
        }

        cout << "Generating Galois keys: ";
        time_start = chrono::high_resolution_clock::now();
        keygen.create_galois_keys(gal_keys);
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        cout << "Done [" << time_diff.count() << " microseconds]" << endl;
    }

    Encryptor encryptor(context, public_key);
    Decryptor decryptor(context, secret_key);
    Evaluator evaluator(context);
    CKKSEncoder ckks_encoder(context);

    chrono::microseconds time_encode_sum(0);
    chrono::microseconds time_decode_sum(0);
    chrono::microseconds time_encrypt_sum(0);
    chrono::microseconds time_decrypt_sum(0);
    chrono::microseconds time_add_sum(0);
    chrono::microseconds time_multiply_sum(0);
    chrono::microseconds time_multiply_plain_sum(0);
    chrono::microseconds time_square_sum(0);
    chrono::microseconds time_relinearize_sum(0);
    chrono::microseconds time_rescale_sum(0);
    chrono::microseconds time_rotate_one_step_sum(0);
    chrono::microseconds time_rotate_random_sum(0);
    chrono::microseconds time_conjugate_sum(0);
    chrono::microseconds time_serialize_sum(0);
#ifdef SEAL_USE_ZLIB
    chrono::microseconds time_serialize_zlib_sum(0);
#endif
#ifdef SEAL_USE_ZSTD
    chrono::microseconds time_serialize_zstd_sum(0);
#endif
    /*
    How many times to run the test?
    */
    long long count = 1;

    /*
    Populate a vector of floating-point values to batch.
    */
    vector<double> pod_vector;
    random_device rd;
    for (size_t i = 0; i < ckks_encoder.slot_count(); i++)
    {
        pod_vector.push_back(1.001 * static_cast<double>(i));
    }

    cout << "Running tests ";
    for (long long i = 0; i < count; i++)
    {
        /*
        [Encoding]
        For scale we use the square root of the last coeff_modulus prime
        from parms.
        */
        Plaintext plain(parms.poly_modulus_degree() * parms.coeff_modulus().size(), 0);
        /*

        */
        double scale = sqrt(static_cast<double>(parms.coeff_modulus().back().value()));

        cout << "SCALE " <<  parms.coeff_modulus().back().value() << "  " << scale;

        time_start = chrono::high_resolution_clock::now();
        ckks_encoder.encode(pod_vector, scale, plain);
        time_end = chrono::high_resolution_clock::now();
        time_encode_sum += chrono::duration_cast<chrono::microseconds>(time_end - time_start);

        /*
        [Decoding]
        */
        vector<double> pod_vector2(ckks_encoder.slot_count());
        time_start = chrono::high_resolution_clock::now();
        ckks_encoder.decode(plain, pod_vector2);
        time_end = chrono::high_resolution_clock::now();
        time_decode_sum += chrono::duration_cast<chrono::microseconds>(time_end - time_start);

        /*
        [Encryption]
        */
        Ciphertext encrypted(context);
        time_start = chrono::high_resolution_clock::now();
        encryptor.encrypt(plain, encrypted);
        time_end = chrono::high_resolution_clock::now();
        time_encrypt_sum += chrono::duration_cast<chrono::microseconds>(time_end - time_start);

        /*
        [Decryption]
        */
        Plaintext plain2(poly_modulus_degree, 0);
        time_start = chrono::high_resolution_clock::now();
        decryptor.decrypt(encrypted, plain2);
        time_end = chrono::high_resolution_clock::now();
        time_decrypt_sum += chrono::duration_cast<chrono::microseconds>(time_end - time_start);

        /*
        [Add]
        */
        Ciphertext encrypted1(context);
        ckks_encoder.encode(i + 1, plain);
        encryptor.encrypt(plain, encrypted1);
        Ciphertext encrypted2(context);
        ckks_encoder.encode(i + 1, plain2);
        encryptor.encrypt(plain2, encrypted2);
        time_start = chrono::high_resolution_clock::now();
        evaluator.add_inplace(encrypted1, encrypted1);
        evaluator.add_inplace(encrypted2, encrypted2);
        evaluator.add_inplace(encrypted1, encrypted2);
        time_end = chrono::high_resolution_clock::now();
        time_add_sum += chrono::duration_cast<chrono::microseconds>(time_end - time_start);

        /*
        [Multiply]
        */
        encrypted1.reserve(3);
        time_start = chrono::high_resolution_clock::now();
        evaluator.multiply_inplace(encrypted1, encrypted2);
        time_end = chrono::high_resolution_clock::now();
        time_multiply_sum += chrono::duration_cast<chrono::microseconds>(time_end - time_start);

        /*
        [Multiply Plain]
        */
        time_start = chrono::high_resolution_clock::now();
        evaluator.multiply_plain_inplace(encrypted2, plain);
        time_end = chrono::high_resolution_clock::now();
        time_multiply_plain_sum += chrono::duration_cast<chrono::microseconds>(time_end - time_start);

        print_ciphertext_info(encrypted2, context);

        /*
        [Square]
        */
        time_start = chrono::high_resolution_clock::now();
        evaluator.square_inplace(encrypted2);
        time_end = chrono::high_resolution_clock::now();
        time_square_sum += chrono::duration_cast<chrono::microseconds>(time_end - time_start);

        print_ciphertext_info(encrypted2, context);

        if (context.using_keyswitching())
        {
            /*
            [Relinearize]
            */
            time_start = chrono::high_resolution_clock::now();
            evaluator.relinearize_inplace(encrypted1, relin_keys);
            time_end = chrono::high_resolution_clock::now();
            time_relinearize_sum += chrono::duration_cast<chrono::microseconds>(time_end - time_start);

            /*
            [Rescale]
            */
            time_start = chrono::high_resolution_clock::now();
            evaluator.rescale_to_next_inplace(encrypted1);
            time_end = chrono::high_resolution_clock::now();
            time_rescale_sum += chrono::duration_cast<chrono::microseconds>(time_end - time_start);

            /*
            [Rotate Vector]
            */
            time_start = chrono::high_resolution_clock::now();
            evaluator.rotate_vector_inplace(encrypted, 1, gal_keys);
            evaluator.rotate_vector_inplace(encrypted, -1, gal_keys);
            time_end = chrono::high_resolution_clock::now();
            time_rotate_one_step_sum += chrono::duration_cast<chrono::microseconds>(time_end - time_start);

            /*
            [Rotate Vector Random]
            */
            // ckks_encoder.slot_count() is always a power of 2.
            int random_rotation = static_cast<int>(rd() & (ckks_encoder.slot_count() - 1));
            time_start = chrono::high_resolution_clock::now();
            evaluator.rotate_vector_inplace(encrypted, random_rotation, gal_keys);
            time_end = chrono::high_resolution_clock::now();
            time_rotate_random_sum += chrono::duration_cast<chrono::microseconds>(time_end - time_start);

            /*
            [Complex Conjugate]
            */
            time_start = chrono::high_resolution_clock::now();
            evaluator.complex_conjugate_inplace(encrypted, gal_keys);
            time_end = chrono::high_resolution_clock::now();
            time_conjugate_sum += chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        }

        /*
        [Serialize Ciphertext]
        */
        size_t buf_size = static_cast<size_t>(encrypted.save_size(compr_mode_type::none));
        vector<seal_byte> buf(buf_size);
        time_start = chrono::high_resolution_clock::now();
        encrypted.save(buf.data(), buf_size, compr_mode_type::none);
        time_end = chrono::high_resolution_clock::now();
        time_serialize_sum += chrono::duration_cast<chrono::microseconds>(time_end - time_start);
#ifdef SEAL_USE_ZLIB
        /*
        [Serialize Ciphertext (ZLIB)]
        */
        buf_size = static_cast<size_t>(encrypted.save_size(compr_mode_type::zlib));
        buf.resize(buf_size);
        time_start = chrono::high_resolution_clock::now();
        encrypted.save(buf.data(), buf_size, compr_mode_type::zlib);
        time_end = chrono::high_resolution_clock::now();
        time_serialize_zlib_sum += chrono::duration_cast<chrono::microseconds>(time_end - time_start);
#endif
#ifdef SEAL_USE_ZSTD
        /*
        [Serialize Ciphertext (Zstandard)]
        */
        buf_size = static_cast<size_t>(encrypted.save_size(compr_mode_type::zstd));
        buf.resize(buf_size);
        time_start = chrono::high_resolution_clock::now();
        encrypted.save(buf.data(), buf_size, compr_mode_type::zstd);
        time_end = chrono::high_resolution_clock::now();
        time_serialize_zstd_sum += chrono::duration_cast<chrono::microseconds>(time_end - time_start);
#endif
        /*
        Print a dot to indicate progress.
        */
        cout << ".";
        cout.flush();
    }

    cout << " Done" << endl << endl;
    cout.flush();

    auto avg_encode = time_encode_sum.count() / count;
    auto avg_decode = time_decode_sum.count() / count;
    auto avg_encrypt = time_encrypt_sum.count() / count;
    auto avg_decrypt = time_decrypt_sum.count() / count;
    auto avg_add = time_add_sum.count() / (3 * count);
    auto avg_multiply = time_multiply_sum.count() / count;
    auto avg_multiply_plain = time_multiply_plain_sum.count() / count;
    auto avg_square = time_square_sum.count() / count;
    auto avg_relinearize = time_relinearize_sum.count() / count;
    auto avg_rescale = time_rescale_sum.count() / count;
    auto avg_rotate_one_step = time_rotate_one_step_sum.count() / (2 * count);
    auto avg_rotate_random = time_rotate_random_sum.count() / count;
    auto avg_conjugate = time_conjugate_sum.count() / count;
    auto avg_serialize = time_serialize_sum.count() / count;
#ifdef SEAL_USE_ZLIB
    auto avg_serialize_zlib = time_serialize_zlib_sum.count() / count;
#endif
#ifdef SEAL_USE_ZSTD
    auto avg_serialize_zstd = time_serialize_zstd_sum.count() / count;
#endif
    cout << "Average encode: " << avg_encode << " microseconds" << endl;
    cout << "Average decode: " << avg_decode << " microseconds" << endl;
    cout << "Average encrypt: " << avg_encrypt << " microseconds" << endl;
    cout << "Average decrypt: " << avg_decrypt << " microseconds" << endl;
    cout << "Average add: " << avg_add << " microseconds" << endl;
    cout << "Average multiply: " << avg_multiply << " microseconds" << endl;
    cout << "Average multiply plain: " << avg_multiply_plain << " microseconds" << endl;
    cout << "Average square: " << avg_square << " microseconds" << endl;
    if (context.using_keyswitching())
    {
        cout << "Average relinearize: " << avg_relinearize << " microseconds" << endl;
        cout << "Average rescale: " << avg_rescale << " microseconds" << endl;
        cout << "Average rotate vector one step: " << avg_rotate_one_step << " microseconds" << endl;
        cout << "Average rotate vector random: " << avg_rotate_random << " microseconds" << endl;
        cout << "Average complex conjugate: " << avg_conjugate << " microseconds" << endl;
    }
    cout << "Average serialize ciphertext: " << avg_serialize << " microseconds" << endl;
#ifdef SEAL_USE_ZLIB
    cout << "Average compressed (ZLIB) serialize ciphertext: " << avg_serialize_zlib << " microseconds" << endl;
#endif
#ifdef SEAL_USE_ZSTD
    cout << "Average compressed (Zstandard) serialize ciphertext: " << avg_serialize_zstd << " microseconds" << endl;
#endif
    cout.flush();
}


void example_ckks_performance_default()
{
    //print_example_banner("CKKS Performance Test with Degrees: 4096, 8192, and 16384");

    // It is not recommended to use BFVDefault primes in CKKS. However, for performance
    // test, BFVDefault primes are good enough.
    EncryptionParameters parms(scheme_type::ckks);
    size_t poly_modulus_degree = 4096;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
    ckks_performance_test(parms);

//    cout << endl;
//    poly_modulus_degree = 8192;
//    parms.set_poly_modulus_degree(poly_modulus_degree);
//    parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
//    ckks_performance_test(parms);
//
//    cout << endl;
//    poly_modulus_degree = 16384;
//    parms.set_poly_modulus_degree(poly_modulus_degree);
//    parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
//    ckks_performance_test(parms);

    /*
    Comment out the following to run the biggest example.
    */
    // cout << endl;
    // poly_modulus_degree = 32768;
    // parms.set_poly_modulus_degree(poly_modulus_degree);
    // parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
    // ckks_performance_test(parms);
}

