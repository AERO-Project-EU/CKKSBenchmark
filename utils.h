/*
 * utils.h
 *
 *  Created on: 14 Dec 2023
 *      Author: massimiliano
 */

#ifndef UTILS_H_
#define UTILS_H_

#include <vector>
#include <random>
#include <iomanip>
#include "seal/seal.h"


using namespace std;
using namespace seal;

/*
 * function to generate vector of random double
 * with size len (default 100) and items between
 * low (default -100) and up (default 100)
 */
inline vector<double> generate_random_data(int len = 100, double low = -100.0, double up = 100.0) {

	vector<double> vec(len);
	uniform_real_distribution<double> unif(low,up);
	default_random_engine re(clock());
	for(int i=0; i<vec.size();i++){
		vec[i] = unif(re);
	}
	return vec;
}


/*
 * function to generate vector of random int
 * with size len (default 100) and items between
 * low (default -100) and up (default 100)
 */
inline vector<int> generate_random_data(int len = 100, int low = -100, int up = 100) {

	vector<int> vec(len);
	uniform_int_distribution<int> unii(low,up);
	default_random_engine re(clock());
	for(int i=0; i<vec.size();i++){
		vec[i] = unii(re);
	}
	return vec;
}


/*
 * function to find the maximum element within the vector
 */
template <typename T>
inline T max_val(vector<T> vec){

	return *max_element(vec.begin(), vec.end());
}


/*
 * function to find the minimum element within the vector
 */
template <typename T>
inline T min_val(vector<T> vec){

	return *min_element(vec.begin(), vec.end());
}


/*
 * function to calculate the average value of the vector elements >0
 */
template <typename T>
inline double average(vector<T> vec) {

	double acc = 0.0;
	int cnt = 0;
	for(int i=0;i<vec.size();i++){
		if(vec[i]>0){
			acc += (double)vec[i];
			cnt++;
		}
	}
	return (double)acc/(double)cnt;
}


/*
 * function to calculate the standard deviation value of the vector elements >0
 */
template <typename T>
inline double std_deviation(vector<T> vec) {

	double s_dev = 0.0;
	double avg = average(vec);
	int cnt = 0;
	for(int i=0; i<vec.size();i++){
		if(vec[i]>0){
			s_dev += pow(vec[i] - avg, 2);
			cnt++;
		}
	}
	return sqrt(s_dev / (double)cnt);
}


/*
 * function to count the positive elements within a vector
 */
template <typename T>
inline int positive_value(vector<T> vec) {
	int cnt = 0;
	for(int i=0;i<vec.size();i++){
		if(vec[i]>0){
			cnt++;
		}
	}
	return cnt;
}


/*
 * check the ciphertext against the expected result
 */
inline bool check_chiphertext(
						Decryptor *decryptor,
						CKKSEncoder *encoder,
						const Ciphertext chiphertext,
						const vector<double> expected,
						const double max_error_perc = 2.0) {
	bool check = true;
	Plaintext plaintext;
	vector<double> result;

	// decrypt
	decryptor->decrypt(chiphertext, plaintext);

	// decode
	encoder->decode(plaintext, result);

	// check considering error percent
	for(int i=0; i<expected.size(); i++){
//		if(expected[i] != result[i]){
//			check = false;
//			cout << "expected[" << i << "]=" << expected[i] << " vs result[" << i << "]=" << result[i] << endl;
//		}
		double real_error_perc = 100 * (abs(1.0 - (expected[i] / result[i])));
		cout << "\texpected[" << i << "]=" << expected[i] << " vs result[" << i << "]=" << result[i] << " error=" << real_error_perc << "%" << endl;
		if(real_error_perc > max_error_perc){
			check = false;
		}
	}
	cout << "\tCHECK " << check << endl << endl;

	return check;
}


/*
 * check the plaintext against the expected result
 */
inline bool check_plaintext(
						CKKSEncoder *encoder,
						const Plaintext plaintext,
						const vector<double> expected,
						const double max_error_perc = 2.0) {
	bool check = true;
	vector<double> result;

	// decode
	encoder->decode(plaintext, result);

	// check considering error percent
	for(int i=0; i<expected.size(); i++){
		double real_error_perc = 100 * (abs(1.0 - (expected[i] / result[i])));
		cout << "\texpected[" << i << "]=" << expected[i] << " vs result[" << i << "]=" << result[i] << " error=" << real_error_perc << "%" << endl;
		if(real_error_perc > max_error_perc){
			check = false;
		}
	}
	cout << "\tCHECK " << check << endl << endl;

	return check;
}


/*
 * check the cleartext against the expected result
 */
inline bool check_cleartext(
						const vector<double> cleartext,
						const vector<double> expected,
						const double max_error_perc = 2.0) {
	bool check = true;

	// check considering error percent
	for(int i=0; i<expected.size(); i++){
		double real_error_perc = 100 * (abs(1.0 - (expected[i] / cleartext[i])));
		cout << "\texpected[" << i << "]=" << expected[i] << " vs result[" << i << "]=" << cleartext[i] << " error=" << real_error_perc << "%" << endl;
		if(real_error_perc > max_error_perc){
			check = false;
		}
	}
	cout << "\tCHECK " << check << endl << endl;

	return check;
}


/*
 * function to print vector. It prints the first and the last print_size elements (default 4)
 * with precision of prec digits (default 3).
 * Taken from example.h in SEAL library code.
 */
template <typename T>
inline void print_vector(std::vector<T> vec, std::size_t print_size = 4, int prec = 3)
{
    /*
    Save the formatting information for std::cout.
    */
    std::ios old_fmt(nullptr);
    old_fmt.copyfmt(std::cout);

    std::size_t slot_count = vec.size();

    std::cout << std::fixed << std::setprecision(prec);
    std::cout << std::endl;
    if (slot_count <= 2 * print_size)
    {
        std::cout << "[";
        for (std::size_t i = 0; i < slot_count; i++)
        {
            std::cout << " " << vec[i] << ((i != slot_count - 1) ? "," : " ]\n");
        }
    }
    else
    {
        vec.resize(std::max(vec.size(), 2 * print_size));
        std::cout << "[";
        for (std::size_t i = 0; i < print_size; i++)
        {
            std::cout << " " << vec[i] << ",";
        }
        if (vec.size() > 2 * print_size)
        {
            std::cout << " ...,";
        }
        for (std::size_t i = slot_count - print_size; i < slot_count; i++)
        {
            std::cout << " " << vec[i] << ((i != slot_count - 1) ? "," : " ]\n");
        }
    }
    std::cout << std::endl;

    /*
    Restore the old std::cout formatting.
    */
    std::cout.copyfmt(old_fmt);
}

/*
 * function to print parameters in a SEALContext.
 * Taken from example.h in SEAL library code.
 */

inline void print_parameters(const seal::SEALContext &context)
{
    auto &context_data = *context.key_context_data();

    /*
    Which scheme are we using?
    */
    std::string scheme_name;
    switch (context_data.parms().scheme())
    {
    case seal::scheme_type::bfv:
        scheme_name = "BFV";
        break;
    case seal::scheme_type::ckks:
        scheme_name = "CKKS";
        break;
    case seal::scheme_type::bgv:
        scheme_name = "BGV";
        break;
    default:
        throw std::invalid_argument("unsupported scheme");
    }
    std::cout << "/" << std::endl;
    std::cout << "| Encryption parameters :" << std::endl;
    std::cout << "|   scheme: " << scheme_name << std::endl;
    std::cout << "|   poly_modulus_degree: " << context_data.parms().poly_modulus_degree() << std::endl;

    /*
    Print the size of the true (product) coefficient modulus.
    */
    std::cout << "|   coeff_modulus size: ";
    std::cout << context_data.total_coeff_modulus_bit_count() << " (";
    auto coeff_modulus = context_data.parms().coeff_modulus();
    std::size_t coeff_modulus_size = coeff_modulus.size();
    for (std::size_t i = 0; i < coeff_modulus_size - 1; i++)
    {
        std::cout << coeff_modulus[i].bit_count() << " + ";
    }
    std::cout << coeff_modulus.back().bit_count();
    std::cout << ") bits" << std::endl;
    //std::cout << "|   max coeff size: " << CoeffModulus::MaxBitCount(context_data.parms().poly_modulus_degree()) << " bits" << std::endl;
    std::cout << "|   using_keyswitching: " << context.using_keyswitching() << endl;

    /*
    For the BFV scheme print the plain_modulus parameter.
    */
    if (context_data.parms().scheme() == seal::scheme_type::bfv)
    {
        std::cout << "|   plain_modulus: " << context_data.parms().plain_modulus().value() << std::endl;
    }

    std::cout << "\\" << std::endl << endl;
}


/*
 * function to print the `parms_id' to std::ostream.
 * Taken from example.h in SEAL library code.
 */
/*
Helper function: Prints the `parms_id' to std::ostream.
*/
inline std::ostream &operator<<(std::ostream &stream, seal::parms_id_type parms_id)
{
    /*
    Save the formatting information for std::cout.
    */
    std::ios old_fmt(nullptr);
    old_fmt.copyfmt(std::cout);

    stream << std::hex << std::setfill('0') << std::setw(16) << parms_id[0] << " " << std::setw(16) << parms_id[1]
           << " " << std::setw(16) << parms_id[2] << " " << std::setw(16) << parms_id[3] << " ";

    /*
    Restore the old std::cout formatting.
    */
    std::cout.copyfmt(old_fmt);

    return stream;
}


/*
 * function to print the modulus switching chain.
 * It is a part of 3_levels.cpp in SEAL library code.
 */
inline void print_modulus_switching_chain(SEALContext context) {
	   /*
	    First print the key level parameter information.
	    */
	    auto context_data = context.key_context_data();
	    cout << "----> Level (chain index): " << context_data->chain_index();
	    cout << " ...... key_context_data()" << endl;
	    cout << "      parms_id: " << context_data->parms_id() << endl;
	    cout << "      coeff_modulus primes: ";
	    cout << hex;
	    for (const auto &prime : context_data->parms().coeff_modulus())
	    {
	        cout << prime.value() << " ";
	    }
	    cout << dec << endl;
	    cout << "\\" << endl;
	    cout << " \\-->";

	    /*
	    Next iterate over the remaining (data) levels.
	    */
	    context_data = context.first_context_data();
	    while (context_data)
	    {
	        cout << " Level (chain index): " << context_data->chain_index();
	        if (context_data->parms_id() == context.first_parms_id())
	        {
	            cout << " ...... first_context_data()" << endl;
	        }
	        else if (context_data->parms_id() == context.last_parms_id())
	        {
	            cout << " ...... last_context_data()" << endl;
	        }
	        else
	        {
	            cout << endl;
	        }
	        cout << "      parms_id: " << context_data->parms_id() << endl;
	        cout << "      coeff_modulus primes: ";
	        cout << hex;
	        for (const auto &prime : context_data->parms().coeff_modulus())
	        {
	            cout << prime.value() << " ";
	        }
	        cout << dec << endl;
	        cout << "\\" << endl;
	        cout << " \\-->";

	        /*
	        Step forward in the chain.
	        */
	        context_data = context_data->next_context_data();
	    }
	    cout << " End of chain reached" << endl << endl;
}


/*
 * print plaintext params and info
 */
inline void print_plaintext_info(const Plaintext plain, const SEALContext context){
    cout << "\tplaintext parms_id() " << plain.parms_id() << endl;
    cout << "\tplaintext modulus chain index " << context.get_context_data(plain.parms_id())->chain_index() << endl;
    cout << "\tplaintext parameter coeff_count() " << plain.coeff_count() << endl;
    cout << "\tplaintext parameter significant_coeff_count() " << plain.significant_coeff_count() << endl;
	ios old_fmt(nullptr);
	old_fmt.copyfmt(cout);
	cout << fixed << setprecision(10);
    cout << "\tplaintext scale() " << plain.scale() << endl;
    cout.copyfmt(old_fmt);
    cout << "\tplaintext scale() " << log2(plain.scale()) << " bit" << endl;
    cout << "\tplaintext parameter is_ntt_form() " << plain.is_ntt_form() << endl << endl;
}

/*
 * print ciphertext params and info
 */
inline void print_ciphertext_info(const Ciphertext encrypted, const SEALContext context){
    cout << "\tciphertext parms_id() " << encrypted.parms_id() << endl;
    cout << "\tciphetext modulus chain index " << context.get_context_data(encrypted.parms_id())->chain_index() << endl;
    cout << "\tciphertext coeff_modulus_size() " << encrypted.coeff_modulus_size() << endl;
    cout << "\tciphertext size() " << encrypted.size() << endl;
    cout << "\tciphertext size_capacity() " << encrypted.size_capacity()<< endl;
    cout << "\tciphertext poly_modulus_degree() " << encrypted.poly_modulus_degree()<< endl;
	ios old_fmt(nullptr);
	old_fmt.copyfmt(cout);
	cout << fixed << setprecision(10);
    cout << "\tciphertext scale() " << encrypted.scale() << endl;
    cout.copyfmt(old_fmt);
    cout << "\tciphertext scale() " << log2(encrypted.scale()) << " bit" << endl;
    cout << "\tciphertext is_ntt_form() " << encrypted.is_ntt_form() << endl << endl;
}


/**
 * function to check if the scale of the operands is the same
 */
inline bool check_operand_scale(Ciphertext op1, Ciphertext op2){
	if(op1.scale() == op2.scale()){
		cout << "\tCheck scale OK" << endl;
		return true;
	} else {
		ios old_fmt(nullptr);
		old_fmt.copyfmt(cout);
		cout << fixed << setprecision(10);
		cout << "\tCheck scale " << op1.scale() << " vs " << op2.scale() << endl;
		cout.copyfmt(old_fmt);
		return false;
	}
}


/**
 * function to check if the scale of the operands is the same
 */
inline bool check_operand_scale(Ciphertext op1, Plaintext op2){
	if(op1.scale() == op2.scale()){
		cout << "\tCheck scale OK" << endl;
		return true;
	} else {
		ios old_fmt(nullptr);
		old_fmt.copyfmt(cout);
		cout << fixed << setprecision(10);
		cout << "\tCheck scale " << op1.scale() << " vs " << op2.scale() << endl;
		cout.copyfmt(old_fmt);
		return false;
	}
}


/**
 * function to check if the scale of the operand is equal to the desired scale
 */
inline bool check_operand_scale(Ciphertext op, double scale){
	if(op.scale() == scale){
		cout << "\tCheck scale OK" << endl;
		return true;
	} else {
		ios old_fmt(nullptr);
		old_fmt.copyfmt(cout);
		cout << fixed << setprecision(10);
		cout << "\tCheck scale " << op.scale() << " vs " << scale << endl;
		cout.copyfmt(old_fmt);
		return false;
	}
}


#endif /* UTILS_H_ */
