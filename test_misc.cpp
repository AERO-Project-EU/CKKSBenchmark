/*
 * test_misc.cpp
 *
 *  Created on: 29 Dec 2023
 *      Author: massimiliano
 */

#include <iostream>
#include "seal/seal.h"
#include "utils.h"
#include "math.h"

using namespace std;
using namespace seal;



void test_misc(){

	cout << "test_misc()" << endl;

	/*
	 * newton's method
	 */
//	double S = 25.0;
//	double x_n = 0.5;
//	double x_n_1;
//
//	for(int i=0; i<10;i++){
//		x_n_1 = (x_n / 2) * (3 - (S*pow(x_n,2.0)));
//
//		// 6/2 * (3 - 25*)
//
//		cout << " -- step " << i+1 << "--" << endl;
//		cout << "x_n_1 = " << x_n_1 << endl;
//		cout << "sqrt(S) = " << S * x_n_1 << endl;
//
//		x_n = x_n_1;
//	}


	/*
	 * Halley's method
	 */
//	cout << "-----------------------------" << endl;
//	cout << "------ Halley's method ------" << endl;
//	cout << "-----------------------------" << endl;
//	double S = 25.0;
//	double x_n = (double) 1/2;
//	double x_n_1;
//	double y_n;
//	double coeff_15_8 = (double)15/8;
//	double coeff_10_8 = (double)10/8;
//	double coeff_3_8 = (double)3/8;
//
//	cout << "coeff_15_8 " << coeff_15_8 << endl;
//	cout << "coeff_10_8 " << coeff_10_8 << endl;
//	cout << "coeff_3_8 " << coeff_3_8 << endl;
//
//	for(int i=0; i<10; i++){
//		cout << " -- step " << i+1 << "--" << endl;
//
//		y_n = S * pow(x_n,2.0);
//		x_n_1 = x_n * (coeff_15_8 - y_n * (coeff_10_8 - (coeff_3_8 * y_n)));
//
//		cout << "x_n " << x_n << endl;
//		cout << "y_n " << y_n << endl;
//		cout << "x_n_1 " << x_n_1 << endl;
//		cout << "sqrt(S) = " << S * x_n_1 << endl;
//
//		x_n = x_n_1;
//
//	}


	/*
	 * Halley's method 2
	 */
	cout << "-----------------------------" << endl;
	cout << "----- Halley's method 2 -----" << endl;
	cout << "-----------------------------" << endl;

	double S = 25.0;
	double x_n = 0.3;
	double x_n_1;
	double y_n;
	double coeff_sqrt_3_8_S = sqrt((double)3/8) * S;
	double coeff_15_8 = (double)15/8;
	double coeff_sqrt_25_6 = sqrt((double)25/6);

	cout << "coeff_sqrt_3_8_S " << coeff_sqrt_3_8_S << endl;
	cout << "coeff_15_8 " << coeff_15_8 << endl;
	cout << "coeff_sqrt_25_6 " << coeff_sqrt_25_6 << endl;

	for(int i=0; i<10; i++){
		cout << " -- step " << i+1 << "--" << endl;

		y_n = coeff_sqrt_3_8_S * pow(x_n,2.0);
		x_n_1 = x_n * (coeff_15_8 - y_n * (coeff_sqrt_25_6 - y_n));

		cout << "y_n " << y_n << endl;
		cout << "x_n " << x_n << endl;
		cout << "x_n_1 " << x_n_1 << endl;
		cout << "sqrt(S) = " << S * x_n_1 << endl;

		x_n = x_n_1;

	}


}
