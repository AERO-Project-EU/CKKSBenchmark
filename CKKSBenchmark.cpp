#include <iostream>
#include "config.h"
#include "utils.h"
#include "test.h"
#include "benchmark.h"

using namespace std;
using namespace seal;

/*
 * +------------+               +------------+                +------------+                 +------------+
 * | input data | -- encode --> | plaintext  | -- encrypt --> | ciphertext | -- evaluator--> | operation  |
 * +------------+               +------------+                +------------+                 +------------+
 *                                                                                                 |
 * +------------+               +------------+                +------------+                       |
 * | out data   | <-- decode -- | plaintext  | <-- decrypt -- | ciphertext | <----------------------
 * +------------+               +------------+                +------------+
 *
 *
 *
 */

int main(int argc, char **argv) {
	cout << "+----------------------------------------+" << endl;
	cout << "| Benchmark Microsoft SEAL CKKS scheme   |" << endl;
	cout << "+----------------------------------------+" << endl;
	cout << "Library version " << SEAL_VERSION << endl;
	cout << "Benchmark version " << CKKSBenchmark_VERSION_MAJOR << "." << CKKSBenchmark_VERSION_MINOR << endl;
	cout << endl;

	while (true) {

		int selection;
		bool valid = true;

		cout << "+-------------------------------------------------------------+" << endl;
		cout << "| ******** Tests ********                                     |" << endl;
		cout << "| 1.  Mul depth 4096, 3 primes, (A*B)*C [error]               |" << endl;
		cout << "| 2.  Mul depth 4096, 4 primes, (A*B)*C [precision]           |" << endl;
		cout << "| 3.  Mul depth 8192, 4 primes, (A*B)*C [ok]                  |" << endl;
		cout << "| 4.  Mul depth 8192, 4 primes, ((A*B)*C)*D [error]           |" << endl;
		cout << "| 5.  Mul depth 8192, 4 primes, (A*B)*(C*D) [ok]              |" << endl;
		cout << "| 6.  Add depth 4096, 3 primes, A+A+A+...+A [ok]              |" << endl;
		cout << "| 7.  Add depth 4096, 4 primes, A+A+A+...+A [ok]              |" << endl;
		cout << "| 8.  Add depth 8192, 4 primes, A+A+A+...+A [ok]              |" << endl;
		cout << "| 9.  Mul/Add depth 4096, 3 primes, (A*B)+C+...+C [ok]        |" << endl;
		cout << "| 10. Mul/Add depth 4096, 4 primes, (A*B)+C+...+C [precision] |" << endl;
		cout << "| 11. Mul/Add depth 8192, 4 primes, (A*B)*C)+D+...+D [ok]     |" << endl;
		cout << "| 12. Square depth 4096, 3 primes, (A^2)^2 [error]            |" << endl;
		cout << "| 13. Square depth 4096, 4 primes, (A^2)^2 [precision]        |" << endl;
		cout << "| 14. Square depth 8192, 4 primes, (A^2)^2 [ok]               |" << endl;
		cout << "| 15. Negate depth 4096, 3 primes, neg(A) [ok]                |" << endl;
		cout << "| 16. Negate depth 4096, 4 primes, neg(A) [ok]                |" << endl;
		cout << "| 17. Negate depth 8192, 4 primes, neg(A) [ok]                |" << endl;
		cout << "| 18. Rotate depth 4096, 3 primes, rotate(A,1) [ok]           |" << endl;
		cout << "| 19. Rotate depth 4096, 4 primes, rotate(A,1) [precision]    |" << endl;
		cout << "| 20. Rotate depth 8192, 4 primes, rotate(A,1) [ok]           |" << endl;
		cout << "| 21. Mulplain depth 4096, 3 primes, 2*(2*A) [error]          |" << endl;
		cout << "| 22. Mulplain depth 4096, 4 primes, 2*(2*A) [precision]      |" << endl;
		cout << "| 23. Mulplain depth 8192, 4 primes, 2*(2*A) [ok]             |" << endl;
		cout << "| 24. Discriminant degr 2 4096, 4 primes, B^2-4AC [precision] |" << endl;
		cout << "| 25. Discriminant degr 2 8912, 4 primes, B^2-4AC [ok]        |" << endl;
		cout << "| 26. Add on different size, 4096, 3 primes, AB+C [ok]        |" << endl;
		cout << "| 27. Add on different size, 8192, 4 primes, AB+C [ok]        |" << endl;
		cout << "| 28. Perfrmance add vs operand size, 4096, 6 primes, AB+C    |" << endl;
		cout << "| 29. Misc                                                    |" << endl;
		cout << "| 30. Misc                                                    |" << endl;
		cout << "| ******** Benchmarks ********                                |" << endl;
		cout << "| 31. Kernel based on -(A^2 + BC + 3D + coeff)                |" << endl;
		cout << "| 32. Kernel based on modified example/8_performance.cpp      |" << endl;
		cout << "| 33. Kernel based example/8_performance.cpp test             |" << endl;
		cout << "+-------------------------------------------------------------+" << endl;

		do {
			cout << endl << "> Run test or exit (0):  ";
			if(!(cin >> selection)){
				valid = false;
			} else if (selection < 0 || selection > 40) {
				valid = false;
			} else {
				valid = true;
			}
			if(!valid){
				cout << "  invalid selection" << endl;
				cin.clear();
				cin.ignore(numeric_limits<streamsize>::max(),'\n');
			}
		} while(!valid);

		try {
			switch (selection) {
			case 0:
				cout << "bye!" << endl;
				return 0;
			case 1:
				test_mul_depth_4096_3_ABC(100.0);
				break;
			case 2:
				test_mul_depth_4096_4_ABC(1.0);
				break;
			case 3:
				test_mul_depth_8192_4_ABC(100.0);
				break;
			case 4:
				test_mul_depth_8192_4_ABCD(100.0);
				break;
			case 5:
				test_mul_depth_8192_4_ABCD_ok(100.0);
				break;
			case 6:
				test_add_depth_4096_3_accA(100.0, 10);
				break;
			case 7:
				test_add_depth_4096_4_accA(100.0, 10);
				break;
			case 8:
				test_add_depth_8192_4_accA(100.0, 10);
				break;
			case 9:
				test_muladd_depth_4096_3_AB_plus_accC(100.0, 10);
				break;
			case 10:
				test_muladd_depth_4096_4_AB_plus_accC(100.0, 10);
				break;
			case 11:
				test_muladd_depth_8192_4_ABC_plus_accD(100.0, 10);
				break;
			case 12:
				test_square_depth_4096_3_A(100.0);
				break;
			case 13:
				test_square_depth_4096_4_A(2.0);
				break;
			case 14:
				test_square_depth_8192_4_A(100.0);
				break;
			case 15:
				test_neg_depth_4096_3_A(100.0, 10);
				break;
			case 16:
				test_neg_depth_4096_4_A(100.0, 10);
				break;
			case 17:
				test_neg_depth_8192_4_A(100.0, 10);
				break;
			case 18:
				test_rotate_depth_4096_3_A(100.0, 10);
				break;
			case 19:
				test_rotate_depth_4096_4_A(100.0, 10);
				break;
			case 20:
				test_rotate_depth_8192_4_A(100.0, 10);
				break;
			case 21:
				test_mulplain_depth_4096_3_A(100.0);
				break;
			case 22:
				test_mulplain_depth_4096_4_A(100.0);
				break;
			case 23:
				test_mulplain_depth_8192_4_A(100.0);
				break;
			case 24:
				test_discriminant_2_4096_4(3.0);
				break;
			case 25:
				test_discriminant_2_8192_4(100.0);
				break;
			case 26:
				test_add_different_size_4096_3_AB_plus_C(100.0);
				break;
			case 27:
				test_add_different_size_8192_4_AB_plus_C(100.0);
				break;
			case 28:
				test_add_vs_size_perf_4096_3_AB_plus_C(100.0);
				break;
			case 29:
				test_misc();
				break;
			case 30:
				test_mul_depth();
				break;
			case 31:
				ckks_kernel_benchmark_expr();
				break;
			case 32:
				ckks_kernel_benchmark_seal();
				break;
			case 33:
				example_ckks_performance_default();
				break;

			default:
				cout << "Not implemented yet!" << endl;
			}
		} catch (const std::exception &e) {
			cout << "Exception -----> " << e.what() << endl << endl;
		}
	}

	return 0;
}
