/*
 * test.h
 *
 *  Created on: 18 Dec 2023
 *      Author: massimiliano
 */

#ifndef TEST_H_
#define TEST_H_


void test_mul_depth();

void test_misc();

void test_mul_depth_4096_3_ABC(double range_limit = 100.0);

void test_mul_depth_4096_4_ABC(double range_limit = 100.0);

void test_mul_depth_8192_4_ABC(double range_limit = 100.0);

void test_mul_depth_8192_4_ABCD(double range_limit = 100.0);

void test_mul_depth_8192_4_ABCD_ok(double range_limit = 100.0);

void test_add_depth_4096_3_accA(double range_limit = 100.0, int acc_run = 10);

void test_add_depth_4096_4_accA(double range_limit = 100.0, int acc_run = 10);

void test_add_depth_8192_4_accA(double range_limit = 100.0, int acc_run = 10);

void test_muladd_depth_4096_3_AB_plus_accC(double range_limit = 100.0, int acc_run = 10);

void test_muladd_depth_4096_4_AB_plus_accC(double range_limit = 100.0, int acc_run = 10);

void test_muladd_depth_8192_4_ABC_plus_accD(double range_limit = 100.0, int acc_run = 10);

void test_square_depth_4096_3_A(double range_limit = 100.0);

void test_square_depth_4096_4_A(double range_limit = 100.0);

void test_square_depth_8192_4_A(double range_limit = 100.0);

void test_neg_depth_4096_3_A(double range_limit = 100.0, int neg_run = 10);

void test_neg_depth_4096_4_A(double range_limit = 100.0, int neg_run = 10);

void test_neg_depth_8192_4_A(double range_limit = 100.0, int neg_run = 10);

void test_rotate_depth_4096_3_A(double range_limit = 100.0, int run = 10);

void test_rotate_depth_4096_4_A(double range_limit = 100.0, int run = 10);

void test_rotate_depth_8192_4_A(double range_limit = 100.0, int run = 10);

void test_mulplain_depth_4096_3_A(double range_limit = 100.0);

void test_mulplain_depth_4096_4_A(double range_limit = 100.0);

void test_mulplain_depth_8192_4_A(double range_limit = 100.0);

void test_discriminant_2_4096_4(double range_limit = 100.0);

void test_discriminant_2_8192_4(double range_limit = 100.0);

void test_add_different_size_4096_3_AB_plus_C(double range_limit = 100.0);

void test_add_different_size_8192_4_AB_plus_C(double range_limit = 100.0);

void test_add_vs_size_perf_4096_3_AB_plus_C(double range_limit = 100.0);

#endif /* TEST_H_ */
