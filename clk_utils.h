/*
 * clk_utils.h
 *
 *  Created on: 17 Jan 2024
 *      Author: massimiliano
 */

#ifndef CLK_UTILS_H_
#define CLK_UTILS_H_

#include <iostream>
#include <stdint.h>
#include "config.h"
#include <inttypes.h>
#include <linux/perf_event.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <errno.h>

using namespace std;

/*
 * Function to initialise the file descriptor to read clock cycles counter
 */
inline int clk_measure_init(){
	int fd;
	struct perf_event_attr pe;

	memset(&pe, 0, sizeof(pe));
	pe.type = PERF_TYPE_HARDWARE;
	pe.size = sizeof(pe);
#if defined(__x86_64__)
	pe.config = PERF_COUNT_HW_REF_CPU_CYCLES;
#elif defined(__aarch64__)
	pe.config = PERF_COUNT_HW_CPU_CYCLES;
#elif
	pe.config = PERF_COUNT_HW_CPU_CYCLES;
#endif
	pe.disabled = 1;
	pe.exclude_kernel = 1;
	pe.exclude_hv = 1;

	fd = syscall(SYS_perf_event_open, &pe, 0, -1, -1, 0);
	if(fd == -1){
		fprintf(stdout, "Error opening leader %11x\n", pe.config);
		cout << errno << " " << strerror(errno) << endl;
		//exit(EXIT_FAILURE);
	}

	return fd;

};


/*
 * Function to read the starting clock cycle.
 * It resets the counter and enable the counting
 */
inline long long clk_read_start(int fd) {
	long long count;
	ioctl(fd, PERF_EVENT_IOC_RESET);
	ioctl(fd, PERF_EVENT_IOC_ENABLE);
	read(fd, &count, sizeof(count));
	return count;
};


/*
 * Function to read the ending clock cycle.
 * It disable the counting
 */
inline long long clk_read_end(int fd) {
	long long count;
	ioctl(fd, PERF_EVENT_IOC_DISABLE);
	read(fd, &count, sizeof(count));
	return count;
};


/*
 * Function to close the file descriptor used to read clock cycles counter
 */
inline void clk_measure_finish(int fd){
	close(fd);
};


#endif /* CLK_UTILS_H_ */
