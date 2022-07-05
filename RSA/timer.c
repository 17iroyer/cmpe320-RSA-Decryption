#include "timer.h"
#include <time.h>
#include <stdio.h>
#include <stdint.h>

/**
 * @brief starts the timer and stores values in a timespec struct
 * @return structure with starting values
 */
struct timespec timer_start() {
    struct timespec starttime;
    clock_gettime(CLOCK_MONOTONIC, &starttime);
    return starttime;
}

/**
 * @brief similar to timer_start, but stops the timer and returns elpsed time in microseconds
 * @param starttime timespec struct holding starting values
 * @return uint64_t elapsed time
 */
uint64_t timer_end(struct timespec starttime) {
    struct timespec stoptime;
    clock_gettime(CLOCK_MONOTONIC, &stoptime);
    uint64_t startmicro = (starttime.tv_sec * 1000000) + (starttime.tv_nsec * 0.001);
    uint64_t endmicro = (stoptime.tv_sec * 1000000) + (stoptime.tv_nsec * 0.001);

    return endmicro-startmicro;
}