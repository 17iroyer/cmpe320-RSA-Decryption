
#ifndef TIMER_HEADER
#define TIMER_HEADER
#include <time.h>
#include <stdint.h>

struct timespec timer_start();
uint64_t timer_end(struct timespec starttime);

#endif