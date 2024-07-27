#include "x7g.h"
#include <string.h>  // Correct header for C code

uint32_t getBlockTimestamp(const struct work *work) {
    if (work == NULL) {
        return 0;  // Return an appropriate error value or handle the error
    }
    return work->header.time;
}
