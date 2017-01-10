#include <stdlib.h>

#include "init.h"
#include "util.h"

int init(void) {
    device = (char*)malloc(5);
    return SUCCESS;
}
