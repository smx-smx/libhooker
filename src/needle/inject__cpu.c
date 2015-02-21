#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/wait.h>

#include "needle.h"
#include "inject.h"

#if __x86_64__
    #include "inject_x64.cx"
#elif __i386__
    #include "inject_i386.cx"
#elif __arm__
    #include "inject_arm.cx"
#endif
