#ifndef __LH_HELPER_INJECT_H
#define __LH_HELPER_INJECT_H

#include <stdint.h>
#include "interface/if_inject.h"
#include "interface/inject_types.h"
#include "lh_module.h"

void *inj_build_payload_user(lh_fn_hook_t *fnh, uintptr_t symboladdr);
int inj_inject_payload(lh_fn_hook_t *fnh, uintptr_t symboladdr);

#endif
