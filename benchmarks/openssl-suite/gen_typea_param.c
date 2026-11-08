#include <pbc/pbc.h>
#include <stdio.h>

int main(void) {
    pbc_param_t par;
    /* PBC Type-A: 256-bit subgroup order, 1536-bit base field. */
    pbc_param_init_a_gen(par, 256, 1536);
    pbc_param_out_str(stdout, par);
    pbc_param_clear(par);
    return 0;
}
