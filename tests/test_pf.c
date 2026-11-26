#include "pf.h"
#include <assert.h>
#include <string.h>

int main(void) {
    assert(pf_valid_address("192.0.2.10"));
    assert(pf_valid_address("2001:db8::10"));
    assert(!pf_valid_address("not-an-ip"));
    assert(!pf_valid_address("192.0.2.999"));
    assert(!pf_valid_address(""));

    assert(pf_init("airbotz_temp", "airbotz_perm") == 0);
    assert(pf_init("same_table", "same_table") == -1);
    assert(pf_init("bad-name", "airbotz_perm") == -1);

    pf_shutdown();
    return 0;
}
