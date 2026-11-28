#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "ssh_parser.h"

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    struct ssh_event event;
    int result;

    /* Keep fuzz iterations bounded even with an unexpectedly large corpus. */
    if (size > 4096)
        return 0;

    memset(&event, 0xa5, sizeof(event));
    result = ssh_parse_record_n(data, size, &event);

    assert(result == 0 || result == -1);
    assert(event.type >= SSH_EVENT_UNKNOWN &&
           event.type <= SSH_EVENT_TRANSPORT_ERROR);
    assert(event.severity >= SSH_LOG_SEVERITY_UNKNOWN &&
           event.severity <= SSH_LOG_SEVERITY_FATAL);

    /* Every exported fixed-size field must remain NUL-terminated. */
    assert(memchr(event.timestamp, '\0', sizeof(event.timestamp)) != NULL);
    assert(memchr(event.hostname, '\0', sizeof(event.hostname)) != NULL);
    assert(memchr(event.pid, '\0', sizeof(event.pid)) != NULL);
    assert(memchr(event.username, '\0', sizeof(event.username)) != NULL);
    assert(memchr(event.address, '\0', sizeof(event.address)) != NULL);
    assert(memchr(event.message, '\0', sizeof(event.message)) != NULL);
    assert(memchr(event.disconnect_reason, '\0',
                  sizeof(event.disconnect_reason)) != NULL);

    if (result == 0) {
        assert(event.has_timestamp);
        assert(event.has_pid);
    }

    return 0;
}
