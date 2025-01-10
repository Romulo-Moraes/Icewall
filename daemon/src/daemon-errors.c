#include <daemon-errors.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

char* management_error_to_str(struct management_error err, char *out) {
    if (err.type == SOURCE_FILE_RELATED_ERROR) {
        sprintf(out, "Error on line %u: %s", err.line, err.msg);
    } else {
        strcpy(out, err.msg);
    }

    return out;
}
