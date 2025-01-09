#include <ctype.h>
#include <source-file-reader.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

static FILE *rules_file;
static size_t line_number;

open_file_status open_rules_file(char *path, const char **err) {
    rules_file = fopen(path, "r");
    line_number = 0;

    if (rules_file == NULL) {
        *err = strerror(errno);

        return OPEN_RULES_FILE_ERROR;
    }

    return OPEN_RULES_FILE_OK;
}

read_file_status read_rules_file_line(char **out, size_t *line_number_out, const char **err) {
    size_t max_sz;
    char *ptr_copy;
    bool empty_line = true;

    *out = NULL;

    while (empty_line) {
        line_number++;
        
        if (getline(out, &max_sz, rules_file) == -1) {
            *err = strerror(errno);
            return READ_RULES_FILE_ERROR;
        }

        for (ptr_copy = *out; *ptr_copy != '\0'; ptr_copy++) {
            if (isprint(*ptr_copy)) {
                empty_line = false;
            }
        }
    }

    *line_number_out = line_number;
    (*out)[strcspn(*out, "\n")] = '\0';

    return READ_RULES_FILE_OK;
}

bool check_rules_file_eof() {
    return feof(rules_file) != 0;
}

void close_rules_file() {
    fclose(rules_file);
}
