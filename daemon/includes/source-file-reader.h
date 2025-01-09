#ifndef __SOURCE_FILE_READER__
#define __SOURCE_FILE_READER__

#include <stdbool.h>
#include <stddef.h>

#define READ_RULES_FILE_ERROR 3
#define READ_RULES_FILE_OK 2
#define OPEN_RULES_FILE_OK 1
#define OPEN_RULES_FILE_ERROR 0

typedef unsigned char open_file_status;
typedef unsigned char read_file_status;

open_file_status open_rules_file(char *path, const char **err);
read_file_status read_rules_file_line(char **out, size_t *line_number_out, const char **err);
bool check_rules_file_eof();
void close_rules_file();

#endif
