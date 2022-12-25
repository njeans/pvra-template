#include <stdio.h>

#include "app.h"

FILE *open_file(const char *const filename, const char *const mode) {
  return fopen(filename, mode);
}