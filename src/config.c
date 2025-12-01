
#include <stdio.h>
#include <stdlib.h>
#include <yaml.h>

int config_load(const char *path, struct passible_config *out) {
  FILE *fh = fopen(path, "r");
  yaml_parser_t parser;
  if (yaml_parser_initialize(&parser)) {
    return EXIT_FAILURE;
  }
  if (fh == NULL) {
    return EXIT_FAILURE;
  }
  fclose(fh);
  return EXIT_SUCCESS;
}

void config_free() {}
