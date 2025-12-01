#include <cstring>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <yaml.h>

int config_load(const char *path, struct passible_config *out) {
  FILE *fh = fopen(path, "r");
  yaml_parser_t parser;
  yaml_token_t token;

  if (yaml_parser_initialize(&parser)) {
    return EXIT_FAILURE;
  }
  if (fh == NULL) {
    return EXIT_FAILURE;
  }
  int next_key = 0;
  int next_value = 0;
  char key_value[32] = "";
  char current_section[32] = "";

  yaml_parser_set_input_file(&parser, fh);
  memset(out, 0, sizeof(*out));
  do {
    yaml_parser_scan(&parser, &token);
    switch (token.type) {
    case YAML_KEY_TOKEN:
      next_key = 1;
      next_value = 0;
      break;
    case YAML_VALUE_TOKEN:
      next_key = 0;
      next_value = 1;
      break;
    case YAML_SCALAR_TOKEN:
      if (next_key == 1) {
        strcpy(key_value, token.data.scalar.value);
        break;
      }
      if (next_value == 1) {

        if (strcmp(key_value, "log_file") == 0) {
          out->log_file = malloc(token.data.scalar.length + 1);
          if (out->log_file) {
            memccpy(out->log_file, token.data.scalar.value,
                    token.data.scalar.length);
            out->log_file[token.data.scalar.length] = '\0';
          }
        } else if (strcmp(key_value, "log_level") == 0) {

          out->log_level = malloc(token.data.scalar.length + 1);
          if (out->log_level) {
            memccpy(out->log_level, token.data.scalar.value,
                    token.data.scalar.length);
            out->log_level[token.data.scalar.length] = '\0';
          }
        } else if (strcmp(key_value, "network") == 0) {
        }
        break;
      }
    }
  } while (token.type != YAML_STREAM_END_TOKEN);
  yaml_token_delete(&token);

  fclose(fh);
  return EXIT_SUCCESS;
}

void config_free(struct passible_config *cfg) { free(cfg); }
