#include "config.h"
#include "types.h"
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <yaml.h>

const char *DEFAULT_LOG_FILE = "/var/log/passible.log";

passible_log_level get_log_level(char *level) {
  if (strcmp(level, "error") == 0) {
    return PASSIBLE_LOG_LEVEL_ERROR;
  } else if (strcmp(level, "warning") == 0) {
    return PASSIBLE_LOG_LEVEL_WARNING;
  } else if (strcmp(level, "info") == 0) {
    return PASSIBLE_LOG_LEVEL_INFO;
  } else if (strcmp(level, "debug") == 0) {
    return PASSIBLE_LOG_LEVEL_DEBUG;
  }
  int num = atoi(level);
  switch (num) {
  case 3:
    return PASSIBLE_LOG_LEVEL_DEBUG;
  case 2:
    return PASSIBLE_LOG_LEVEL_INFO;
  case 1:
    return PASSIBLE_LOG_LEVEL_WARNING;
  default:
    return PASSIBLE_LOG_LEVEL_ERROR;
  }
}

int config_load(const char *path, passible_config *out) {
  FILE *fh = fopen(path, "r");
  if (fh == NULL) {
    return EXIT_WITH_ERROR;
  }
  yaml_parser_t parser;
  yaml_document_t document;

  if (!yaml_parser_initialize(&parser)) {
    fclose(fh);
    return EXIT_WITH_ERROR;
  }
  yaml_parser_set_input_file(&parser, fh);
  if (yaml_parser_load(&parser, &document) != 1) {
    fclose(fh);
    return EXIT_WITH_ERROR;
  }

  yaml_node_t *root = yaml_document_get_root_node(&document);
  if (!root || root->type != YAML_MAPPING_NODE) {
    yaml_document_delete(&document);
    fclose(fh);
    return EXIT_WITH_ERROR;
  }
  memset(out, 0, sizeof(*out));
  out->log_file = strdup(DEFAULT_LOG_FILE);
  out->log_level = PASSIBLE_LOG_LEVEL_ERROR;
  out->network.ignore_localhost = 1;
  out->network.ignore_private_networks = 1;
  out->detection.min_heartbeat_interval_sec = 20;
  out->detection.enable_entropy_check = 1;
  out->prometheus.enabled = 0;
  out->prometheus.port = 0;

  for (yaml_node_pair_t *pair = root->data.mapping.pairs.start;
       pair < root->data.mapping.pairs.top; pair++) {
    yaml_node_t *key_node = yaml_document_get_node(&document, pair->key);
    yaml_node_t *value_node = yaml_document_get_node(&document, pair->value);

    if (key_node->type == YAML_SCALAR_NODE) {
      if (value_node->type == YAML_MAPPING_NODE) {
        if (strcmp((char *)key_node->data.scalar.value, "network") == 0) {
          // PARSE NETWORK BLOCK
          for (yaml_node_pair_t *network_pair =
                   value_node->data.mapping.pairs.start;
               network_pair < value_node->data.mapping.pairs.top;
               network_pair++) {
            yaml_node_t *network_key_node =
                yaml_document_get_node(&document, network_pair->key);
            yaml_node_t *network_value_node =
                yaml_document_get_node(&document, network_pair->value);
            if (network_key_node->type == YAML_SCALAR_NODE) {
              if (strcmp((char *)network_key_node->data.scalar.value,
                         "ignore_localhost") == 0) {
                if (network_value_node->data.scalar.value) {
                  out->network.ignore_localhost =
                      atoi((char *)network_value_node->data.scalar.value);
                }
              } else if (strcmp((char *)network_key_node->data.scalar.value,
                                "ignore_private_networks") == 0) {

                if (network_value_node->data.scalar.value) {
                  out->network.ignore_private_networks =
                      atoi((char *)network_value_node->data.scalar.value);
                }
              } else if (strcmp((char *)network_key_node->data.scalar.value,
                                "ignore_public_dns") == 0) {
                if (network_value_node->data.scalar.value) {
                  out->network.ignore_public_dns =
                      atoi((char *)network_value_node->data.scalar.value);
                }
              } else if (strcmp((char *)network_key_node->data.scalar.value,
                                "ignore_destinations") == 0 &&
                         network_value_node->type == YAML_SEQUENCE_NODE) {
                out->network.ignore_destinations_len =
                    network_value_node->data.sequence.items.top -
                    network_value_node->data.sequence.items.start;
                if (out->network.ignore_destinations_len > 0) {
                  out->network.ignore_destinations = malloc(
                      out->network.ignore_destinations_len * sizeof(char *));
                  size_t index = 0;
                  for (yaml_node_item_t *item =
                           network_value_node->data.sequence.items.start;
                       item < network_value_node->data.sequence.items.top;
                       item++, index++) {
                    yaml_node_t *arr_item_node =
                        yaml_document_get_node(&document, *item);
                    if (arr_item_node->type == YAML_SCALAR_NODE) {
                      if (arr_item_node->data.scalar.value) {
                        char *copy =
                            strdup((char *)arr_item_node->data.scalar.value);
                        if (!copy) {
                          config_free(out);
                          return EXIT_WITH_ERROR;
                        }
                        out->network.ignore_destinations[index] = copy;
                      }
                    }
                  }
                }
              }
            }
          }
        } else if (strcmp((char *)key_node->data.scalar.value, "detection") ==
                   0) {
          // PARSE DETECTION BLOCK
          for (yaml_node_pair_t *detection_pair =
                   value_node->data.mapping.pairs.start;
               detection_pair < value_node->data.mapping.pairs.top;
               detection_pair++) {
            yaml_node_t *detection_key_node =
                yaml_document_get_node(&document, detection_pair->key);
            yaml_node_t *detection_value_node =
                yaml_document_get_node(&document, detection_pair->value);
            if (detection_key_node->type == YAML_SCALAR_NODE) {
              if (strcmp((char *)detection_key_node->data.scalar.value,
                         "trusted_processes") == 0 &&
                  detection_value_node->type == YAML_SEQUENCE_NODE) {
                out->detection.trusted_processes_len =
                    detection_value_node->data.sequence.items.top -
                    detection_value_node->data.sequence.items.start;
                if (out->detection.trusted_processes_len > 0) {
                  out->detection.trusted_processes = malloc(
                      out->detection.trusted_processes_len * sizeof(char *));
                  size_t index = 0;
                  for (yaml_node_item_t *item =
                           detection_value_node->data.sequence.items.start;
                       item < detection_value_node->data.sequence.items.top;
                       item++, index++) {
                    yaml_node_t *arr_item_node =
                        yaml_document_get_node(&document, *item);
                    if (arr_item_node->type == YAML_SCALAR_NODE) {
                      if (arr_item_node->data.scalar.value) {
                        char *copy =
                            strdup((char *)arr_item_node->data.scalar.value);
                        if (!copy) {
                          config_free(out);
                          return EXIT_WITH_ERROR;
                        }
                        out->detection.trusted_processes[index] = copy;
                      }
                    }
                  }
                }
              } else if (strcmp((char *)detection_key_node->data.scalar.value,
                                "suspicious_ports") == 0 &&
                         detection_value_node->type == YAML_SEQUENCE_NODE) {
                out->detection.suspicious_ports_len =
                    detection_value_node->data.sequence.items.top -
                    detection_value_node->data.sequence.items.start;
                if (out->detection.suspicious_ports_len > 0) {
                  out->detection.suspicious_ports =
                      malloc(out->detection.suspicious_ports_len * sizeof(int));
                  size_t index = 0;
                  for (yaml_node_item_t *item =
                           detection_value_node->data.sequence.items.start;
                       item < detection_value_node->data.sequence.items.top;
                       item++, index++) {
                    yaml_node_t *arr_item_node =
                        yaml_document_get_node(&document, *item);
                    if (arr_item_node->type == YAML_SCALAR_NODE) {
                      if (arr_item_node->data.scalar.value) {
                        out->detection.suspicious_ports[index] =
                            atoi((char *)arr_item_node->data.scalar.value);
                      }
                    }
                  }
                }
              } else if (strcmp((char *)detection_key_node->data.scalar.value,
                                "min_heartbeat_interval_sec") == 0) {
                if (detection_value_node->data.scalar.value) {
                  out->detection.min_heartbeat_interval_sec =
                      atoi((char *)detection_value_node->data.scalar.value);
                }
              } else if (strcmp((char *)detection_key_node->data.scalar.value,
                                "enable_entropy_check") == 0) {
                if (detection_value_node->data.scalar.value) {
                  out->detection.enable_entropy_check =
                      atoi((char *)detection_value_node->data.scalar.value);
                }
              }
            }
          }
        } else if (strcmp((char *)key_node->data.scalar.value, "prometheus") ==
                   0) {
          // PARSE PROMETHEUS BLOCK
          for (yaml_node_pair_t *prometheus_pair =
                   value_node->data.mapping.pairs.start;
               prometheus_pair < value_node->data.mapping.pairs.top;
               prometheus_pair++) {
            yaml_node_t *prometheus_key_node =
                yaml_document_get_node(&document, prometheus_pair->key);
            yaml_node_t *prometheus_value_node =
                yaml_document_get_node(&document, prometheus_pair->value);
            if (prometheus_key_node->type == YAML_SCALAR_NODE) {
              if (strcmp((char *)prometheus_key_node->data.scalar.value,
                         "enabled") == 0) {

                if (prometheus_value_node->data.scalar.value) {
                  out->prometheus.enabled =
                      atoi((char *)prometheus_value_node->data.scalar.value);
                }
              } else if (strcmp((char *)prometheus_key_node->data.scalar.value,
                                "port") == 0) {
                if (prometheus_value_node->data.scalar.value) {
                  out->prometheus.port =
                      atoi((char *)prometheus_value_node->data.scalar.value);
                }
              }
            }
          }
        }
      } else {
        // PARSE NON BLOCK
        if (strcmp((char *)key_node->data.scalar.value, "log_file") == 0) {

          if (value_node->data.scalar.value) {
            char *copy = strdup((char *)value_node->data.scalar.value);
            if (!copy) {
              config_free(out);
              return EXIT_WITH_ERROR;
            }
            out->log_file = copy;
          }
        } else if (strcmp((char *)key_node->data.scalar.value, "log_level") ==
                   0) {
          if (value_node->data.scalar.value) {
            out->log_level =
                get_log_level((char *)value_node->data.scalar.value);
          }
        }
      }
    }
  }

  return EXIT_OK;
}

void config_free(passible_config *cfg) {
  if (!cfg)
    return;
  free(cfg->log_file);
  free(cfg->network.ignore_destinations);
  free(cfg->detection.trusted_processes);
  free(cfg->detection.suspicious_ports);
}

void print_config(passible_config *conf) {
  fprintf(stderr, "Log file: %s\n", conf->log_file ? conf->log_file : "(null)");
  fprintf(stderr, "Log level: %d\n", (int)conf->log_level);

  // NETWORK
  fprintf(stderr, "Network:\n");
  fprintf(stderr, "  Ignore localhost: %d\n", conf->network.ignore_localhost);
  fprintf(stderr, "  Ignore private networks: %d\n",
          conf->network.ignore_private_networks);
  fprintf(stderr, "  Ignore public dns: %d\n", conf->network.ignore_public_dns);
  fprintf(stderr, "  Ignore destinations:\n");
  for (size_t i = 0; i < conf->network.ignore_destinations_len; i++) {
    char *dest = conf->network.ignore_destinations[i];
    fprintf(stderr, "    - %s\n", dest ? dest : "(null)");
  }
  // DETECTION
  fprintf(stderr, "Detection:\n");
  fprintf(stderr, "  Min heartbeat interval: %d(sec)\n",
          conf->detection.min_heartbeat_interval_sec);
  fprintf(stderr, "  Enable entropy check: %d\n",
          (int)conf->detection.enable_entropy_check);
  fprintf(stderr, "  Trusted processes:\n");
  for (size_t i = 0; i < conf->detection.trusted_processes_len; i++) {
    char *dest = conf->detection.trusted_processes[i];
    fprintf(stderr, "    - %s\n", dest ? dest : "(null)");
  }
  fprintf(stderr, "  Suspicious ports:\n");
  for (size_t i = 0; i < conf->detection.suspicious_ports_len; i++) {
    fprintf(stderr, "    - %d\n", (int)conf->detection.suspicious_ports[i]);
  }
  // PROMETHEUS
  fprintf(stderr, "Prometheus:\n");
  fprintf(stderr, "  Enabled: %d\n", (int)conf->prometheus.enabled);
  fprintf(stderr, "  Port: %d\n", (int)conf->prometheus.port);
}
