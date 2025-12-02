#include "config.h"
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <yaml.h>

int config_load(const char *path, passible_config *out) {
  FILE *fh = fopen(path, "r");
  if (fh == NULL) {
    return EXIT_FAILURE;
  }
  yaml_parser_t parser;
  yaml_document_t document;

  if (!yaml_parser_initialize(&parser)) {
    fclose(fh);
    return EXIT_FAILURE;
  }
  yaml_parser_set_input_file(&parser, fh);
  if (yaml_parser_load(&parser, &document) != 1) {
    fclose(fh);
    return EXIT_FAILURE;
  }

  yaml_node_t *root = yaml_document_get_root_node(&document);
  if (!root || root->type != YAML_MAPPING_NODE) {
    yaml_document_delete(&document);
    fclose(fh);
    return EXIT_FAILURE;
  }
  memset(out, 0, sizeof(*out));
  out->log_level = 2;
  out->network.ignore_localhost = 1;
  out->network.ignore_private_networks = 1;
  out->detection.min_heartbeat_interval_sec = 20;

  for (yaml_node_pair_t *pair = root->data.mapping.pairs.start;
       pair < root->data.mapping.pairs.top; pair++) {
    yaml_node_t *key_node = yaml_document_get_node(&document, pair->key);
    yaml_node_t *value_node = yaml_document_get_node(&document, pair->value);

    if (key_node->type == YAML_SCALAR_NODE) {
      if (strcmp((char *)key_node->data.scalar.value, "network") &&
          value_node->type == YAML_MAPPING_NODE) {
        for (yaml_node_pair_t *network_pair =
                 key_node->data.mapping.pairs.start;
             network_pair < key_node->data.mapping.pairs.top; network_pair++) {
          yaml_node_t *network_key_node =
              yaml_document_get_node(&document, network_pair->key);
          yaml_node_t *network_value_node =
              yaml_document_get_node(&document, network_pair->value);
          if (network_key_node->type == YAML_SCALAR_NODE) {
            if (strcmp((char *)network_key_node->data.scalar.value,
                       "ignore_localhost")) {
              out->network.ignore_localhost =
                  atoi((char *)network_value_node->data.scalar.value);
            } else if (strcmp((char *)network_key_node->data.scalar.value,
                              "ignore_private_networks")) {
              out->network.ignore_private_networks =
                  atoi((char *)network_value_node->data.scalar.value);
            } else if (strcmp((char *)network_key_node->data.scalar.value,
                              "ignore_public_dns")) {
              out->network.ignore_public_dns =
                  atoi((char *)network_value_node->data.scalar.value);
            } else if (strcmp((char *)network_key_node->data.scalar.value,
                              (char *)network_key_node->data.scalar.value) ==
                           0 &&
                       network_value_node->type == YAML_SCALAR_NODE) {
              out->network.ignore_destions_len =
                  network_value_node->data.sequence.items.top -
                  network_value_node->data.sequence.items.start;
              out->network.ignore_destinations =
                  malloc(out->network.ignore_destions_len * sizeof(char *));
              size_t index = 0;
              for (yaml_node_item_t *item =
                       network_value_node->data.sequence.items.start;
                   item < network_value_node->data.sequence.items.top;
                   item++, index++) {
                yaml_node_t *arr_item_node =
                    yaml_document_get_node(&document, *item);
                if (arr_item_node->type == YAML_SCALAR_NODE) {
                  out->network.ignore_destinations[index] =
                      strdup((char *)arr_item_node->data.scalar.value);
                }
              }
            }
          }
        }
      } else if (strcmp((char *)key_node->data.scalar.value, "detection") &&
                 value_node->type == YAML_MAPPING_NODE) {
        for (yaml_node_pair_t *detection_pair =
                 key_node->data.mapping.pairs.start;
             detection_pair < key_node->data.mapping.pairs.top;
             detection_pair++) {
          yaml_node_t *detection_key_node =
              yaml_document_get_node(&document, detection_pair->key);
          yaml_node_t *detection_value_node =
              yaml_document_get_node(&document, detection_pair->value);
          if (detection_key_node->type == YAML_SCALAR_NODE) {
            if (strcmp((char *)detection_key_node->data.scalar.value,
                       "trusted_processes") == 0 &&
                detection_value_node->type == YAML_SCALAR_NODE) {
              out->detection.trusted_processes_len =
                  detection_value_node->data.sequence.items.top -
                  detection_value_node->data.sequence.items.start;
              out->detection.trusted_processes =
                  malloc(out->detection.trusted_processes_len * sizeof(char *));
              size_t index = 0;
              for (yaml_node_item_t *item =
                       detection_value_node->data.sequence.items.start;
                   item < detection_value_node->data.sequence.items.top;
                   item++, index++) {
                yaml_node_t *arr_item_node =
                    yaml_document_get_node(&document, *item);
                if (arr_item_node->type == YAML_SCALAR_NODE) {
                  out->detection.trusted_processes[index] =
                      strdup((char *)arr_item_node->data.scalar.value);
                }
              }
            } else if (strcmp((char *)detection_key_node->data.scalar.value,
                              "suspicious_ports") == 0 &&
                       detection_value_node->type == YAML_SCALAR_NODE) {
              out->detection.suspicious_ports_len =
                  detection_value_node->data.sequence.items.top -
                  detection_value_node->data.sequence.items.start;
              out->detection.suspicious_ports =
                  malloc(out->detection.suspicious_ports_len * sizeof(char *));
              size_t index = 0;
              for (yaml_node_item_t *item =
                       detection_value_node->data.sequence.items.start;
                   item < detection_value_node->data.sequence.items.top;
                   item++, index++) {
                yaml_node_t *arr_item_node =
                    yaml_document_get_node(&document, *item);
                if (arr_item_node->type == YAML_SCALAR_NODE) {
                  out->detection.suspicious_ports[index] =
                      atoi((char *)arr_item_node->data.scalar.value);
                }
              }
            } else if (strcmp((char *)detection_key_node->data.scalar.value,
                              "min_heartbeat_interval_sec") == 0) {
              out->detection.min_heartbeat_interval_sec =
                  atoi((char *)detection_value_node->data.scalar.value);
            } else if (strcmp((char *)detection_key_node->data.scalar.value,
                              "enable_entropy_check") == 0) {
              out->detection.enable_entropy_check =
                  atoi((char *)detection_value_node->data.scalar.value);
            }
          }
        }
      }
    }
  }

  return EXIT_SUCCESS;
}

void config_free(passible_config *cfg) {
  if (!cfg)
    return;
  free(cfg->log_file);
  cfg->log_file = NULL;
  free(cfg->network.ignore_destinations);
  cfg->network.ignore_destinations = NULL;
}
