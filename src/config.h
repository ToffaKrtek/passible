#include <stddef.h>

struct passible_config {
  char *log_file;
  int log_level; // 0=error, 1=warning, 2=info, 3=debug
                 //
  struct {
    int ignore_localhost;
    int ignore_private_networks;
    int ignore_public_dns;
    char **ignore_destinations; // NULL-terminated array
    size_t ignore_destions_len;
  } network;

  struct {
    char **trusted_processes;
    size_t trusted_processes_len;
    int *suspicious_ports;
    size_t suspicious_ports_len;
    int min_heartbeat_interval_sec;
    int enable_entropy_check;
  } detection;

  struct {
    int enabled;
    int port;
  } prometheus;
};

int config_load(const char *path, struct passible_config *out);

void config_free();
