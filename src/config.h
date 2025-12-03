#include <stddef.h>
#include <yaml.h>

typedef struct {
  int ignore_localhost;
  int ignore_private_networks;
  int ignore_public_dns;
  char **ignore_destinations; // NULL-terminated array
  size_t ignore_destinations_len;
} passible_network_config;

typedef struct {
  char **trusted_processes;
  size_t trusted_processes_len;
  int *suspicious_ports;
  size_t suspicious_ports_len;
  int min_heartbeat_interval_sec;
  int enable_entropy_check;
} passible_detection_config;

typedef struct {
  int enabled;
  int port;
} passible_prometheus_config;

typedef enum {
  PASSIBLE_LOG_LEVEL_ERROR = 0,
  PASSIBLE_LOG_LEVEL_WARNING = 1,
  PASSIBLE_LOG_LEVEL_INFO = 2,
  PASSIBLE_LOG_LEVEL_DEBUG = 3,
} passible_log_level;

typedef struct {
  char *log_file;
  passible_log_level log_level; // 0=error, 1=warning, 2=info, 3=debug
  passible_network_config network;
  passible_detection_config detection;
  passible_prometheus_config prometheus;
} passible_config;

passible_log_level get_log_level(char *level);

int config_load(const char *path, passible_config *out);

void config_free(passible_config *cfg);

void print_config(passible_config *conf);
