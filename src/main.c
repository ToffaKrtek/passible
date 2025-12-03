#include "config.h"
#include "logging.h"
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char *argv[]) {
  // TODO:: init loger (open file/join to journald)
  // logging_init("/tmp/passible_test.log"); // TEST
  // logging_alert("{\"test\" : true}");     // TEST
  // logging_shutdown();                     // TEST

  // TODO:: load conf.yml + optional flag '-c'
  passible_config conf;
  config_load("conf.yml", &conf);
  print_config(&conf);
  config_free(&conf);

  // TODO:: load eBPF-app by skeleton
  // TODO:: SIGINT/SIGTERM -> correctly upload BPF and exit
  // TODO:: loop for ring buffer:
  //               a. PID -> proc name
  //               b. Check whitelist (IP, port, proc)
  //               c. if not exclude -> check in detector
  //               d. if detector triggered -> write to log
  // TODO:: check activate prometheus (run http-server on other thread)
  printf("passible starting...");
  return EXIT_SUCCESS;
}
