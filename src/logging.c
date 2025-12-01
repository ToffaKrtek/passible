#include <stdio.h>
#include <stdlib.h>

static FILE *fptr;

int logging_init(const char *log_path) {
  if (!log_path || log_path[0] == '\0') {
    fptr = stderr;
  } else {
    fptr = fopen(log_path, "a");
  }

  if (fptr == NULL) {
    return EXIT_FAILURE;
  }
  return EXIT_SUCCESS;
}

void logging_alert(const char *event) {
  if (!event)
    return;
  fprintf(fptr, "%s\n", event);
  fflush(fptr);
}

void logging_shutdown() {
  if (fptr && fptr != stdout && fptr != stderr) {
    fclose(fptr);
  }
  fptr = NULL;
}
