#include "bpf/event.h"
#include "logging.h"
#include <stddef.h>

int handle_event(void *ctx, void *data, size_t data_sz) {
  if (data_sz != sizeof(struct passible_event)) {
    return -1;
  }
  struct passible_event *p_data;
  p_data = (struct passible_event *)data;
  logging_alert("THIS IS EVENT");
  return 0;
}
