#include "bpf/passible.skel.h" // сгенерированный skeleton
#include "event_handler.h"
#include "types.h"
#include <asm-generic/errno-base.h>
#include <bpf/libbpf.h>
#include <signal.h>
#include <stdio.h>
#include <unistd.h>

static struct passible_bpf *skel = NULL;

int bpf_loader_init(void) {
  skel = passible_bpf__open_and_load();
  if (!skel) {
    fprintf(stderr, "Failed to open and load BPF skeleton\n");
    return EXIT_WITH_ERROR;
  }
  return EXIT_OK;
}

int bpf_loader_start_event_loop(void) {
  struct ring_buffer *rb =
      ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);

  if (!rb) {
    fprintf(stderr, "Failed to create ring buffer\n");
    return EXIT_WITH_ERROR;
  }

  printf("Starting event loop...\n");
  while (1) {
    int ret = ring_buffer__poll(rb, 100);
    if (ret < 0 && errno == EINTR) {
      break;
    }
  }

  ring_buffer__free(rb);
  return EXIT_OK;
}

void bpf_loader_destroy(void) {
  if (skel) {
    passible_bpf__destroy(skel);
  }
}
