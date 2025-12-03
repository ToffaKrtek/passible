#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "event.h"

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 1 << 24);
} rb SEC(".maps");

SEC("tracepoint/sock/inet_sock_set_state")
int handle_tcp_event(struct trace_event_raw_inet_sock_set_state *ctx) {
  if (ctx->newstate != 4) {
    return 0;
  }
  if (ctx->oldstate != 0) {
    return 0;
  }

  struct passible_event *e;
  e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
  if (!e) {
    return 0;
  }

  e->timestamp_ns = bpf_ktime_get_ns();
  e->pid = bpf_get_current_pid_tgid() >> 32;
  e->uid = bpf_get_current_uid_gid();
  e->dst_ip4 = *((__u32 *)ctx->daddr);
  e->dst_port = ctx->dport;
  e->proto = IPPROTO_TCP;
  e->bytes = 0;

  // PROCESS NAME !!
  bpf_get_current_comm(&e->comm, sizeof(e->comm));

  bpf_ringbuf_submit(e, 0);
  return 0;
}

char LICENSE[] SEC("license") = "MIT";
