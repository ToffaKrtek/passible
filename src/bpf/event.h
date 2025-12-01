#ifndef PASSIBLE_EVENT_H
#define PASSIBLE_EVENT_H

#define TASK_COMM_LEN 16
#define MAX_PAYLOAD 128

struct passible_event {
  unsigned long long timestamp_ns;
  unsigned int pid;
  unsigned int uid;
  unsigned int dst_ip4;
  unsigned short dst_port;
  unsigned short proto;
  unsigned int bytes;
  char comm[TASK_COMM_LEN];
  unsigned char payload[MAX_PAYLOAD];
  unsigned char payload_len;
};

#endif // !PASSIBLE_EVENT_H
