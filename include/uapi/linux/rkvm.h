#ifndef __LINUX_USER_RKVM_H
#define __LINUX_USER_RKVM_H

#include <linux/types.h>

struct rkvm_vcpu_debug_data {
	__u64 cnt;

	__u64 accumulate_ucc;
	__u64 reported_secs;
	
	__u32 userspace_running;
	
	__u64 front;
	__u64 back;
	__u64 steal;
	__u64 last_read_tsc;
	__u32 last_read_tsc_aux;
	__u32 tscp_counter;
};

struct rkvm_userspace_data {
	__u64 accumulate_ucc;
	__u64 back;
	__u32 quantum;
	__u32 running;
};

struct rkvm_stream_fds {
	int fd[32];
	char name[32][8];
	int count;
};

struct rkvm_xfer {
	const void *src;
	void *dest;
	__u32 size;
};

#define RKVM_EXECUTION_MODE_LOCKSTEP (1 << 0)
#define RKVM_EXECUTION_MODE_PREEMPT  (1 << 1)
#define RKVM_EXECUTION_MODE_RECORD   (1 << 2)
#define RKVM_EXECUTION_MODE_REPLAY   (1 << 3)

#endif
