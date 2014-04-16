#ifndef __LINUX_USER_RKVM_H
#define __LINUX_USER_RKVM_H

#include <linux/types.h>

struct rkvm_vcpu_debug_data {
	__u64 accumulate_preemption_timer;
	__u64 accumulate_retired_branch_counter;
	__u64 reported_secs;
	
	__u32 num_unhalted_vcpus;
	__u32 userspace_running;
	
	__u64 front;
	__u64 back;
	__u64 steal;
	__u64 private_steal;
	__u64 last_read_tsc;
	__u32 last_read_tsc_aux;
	__u32 tscp_counter;

	__u64 exit_counter;
};

struct rkvm_userspace_data {
	__u64 accumulate_preemption_timer;
	__u64 preemption_timer_back;
	__u32 preemption_timer_quantum;
	__u32 running;
	__u32 locked;
};

#define RKVM_EXECUTION_MODE_LOCKSTEP 1
#define RKVM_EXECUTION_MODE_RECORD (1 << 1)
#define RKVM_EXECUTION_MODE_REPLAY (1 << 2)

#endif
