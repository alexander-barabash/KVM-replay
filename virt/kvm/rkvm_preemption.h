#ifndef __RKVM_PREEMPTION_H
#define __RKVM_PREEMPTION_H

#include <linux/rkvm_host.h>

struct rkvm_preemption;
struct rkvm_vcpu_preemption;
struct rkvm_userspace_data;

extern int rkvm_preemption_init(rkvm_host *host, struct rkvm_ops *ops);
extern void rkvm_preemption_destroy(rkvm_host *host);

extern int rkvm_vcpu_preemption_init(rkvm_vcpu_host *vcpu);
extern void rkvm_vcpu_preemption_destroy(rkvm_vcpu_host *host);

extern int rkvm_preemption_set_timer_quantum(rkvm_host *host, u32 preemption_timer_quantum);

extern void rkvm_preemption_on_vmentry(rkvm_vcpu_host *vcpu, struct rkvm_local_ops *lops);
extern void rkvm_preemption_on_vmexit(rkvm_vcpu_host *vcpu, struct rkvm_userspace_data *userspace,
				      struct rkvm_local_ops *lops);
extern void rkvm_preemption_on_update_vmexit_state(rkvm_vcpu_host *vcpu,
						   struct rkvm_userspace_data *userspace);

extern void rkvm_preemption_on_vcpu_exit(rkvm_vcpu_host *vcpu,
					 struct rkvm_userspace_data *userspace,
					 bool internal);

extern bool rkvm_preemption_handle_halt(rkvm_vcpu_host *vcpu);

extern void rkvm_preemption_vcpu_halted(rkvm_vcpu_host *vcpu);
extern void rkvm_preemption_step_locked(rkvm_vcpu_host *vcpu);
extern void rkvm_preemption_step_unlocked(rkvm_vcpu_host *vcpu);

extern void rkvm_preemption_userspace_entry(rkvm_host *host,
					    struct rkvm_userspace_data *userspace,
					    struct rkvm_userspace_data *out_userspace);
extern void rkvm_preemption_userspace_exit(rkvm_host *host,
					   struct rkvm_userspace_data *userspace,
					   struct rkvm_userspace_data *in_userspace);

extern u64 rkvm_preemption_get_tsc(rkvm_vcpu_host *vcpu);

extern void rkvm_preemption_update_debug_data(rkvm_vcpu_host *vcpu);

extern void rkvm_preemption_run_free(rkvm_vcpu_host *vcpu, bool on, struct rkvm_local_ops *lops);


extern bool kvm_has_preemption_timer;
extern int kvm_preemption_timer_rate;

struct rkvm_preemption {
	struct rkvm_ops *ops;
	spinlock_t spinlock;
	u64 front;
	u64 back;
	u64 steal;
	u64 tsc_when_stopped;
	u32 quantum;
	bool all_stopped;
};

struct rkvm_vcpu_preemption {
	u64 accumulate_preemption_timer;
	u32 entry_preemption_timer;
	bool vcpu_launched;
	bool vcpu_halted;
	bool step_locked;
	bool run_free;
};

#endif /* __RKVM_PREEMPTION_H */
