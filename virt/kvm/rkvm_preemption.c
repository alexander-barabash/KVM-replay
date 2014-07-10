#include "rkvm_preemption.h"
#include <linux/kvm_host.h>
#include <linux/export.h>

static void rkvm_preemption_update_tsc(struct rkvm_preemption *preemption);
static void rkvm_preemption_update(rkvm_host *host, struct rkvm_userspace_data *userspace);
static void rkvm_preemption_run_resume(struct rkvm_preemption *preemption);

#define RKVM_STATIC_CHECK(name, expr) \
	u8 static_check_##name[(expr)? 1: -1] __attribute__((unused))

#define RKVM_PREEMPTION(host) \
	((host)->rkvm_preemption)

#define RKVM_VCPU_PREEMPTION(vcpu) \
	((vcpu)->rkvm_vcpu_preemption)

#define RKVM_VCPU_DEBUG_DATA(vcpu) \
	((struct rkvm_vcpu_debug_data *)(&(vcpu)->run->rkvm_vcpu_debug_data))

#define PREEMPTION_LOCKED(preemption, ...)			\
	do {							\
		spinlock_t *__spinlock;				\
		__spinlock = &(preemption)->spinlock;		\
		spin_lock(__spinlock);				\
		do { __VA_ARGS__; } while (0);			\
		spin_unlock(__spinlock);			\
	} while (0)

#define PREEMPTION_LOCKED_READ(preemption, ...)			\
	do {								\
		spinlock_t *__spinlock;					\
		__spinlock = &(preemption)->spinlock;			\
		spin_lock(__spinlock);					\
		do { __VA_ARGS__; } while (0);				\
		spin_unlock(__spinlock);				\
	} while (0)

#define PREEMPTION_LOCKED_WRITE(preemption, ...)			\
	do {								\
		spinlock_t *__spinlock;					\
		__spinlock = &(preemption)->spinlock;			\
		spin_lock(__spinlock);					\
		do { __VA_ARGS__; } while (0);				\
		spin_unlock(__spinlock);				\
	} while (0)

static inline
bool rkvm_preemption_vcpu_running(struct rkvm_vcpu_preemption *vcpu_preemption)
{
	return likely(vcpu_preemption->vcpu_launched) &&
		!vcpu_preemption->vcpu_halted;
}

static inline void rkvm_preemption_all_stopped(struct rkvm_preemption *preemption)
{
	preemption->back = ~(u64)0;
	preemption->all_stopped = true;
}

static inline void rkvm_preemption_update_vcpu(struct rkvm_preemption *preemption,
					       bool running,
					       u64 accumulate_ucc)
{
	if (running) {
		preemption->all_stopped = false;
		preemption->back =
			min(preemption->back, accumulate_ucc);
	}
	preemption->front = max(preemption->front, accumulate_ucc);
}

u64 rkvm_preemption_get_tsc(rkvm_vcpu_host *vcpu)
{
	rkvm_host *host = RKVM_HOST(vcpu);
	struct rkvm_preemption *preemption = RKVM_PREEMPTION(host);
	struct rkvm_vcpu_preemption *vcpu_preemption = RKVM_VCPU_PREEMPTION(vcpu);

	u64 steal;
	PREEMPTION_LOCKED_READ(preemption, steal = preemption->steal);
	return steal + vcpu_preemption->accumulate_ucc;
}

void rkvm_preemption_on_vmentry(rkvm_vcpu_host *vcpu, struct rkvm_local_ops *lops)
{
	rkvm_host *host = RKVM_HOST(vcpu);
	struct rkvm_preemption *preemption = RKVM_PREEMPTION(host);
	struct rkvm_ops *ops = preemption->ops;

	struct rkvm_vcpu_preemption *vcpu_preemption = RKVM_VCPU_PREEMPTION(vcpu);
	u64 ucc_horizon;

	PREEMPTION_LOCKED_READ(preemption,
			       ucc_horizon = preemption->back + preemption->quantum);
	if (!rkvm_preemption_vcpu_running(vcpu_preemption))
		PREEMPTION_LOCKED(preemption,
				  vcpu_preemption->vcpu_launched = true;
				  vcpu_preemption->vcpu_halted = false;
				  vcpu_preemption->accumulate_ucc = preemption->front;
				  rkvm_preemption_run_resume(preemption));

	if (!vcpu_preemption->run_free) {
		s64 ucc_delta = ucc_horizon - vcpu_preemption->accumulate_ucc;
		if (ucc_delta <= 0)
			vcpu_preemption->entry_ucc = -1;
		else
			vcpu_preemption->entry_ucc = -ucc_delta;
		lops->make_apic_deliver_nmi_on_pmi();
	} else {
		vcpu_preemption->entry_ucc = 0;
	}

	ops->set_ucc(vcpu, vcpu_preemption->entry_ucc);
	rkvm_print_ucc(vcpu, vcpu_preemption->entry_ucc, true);
}

void rkvm_preemption_on_vmexit(rkvm_vcpu_host *vcpu, struct rkvm_userspace_data *userspace,
			       struct rkvm_local_ops *lops)
{
	rkvm_host *host = RKVM_HOST(vcpu);
	struct rkvm_preemption *preemption = RKVM_PREEMPTION(host);
	struct rkvm_ops *ops = preemption->ops;
	struct rkvm_vcpu_preemption *vcpu_preemption = RKVM_VCPU_PREEMPTION(vcpu);
	bool halted = ops->guest_halted(vcpu);
	u64 exit_ucc = ops->read_ucc(vcpu);

	u64 accumulate_ucc =
		vcpu_preemption->accumulate_ucc +
		exit_ucc -
		vcpu_preemption->entry_ucc;

	rkvm_print_ucc(vcpu, exit_ucc, false);

	PREEMPTION_LOCKED_WRITE(preemption,
				vcpu_preemption->accumulate_ucc =
				accumulate_ucc;
				vcpu_preemption->vcpu_halted = halted);

	if (!vcpu_preemption->step_locked)
		rkvm_preemption_update(host, userspace);
}

void rkvm_preemption_on_update_vmexit_state(rkvm_vcpu_host *vcpu, struct rkvm_userspace_data *userspace)
{
}

void rkvm_preemption_on_vcpu_exit(rkvm_vcpu_host *vcpu,
				  struct rkvm_userspace_data *userspace,
				  bool internal)
{
	rkvm_host *host = RKVM_HOST(vcpu);
	struct rkvm_vcpu_preemption *vcpu_preemption = RKVM_VCPU_PREEMPTION(vcpu);
	if (vcpu_preemption->step_locked || vcpu_preemption->vcpu_halted) {
		rkvm_preemption_update(host, userspace);
	}
}

bool rkvm_preemption_handle_halt(rkvm_vcpu_host *vcpu)
{
	rkvm_preemption_vcpu_halted(vcpu);
	return false;
}

void rkvm_preemption_userspace_entry(rkvm_host *host,
				     struct rkvm_userspace_data *userspace,
				     struct rkvm_userspace_data *out_userspace)
{
	struct rkvm_preemption *preemption = RKVM_PREEMPTION(host);

	PREEMPTION_LOCKED(preemption,
			  out_userspace->quantum = preemption->quantum;
			  out_userspace->back = preemption->back;
			  if (userspace->running == 0) {
				  userspace->accumulate_ucc = preemption->front;
				  rkvm_preemption_run_resume(preemption);
			  }
			  userspace->running++;
			  out_userspace->running = userspace->running;
			  out_userspace->accumulate_ucc =
			  userspace->accumulate_ucc);

}

void rkvm_preemption_userspace_exit(rkvm_host *host,
				    struct rkvm_userspace_data *userspace,
				    struct rkvm_userspace_data *in_userspace)
{
	struct rkvm_preemption *preemption = RKVM_PREEMPTION(host);
	u64 accumulate_ucc = in_userspace->accumulate_ucc;
	PREEMPTION_LOCKED(preemption,
			  if (accumulate_ucc > userspace->accumulate_ucc)
				  userspace->accumulate_ucc = accumulate_ucc;
			  userspace->running--);
}

void rkvm_preemption_vcpu_halted(rkvm_vcpu_host *vcpu)
{
	rkvm_host *host = RKVM_HOST(vcpu);
	struct rkvm_preemption *preemption = RKVM_PREEMPTION(host);
	struct rkvm_vcpu_preemption *vcpu_preemption = RKVM_VCPU_PREEMPTION(vcpu);

	PREEMPTION_LOCKED_WRITE(preemption,
				vcpu_preemption->vcpu_halted = true);
}

void rkvm_preemption_step_locked(rkvm_vcpu_host *vcpu)
{
	RKVM_VCPU_PREEMPTION(vcpu)->step_locked = true;
}

void rkvm_preemption_step_unlocked(rkvm_vcpu_host *vcpu)
{
	RKVM_VCPU_PREEMPTION(vcpu)->step_locked = false;
}

static void rkvm_preemption_update(rkvm_host *host, struct rkvm_userspace_data *userspace)
{
	struct rkvm_preemption *preemption = RKVM_PREEMPTION(host);
	int vcpu_index;
	rkvm_vcpu_host *vcpu;

	PREEMPTION_LOCKED(preemption,
			  rkvm_preemption_all_stopped(preemption);
			  kvm_for_each_vcpu(vcpu_index, vcpu, host) {
				  struct rkvm_vcpu_preemption *vcpu_preemption =
					  RKVM_VCPU_PREEMPTION(vcpu);
				  rkvm_preemption_update_vcpu(preemption,
							      rkvm_preemption_vcpu_running(vcpu_preemption),
							      vcpu_preemption->accumulate_ucc);
			  }
			  rkvm_preemption_update_vcpu(preemption,
						      (userspace->running > 0),
						      userspace->accumulate_ucc);
			  rkvm_preemption_update_tsc(preemption));
}

static void rkvm_preemption_update_tsc(struct rkvm_preemption *preemption)
{
	if(preemption->all_stopped)
		preemption->tsc_when_stopped = native_read_tsc();
	else
		preemption->tsc_when_stopped = 0;
}

static void rkvm_preemption_run_resume(struct rkvm_preemption *preemption)
{
	if(preemption->all_stopped) {
		u64 initial_tsc = preemption->tsc_when_stopped;
		u64 current_tsc = native_read_tsc();
		s64 delta = current_tsc - initial_tsc;
		if (delta > 0)
			preemption->steal += delta;
		preemption->all_stopped = false;
	}
}

int rkvm_preemption_init(rkvm_host *host, struct rkvm_ops *ops)
{
	struct rkvm_preemption *preemption;

	host->rkvm_preemption =
		(struct rkvm_preemption *)kzalloc(sizeof(*host->rkvm_preemption), GFP_KERNEL);
	preemption = RKVM_PREEMPTION(host);
	if (!preemption)
		return -ENOMEM;
	preemption->ops = ops;
	spin_lock_init(&preemption->spinlock);	
	preemption->back = ~(u64)0;
	return 0;
}

void rkvm_preemption_destroy(rkvm_host *host)
{
	if (host->rkvm_preemption != NULL) {
		kfree(host->rkvm_preemption);
		host->rkvm_preemption = NULL;
	}
}

int rkvm_vcpu_preemption_init(rkvm_vcpu_host *vcpu)
{
	vcpu->rkvm_vcpu_preemption = (struct rkvm_vcpu_preemption *)kzalloc(sizeof(*vcpu->rkvm_vcpu_preemption), GFP_KERNEL);
	if (!vcpu->rkvm_vcpu_preemption)
		return -ENOMEM;
	return 0;
}

void rkvm_vcpu_preemption_destroy(rkvm_vcpu_host *vcpu)
{
	struct rkvm_vcpu_preemption *vcpu_preemption = RKVM_VCPU_PREEMPTION(vcpu);
	if (vcpu_preemption) {
		kfree(vcpu_preemption);
		vcpu->rkvm_vcpu_preemption = NULL;
	}
}

u64 rkvm_get_quantum(rkvm_host *host)
{
	struct rkvm_preemption *preemption = RKVM_PREEMPTION(host);
	u32 quantum;
	PREEMPTION_LOCKED_READ(preemption,
			       quantum = preemption->quantum);
	return quantum;
}
EXPORT_SYMBOL_GPL(rkvm_get_quantum);

int rkvm_preemption_set_quantum(rkvm_host *host, u64 quantum)
{
	struct rkvm_preemption *preemption = RKVM_PREEMPTION(host);
	int ret;

	PREEMPTION_LOCKED(preemption,
			  if (quantum == preemption->quantum) {
				  ret = 0;
			  } else if (quantum == 0) {
				  ret = -EINVAL;
			  } else {
				  ret = 0;
				  preemption->quantum = quantum;
			  });

	return ret;
}

void rkvm_preemption_update_debug_data(rkvm_vcpu_host *vcpu)
{
	rkvm_host *host = RKVM_HOST(vcpu);
	struct rkvm_vcpu_debug_data *debug = RKVM_VCPU_DEBUG_DATA(vcpu);
	struct rkvm_preemption *preemption = RKVM_PREEMPTION(host);
	struct rkvm_vcpu_preemption *vcpu_preemption = RKVM_VCPU_PREEMPTION(vcpu);

	debug->front = preemption->front;
	debug->back = preemption->back;
	debug->steal = preemption->steal;
	debug->accumulate_ucc = vcpu_preemption->accumulate_ucc;
}

void rkvm_preemption_run_free(rkvm_vcpu_host *vcpu, bool on, struct rkvm_local_ops *lops)
{
	rkvm_host *host = RKVM_HOST(vcpu);
	struct rkvm_vcpu_preemption *vcpu_preemption = RKVM_VCPU_PREEMPTION(vcpu);
	struct rkvm_preemption *preemption = RKVM_PREEMPTION(host);
	struct rkvm_ops *ops = preemption->ops;
	vcpu_preemption->run_free = on;
	if (on) {
		vcpu_preemption->entry_ucc = 0;
		ops->set_ucc(vcpu, vcpu_preemption->entry_ucc);
		rkvm_print_ucc(vcpu, vcpu_preemption->entry_ucc, true);
	}
}
