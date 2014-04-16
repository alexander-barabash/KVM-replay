#include <linux/rkvm_data.h>
#include <linux/bscript.h>
#include <linux/bstream.h>
#include <linux/kvm_host.h>
#include <linux/export.h>

#define KVM_STATIC_CHECK(name, expr) \
	u8 static_check_##name[(expr)? 1: -1] __attribute__((unused))

struct rkvm_data {
	struct rkvm_ops *ops;

	spinlock_t spinlock;
	spinlock_t lockstep_spinlock;

	u64 preemption_timer_front;
	u64 preemption_timer_back;
	u64 preemption_timer_steal;
	u64 tsc_when_stopped;
	u32 preemption_timer_quantum;
	u16 num_unhalted_vcpus;
	bool all_stopped;

	bool use_preemption_timer;
	bool execute_in_lockstep;
	bool record_execution;
	bool replay_execution;

	struct kvm_userspace_preemption_data userspace;

	u64 last_record_id;
};

struct kvm_stream_data {
	struct kvm_stream_data **back_pointer;
	struct kvm_vcpu *vcpuX;
	int fdX;
	struct bstream *bstream;
	u32 bstream_use_count;
};

static inline struct kvm_vcpu *kvm_stream_vcpu(struct kvm_stream_data *data)
{
	return data->vcpuX;
}

static inline int kvm_stream_fd(struct kvm_stream_data *data)
{
	return data->fdX;
}

static inline void set_kvm_stream_data(struct kvm_stream_data *data,
				       struct kvm_vcpu *vcpu,
				       int fd,
				       struct bstream *bstream)
{
	data->vcpuX = vcpu;
	data->fdX = fd;
	data->bstream = bstream;
	data->bstream_use_count = 1;
}

static inline void clear_kvm_stream_data(struct kvm_stream_data *data)
{
	data->vcpuX = 0;
	data->fdX = -1;
}

struct kvm_vcpu_preemption_data {
	u64 accumulate_preemption_timer;
	u32 entry_preemption_timer_value;
	bool vcpu_launched;
	bool vcpu_halted;
	bool vcpu_locked;
	bool exit_on_preemption;
	bool need_vmexit_recorded;
	u64 entry_retired_branch_counter;

	u64 reported_record_id;
	u64 reported_retired_branch_counter;
	u64 reported_guest_rip;
	u32 reported_guest_ecx;

	u64 accumulate_retired_branch_counter;

	u32 entry_intr_info;
	struct kvm_stream_data *record_stream_data;
	struct kvm_stream_data *replay_stream_data;
};

#define RKVM_DATA(kvm) \
	((struct rkvm_data *)(&(kvm)->preemption_data))

#define VCPU_PREEMPTION_DATA(vcpu) \
	((struct kvm_vcpu_preemption_data *)(&(vcpu)->preemption_data))

#define VCPU_PREEMPTION_DEBUG_DATA(vcpu) \
	((struct preemption_debug_data *)(&(vcpu)->run->preemption_debug_data))

bool kvm_has_preemption_timer;
EXPORT_SYMBOL_GPL(kvm_has_preemption_timer);
int rkvm_timer_rate;
EXPORT_SYMBOL_GPL(rkvm_timer_rate);

static inline u64 preemption_timer_to_tsc(u64 preemption_timer)
{
	return preemption_timer << rkvm_timer_rate;
}

static inline u64 tsc_to_preemption_timer(u64 tsc)
{
	return (tsc + (1 << rkvm_timer_rate) - 1) >> rkvm_timer_rate;
}

static inline u64 preemption_timer_since_tsc(u64 initial_tsc) {
	u64 current_tsc = native_read_tsc();
	s64 delta = current_tsc - initial_tsc;
	u64 preemption_delta;
	if (delta <= 0)
		preemption_delta = 0;
	else
		preemption_delta = tsc_to_preemption_timer(delta);
	return preemption_delta;
}

static inline bool
rkvm_vcpu_launched(struct kvm_vcpu_preemption_data *vcpu_data)
{
	return likely(vcpu_data->vcpu_launched);
}

static inline bool
rkvm_vcpu_running(struct kvm_vcpu_preemption_data *vcpu_data)
{
	return rkvm_vcpu_launched(vcpu_data) &&
		!vcpu_data->vcpu_halted;
}

#define PREEMPTION_LOCKED(kvm_data, ...) \
	do {							\
		spinlock_t *__spinlock;				\
		__spinlock = &(kvm_data)->spinlock;	\
		spin_lock(__spinlock);				\
		do { __VA_ARGS__; } while (0);			\
		spin_unlock(__spinlock);			\
	} while (0)

static inline void update_preemption_debug_data(struct preemption_debug_data *debug,
						struct rkvm_data *kvm_data,
						struct kvm_vcpu_preemption_data *vcpu_data,
						bool counted_exit)
{
	PREEMPTION_LOCKED(kvm_data,
			  debug->front = kvm_data->preemption_timer_front;
			  debug->back = kvm_data->preemption_timer_back;
			  debug->accumulate_preemption_timer = vcpu_data->accumulate_preemption_timer;
			  debug->accumulate_retired_branch_counter = vcpu_data->accumulate_retired_branch_counter;
			  debug->num_unhalted_vcpus = kvm_data->num_unhalted_vcpus;
			  debug->userspace_running = kvm_data->userspace.running;
			  debug->steal = kvm_data->preemption_timer_steal;
			  debug->exit_counter += counted_exit ? 1 : 0);
}

bool kvm_enable_preemption_timer(struct kvm_vcpu *vcpu)
{
	struct kvm *kvm = vcpu->kvm;
	struct rkvm_data *kvm_data = RKVM_DATA(kvm);
	bool preemption_on;
	if (kvm_has_preemption_timer) {
		PREEMPTION_LOCKED(kvm_data,
				  preemption_on = (kvm_data->replay_execution || kvm_data->use_preemption_timer));
	} else {
		preemption_on = false;
	}
	return preemption_on;
}
EXPORT_SYMBOL_GPL(kvm_enable_preemption_timer);

bool rkvm_on(struct kvm *kvm)
{
	struct rkvm_data *kvm_data = RKVM_DATA(kvm);
	bool preemption_on;
	if (kvm_has_preemption_timer) {
		PREEMPTION_LOCKED(kvm_data,
				  preemption_on = (kvm_data->replay_execution || (kvm_data->preemption_timer_quantum != 0)));
	} else {
		preemption_on = false;
	}
	return preemption_on;
}
EXPORT_SYMBOL_GPL(rkvm_on);

static inline struct bstream *get_record_bstream(struct kvm_vcpu *vcpu)
{
	struct kvm_vcpu_preemption_data *vcpu_data = VCPU_PREEMPTION_DATA(vcpu);
	struct kvm_stream_data *stream_data = vcpu_data->record_stream_data;
	struct bstream *record_bstream;
	if (stream_data)
		record_bstream = stream_data->bstream;
	else
		record_bstream = NULL;
	return record_bstream;
}

static inline struct bstream *get_replay_bstream(struct kvm_vcpu *vcpu)
{
	struct kvm_vcpu_preemption_data *vcpu_data = VCPU_PREEMPTION_DATA(vcpu);
	struct kvm_stream_data *stream_data = vcpu_data->replay_stream_data;
	struct bstream *replay_bstream;
	if (stream_data)
		replay_bstream = stream_data->bstream;
	else
		replay_bstream = NULL;
	return replay_bstream;
}

static void kvm_update_preemption_data(struct kvm *kvm);

static inline void
kvm_record_vmexit(struct kvm_vcpu *vcpu)
{
	struct kvm *kvm = vcpu->kvm;
	struct kvm_vcpu_preemption_data *vcpu_data = VCPU_PREEMPTION_DATA(vcpu);
	struct rkvm_data *kvm_data = RKVM_DATA(kvm);
	struct rkvm_ops *ops = kvm_data->ops;
	u64 guest_rip;
	u32 guest_ecx;
	u64 retired_branch_counter = vcpu_data->accumulate_retired_branch_counter;
	struct bstream *record_bstream = get_record_bstream(vcpu);
	u64 record_id;
	
	if (!record_bstream)
		return;
	if (!vcpu_data->need_vmexit_recorded)
		return;
	vcpu_data->need_vmexit_recorded = false;
	record_id = ++kvm_data->last_record_id;

	guest_rip = ops->read_guest_program_counter(vcpu);
	guest_ecx = ops->read_guest_ecx(vcpu);

	bscript_write_u64(record_bstream,
			  record_id - vcpu_data->reported_record_id);
	bscript_write_u64(record_bstream,
			  retired_branch_counter - vcpu_data->reported_retired_branch_counter);
#if 0
	bscript_write_s64(record_bstream,
			  guest_rip - vcpu_data->reported_guest_rip);
	bscript_write_s32(record_bstream,
			  guest_ecx - vcpu_data->reported_guest_ecx);
#endif
	bscript_write_s32(record_bstream,
			  vcpu_data->entry_intr_info);
	
	vcpu_data->reported_record_id = record_id;
	vcpu_data->reported_retired_branch_counter = retired_branch_counter;
	vcpu_data->reported_guest_rip = guest_rip;
	vcpu_data->reported_guest_ecx = guest_ecx;
}

void rkvm_lock_vcpu(struct kvm_vcpu *vcpu)
{
	struct kvm *kvm = vcpu->kvm;
	struct kvm_vcpu_preemption_data *vcpu_data = VCPU_PREEMPTION_DATA(vcpu);
	struct rkvm_data *kvm_data = RKVM_DATA(kvm);
	bool need_lockstep_lock;

	PREEMPTION_LOCKED(kvm_data,
			  need_lockstep_lock = kvm_data->execute_in_lockstep);
	if (need_lockstep_lock && !vcpu_data->vcpu_locked) {
		spin_lock(&kvm_data->lockstep_spinlock);
		vcpu_data->vcpu_locked = true;
	}
}
EXPORT_SYMBOL_GPL(rkvm_lock_vcpu);

void rkvm_vcpu_halted(struct kvm_vcpu *vcpu)
{
	struct kvm *kvm = vcpu->kvm;
	struct kvm_vcpu_preemption_data *vcpu_data = VCPU_PREEMPTION_DATA(vcpu);
	struct rkvm_data *kvm_data = RKVM_DATA(kvm);

	PREEMPTION_LOCKED(kvm_data,
			  vcpu_data->vcpu_halted = true);
}
EXPORT_SYMBOL_GPL(rkvm_vcpu_halted);

void rkvm_unlock_vcpu(struct kvm_vcpu *vcpu)
{
	struct kvm *kvm = vcpu->kvm;
	struct kvm_vcpu_preemption_data *vcpu_data = VCPU_PREEMPTION_DATA(vcpu);
	struct rkvm_data *kvm_data = RKVM_DATA(kvm);

	kvm_record_vmexit(vcpu);

	if (vcpu_data->vcpu_locked || vcpu_data->vcpu_halted) {
		kvm_update_preemption_data(kvm);
	}
	if (vcpu_data->vcpu_locked) {
		vcpu_data->vcpu_locked = false;
		spin_unlock(&kvm_data->lockstep_spinlock);
	}

	update_preemption_debug_data(VCPU_PREEMPTION_DEBUG_DATA(vcpu),
				     kvm_data,
				     vcpu_data,
				     vcpu_data->entry_preemption_timer_value > 0);

}
EXPORT_SYMBOL_GPL(rkvm_unlock_vcpu);

void
rkvm_on_vmexit(struct kvm_vcpu *vcpu)
{
	struct kvm *kvm = vcpu->kvm;
	struct kvm_vcpu_preemption_data *vcpu_data = VCPU_PREEMPTION_DATA(vcpu);
	struct rkvm_data *kvm_data = RKVM_DATA(kvm);
	struct rkvm_ops *ops = kvm_data->ops;
	struct bstream *record_bstream = get_record_bstream(vcpu);
	u32 preemption_delta =
		vcpu_data->entry_preemption_timer_value -
		ops->read_preemption_timer_value(vcpu);
	bool halted = ops->guest_halted(vcpu);

	PREEMPTION_LOCKED(kvm_data,
			  vcpu_data->accumulate_preemption_timer += preemption_delta;
			  vcpu_data->vcpu_halted = halted);

	if (record_bstream) {
		vcpu_data->accumulate_retired_branch_counter +=
			ops->read_retired_branch_counter(vcpu) -
			vcpu_data->entry_retired_branch_counter;

		if (vcpu_data->entry_intr_info)
			kvm_record_vmexit(vcpu);
	}

	if (!vcpu_data->vcpu_locked)
		kvm_update_preemption_data(kvm);
}
EXPORT_SYMBOL_GPL(rkvm_on_vmexit);

int kvm_init_preemption_data(struct kvm *kvm,
			     struct rkvm_ops *ops)
{
	KVM_STATIC_CHECK(kvm_run_size, sizeof(struct kvm_run) <= PAGE_SIZE);
	KVM_STATIC_CHECK(kvm_data_size, sizeof(struct rkvm_data) <= sizeof(kvm->preemption_data));
	struct rkvm_data *kvm_data = RKVM_DATA(kvm);
	if (!ops)
		return -EINVAL; /* TODO: Should be: unsupported. */
	kvm_data->ops = ops;
	kvm_data->preemption_timer_front = 0;
	kvm_data->preemption_timer_back = ~(u64)0;
	spin_lock_init(&kvm_data->spinlock);
	spin_lock_init(&kvm_data->lockstep_spinlock);

	return 0;
}
EXPORT_SYMBOL_GPL(kvm_init_preemption_data);

void kvm_destroy_preemption_data(struct kvm *kvm)
{
}
EXPORT_SYMBOL_GPL(kvm_destroy_preemption_data);

static inline void
update_preemption_parameters(struct rkvm_data *kvm_data,
			     u64 accumulate_preemption_timer,
			     bool running)
{
	if(running) {
		if (accumulate_preemption_timer < kvm_data->preemption_timer_back) {
			kvm_data->preemption_timer_back = accumulate_preemption_timer;
		}
		kvm_data->num_unhalted_vcpus++;
	}
	if (accumulate_preemption_timer > kvm_data->preemption_timer_front) {
		kvm_data->preemption_timer_front = accumulate_preemption_timer;
	}
}

static void kvm_update_preemption_data(struct kvm *kvm)
{
	struct rkvm_data *kvm_data = RKVM_DATA(kvm);
	struct kvm_userspace_preemption_data *userspace = 
		&kvm_data->userspace;

	int vcpu_index;
	struct kvm_vcpu *vcpu;
	struct kvm_vcpu_preemption_data *vcpu_data;

	spin_lock(&kvm_data->spinlock);
	kvm_data->preemption_timer_back = ~(u64)0;
	kvm_data->num_unhalted_vcpus = 0;
	kvm_for_each_vcpu(vcpu_index, vcpu, kvm) {
		vcpu_data = VCPU_PREEMPTION_DATA(vcpu);
		update_preemption_parameters(kvm_data,
					     vcpu_data->accumulate_preemption_timer,
					     rkvm_vcpu_running(vcpu_data));
	}
	update_preemption_parameters(kvm_data,
				     userspace->accumulate_preemption_timer,
				     userspace->running);
	if(kvm_data->num_unhalted_vcpus == 0) {
		kvm_data->all_stopped = 1;
		kvm_data->tsc_when_stopped = native_read_tsc();
	}
	spin_unlock(&kvm_data->spinlock);
}

void rkvm_on_vmentry(struct kvm_vcpu *vcpu)
{
	KVM_STATIC_CHECK(vcpu_preemption_data_size, sizeof(struct kvm_vcpu_preemption_data) <= sizeof(vcpu->preemption_data));
	struct kvm *kvm = vcpu->kvm;
	struct kvm_vcpu_preemption_data *vcpu_data = VCPU_PREEMPTION_DATA(vcpu);
	struct rkvm_data *kvm_data = RKVM_DATA(kvm);
	struct rkvm_ops *ops = kvm_data->ops;
	bool use_preemption_timer;
	u64 preemption_timer_value;
	u32 preemption_timer_quantum;
	u64 preemption_timer_horizon;
	bool was_running = rkvm_vcpu_running(vcpu_data);

	spin_lock(&kvm_data->spinlock);
	preemption_timer_quantum = kvm_data->preemption_timer_quantum;
	preemption_timer_horizon = kvm_data->preemption_timer_back + preemption_timer_quantum;
	vcpu_data->vcpu_launched = true;
	vcpu_data->vcpu_halted = false;
	if (!was_running) {
		VCPU_PREEMPTION_DEBUG_DATA(vcpu)->private_steal +=
			kvm_data->preemption_timer_front -
			vcpu_data->accumulate_preemption_timer;
		vcpu_data->accumulate_preemption_timer =
			kvm_data->preemption_timer_front;
		kvm_data->num_unhalted_vcpus++;
		if(kvm_data->all_stopped) {
			kvm_data->all_stopped = 0;
			kvm_data->preemption_timer_steal +=
				preemption_timer_since_tsc(kvm_data->tsc_when_stopped);
		}
	}
	spin_unlock(&kvm_data->spinlock);

	if (get_replay_bstream(vcpu)) {
		struct bstream *replay_bstream = get_replay_bstream(vcpu);
		u64 replay_record_id;
		u64 replay_retired_branch_counter;
		u64 replay_guest_rip;
		u32 replay_guest_ecx;
		u32 replay_entry_intr_info;
#if 1
		bscript_read_u64(replay_bstream, &replay_record_id) &&
			bscript_read_u64(replay_bstream, &replay_retired_branch_counter) &&
#if 0
			bscript_read_s64(replay_bstream, &replay_guest_rip) &&
			bscript_read_s32(replay_bstream, &replay_guest_ecx) &&
#endif
			bscript_read_s32(replay_bstream, &replay_entry_intr_info);
#endif
	}

	if (get_record_bstream(vcpu)) {
		vcpu_data->entry_retired_branch_counter = ops->read_retired_branch_counter(vcpu);
		vcpu_data->entry_intr_info = ops->read_hw_intr_info(vcpu);
		vcpu_data->need_vmexit_recorded = true;
	}

	if (preemption_timer_quantum > 0) {
		use_preemption_timer = true;
		preemption_timer_value = preemption_timer_horizon - vcpu_data->accumulate_preemption_timer;
		if (preemption_timer_value > preemption_timer_horizon)
			preemption_timer_value = 0;
	} else {
		use_preemption_timer = false;
		preemption_timer_value = 0x80000000u;
	}

	if (use_preemption_timer) {
		vcpu_data->exit_on_preemption = true; // TEMP
		if (preemption_timer_value != (u32)preemption_timer_value) {
			vcpu_data->entry_preemption_timer_value = 0x80000000u;
		} else {
			if (preemption_timer_value == 0)
				vcpu_data->exit_on_preemption = true;
			vcpu_data->entry_preemption_timer_value = (u32)preemption_timer_value;
		}
		ops->write_preemption_timer_value(vcpu, vcpu_data->entry_preemption_timer_value);
	}
	(*ops->save_preemption_timer_on_exit)(vcpu, use_preemption_timer);
}
EXPORT_SYMBOL_GPL(rkvm_on_vmentry);

void rkvm_userspace_entry(struct kvm *kvm,
				    struct kvm_userspace_preemption_data *out_userspace)
{
	struct rkvm_data *kvm_data = RKVM_DATA(kvm);
	struct kvm_userspace_preemption_data *userspace = &kvm_data->userspace;
	bool need_lockstep_lock;

	spin_lock(&kvm_data->spinlock);
	out_userspace->preemption_timer_quantum = kvm_data->preemption_timer_quantum;
	out_userspace->preemption_timer_back = kvm_data->preemption_timer_back;
	if (userspace->running == 0) {
		need_lockstep_lock = kvm_data->execute_in_lockstep;
		userspace->accumulate_preemption_timer = kvm_data->preemption_timer_front;
		if(kvm_data->all_stopped) {
			kvm_data->all_stopped = 0;
			kvm_data->preemption_timer_steal +=
				preemption_timer_since_tsc(kvm_data->tsc_when_stopped);
		}
	} else {
		need_lockstep_lock = false;
	}
	if (need_lockstep_lock)
		userspace->locked = 1;
	userspace->running++;
	out_userspace->running = userspace->running;
	out_userspace->accumulate_preemption_timer = userspace->accumulate_preemption_timer;
	spin_unlock(&kvm_data->spinlock);
	/*
	if (need_lockstep_lock)
		spin_lock(&kvm_data->lockstep_spinlock);
	*/
}
EXPORT_SYMBOL_GPL(rkvm_userspace_entry);

void rkvm_userspace_exit(struct kvm *kvm,
				   struct kvm_userspace_preemption_data *userspace_in)
{
	struct rkvm_data *kvm_data = RKVM_DATA(kvm);
	struct kvm_userspace_preemption_data *userspace = &kvm_data->userspace;
	bool need_lockstep_unlock;
	spin_lock(&kvm_data->spinlock);
	if (userspace_in->accumulate_preemption_timer > userspace->accumulate_preemption_timer)
		userspace->accumulate_preemption_timer = userspace_in->accumulate_preemption_timer;
	userspace->running--;
	need_lockstep_unlock = (userspace->running == 0) && userspace->locked;
	if (need_lockstep_unlock)
		userspace->locked = 0;
	spin_unlock(&kvm_data->spinlock);
	/*
	if (need_lockstep_unlock)
		spin_unlock(&kvm_data->lockstep_spinlock);
	*/
}
EXPORT_SYMBOL_GPL(rkvm_userspace_exit);

bool rkvm_retrieve_rdtsc_value(struct kvm_vcpu *vcpu,
					 u64 *out_tsc_value,
					 bool *out_do_record)
{
	struct kvm *kvm = vcpu->kvm;
	struct rkvm_data *kvm_data = RKVM_DATA(kvm);
	struct kvm_vcpu_preemption_data *vcpu_data = VCPU_PREEMPTION_DATA(vcpu);
	bool retrieved;
	bool do_record;
	u64 preemption_timer_value;
	spin_lock(&kvm_data->spinlock);
	if (kvm_data->preemption_timer_quantum != 0) {
		do_record = kvm_data->record_execution;
		retrieved = true;
		preemption_timer_value =
			kvm_data->preemption_timer_steal +
			vcpu_data->accumulate_preemption_timer;
		*out_do_record = do_record;
	} else {
		retrieved = false;
	}
	spin_unlock(&kvm_data->spinlock);
	if (retrieved) {
		*out_tsc_value = preemption_timer_to_tsc(preemption_timer_value);
		VCPU_PREEMPTION_DEBUG_DATA(vcpu)->last_read_tsc = *out_tsc_value;
	}
	return retrieved;
}
EXPORT_SYMBOL_GPL(rkvm_retrieve_rdtsc_value);

int kvm_set_preemption_timer_quantum(struct kvm *kvm, u32 preemption_timer_quantum)
{
	struct rkvm_data *kvm_data = RKVM_DATA(kvm);
	struct rkvm_ops *ops = kvm_data->ops;
	struct kvm_vcpu *vcpu;
	int i;
	int ret;
	bool use_preemption_timer;

	spin_lock(&kvm_data->spinlock);
	if (preemption_timer_quantum == kvm_data->preemption_timer_quantum) {
		ret = 0;
	} else if (preemption_timer_quantum == 0) {
		ret = -EINVAL;
	} else {
		if(kvm_has_preemption_timer) {
			ret = 0;
			kvm_data->preemption_timer_quantum = preemption_timer_quantum;
			use_preemption_timer = (preemption_timer_quantum > 0);
			kvm_data->use_preemption_timer = use_preemption_timer;
			kvm_for_each_vcpu(i, vcpu, kvm) {
				(*ops->setup_preemption_timer)(vcpu, use_preemption_timer);
			}
		} else {
			ret = -EINVAL;
		}
	}
	spin_unlock(&kvm_data->spinlock);
	return ret;
}
EXPORT_SYMBOL_GPL(kvm_set_preemption_timer_quantum);

int kvm_get_preemption_timer_quantum(struct kvm *kvm, u32 *preemption_timer_quantum)
{
	struct rkvm_data *kvm_data = RKVM_DATA(kvm);
	PREEMPTION_LOCKED(kvm_data,
			  *preemption_timer_quantum = kvm_data->preemption_timer_quantum);
	return 0;
}
EXPORT_SYMBOL_GPL(kvm_get_preemption_timer_quantum);

int kvm_on_preemption_timer_exit(struct kvm_vcpu *vcpu)
{
	struct kvm_vcpu_preemption_data *vcpu_data = VCPU_PREEMPTION_DATA(vcpu);
	int handled = 1;

	if (vcpu_data->exit_on_preemption) {
		vcpu_data->exit_on_preemption = false;
		handled = 0;
	}
	return handled;
}
EXPORT_SYMBOL_GPL(kvm_on_preemption_timer_exit);

static inline bool kvm_execution_mode_valid(struct kvm *kvm, u32 execution_mode)
{
	u32 permitted_execution_modes =
		KVM_EXECUTION_MODE_LOCKSTEP |
		KVM_EXECUTION_MODE_RECORD |
		KVM_EXECUTION_MODE_REPLAY;
	return (execution_mode & ~permitted_execution_modes) == 0;
}

int kvm_set_execution_flag(struct kvm *kvm, u32 execution_mode)
{
	struct rkvm_data *kvm_data = RKVM_DATA(kvm);
	bool execute_in_lockstep = ((execution_mode & KVM_EXECUTION_MODE_LOCKSTEP) == KVM_EXECUTION_MODE_LOCKSTEP);
	bool record_execution = ((execution_mode & KVM_EXECUTION_MODE_RECORD) == KVM_EXECUTION_MODE_RECORD);
	bool replay_execution = ((execution_mode & KVM_EXECUTION_MODE_REPLAY) == KVM_EXECUTION_MODE_REPLAY);

	PREEMPTION_LOCKED(kvm_data, {
			kvm_data->record_execution =
				kvm_data->record_execution || record_execution;
			kvm_data->replay_execution =
				kvm_data->replay_execution || replay_execution;
			kvm_data->execute_in_lockstep =
				kvm_data->record_execution || kvm_data->replay_execution ||
				kvm_data->execute_in_lockstep || execute_in_lockstep;
		});
	return 0;
}
EXPORT_SYMBOL_GPL(kvm_set_execution_flag);

int kvm_clear_execution_flag(struct kvm *kvm, u32 execution_mode)
{
	struct rkvm_data *kvm_data = RKVM_DATA(kvm);
	bool execute_in_lockstep = ((~execution_mode & KVM_EXECUTION_MODE_LOCKSTEP) == KVM_EXECUTION_MODE_LOCKSTEP);
	bool record_execution = ((~execution_mode & KVM_EXECUTION_MODE_RECORD) == KVM_EXECUTION_MODE_RECORD);
	bool replay_execution = ((~execution_mode & KVM_EXECUTION_MODE_REPLAY) == KVM_EXECUTION_MODE_REPLAY);

	PREEMPTION_LOCKED(kvm_data, {
			kvm_data->record_execution =
				kvm_data->record_execution && record_execution;
			kvm_data->replay_execution =
				kvm_data->replay_execution && replay_execution;
			kvm_data->execute_in_lockstep =
				(kvm_data->record_execution || kvm_data->replay_execution ||
				 kvm_data->execute_in_lockstep) && execute_in_lockstep;
		});
	return 0;
}
EXPORT_SYMBOL_GPL(kvm_clear_execution_flag);

int kvm_get_execution_mode(struct kvm *kvm, u32 *execution_mode)
{
	struct rkvm_data *kvm_data = RKVM_DATA(kvm);
	PREEMPTION_LOCKED(kvm_data,
			  *execution_mode =
			  (kvm_data->execute_in_lockstep ? KVM_EXECUTION_MODE_LOCKSTEP : 0) |
			  (kvm_data->record_execution ? KVM_EXECUTION_MODE_RECORD : 0) |
			  (kvm_data->replay_execution ? KVM_EXECUTION_MODE_REPLAY : 0));
	return 0;
}
EXPORT_SYMBOL_GPL(kvm_get_execution_mode);

static ssize_t kvm_bstream_read(struct file *filp, char __user *buf, size_t size, loff_t *ppos)
{
	struct kvm_stream_data *stream_data = filp->private_data;
	struct bstream *bstream;

	bstream = stream_data->bstream;
	if (bstream != NULL)
		return bstream_read(bstream, buf, size, ppos);
	else
		return -EINVAL;
}

static ssize_t kvm_bstream_write(struct file *filp, const char __user *buf, size_t size, loff_t *ppos)
{
	struct kvm_stream_data *stream_data = filp->private_data;
	struct bstream *bstream;

	bstream = stream_data->bstream;
	if (bstream != NULL)
		return bstream_write(bstream, buf, size, ppos);
	else
		return -EINVAL;
}

static void kvm_do_bstream_release(struct kvm_vcpu *vcpu, struct kvm_stream_data *stream_data)
{
	struct kvm *kvm = vcpu->kvm;
	struct rkvm_data *kvm_data = RKVM_DATA(kvm);
	struct bstream *bstream;

	PREEMPTION_LOCKED(kvm_data,
			  stream_data->bstream_use_count--;
			  if (stream_data->bstream_use_count == 0) {
				  bstream = stream_data->bstream;
				  stream_data->bstream = NULL;
			  } else {
				  bstream = NULL;
			  });
	
	if (bstream != NULL)
		bstream_free(bstream);
}

static int kvm_bstream_release(struct inode *inode, struct file *filp)
{
	struct kvm_stream_data *stream_data = filp->private_data;
	struct kvm_vcpu *vcpu = kvm_stream_vcpu(stream_data);

	if (vcpu) {
		struct kvm *kvm = vcpu->kvm;
		struct rkvm_data *kvm_data = RKVM_DATA(kvm);
		bool need_cleanup;
		PREEMPTION_LOCKED(kvm_data,
				  if (stream_data->back_pointer) {
					  if (*stream_data->back_pointer) {
						  *stream_data->back_pointer = NULL;
						  need_cleanup = true;
					  } else {
						  need_cleanup = false;
					  }
					  stream_data->back_pointer = NULL;
				  } else {
					  need_cleanup = false;
				  });
		if (need_cleanup)
			kvm_do_bstream_release(vcpu, stream_data);
	}
	kfree(stream_data);
	return 0;
}

static void kvm_vcpu_uninit_bstream_data(struct kvm_vcpu *vcpu, struct kvm_stream_data **back_pointer)
{
	struct kvm *kvm = vcpu->kvm;
	struct rkvm_data *kvm_data = RKVM_DATA(kvm);
	struct kvm_stream_data *stream_data;
	bool need_cleanup;
	PREEMPTION_LOCKED(kvm_data,
			  stream_data = *back_pointer;
			  *back_pointer = NULL;
			  if (stream_data) {
				  clear_kvm_stream_data(stream_data);
				  need_cleanup = true;
			  } else {
				  need_cleanup = false;
			  });
	if (need_cleanup)
		kvm_do_bstream_release(vcpu, stream_data);
}

void kvm_vcpu_uninit_preemption_data(struct kvm_vcpu *vcpu)
{
	struct kvm_vcpu_preemption_data *vcpu_data = VCPU_PREEMPTION_DATA(vcpu);
	kvm_vcpu_uninit_bstream_data(vcpu, &vcpu_data->record_stream_data);
	kvm_vcpu_uninit_bstream_data(vcpu, &vcpu_data->replay_stream_data);
}
EXPORT_SYMBOL_GPL(kvm_vcpu_uninit_preemption_data);

static struct file_operations kvm_bstream_fops = {
	.read           = kvm_bstream_read,
	.write          = kvm_bstream_write,
	.release        = kvm_bstream_release,
	.llseek		= noop_llseek,
};

static int create_kvm_stream(const char *name, struct kvm_vcpu *vcpu, int permission,
			     struct kvm_stream_data **back_pointer)
{
	struct bstream *bstream;
	struct kvm_stream_data *stream_data;
	int r;

	bstream = bstream_create(2 /* TODO: parametrize */, 
				 4 /* TODO: parametrize */);
	if (bstream) {
		stream_data = kzalloc(sizeof(struct kvm_stream_data), GFP_KERNEL);
		if (stream_data != NULL) {
			r = anon_inode_getfd(name, &kvm_bstream_fops, stream_data, permission);
			if (r >= 0) {
				set_kvm_stream_data(stream_data, vcpu, r, bstream);
				stream_data->back_pointer = back_pointer;
				*back_pointer = stream_data;
			} else {
				kfree(stream_data);
			}
		} else {
			r = -ENOMEM;
		}
		if (r < 0)
			bstream_free(bstream);
	} else {
		r = -ENOMEM;
	}
	return r;
}

/*
 * Allocates an inode for KVM record.
 */
int kvm_open_record_stream(struct kvm_vcpu *vcpu)
{
	/* TODO: Solve creation race. */
	struct kvm_vcpu_preemption_data *vcpu_data = VCPU_PREEMPTION_DATA(vcpu);
	if (vcpu_data->record_stream_data == NULL)
		return create_kvm_stream("kvm-record", vcpu, O_RDONLY, &vcpu_data->record_stream_data);
	else
		return kvm_stream_fd(vcpu_data->record_stream_data); /* TODO: We should duplicate. */
}
EXPORT_SYMBOL_GPL(kvm_open_record_stream);

/*
 * Allocates an inode for KVM record.
 */
int kvm_open_replay_stream(struct kvm_vcpu *vcpu)
{
	/* TODO: Solve creation race. */
	struct kvm_vcpu_preemption_data *vcpu_data = VCPU_PREEMPTION_DATA(vcpu);
	if (vcpu_data->replay_stream_data == NULL)
		return create_kvm_stream("kvm-replay", vcpu, O_WRONLY, &vcpu_data->replay_stream_data);
	else
		return kvm_stream_fd(vcpu_data->replay_stream_data); /* TODO: We should duplicate. */
}
EXPORT_SYMBOL_GPL(kvm_open_replay_stream);

void kvm_register_bstream_ops(struct module *module)
{
	kvm_bstream_fops.owner = module;
}
EXPORT_SYMBOL_GPL(kvm_register_bstream_ops);

void kvm_record_tsc(struct kvm_vcpu *vcpu, u64 tsc_value)
{
	/* TODO */
}
EXPORT_SYMBOL_GPL(kvm_record_tsc);
