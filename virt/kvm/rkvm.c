#include "rkvm_internal.h"
#include "rkvm_preemption.h"

#include <linux/rkvm_host.h>
#include <linux/bscript.h>
#include <linux/bstream_ops.h>
#include <linux/kvm_host.h>
#include <linux/export.h>

struct rkvm_data;

static const char stream_suffixes[][8] = {
	"rid",
	"rsn",
	"rbc",
	"pc",
	"ecx",
	"tsc",
	"irq",
	"irqcnt",
	"irqpc",
	"irqecx",
	"pio",
	"regs",
	"sregs",
	"exitrsn",
	"insize",
	"outsize",
	"inport",
	"outport",
	"mmiosiz",
	"mmioadr",
};

static void rkvm_recording_on_vmentry(rkvm_vcpu_host *vcpu, struct rkvm_local_ops *lops);
static void rkvm_replaying_on_vmentry(rkvm_vcpu_host *vcpu, struct rkvm_local_ops *lops);

static void rkvm_recording_on_vmexit(rkvm_vcpu_host *vcpu,
				     bool reinject_external_interrupt, u32 exit_reason,
				     struct rkvm_local_ops *lops);
static void rkvm_replaying_on_vmexit(rkvm_vcpu_host *vcpu,
				     bool reinject_external_interrupt, u32 exit_reason,
				     struct rkvm_local_ops *lops);

static void rkvm_recording_on_update_vmexit_state(rkvm_vcpu_host *vcpu);
static void rkvm_replaying_on_update_vmexit_state(rkvm_vcpu_host *vcpu);

static bool rkvm_recording_on_vcpu_entry(rkvm_vcpu_host *vcpu);
static bool rkvm_replaying_on_vcpu_entry(rkvm_vcpu_host *vcpu);

static void rkvm_recording_on_vcpu_exit(rkvm_vcpu_host *vcpu, bool internal);
static void rkvm_replaying_on_vcpu_exit(rkvm_vcpu_host *vcpu, bool internal);

static bool rkvm_recording_can_reschedule(rkvm_vcpu_host *vcpu);
static bool rkvm_replaying_can_reschedule(rkvm_vcpu_host *vcpu);

static void rkvm_recording_vcpu_halted(rkvm_vcpu_host *vcpu);
static void rkvm_replaying_vcpu_halted(rkvm_vcpu_host *vcpu);

static bool rkvm_recording_before_inject_rmod_irq(rkvm_vcpu_host *vcpu, int irq);
static bool rkvm_replaying_before_inject_rmod_irq(rkvm_vcpu_host *vcpu, int irq);

static bool rkvm_recording_after_inject_irq(rkvm_vcpu_host *vcpu, int irq);
static bool rkvm_replaying_after_inject_irq(rkvm_vcpu_host *vcpu, int irq);

static bool rkvm_recording_on_pio_in_data_avail(rkvm_vcpu_host *vcpu,
						void *target, const void *src, int size);
static bool rkvm_replaying_on_pio_in_data_avail(rkvm_vcpu_host *vcpu,
						void *target, const void *src, int size);

static void rkvm_recording_on_set_regs(rkvm_vcpu_host *vcpu, void *src, unsigned size);
static void rkvm_replaying_on_set_regs(rkvm_vcpu_host *vcpu, void *src, unsigned size);

static void rkvm_recording_on_set_sregs(rkvm_vcpu_host *vcpu, void *src, unsigned size);
static void rkvm_replaying_on_set_sregs(rkvm_vcpu_host *vcpu, void *src, unsigned size);

static bool rkvm_recording_handle_halt(rkvm_vcpu_host *vcpu);
static bool rkvm_replaying_handle_halt(rkvm_vcpu_host *vcpu);

static void rkvm_replaying_update(rkvm_vcpu_host *vcpu, const char *debug_info);
static bool read_next_replay_target_point(rkvm_vcpu_host *vcpu);

static void rkvm_lockstep_lock(rkvm_vcpu_host *vcpu);
static void rkvm_lockstep_unlock(rkvm_vcpu_host *vcpu);

static void rkvm_prerecord_point(rkvm_vcpu_host *vcpu, enum rkvm_sync_reason sync_reason);
static void rkvm_record_vcpu_exit(rkvm_vcpu_host *vcpu, bool internal);

static void rkvm_prerecord_irq_point(rkvm_vcpu_host *vcpu,
				     enum rkvm_sync_reason sync_reason, int irq);

static void rkvm_record_pending_vmexit(rkvm_vcpu_host *vcpu);

static int on_rkvm_xfer(rkvm_host *host, struct rkvm_xfer *rkvm_xfer);
static int do_rkvm_xfer(rkvm_host *host, struct rkvm_xfer *rkvm_xfer);

#define RKVM_STATIC_CHECK(name, expr) \
	u8 static_check_##name[(expr)? 1: -1] __attribute__((unused))

#define RKVM_DATA(host) \
	((host)->rkvm_data)

#define RKVM_RECORDING(host) \
	(&(host)->rkvm_data->recording)

#define RKVM_REPLAYING(host) \
	(&(host)->rkvm_data->replaying)

#define RKVM_VCPU_DATA(vcpu) \
	((vcpu)->rkvm_vcpu_data)

#define RKVM_VCPU_RECORDING(vcpu) \
	(&(vcpu)->rkvm_vcpu_data->recording)

#define RKVM_VCPU_REPLAYING(vcpu) \
	(&(vcpu)->rkvm_vcpu_data->replaying)

#define RKVM_VCPU_DEBUG_DATA(vcpu) \
	((struct rkvm_vcpu_debug_data *)(&(vcpu)->run->rkvm_vcpu_debug_data))

#define RKVM_MODE_FLAG_PREEMPT   (1 << 0)
#define RKVM_MODE_FLAG_RECORD    (1 << 1)
#define RKVM_MODE_FLAG_REPLAY    (1 << 2)
#define RKVM_MODE_FLAG_LOCK_STEP (1 << 3)

#define EXTRACT_MODE(host)						\
	do {								\
		struct rkvm_data *extract_rkvm_data = RKVM_DATA(host);	\
		int rkvm_mode = atomic_read(&extract_rkvm_data->mode);	\
		preempt = (rkvm_mode & RKVM_MODE_FLAG_PREEMPT) != 0;	\
		record = (rkvm_mode & RKVM_MODE_FLAG_RECORD)  != 0;	\
		replay = (rkvm_mode & RKVM_MODE_FLAG_REPLAY)  != 0;	\
		lock_step = (rkvm_mode & RKVM_MODE_FLAG_LOCK_STEP)  != 0; \
	} while (0)

#define EXTRACT_VCPU_MODE(vcpu) EXTRACT_MODE(RKVM_HOST(vcpu))

#define UPDATE_MODE(host)						\
	do {								\
		struct rkvm_data *update_rkvm_data = RKVM_DATA(host);	\
		int rkvm_mode =						\
			(preempt ? RKVM_MODE_FLAG_PREEMPT : 0) |	\
			(record ? RKVM_MODE_FLAG_RECORD : 0) |		\
			(replay ? RKVM_MODE_FLAG_REPLAY : 0) |		\
			(lock_step ? RKVM_MODE_FLAG_LOCK_STEP : 0);	\
		atomic_set(&update_rkvm_data->mode, rkvm_mode);		\
	} while (0)

#define RKVM_DEBUG_PRINT(vcpu, ...)					\
	do {								\
		static int spill_counter = 0;				\
		char debug_print_buffer[256];				\
		struct bstream *debug_bstream = get_debug_bstream(vcpu); \
		size_t debug_buffer_length;				\
		if (debug_bstream) {					\
			sprintf(debug_print_buffer, __VA_ARGS__);	\
			debug_buffer_length = strlen(debug_print_buffer); \
			if (debug_buffer_length > 0) {			\
				if (!bscript_write_raw_data(debug_bstream, \
							    debug_print_buffer, \
							    debug_buffer_length)) { \
					if (spill_counter < 10000) {	\
						++spill_counter;	\
						printk(KERN_WARNING "SPILL: cpu %d %s", \
						       vcpu->vcpu_id,	\
						       debug_print_buffer); \
					}				\
				}					\
			}						\
		}							\
	} while (false)

#define RKVM_RECORD_VALUE(vcpu, type, stream, value)			\
	bscript_write_##type(get_record_bstream(vcpu, stream), value)

#define RKVM_READ_REPLAY_VALUE(vcpu, type, stream, pvalue)		\
	bscript_read_##type(get_replay_bstream(vcpu, stream), pvalue)

#define RKVM_RECORD_DATA(vcpu, stream, src, size)			\
	bscript_write_raw_data(get_record_bstream(vcpu, stream), src, size)

#define RKVM_READ_REPLAY_DATA(vcpu, stream, target, size)		\
	bscript_read_raw_data(get_replay_bstream(vcpu, stream), target, size)


static inline struct bstream *get_debug_bstream(rkvm_vcpu_host *vcpu)
{
	struct rkvm_vcpu_data *vcpu_data = RKVM_VCPU_DATA(vcpu);
	struct bstream_file_data *stream_data =
		get_bstream_file_data(&vcpu_data->debug_stream_data);
	struct bstream *bstream;
	if (stream_data) {
		bstream = stream_data->bstream;
		vcpu_data->must_exit = vcpu_data->must_exit || bstream_on_last_write_page(bstream);
	} else {
		bstream = NULL;
	}
	return bstream;
}

static inline struct bstream *get_record_bstream(rkvm_vcpu_host *vcpu, enum rkvm_stream_index id)
{
	struct rkvm_vcpu_data *vcpu_data = RKVM_VCPU_DATA(vcpu);
	struct bstream_file_data *stream_data =
		get_bstream_file_data(&vcpu_data->record_stream_data[id]);
	struct bstream *bstream;
	if (stream_data) {
		bstream = stream_data->bstream;
		vcpu_data->must_exit = vcpu_data->must_exit || bstream_on_last_write_page(bstream);
	} else {
		bstream = NULL;
	}
	return bstream;
}

static inline struct bstream *get_replay_bstream(rkvm_vcpu_host *vcpu, enum rkvm_stream_index id)
{
	struct rkvm_vcpu_data *vcpu_data = RKVM_VCPU_DATA(vcpu);
	struct bstream_file_data *stream_data =
		get_bstream_file_data(&vcpu_data->replay_stream_data[id]);
	struct bstream *bstream;
	if (stream_data) {
		bstream = stream_data->bstream;
		vcpu_data->must_exit = vcpu_data->must_exit || bstream_on_last_read_page(bstream);
	} else {
		bstream = NULL;
	}
	return bstream;
}

static inline bool is_natural_exit_reason(u32 reason)
{
	switch (reason) {
	case KVM_EXIT_PREEMPTION_TIMER:
	case KVM_EXIT_RKVM:
		return false;
	default:
		return true;
	}
}

static inline bool is_synchronous_exit_reason(u32 reason)
{
	switch (reason) {
	case KVM_EXIT_PREEMPTION_TIMER:
	case KVM_EXIT_RKVM:
	case KVM_EXIT_INTR:
	case KVM_EXIT_IRQ_WINDOW_OPEN:
	case KVM_EXIT_UNKNOWN:
		return false;
	default:
		return true;
	}
}

static inline bool write_delta(rkvm_vcpu_host *vcpu,
			       struct rkvm_delta *delta)
{
	return (RKVM_RECORD_VALUE(vcpu, u64, RKVM_RBC_STREAM, delta->rbc_delta) &&
		RKVM_RECORD_VALUE(vcpu, s64, RKVM_PC_STREAM, delta->pc_delta) &&
		RKVM_RECORD_VALUE(vcpu, s32, RKVM_ECX_STREAM, delta->ecx_delta));
}

static inline bool read_delta(rkvm_vcpu_host *vcpu,
			      struct rkvm_delta *delta)
{
	return (RKVM_READ_REPLAY_VALUE(vcpu, u64, RKVM_RBC_STREAM, &delta->rbc_delta) &&
		RKVM_READ_REPLAY_VALUE(vcpu, s64, RKVM_PC_STREAM, &delta->pc_delta) &&
		RKVM_READ_REPLAY_VALUE(vcpu, s32, RKVM_ECX_STREAM, &delta->ecx_delta));
}

static inline void update_point(struct rkvm_point *point,
				struct rkvm_delta *delta)
{
	point->rbc += delta->rbc_delta;
	point->pc += delta->pc_delta;
	point->ecx += delta->ecx_delta;
}

static inline void create_delta(struct rkvm_delta *delta,
				struct rkvm_point *curr_point,
				struct rkvm_point *prev_point)
{
	delta->rbc_delta = curr_point->rbc - prev_point->rbc;
	delta->pc_delta = curr_point->pc - prev_point->pc;
	delta->ecx_delta = curr_point->ecx - prev_point->ecx;
}

static inline void update_rkvm_vcpu_debug_data(rkvm_vcpu_host *vcpu)
{
	rkvm_host *host = RKVM_HOST(vcpu);
	struct rkvm_data *rkvm_data = RKVM_DATA(host);
	struct rkvm_vcpu_debug_data *debug = RKVM_VCPU_DEBUG_DATA(vcpu);
	debug->userspace_running = rkvm_data->userspace.running;
}

static int on_rkvm_xfer(rkvm_host *host, struct rkvm_xfer *rkvm_xfer)
{
	int r;
	struct rkvm_data *rkvm_data = RKVM_DATA(host);

	bool preempt, record, replay, lock_step;
	EXTRACT_MODE(host);

	
	printk(KERN_WARNING "on_rkvm_xfer: %d bytes\n", rkvm_xfer->size);

	spin_lock(&rkvm_data->lockstep_spinlock);
	r = do_rkvm_xfer(host, rkvm_xfer);
	spin_unlock(&rkvm_data->lockstep_spinlock);

	return r;
}

static int do_rkvm_xfer(rkvm_host *host, struct rkvm_xfer *rkvm_xfer)
{
	int r;

	void *buffer = kzalloc(rkvm_xfer->size, GFP_KERNEL);
	if (buffer == NULL)
		return -ENOMEM;

	r = -EFAULT;
	if (copy_from_user(buffer, rkvm_xfer->src, rkvm_xfer->size))
		goto out;
	if (copy_to_user(rkvm_xfer->dest, buffer, rkvm_xfer->size))
		goto out;
	r = 0;
 out:
	kfree(buffer);
	return r;
}

void rkvm_on_vmentry(rkvm_vcpu_host *vcpu, struct rkvm_local_ops *lops)
{
	bool preempt, record, replay, lock_step;
	EXTRACT_VCPU_MODE(vcpu);

	if (preempt)
		rkvm_preemption_on_vmentry(vcpu, lops);
	if (record)
		rkvm_recording_on_vmentry(vcpu, lops);
	if (replay)
		rkvm_replaying_on_vmentry(vcpu, lops);
}
EXPORT_SYMBOL_GPL(rkvm_on_vmentry);

void rkvm_on_vmexit(rkvm_vcpu_host *vcpu,
		    bool reinject_external_interrupt, u32 exit_reason,
		    struct rkvm_local_ops *lops)
{
	rkvm_host *host = RKVM_HOST(vcpu);
	struct rkvm_data *rkvm_data = RKVM_DATA(host);

	bool preempt, record, replay, lock_step;
	EXTRACT_VCPU_MODE(vcpu);

	if (preempt)
		rkvm_preemption_on_vmexit(vcpu, &rkvm_data->userspace, lops);
	if (record)
		rkvm_recording_on_vmexit(vcpu, reinject_external_interrupt, exit_reason, lops);
	if (replay)
		rkvm_replaying_on_vmexit(vcpu, reinject_external_interrupt, exit_reason, lops);
}
EXPORT_SYMBOL_GPL(rkvm_on_vmexit);

void rkvm_on_update_vmexit_state(rkvm_vcpu_host *vcpu)
{
	rkvm_host *host = RKVM_HOST(vcpu);
	struct rkvm_data *rkvm_data = RKVM_DATA(host);

	bool preempt, record, replay, lock_step;
	EXTRACT_VCPU_MODE(vcpu);

	if (preempt)
		rkvm_preemption_on_update_vmexit_state(vcpu, &rkvm_data->userspace);
	if (record)
		rkvm_recording_on_update_vmexit_state(vcpu);
	if (replay)
		rkvm_replaying_on_update_vmexit_state(vcpu);
}
EXPORT_SYMBOL_GPL(rkvm_on_update_vmexit_state);

bool rkvm_before_inject_rmod_irq(rkvm_vcpu_host *vcpu, int irq)
{
	bool success = true;

	bool preempt, record, replay, lock_step;
	EXTRACT_VCPU_MODE(vcpu);

	if (record)
		success = rkvm_recording_before_inject_rmod_irq(vcpu, irq) && success;
	if (replay)
		success = rkvm_replaying_before_inject_rmod_irq(vcpu, irq) && success;

	return success;
}
EXPORT_SYMBOL_GPL(rkvm_before_inject_rmod_irq);

bool rkvm_after_inject_irq(rkvm_vcpu_host *vcpu, int irq)
{
	bool success = true;

	bool preempt, record, replay, lock_step;
	EXTRACT_VCPU_MODE(vcpu);

	if (record)
		success = rkvm_recording_after_inject_irq(vcpu, irq) && success;
	if (replay)
		success = rkvm_replaying_after_inject_irq(vcpu, irq) && success;

	return success;
}
EXPORT_SYMBOL_GPL(rkvm_after_inject_irq);

bool rkvm_on_pio_in_data_avail(rkvm_vcpu_host *vcpu,
			       void *target, const void *src, int size)
{
	bool success = true;

	bool preempt, record, replay, lock_step;
	EXTRACT_VCPU_MODE(vcpu);

	if (record)
		success = rkvm_recording_on_pio_in_data_avail(vcpu, target, src, size) && success;
	if (replay)
		success = rkvm_replaying_on_pio_in_data_avail(vcpu, target, src, size) && success;

	return success;
}
EXPORT_SYMBOL_GPL(rkvm_on_pio_in_data_avail);

void rkvm_on_set_regs(rkvm_vcpu_host *vcpu, void *src, unsigned size)
{
	bool preempt, record, replay, lock_step;
	EXTRACT_VCPU_MODE(vcpu);

	if (record)
		rkvm_recording_on_set_regs(vcpu, src, size);
	if (replay)
		rkvm_replaying_on_set_regs(vcpu, src, size);
}
EXPORT_SYMBOL_GPL(rkvm_on_set_regs);

void rkvm_on_set_sregs(rkvm_vcpu_host *vcpu, void *src, unsigned size)
{
	bool preempt, record, replay, lock_step;
	EXTRACT_VCPU_MODE(vcpu);

	if (record)
		rkvm_recording_on_set_sregs(vcpu, src, size);
	if (replay)
		rkvm_replaying_on_set_sregs(vcpu, src, size);
}
EXPORT_SYMBOL_GPL(rkvm_on_set_sregs);

bool kvm_enable_preemption_timer(rkvm_vcpu_host *vcpu)
{
	if (kvm_has_preemption_timer) {
		bool preempt, record, replay, lock_step;
		EXTRACT_VCPU_MODE(vcpu);
		return preempt;
	} else {
		return false;
	}
}
EXPORT_SYMBOL_GPL(kvm_enable_preemption_timer);

bool rkvm_preempting(rkvm_host *host)
{
	bool preempt, record, replay, lock_step;
	EXTRACT_MODE(host);
	return preempt;
}
EXPORT_SYMBOL_GPL(rkvm_preempting);

bool rkvm_replaying(rkvm_host *host)
{
	bool preempt, record, replay, lock_step;
	EXTRACT_MODE(host);
	return replay;
}
EXPORT_SYMBOL_GPL(rkvm_replaying);

bool rkvm_recording(rkvm_host *host)
{
	bool preempt, record, replay, lock_step;
	EXTRACT_MODE(host);
	return record;
}
EXPORT_SYMBOL_GPL(rkvm_recording);

bool rkvm_recording_or_replaying(rkvm_host *host)
{
	bool preempt, record, replay, lock_step;
	EXTRACT_MODE(host);
	return record || replay;
}
EXPORT_SYMBOL_GPL(rkvm_recording_or_replaying);

bool rkvm_guest_reg_available(rkvm_host *host, u32 reg)
{
	struct rkvm_data *rkvm_data = RKVM_DATA(host);
	int i;
	if (rkvm_recording_or_replaying(host)) {
		for (i = 0; i < sizeof(rkvm_data->unavailable_regs) /
			     sizeof(rkvm_data->unavailable_regs[0]); ++i) {
			u32 unavailable_reg = rkvm_data->unavailable_regs[i];
			if (!unavailable_reg)
				break;
			if (unavailable_reg == reg)
				return false;
		}
	}
	return true;
}
EXPORT_SYMBOL_GPL(rkvm_guest_reg_available);

void rkvm_mark_guest_reg_unavailable(rkvm_host *host, u32 reg)
{
	struct rkvm_data *rkvm_data = RKVM_DATA(host);
	int i;
	for (i = 0; i < sizeof(rkvm_data->unavailable_regs) /
		     sizeof(rkvm_data->unavailable_regs[0]); ++i) {
		u32 unavailable_reg = rkvm_data->unavailable_regs[i];
		if (!unavailable_reg) {
			rkvm_data->unavailable_regs[i] = reg;
			break;
		}
		if (unavailable_reg == reg)
			break;
	}
}
EXPORT_SYMBOL_GPL(rkvm_mark_guest_reg_unavailable);

static void rkvm_prerecord_point(rkvm_vcpu_host *vcpu, enum rkvm_sync_reason sync_reason)
{
	rkvm_host *host = RKVM_HOST(vcpu);
	struct rkvm_vcpu_data *vcpu_data = RKVM_VCPU_DATA(vcpu);
	struct rkvm_vcpu_recording *vcpu_recording = RKVM_VCPU_RECORDING(vcpu);
	struct rkvm_data *rkvm_data = RKVM_DATA(host);
	struct rkvm_ops *ops = rkvm_data->ops;
	struct rkvm_point *point = &vcpu_recording->pending_point;

	point->rbc = vcpu_data->accumulate_rbc;
	point->pc = vcpu_data->vmexit_guest_pc;
	point->ecx = vcpu_data->vmexit_guest_ecx;
	if (unlikely(!point->pc)) {
		point->pc = vcpu_data->vmexit_guest_pc = ops->read_guest_pc(vcpu);
		point->ecx = vcpu_data->vmexit_guest_ecx = ops->read_guest_ecx(vcpu);
	}
	vcpu_recording->pending_sync_reason = sync_reason;
}

static void rkvm_record_vcpu_exit(rkvm_vcpu_host *vcpu, bool internal)
{
	rkvm_host *host = RKVM_HOST(vcpu);
	struct rkvm_vcpu_recording *vcpu_recording = RKVM_VCPU_RECORDING(vcpu);
	struct rkvm_data *rkvm_data = RKVM_DATA(host);
	struct rkvm_ops *ops = rkvm_data->ops;

	rkvm_prerecord_point(vcpu, RKVM_RSN_VCPU_EXIT);
	if (internal) {
		if (vcpu_recording->vcpu_halted)
			vcpu_recording->pending_exitrsn = KVM_EXIT_HLT;
		else
			vcpu_recording->pending_exitrsn = KVM_EXIT_UNKNOWN;
	} else {
		vcpu_recording->pending_exitrsn = ops->userspace_exit_reason(vcpu);
	}
	rkvm_record_pending_vmexit(vcpu);
}

static void rkvm_prerecord_irq_point(rkvm_vcpu_host *vcpu,
				     enum rkvm_sync_reason sync_reason, int irq)
{
	rkvm_host *host = RKVM_HOST(vcpu);
	struct rkvm_vcpu_data *vcpu_data = RKVM_VCPU_DATA(vcpu);
	struct rkvm_vcpu_recording *vcpu_recording = RKVM_VCPU_RECORDING(vcpu);
	struct rkvm_data *rkvm_data = RKVM_DATA(host);
	struct rkvm_ops *ops = rkvm_data->ops;
	int irqcnt = atomic_read(&vcpu_data->irq_counts[irq]);
	
	rkvm_prerecord_point(vcpu, sync_reason);
	vcpu_recording->pending_irq = irq;
	vcpu_recording->pending_irqcnt = irqcnt;
	vcpu_recording->pending_irqpc = ops->read_guest_pc(vcpu);
	vcpu_recording->pending_irqecx = ops->read_guest_ecx(vcpu);
}

static void rkvm_record_pending_vmexit(rkvm_vcpu_host *vcpu)
{
	struct rkvm_vcpu_data *vcpu_data = RKVM_VCPU_DATA(vcpu);
	struct rkvm_vcpu_recording *vcpu_recording = RKVM_VCPU_RECORDING(vcpu);
	struct rkvm_delta delta;
	u8 rsn = (u8)vcpu_recording->pending_sync_reason;
	u64 cnt;

	if (rsn == RKVM_NO_RSN)
		return;

	cnt = ++vcpu_recording->record_write_counter;

	RKVM_DEBUG_PRINT(vcpu, "rid=%lld rsn=%d",
			 vcpu_recording->recorded_rid, rsn);

	switch (rsn) {
	case RKVM_NO_RSN:
		break;
	case RKVM_RSN_PROTECTED_MOD_IRQ:
	case RKVM_RSN_REAL_MOD_IRQ:
		RKVM_RECORD_VALUE(vcpu, u8, RKVM_IRQ_STREAM,
				  vcpu_recording->pending_irq);
		RKVM_RECORD_VALUE(vcpu, u32, RKVM_IRQCNT_STREAM,
				  vcpu_recording->pending_irqcnt);
		RKVM_RECORD_VALUE(vcpu, s64, RKVM_IRQPC_STREAM,
				  vcpu_recording->pending_irqpc - vcpu_data->vmexit_guest_pc);
		RKVM_RECORD_VALUE(vcpu, s32, RKVM_IRQECX_STREAM,
				  vcpu_recording->pending_irqecx - vcpu_data->vmexit_guest_ecx);
		RKVM_DEBUG_PRINT(vcpu, " irq=%d", vcpu_recording->pending_irq);
		goto common;
	case RKVM_RSN_VCPU_EXIT:
		RKVM_RECORD_VALUE(vcpu, u32, RKVM_EXITRSN_STREAM,
				   vcpu_recording->pending_exitrsn);
		RKVM_DEBUG_PRINT(vcpu, " exitrsn=%d", vcpu_recording->pending_exitrsn);
		goto common;
	}
	return;
 common:
	create_delta(&delta, &vcpu_recording->pending_point, &vcpu_recording->recorded_point);
	write_delta(vcpu, &delta);
	RKVM_RECORD_VALUE(vcpu, u8, RKVM_RSN_STREAM, rsn);
	vcpu_recording->recorded_point = vcpu_recording->pending_point;
	vcpu_recording->pending_sync_reason = RKVM_NO_RSN;

	RKVM_DEBUG_PRINT(vcpu, " rbc=%lld pc=0x%llx ecx=0x%x cnt=%lld\n",
			 (long long)vcpu_recording->recorded_point.rbc,
			 (long long)vcpu_recording->recorded_point.pc,
			 vcpu_recording->recorded_point.ecx,
			 cnt);
}

static void rkvm_lockstep_lock(rkvm_vcpu_host *vcpu)
{
	rkvm_host *host = RKVM_HOST(vcpu);
	struct rkvm_vcpu_data *vcpu_data = RKVM_VCPU_DATA(vcpu);
	struct rkvm_data *rkvm_data = RKVM_DATA(host);

	bool preempt, record, replay, lock_step;
	EXTRACT_VCPU_MODE(vcpu);

	if (!vcpu_data->lockstep_owner) {
		spin_lock(&rkvm_data->lockstep_spinlock);
		vcpu_data->lockstep_owner = true;
		if (preempt)
			rkvm_preemption_step_locked(vcpu);
	}
}

static void rkvm_lockstep_unlock(rkvm_vcpu_host *vcpu)
{
	rkvm_host *host = RKVM_HOST(vcpu);
	struct rkvm_vcpu_data *vcpu_data = RKVM_VCPU_DATA(vcpu);
	struct rkvm_data *rkvm_data = RKVM_DATA(host);

	if (vcpu_data->lockstep_owner) {
		bool preempt, record, replay, lock_step;
		EXTRACT_VCPU_MODE(vcpu);

		spin_unlock(&rkvm_data->lockstep_spinlock);
		if (preempt)
			rkvm_preemption_step_unlocked(vcpu);
		vcpu_data->lockstep_owner = false;
	}
}

bool rkvm_on_vcpu_entry(rkvm_vcpu_host *vcpu)
{
	struct rkvm_vcpu_data *vcpu_data = RKVM_VCPU_DATA(vcpu);
	bool success = true;

	bool preempt, record, replay, lock_step;
	EXTRACT_VCPU_MODE(vcpu);

	if (lock_step)
		rkvm_lockstep_lock(vcpu);
	if (record)
		success = rkvm_recording_on_vcpu_entry(vcpu) && success;
	if (replay)
		success = rkvm_replaying_on_vcpu_entry(vcpu) && success;

	if (!success) {
		if (lock_step)
			rkvm_lockstep_unlock(vcpu);
		vcpu->run->exit_reason = KVM_EXIT_RKVM;
	}
	vcpu_data->vcpu_entered = success;
	return success;
}
EXPORT_SYMBOL_GPL(rkvm_on_vcpu_entry);

void rkvm_on_vcpu_exit(rkvm_vcpu_host *vcpu, bool internal)
{
	rkvm_host *host = RKVM_HOST(vcpu);
	struct rkvm_vcpu_data *vcpu_data = RKVM_VCPU_DATA(vcpu);
	struct rkvm_data *rkvm_data = RKVM_DATA(host);

	bool preempt, record, replay, lock_step;
	EXTRACT_VCPU_MODE(vcpu);

	if (!vcpu_data->vcpu_entered)
		return;

	vcpu_data->vcpu_entered = false;
	vcpu_data->must_exit = false;

	if (preempt)
		rkvm_preemption_on_vcpu_exit(vcpu, &rkvm_data->userspace, internal);
	if (record)
		rkvm_recording_on_vcpu_exit(vcpu, internal);
	if (replay)
		rkvm_replaying_on_vcpu_exit(vcpu, internal);
	if (lock_step)
		rkvm_lockstep_unlock(vcpu);

	update_rkvm_vcpu_debug_data(vcpu);
	if (preempt)
		rkvm_preemption_update_debug_data(vcpu);
}
EXPORT_SYMBOL_GPL(rkvm_on_vcpu_exit);

bool rkvm_can_reschedule(rkvm_vcpu_host *vcpu)
{
	bool success = true;

	bool preempt, record, replay, lock_step;
	EXTRACT_VCPU_MODE(vcpu);

	if (record)
		success = success && rkvm_recording_can_reschedule(vcpu);
	if (replay)
		success = success && rkvm_replaying_can_reschedule(vcpu);

	return success;
}
EXPORT_SYMBOL_GPL(rkvm_can_reschedule);

bool rkvm_handle_halt(rkvm_vcpu_host *vcpu)
{
	bool handled = false;

	bool preempt, record, replay, lock_step;
	EXTRACT_VCPU_MODE(vcpu);

	if (preempt)
		handled = rkvm_preemption_handle_halt(vcpu) || handled;
	if (record)
		handled = rkvm_recording_handle_halt(vcpu) || handled;
	if (replay)
		handled = rkvm_replaying_handle_halt(vcpu) || handled;

	return handled;
}
EXPORT_SYMBOL_GPL(rkvm_handle_halt);

void rkvm_handle_external_interrupt(rkvm_vcpu_host *vcpu)
{
	bool preempt, record, replay, lock_step;
	EXTRACT_VCPU_MODE(vcpu);

	if (record) {
		struct rkvm_vcpu_recording *vcpu_recording = RKVM_VCPU_RECORDING(vcpu);
		vcpu_recording->make_one_more_step = true;
	}
}
EXPORT_SYMBOL_GPL(rkvm_handle_external_interrupt);

void rkvm_vcpu_halted(rkvm_vcpu_host *vcpu)
{
	bool preempt, record, replay, lock_step;
	EXTRACT_VCPU_MODE(vcpu);

	if (preempt)
		rkvm_preemption_vcpu_halted(vcpu);
	if (record)
		rkvm_recording_vcpu_halted(vcpu);
	if (replay)
		rkvm_replaying_vcpu_halted(vcpu);
}
EXPORT_SYMBOL_GPL(rkvm_vcpu_halted);

static void rkvm_recording_vcpu_halted(rkvm_vcpu_host *vcpu)
{
	struct rkvm_vcpu_recording *vcpu_recording = RKVM_VCPU_RECORDING(vcpu);

	vcpu_recording->vcpu_halted = true;
}

static bool rkvm_recording_on_vcpu_entry(rkvm_vcpu_host *vcpu)
{
	rkvm_host *host = RKVM_HOST(vcpu);
	struct rkvm_vcpu_recording *vcpu_recording = RKVM_VCPU_RECORDING(vcpu);
	struct rkvm_recording *recording = RKVM_RECORDING(host);
	u64 rid = recording->recorded_rid;

	vcpu_recording->vcpu_halted = false;

	RKVM_RECORD_VALUE(vcpu, u64, RKVM_RID_STREAM, rid - vcpu_recording->recorded_rid);
	recording->recorded_rid = vcpu_recording->recorded_rid = rid + 1;

	return true;
}

static void rkvm_recording_on_vcpu_exit(rkvm_vcpu_host *vcpu, bool internal)
{
	rkvm_host *host = RKVM_HOST(vcpu);
	struct rkvm_vcpu_data *vcpu_data = RKVM_VCPU_DATA(vcpu);
	struct rkvm_vcpu_recording *vcpu_recording = RKVM_VCPU_RECORDING(vcpu);
	struct rkvm_data *rkvm_data = RKVM_DATA(host);
	struct rkvm_ops *ops = rkvm_data->ops;
	u32 exitrsn = ops->userspace_exit_reason(vcpu);

	if (!internal) {
		switch (exitrsn) {
		case KVM_EXIT_IO:
			if (vcpu->run->io.direction) {
				RKVM_RECORD_VALUE(vcpu, u8, RKVM_OUTSIZE_STREAM, vcpu->run->io.size);
				RKVM_RECORD_VALUE(vcpu, u16, RKVM_OUTPORT_STREAM, vcpu->run->io.port);
				RKVM_DEBUG_PRINT(vcpu, "OUT of size %d to port %d. Count=%d ",
						 vcpu->run->io.size, vcpu->run->io.port,
						 ++vcpu_data->out_counter);
			} else {
				RKVM_RECORD_VALUE(vcpu, u8, RKVM_INSIZE_STREAM, vcpu->run->io.size);
				RKVM_RECORD_VALUE(vcpu, u16, RKVM_INPORT_STREAM, vcpu->run->io.port);
				RKVM_DEBUG_PRINT(vcpu, "IN of size %d from port %d. Count=%d ",
						 vcpu->run->io.size, vcpu->run->io.port,
						 ++vcpu_data->in_counter);
			}
			break;
		case KVM_EXIT_MMIO:
			if (vcpu_recording->has_internal_exit_reason) {
				internal = true;
				break;
			}
			RKVM_RECORD_VALUE(vcpu, u32, RKVM_MMIOSIZ_STREAM, vcpu->run->mmio.len);
			RKVM_RECORD_VALUE(vcpu, u64, RKVM_MMIOADR_STREAM, vcpu->run->mmio.phys_addr);
			break;
		}
	}
	rkvm_record_vcpu_exit(vcpu, internal);
}

static bool rkvm_recording_can_reschedule(rkvm_vcpu_host *vcpu)
{
	struct rkvm_vcpu_recording *vcpu_recording = RKVM_VCPU_RECORDING(vcpu);
	return !vcpu_recording->make_one_more_step;
}

static void rkvm_recording_on_vmentry(rkvm_vcpu_host *vcpu, struct rkvm_local_ops *lops)
{
	rkvm_host *host = RKVM_HOST(vcpu);
	struct rkvm_vcpu_data *vcpu_data = RKVM_VCPU_DATA(vcpu);
	struct rkvm_vcpu_recording *vcpu_recording = RKVM_VCPU_RECORDING(vcpu);
	struct rkvm_data *rkvm_data = RKVM_DATA(host);
	struct rkvm_ops *ops = rkvm_data->ops;
	int irq;

	vcpu_recording->has_internal_exit_reason = false;
	
	if (vcpu_recording->make_one_more_step) {
		if (!lops->inject_immediate_exit())
			RKVM_DEBUG_PRINT(vcpu, "FAILED to inject immediate exit\n");
	}

	lops->disable_host_pmc_counters();
	if (lops->read_hw_intr_info(&irq))
		rkvm_prerecord_irq_point(vcpu, RKVM_RSN_PROTECTED_MOD_IRQ, irq);

	vcpu_data->entry_rbc = ops->read_rbc(vcpu);
}

static void rkvm_recording_on_vmexit(rkvm_vcpu_host *vcpu,
				     bool reinject_external_interrupt,
				     u32 exit_reason,
				     struct rkvm_local_ops *lops)
{
	rkvm_host *host = RKVM_HOST(vcpu);
	struct rkvm_vcpu_data *vcpu_data = RKVM_VCPU_DATA(vcpu);
	struct rkvm_vcpu_recording *vcpu_recording = RKVM_VCPU_RECORDING(vcpu);
	struct rkvm_data *rkvm_data = RKVM_DATA(host);
	struct rkvm_ops *ops = rkvm_data->ops;

	vcpu_recording->has_internal_exit_reason = ops->has_internal_exit_reason(vcpu);

	if (vcpu_recording->make_one_more_step) {
		vcpu_recording->make_one_more_step = false;
		vcpu_data->must_exit = true;
		rkvm_preemption_run_free(vcpu, false);
		lops->clear_immediate_exit();
	}
	vcpu_data->accumulate_rbc += ops->read_rbc(vcpu) - vcpu_data->entry_rbc;

	RKVM_DEBUG_PRINT(vcpu, "Exit %d. pc=0x%llx ecx=0x%x rbc=%lld\n",
			 exit_reason,
			 (long long)ops->read_guest_pc(vcpu),
			 ops->read_guest_ecx(vcpu),
			 (long long)vcpu_data->accumulate_rbc);

	if (!reinject_external_interrupt) {
		rkvm_record_pending_vmexit(vcpu);
	} else {
		/* TODO */
	}
}

static void rkvm_recording_on_update_vmexit_state(rkvm_vcpu_host *vcpu)
{
	rkvm_host *host = RKVM_HOST(vcpu);
	struct rkvm_vcpu_data *vcpu_data = RKVM_VCPU_DATA(vcpu);
	struct rkvm_data *rkvm_data = RKVM_DATA(host);
	struct rkvm_ops *ops = rkvm_data->ops;
	
	vcpu_data->vmexit_guest_pc = ops->read_guest_pc(vcpu);
	vcpu_data->vmexit_guest_ecx = ops->read_guest_ecx(vcpu);
}

static bool rkvm_recording_before_inject_rmod_irq(rkvm_vcpu_host *vcpu, int irq)
{
	struct rkvm_vcpu_recording *vcpu_recording = RKVM_VCPU_RECORDING(vcpu);
	rkvm_prerecord_irq_point(vcpu, RKVM_RSN_REAL_MOD_IRQ, irq);
	RKVM_DEBUG_PRINT(vcpu, "RECORD See injecting real mode interrupt %d (rid=%lld)\n",
			 irq, vcpu_recording->recorded_rid);
	return true;
}

static bool rkvm_recording_after_inject_irq(rkvm_vcpu_host *vcpu, int irq)
{
	struct rkvm_vcpu_recording *vcpu_recording = RKVM_VCPU_RECORDING(vcpu);
	RKVM_DEBUG_PRINT(vcpu, "RECORD See injecting protected mode interrupt %d (rid=%lld)\n",
			 irq, vcpu_recording->recorded_rid);
	return true;
}

static bool rkvm_recording_on_pio_in_data_avail(rkvm_vcpu_host *vcpu,
						void *target, const void *src, int size)
{
	RKVM_RECORD_DATA(vcpu, RKVM_PIO_STREAM, src, size);
	return true;
}

static void rkvm_recording_on_set_regs(rkvm_vcpu_host *vcpu, void *src, unsigned size)
{
	RKVM_RECORD_DATA(vcpu, RKVM_REGS_STREAM, src, size);
}

static void rkvm_recording_on_set_sregs(rkvm_vcpu_host *vcpu, void *src, unsigned size)
{
	RKVM_RECORD_DATA(vcpu, RKVM_SREGS_STREAM, src, size);
}

static bool rkvm_recording_handle_halt(rkvm_vcpu_host *vcpu)
{
	return false;
}


static s64 rbc_threshold = 32;

static void rkvm_replaying_on_vmentry(rkvm_vcpu_host *vcpu, struct rkvm_local_ops *lops)
{
	rkvm_host *host = RKVM_HOST(vcpu);
	struct rkvm_vcpu_data *vcpu_data = RKVM_VCPU_DATA(vcpu);
	struct rkvm_vcpu_replaying *vcpu_replaying = RKVM_VCPU_REPLAYING(vcpu);
	struct rkvm_data *rkvm_data = RKVM_DATA(host);
	struct rkvm_ops *ops = rkvm_data->ops;
	u64 rbc;
	u64 new_rbc = rbc_threshold + vcpu_data->accumulate_rbc - vcpu_replaying->replay_target_point.rbc;
	bool single_step = false;

	vcpu_replaying->has_internal_exit_reason = false;

	if (lops->clear_rbc_pmi()) {
		rbc = 0;
		ops->set_rbc(vcpu, 0);
	} else {
		rbc = ops->read_rbc(vcpu);
	}

	rkvm_replaying_update(vcpu, "Before vmentry: ");

	switch (vcpu_replaying->replay_state) {
	case NO_REPLAY:
		lops->enable_single_step(false);
		return;
	case REPLAY_WAIT_FOR_PMI:
		if ((vcpu_replaying->replay_sync_reason == RKVM_RSN_VCPU_EXIT) &&
		    is_synchronous_exit_reason(vcpu_replaying->pending_exitrsn))
			break;
		if ((s64)new_rbc < 0) {
			if (rbc != new_rbc) {
				rbc = new_rbc;
				ops->set_rbc(vcpu, rbc);
				RKVM_DEBUG_PRINT(vcpu,
						 "wait for PMI at %lld branches\n",
						 (long long)rbc);
				lops->make_apic_deliver_nmi_on_pmi();
			}
			break;
		}
		vcpu_replaying->replay_state = REPLAY_SINGLE_STEP;
		/* fallthru */
	case REPLAY_SINGLE_STEP:
		if ((vcpu_replaying->replay_sync_reason == RKVM_RSN_VCPU_EXIT) &&
		    is_synchronous_exit_reason(vcpu_replaying->pending_exitrsn))
			break;
		single_step = true;
		RKVM_DEBUG_PRINT(vcpu, "single stepping\n");
		break;
	case REPLAY_NEW_TARGET:
		RKVM_DEBUG_PRINT(vcpu, "ERROR: rkvm_replaying_on_vmentry: REPLAY_NEW_TARGET\n");
		/* TODO: Is it even possible? */
		break;
	case REPLAY_UNINITIALIZED:
		RKVM_DEBUG_PRINT(vcpu, "ERROR: rkvm_replaying_on_vmentry: REPLAY_UNINITIALIZED\n");
		/* TODO: Is it even possible? */
		break;
	case REPLAY_HIT_EVENT:
		switch (vcpu_replaying->replay_sync_reason) {
		case RKVM_NO_RSN:
			/* TODO: Is it even possible? */
			RKVM_DEBUG_PRINT(vcpu, "IMPOSSIBLE: event hit : no reason\n");
			break;
		case RKVM_RSN_VCPU_EXIT:
			if (!is_synchronous_exit_reason(vcpu_replaying->pending_exitrsn)) {
				vcpu_data->must_exit = true;
				vcpu_data->exit_immediately = true;
				RKVM_DEBUG_PRINT(vcpu, "event hit : exit immediately\n");
				if (!lops->inject_immediate_exit())
					RKVM_DEBUG_PRINT(vcpu, "FAILED to inject immediate exit\n");
			}
			break;
		case RKVM_RSN_REAL_MOD_IRQ:
			RKVM_DEBUG_PRINT(vcpu, "Injecting real mode interrupt %d\n",
					 vcpu_replaying->pending_irq);
			ops->inject_external_realmod_int(vcpu, vcpu_replaying->pending_irq);
			break;
		case RKVM_RSN_PROTECTED_MOD_IRQ:
			RKVM_DEBUG_PRINT(vcpu, "Injecting protected mode interrupt %d\n",
					 vcpu_replaying->pending_irq);
			lops->set_hw_intr_info(vcpu_replaying->pending_irq);
			break;
		}
		break;
	}

	lops->disable_host_pmc_counters();
	lops->enable_single_step(single_step);
	lops->disable_pending_virtual_intr();
	lops->ensure_rdtsc_exiting();
	vcpu_data->entry_rbc = rbc;

	return;
}

static void rkvm_replaying_on_vmexit(rkvm_vcpu_host *vcpu,
				     bool reinject_external_interrupt, u32 exit_reason,
				     struct rkvm_local_ops *lops)
{
	rkvm_host *host = RKVM_HOST(vcpu);
	struct rkvm_vcpu_data *vcpu_data = RKVM_VCPU_DATA(vcpu);
	struct rkvm_vcpu_replaying *vcpu_replaying = RKVM_VCPU_REPLAYING(vcpu);
	struct rkvm_data *rkvm_data = RKVM_DATA(host);
	struct rkvm_ops *ops = rkvm_data->ops;
	bool has_pmi;

	if (vcpu_data->exit_immediately) {
		vcpu_data->exit_immediately = false;
		lops->clear_immediate_exit();
	}

	if (vcpu_replaying->replay_state == NO_REPLAY)
		return;

	vcpu_replaying->has_internal_exit_reason = ops->has_internal_exit_reason(vcpu);

	vcpu_data->accumulate_rbc += ops->read_rbc(vcpu) - vcpu_data->entry_rbc;
	has_pmi = lops->has_rbc_pmi();

	RKVM_DEBUG_PRINT(vcpu, "Exit %d%s. pc=0x%llx ecx=0x%x rbc=%lld d=%lld\n",
			 exit_reason,
			 has_pmi ? " (has PMI)" : "",
			 (long long)ops->read_guest_pc(vcpu),
			 ops->read_guest_ecx(vcpu),
			 (long long)vcpu_data->accumulate_rbc,
			 (long long)vcpu_replaying->accumulate_rbc_delta);

	if ((vcpu_replaying->replay_state != NO_REPLAY) && reinject_external_interrupt) {
		RKVM_DEBUG_PRINT(vcpu, "See reinject\n");
	}

	if (vcpu_replaying->replay_state == REPLAY_HIT_EVENT) {
		if ((vcpu_replaying->replay_sync_reason == RKVM_RSN_PROTECTED_MOD_IRQ) ||
		    (vcpu_replaying->replay_sync_reason == RKVM_RSN_REAL_MOD_IRQ)) {
			if (!reinject_external_interrupt) {
				if (!read_next_replay_target_point(vcpu))
					vcpu_replaying->replay_state = NO_REPLAY;
			} else {
				RKVM_DEBUG_PRINT(vcpu, "Need reinject\n");
			}
		}
	}
}

static void rkvm_replaying_on_update_vmexit_state(rkvm_vcpu_host *vcpu)
{
	rkvm_host *host = RKVM_HOST(vcpu);
	struct rkvm_vcpu_data *vcpu_data = RKVM_VCPU_DATA(vcpu);
	struct rkvm_vcpu_replaying *vcpu_replaying = RKVM_VCPU_REPLAYING(vcpu);
	struct rkvm_data *rkvm_data = RKVM_DATA(host);
	struct rkvm_ops *ops = rkvm_data->ops;

	if (vcpu_replaying->replay_state == NO_REPLAY)
		return;

	vcpu_data->vmexit_guest_pc = ops->read_guest_pc(vcpu);
	vcpu_data->vmexit_guest_ecx = ops->read_guest_ecx(vcpu);

	vcpu_data->process_exit = true;
	rkvm_replaying_update(vcpu, "After update: ");
}

static void rkvm_replaying_vcpu_halted(rkvm_vcpu_host *vcpu)
{
	struct rkvm_vcpu_replaying *vcpu_replaying = RKVM_VCPU_REPLAYING(vcpu);

	vcpu_replaying->vcpu_halted = true;
}

static bool rkvm_replaying_on_vcpu_entry(rkvm_vcpu_host *vcpu)
{
	rkvm_host *host = RKVM_HOST(vcpu);
	struct rkvm_vcpu_data *vcpu_data = RKVM_VCPU_DATA(vcpu);
	struct rkvm_vcpu_replaying *vcpu_replaying = RKVM_VCPU_REPLAYING(vcpu);
	struct rkvm_replaying *replaying = RKVM_REPLAYING(host);

	if (vcpu_replaying->replay_state == NO_REPLAY)
		return true;

	if (vcpu_replaying->next_rid == vcpu_replaying->replayed_rid) {
		u64 rid_delta;
		RKVM_READ_REPLAY_VALUE(vcpu, u64, RKVM_RID_STREAM, &rid_delta);
		vcpu_replaying->next_rid = vcpu_replaying->replayed_rid + rid_delta + 1;
	}

	if (vcpu_replaying->next_rid != replaying->replayed_rid + 1)
		return false;

	vcpu_replaying->vcpu_halted = false;

	if (vcpu_replaying->replay_state == REPLAY_UNINITIALIZED) {
		if (!read_next_replay_target_point(vcpu))
			vcpu_replaying->replay_state = NO_REPLAY;
	}
	if (vcpu_data->must_exit) {
		vcpu_data->must_exit = false;
		rkvm_replaying_on_vcpu_exit(vcpu, false);
		return false;
	}

	return true;
}

static void rkvm_replaying_on_vcpu_exit(rkvm_vcpu_host *vcpu, bool internal)
{
	rkvm_host *host = RKVM_HOST(vcpu);
	struct rkvm_vcpu_data *vcpu_data = RKVM_VCPU_DATA(vcpu);
	struct rkvm_vcpu_replaying *vcpu_replaying = RKVM_VCPU_REPLAYING(vcpu);
	struct rkvm_data *rkvm_data = RKVM_DATA(host);
	struct rkvm_replaying *replaying = RKVM_REPLAYING(host);
	struct rkvm_ops *ops = rkvm_data->ops;
	bool unplanned = false;
	bool natural = false;
	bool technical = false;
	bool wrong = false;
	bool fixed = false;
	u32 exit_reason = ops->userspace_exit_reason(vcpu);
	u32 original_reason = vcpu_replaying->pending_exitrsn;

	if (!vcpu_data->process_exit)
		return;
	vcpu_data->process_exit = false;

	if (vcpu_replaying->replay_state == NO_REPLAY)
		return;

	if (vcpu_replaying->has_internal_exit_reason && (exit_reason == KVM_EXIT_MMIO))
		internal = true;
	if (internal)
		exit_reason = vcpu_replaying->vcpu_halted ? KVM_EXIT_HLT : KVM_EXIT_UNKNOWN;

	if (original_reason == exit_reason) {
		switch (original_reason) {
		case KVM_EXIT_IO:
			{
				u8 size;
				u16 port;
				int counter;
				if (vcpu->run->io.direction) {
					counter = ++vcpu_data->out_counter;
					if (RKVM_READ_REPLAY_VALUE(vcpu, u8, RKVM_OUTSIZE_STREAM, &size)) {
						if (vcpu->run->io.size != size)
							RKVM_DEBUG_PRINT(vcpu, "Mismatched OUT size: %d and not %d. Count=%d\n",
									 vcpu->run->io.size, size, counter);
						else
							RKVM_DEBUG_PRINT(vcpu, "Recorded OUT of size %d. Count=%d\n",
									 vcpu->run->io.size, counter);
					} else {
						RKVM_DEBUG_PRINT(vcpu, "Unrecorded OUT of size %d. Count=%d\n",
								 vcpu->run->io.size, counter);
					}
					if (RKVM_READ_REPLAY_VALUE(vcpu, u16, RKVM_OUTPORT_STREAM, &port)) {
						if (vcpu->run->io.port != port)
							RKVM_DEBUG_PRINT(vcpu, "Mismatched OUT port: %d and not %d. Count=%d\n",
									 vcpu->run->io.port, port, counter);
						else
							RKVM_DEBUG_PRINT(vcpu, "Recorded OUT to port %d. Count=%d\n",
									 vcpu->run->io.port,
									 counter);
					} else {
						RKVM_DEBUG_PRINT(vcpu, "Unrecorded OUT to port %d. Count=%d\n",
							 vcpu->run->io.port, counter);
					}
				} else {
					counter = ++vcpu_data->in_counter;
					if (RKVM_READ_REPLAY_VALUE(vcpu, u8, RKVM_INSIZE_STREAM, &size)) {
						if (vcpu->run->io.size != size)
							RKVM_DEBUG_PRINT(vcpu, "Mismatched IN size: %d and not %d. Count=%d\n",
									 vcpu->run->io.size, size, counter);
						else
							RKVM_DEBUG_PRINT(vcpu, "Recorded IN of size %d. Count=%d\n",
									 vcpu->run->io.size, counter);
					} else {
						RKVM_DEBUG_PRINT(vcpu, "Unrecorded IN of size %d. Count=%d\n",
								 vcpu->run->io.size, counter);
					}
					if (RKVM_READ_REPLAY_VALUE(vcpu, u16, RKVM_INPORT_STREAM, &port)) {
						if (vcpu->run->io.port != port)
							RKVM_DEBUG_PRINT(vcpu, "Mismatched IN port: %d and not %d. Count=%d\n",
									 vcpu->run->io.port, port, counter);
						else
							RKVM_DEBUG_PRINT(vcpu, "Recorded IN from port %d. Count=%d\n",
									 vcpu->run->io.port,
									 counter);
					} else {
						RKVM_DEBUG_PRINT(vcpu, "Unrecorded IN from port %d. Count=%d\n",
							 vcpu->run->io.port, counter);
					}
				}
			}
			break;
		case KVM_EXIT_MMIO:
			{
				u32 len;
				u64 phys_addr;
				if (RKVM_READ_REPLAY_VALUE(vcpu, u32, RKVM_MMIOSIZ_STREAM, &len)) {
					if (vcpu->run->mmio.len != len)
						RKVM_DEBUG_PRINT(vcpu, "Mismatched MMIO len: %d and not %d\n",
								 vcpu->run->mmio.len, len);
				} else {
					RKVM_DEBUG_PRINT(vcpu, "Unrecorded MMIO of len %d\n", vcpu->run->mmio.len);
				}
				if (RKVM_READ_REPLAY_VALUE(vcpu, u64, RKVM_MMIOADR_STREAM, &phys_addr)) {
					if (vcpu->run->mmio.phys_addr != phys_addr)
						RKVM_DEBUG_PRINT(vcpu, "Mismatched MMIO address: 0x%llx and not 0x%llx\n",
								 (long long)vcpu->run->mmio.phys_addr,
								 (long long)phys_addr);
				} else {
					RKVM_DEBUG_PRINT(vcpu, "Unrecorded MMIO to address 0x%llx\n",
							 (long long)vcpu->run->mmio.phys_addr);
				}
			}
			break;
		}
	} else if (exit_reason == ops->userspace_exit_reason(vcpu)) {
		switch (exit_reason) {
		case KVM_EXIT_IO:
			if (vcpu->run->io.direction)
				RKVM_DEBUG_PRINT(vcpu, "Unplanned OUT of size %d to port %d.\n",
						 vcpu->run->io.size, vcpu->run->io.port);
			else
				RKVM_DEBUG_PRINT(vcpu, "Unplanned IN of size %d from port %d.\n",
						 vcpu->run->io.size, vcpu->run->io.port);
			break;
		case KVM_EXIT_MMIO:
			RKVM_DEBUG_PRINT(vcpu, "Unplanned MMIO of len %d to address 0x%llx\n",
					 vcpu->run->mmio.len,
					 (long long)vcpu->run->mmio.phys_addr);
			break;
		}
	} else {
		switch (ops->userspace_exit_reason(vcpu)) {
		case KVM_EXIT_IO:
			if (vcpu->run->io.direction)
				RKVM_DEBUG_PRINT(vcpu, "Masked OUT of size %d to port %d.\n",
						 vcpu->run->io.size, vcpu->run->io.port);
			else
				RKVM_DEBUG_PRINT(vcpu, "Masked IN of size %d from port %d.\n",
						 vcpu->run->io.size, vcpu->run->io.port);
			break;
		case KVM_EXIT_MMIO:
			RKVM_DEBUG_PRINT(vcpu, "Masked MMIO of len %d to address 0x%llx\n",
					 vcpu->run->mmio.len,
					 (long long)vcpu->run->mmio.phys_addr);
			break;
		}
	}
	

	switch (vcpu_replaying->replay_state) {
	default:
		unplanned = true;
		if (is_synchronous_exit_reason(exit_reason)) {
			u64 pc = vcpu_data->vmexit_guest_pc;
			s64 pc_to_target = vcpu_replaying->replay_target_point.pc - pc;
			u64 rbc = vcpu_data->accumulate_rbc;
			s64 rbc_to_target = vcpu_replaying->replay_target_point.rbc - rbc;
			u32 ecx = vcpu_data->vmexit_guest_ecx;
			s32 ecx_to_target = ecx - vcpu_replaying->replay_target_point.ecx;
			if (pc_to_target != 0)
				break;
			if (ecx_to_target > 0)
				break;
			if (original_reason != exit_reason) {
				if (is_synchronous_exit_reason(original_reason))
					break;
			}
			if (rbc_to_target > 0)
				RKVM_DEBUG_PRINT(vcpu, "Skipped %lld branches\n", (long long)rbc_to_target);
			else if (rbc_to_target < 0)
				RKVM_DEBUG_PRINT(vcpu, "Missing %lld branches\n", (long long)-rbc_to_target);
			if (ecx_to_target)
				RKVM_DEBUG_PRINT(vcpu, "Missed ecx by %d\n", ecx_to_target);
			vcpu_data->accumulate_rbc = vcpu_replaying->replay_target_point.rbc;
			vcpu_replaying->accumulate_rbc_delta += rbc_to_target;
			unplanned = false;
			fixed = true;
		} else if (is_natural_exit_reason(exit_reason)) {
			unplanned = false;
			natural = true;
		} else {
			unplanned = false;
			technical = true;
		}
		break;
	case REPLAY_HIT_EVENT:
		if (vcpu_replaying->replay_sync_reason != RKVM_RSN_VCPU_EXIT) {
			wrong = true;
		} else {
			if (original_reason != exit_reason) {
				if (is_natural_exit_reason(exit_reason)) {
					if (is_synchronous_exit_reason(original_reason)) {
						if (is_synchronous_exit_reason(exit_reason))
							unplanned = true;
						else
							natural = true;
						break;
					} else if (is_synchronous_exit_reason(exit_reason)) {
						/* TODO: What happens here? */
						unplanned = true;
					} else {
						/* OK */
					}
				} else if (is_synchronous_exit_reason(original_reason)) {
					technical = true;
				}
			}
		}
		break;
	}
	RKVM_DEBUG_PRINT(vcpu, "%s vcpu_exit (reason %d)%s\n",
			 unplanned ? "Unplanned" : fixed ? "Fixed" : natural ? "Natural" : technical ? "Technical" : "Planned",
			 exit_reason,
			 wrong ? " instead of irq" : "");
	if (unplanned)
		return;
	if (natural)
		return;
	if (technical)
		return;
	if (wrong)
		return;

	replaying->replayed_rid = vcpu_replaying->replayed_rid = vcpu_replaying->next_rid;
	if (read_next_replay_target_point(vcpu))
		rkvm_replaying_update(vcpu, "After vcpu_exit: ");
	else
		vcpu_replaying->replay_state = NO_REPLAY;
}

static bool rkvm_replaying_can_reschedule(rkvm_vcpu_host *vcpu)
{
	return true;
}

static bool rkvm_replaying_before_inject_rmod_irq(rkvm_vcpu_host *vcpu, int irq)
{
	struct rkvm_vcpu_replaying *vcpu_replaying = RKVM_VCPU_REPLAYING(vcpu);
	if (vcpu_replaying->replay_state == NO_REPLAY)
		return true;
	RKVM_DEBUG_PRINT(vcpu, "REPLAY Not injecting real mode interrupt %d\n", irq);
	return false;
}

static bool rkvm_replaying_after_inject_irq(rkvm_vcpu_host *vcpu, int irq)
{
	struct rkvm_vcpu_replaying *vcpu_replaying = RKVM_VCPU_REPLAYING(vcpu);
	if (vcpu_replaying->replay_state == NO_REPLAY)
		return true;
	RKVM_DEBUG_PRINT(vcpu, "REPLAY Not injecting protected mode interrupt %d\n", irq);
	return false;
}

static bool rkvm_replaying_on_pio_in_data_avail(rkvm_vcpu_host *vcpu,
						void *target, const void *src, int size)
{
	struct rkvm_vcpu_replaying *vcpu_replaying = RKVM_VCPU_REPLAYING(vcpu);
	if (vcpu_replaying->replay_state == NO_REPLAY)
		return true;
	if (!RKVM_READ_REPLAY_DATA(vcpu, RKVM_PIO_STREAM, target, size))
		return true;
	return false;
}

static void rkvm_replaying_on_set_regs(rkvm_vcpu_host *vcpu, void *src, unsigned size)
{
	struct rkvm_vcpu_replaying *vcpu_replaying = RKVM_VCPU_REPLAYING(vcpu);
	if (vcpu_replaying->replay_state == NO_REPLAY)
		return;
	RKVM_READ_REPLAY_DATA(vcpu, RKVM_REGS_STREAM, src, size);
}

static void rkvm_replaying_on_set_sregs(rkvm_vcpu_host *vcpu, void *src, unsigned size)
{
	struct rkvm_vcpu_replaying *vcpu_replaying = RKVM_VCPU_REPLAYING(vcpu);
	if (vcpu_replaying->replay_state == NO_REPLAY)
		return;
	RKVM_READ_REPLAY_DATA(vcpu, RKVM_SREGS_STREAM, src, size);
}

static bool rkvm_replaying_handle_halt(rkvm_vcpu_host *vcpu)
{
	struct rkvm_vcpu_replaying *vcpu_replaying = RKVM_VCPU_REPLAYING(vcpu);
	if (vcpu_replaying->replay_state == NO_REPLAY)
		return false;
	/* Halt is noop during replay. */
	//return true;
	return false;
}

static inline void rkvm_replaying_event_hit(rkvm_vcpu_host *vcpu)
{
	struct rkvm_vcpu_data *vcpu_data = RKVM_VCPU_DATA(vcpu);
	struct rkvm_vcpu_replaying *vcpu_replaying = RKVM_VCPU_REPLAYING(vcpu);
	vcpu_replaying->replay_state = REPLAY_HIT_EVENT;
	if (vcpu_replaying->replay_sync_reason == RKVM_RSN_VCPU_EXIT) {
		if (!is_synchronous_exit_reason(vcpu_replaying->pending_exitrsn))
			vcpu_data->must_exit = true;
	}
}

static void rkvm_replaying_update(rkvm_vcpu_host *vcpu, const char *debug_info)
{
	rkvm_host *host = RKVM_HOST(vcpu);
	struct rkvm_vcpu_data *vcpu_data = RKVM_VCPU_DATA(vcpu);
	struct rkvm_vcpu_replaying *vcpu_replaying = RKVM_VCPU_REPLAYING(vcpu);
	struct rkvm_data *rkvm_data = RKVM_DATA(host);
	struct rkvm_ops *ops = rkvm_data->ops;

	enum rkvm_replay_state initial_replay_state = vcpu_replaying->replay_state;
	u64 rbc = vcpu_data->accumulate_rbc;
	s64 rbc_to_target = vcpu_replaying->replay_target_point.rbc - rbc;

	u64 pc = vcpu_data->vmexit_guest_pc;
	s64 pc_to_target = vcpu_replaying->replay_target_point.pc - pc;
	u32 ecx = vcpu_data->vmexit_guest_ecx;
	s32 ecx_to_target = ecx - vcpu_replaying->replay_target_point.ecx;

	if (unlikely(!pc)) {
		pc = vcpu_data->vmexit_guest_pc = ops->read_guest_pc(vcpu);
		ecx = vcpu_data->vmexit_guest_ecx = ops->read_guest_ecx(vcpu);
		pc_to_target = vcpu_replaying->replay_target_point.pc - pc;
		ecx_to_target = ecx - vcpu_replaying->replay_target_point.ecx;
	}

	switch (initial_replay_state) {
	case NO_REPLAY:
		return;
	case REPLAY_HIT_EVENT:
		return;
	default:
		RKVM_DEBUG_PRINT(vcpu,
				 "%s rid=%lld rsn=%d exitrsn=%d rbc=%lld target=%lld pc=0x%llx target=0x%llx ecx=0x%x target=0x%x cnt=%lld\n",
				 debug_info,
				 vcpu_replaying->next_rid,
				 (int)vcpu_replaying->replay_sync_reason,
				 vcpu_replaying->pending_exitrsn,
				 (long long)rbc,
				 (long long)vcpu_replaying->replay_target_point.rbc,
				 (long long)pc,
				 (long long)vcpu_replaying->replay_target_point.pc,
				 ecx,
				 vcpu_replaying->replay_target_point.ecx,
				 (long long)vcpu_replaying->replay_read_counter);
		if (rbc_to_target > rbc_threshold) {
			vcpu_replaying->replay_state = REPLAY_WAIT_FOR_PMI;
		} else /* rbc_to_target <= rbc_threshold */ {
			if (pc_to_target == 0) {
				if (ecx_to_target == 0) {
					if (rbc_to_target == 0) {
						rkvm_replaying_event_hit(vcpu);
					} else if (rbc_to_target > 0) {
						/* There is up to rbc_threshold branches left. What to do? */
						vcpu_replaying->replay_state = REPLAY_SINGLE_STEP;
					} else /* (rbc_to_target < 0) */ {
						RKVM_DEBUG_PRINT(vcpu, "Fixed rbc by %lld\n", (long long)-rbc_to_target);
						vcpu_data->accumulate_rbc += rbc_to_target;
						vcpu_replaying->accumulate_rbc_delta += rbc_to_target;
						rkvm_replaying_event_hit(vcpu);
					}
				} else if (ecx_to_target > 0) {
					vcpu_replaying->replay_state = REPLAY_SINGLE_STEP;
				} else /* (ecx_to_target < 0) */ {
					if (rbc_to_target == 0) {
						//RKVM_DEBUG_PRINT(vcpu, "Fixed ecx by %d\n", -ecx_to_target);
						rkvm_replaying_event_hit(vcpu);
					} else if (rbc_to_target > 0) {
						/* There is up to rbc_threshold branches left. What to do? */
						vcpu_replaying->replay_state = REPLAY_SINGLE_STEP;
					} else /* (rbc_to_target < 0) */ {
						//RKVM_DEBUG_PRINT(vcpu, "Fixed ecx by %d\n", -ecx_to_target);
						RKVM_DEBUG_PRINT(vcpu, "Fixed rbc by %lld\n", (long long)-rbc_to_target);
						vcpu_data->accumulate_rbc += rbc_to_target;
						vcpu_replaying->accumulate_rbc_delta += rbc_to_target;
						rkvm_replaying_event_hit(vcpu);
					}
				}
			} else /* (pc_to_target != 0) */ {
				vcpu_replaying->replay_state = REPLAY_SINGLE_STEP;
			}
		}
	}
}

static bool read_next_replay_target_point(rkvm_vcpu_host *vcpu)
{
	struct rkvm_vcpu_replaying *vcpu_replaying = RKVM_VCPU_REPLAYING(vcpu);
	struct rkvm_delta delta;
	u8 rsn;
	u8 irq;
	u32 irqcnt;
	s64 pc_delta;
	s32 ecx_delta;
	vcpu_replaying->replay_state = REPLAY_NEW_TARGET;
	vcpu_replaying->replay_read_counter++;
	if (!read_delta(vcpu, &delta) ||
	    !RKVM_READ_REPLAY_VALUE(vcpu, u8, RKVM_RSN_STREAM, &rsn)) {
		RKVM_DEBUG_PRINT(vcpu, "Could not read bscript (cnt=%lld).\n",
				 (long long)vcpu_replaying->replay_read_counter);
		return false;
	}
	update_point(&vcpu_replaying->replay_target_point, &delta);
	vcpu_replaying->replay_sync_reason = rsn;
	switch (rsn) {
	case RKVM_RSN_REAL_MOD_IRQ:
	case RKVM_RSN_PROTECTED_MOD_IRQ:
		if (!RKVM_READ_REPLAY_VALUE(vcpu, u8, RKVM_IRQ_STREAM, &irq) ||
		    !RKVM_READ_REPLAY_VALUE(vcpu, u32, RKVM_IRQCNT_STREAM, &irqcnt) ||
		    !RKVM_READ_REPLAY_VALUE(vcpu, s64, RKVM_IRQPC_STREAM, &pc_delta) ||
		    !RKVM_READ_REPLAY_VALUE(vcpu, s32, RKVM_IRQECX_STREAM, &ecx_delta))
			return false;
		vcpu_replaying->pending_irq = irq;
		vcpu_replaying->pending_irqcnt = irqcnt;
		vcpu_replaying->pending_irqpc = vcpu_replaying->replay_target_point.pc + pc_delta;
		vcpu_replaying->pending_irqecx = vcpu_replaying->replay_target_point.ecx + ecx_delta;
		break;
	case RKVM_RSN_VCPU_EXIT:
		if (!RKVM_READ_REPLAY_VALUE(vcpu, u32, RKVM_EXITRSN_STREAM,
					    &vcpu_replaying->pending_exitrsn))
			return false;
		break;
	default:
		break;
	}
	return true;
}

int rkvm_init(rkvm_host *host, struct rkvm_ops *ops)
{
	int rc = 0;
	struct rkvm_data *rkvm_data;

	if (!ops)
		return -EINVAL; /* TODO: Should be: unsupported. */
	host->rkvm_data = (struct rkvm_data *)kzalloc(sizeof(*host->rkvm_data), GFP_KERNEL);
	rkvm_data = RKVM_DATA(host);
	if (!rkvm_data)
		return -ENOMEM;
	rkvm_data->ops = ops;
	rc = rkvm_preemption_init(host, ops);
	if (rc < 0)
		goto cleanup;
	spin_lock_init(&rkvm_data->lockstep_spinlock);

	rc = ops->rkvm_host_init(host);
	if (rc < 0)
		goto cleanup;
	return rc;

 cleanup:
	rkvm_destroy(host);
	return rc;
}
EXPORT_SYMBOL_GPL(rkvm_init);

void rkvm_destroy(rkvm_host *host)
{
	rkvm_preemption_destroy(host);
	if (host->rkvm_data != NULL) {
		kfree(host->rkvm_data);
		host->rkvm_data = NULL;
	}
}
EXPORT_SYMBOL_GPL(rkvm_destroy);

bool rkvm_must_exit(rkvm_vcpu_host *vcpu)
{
	struct rkvm_vcpu_data *vcpu_data = RKVM_VCPU_DATA(vcpu);
	return vcpu_data->must_exit;
}
EXPORT_SYMBOL_GPL(rkvm_must_exit);

void rkvm_userspace_entry(rkvm_host *host,
			  struct rkvm_userspace_data *out_userspace)
{
	struct rkvm_data *rkvm_data = RKVM_DATA(host);
	struct rkvm_userspace_data *userspace = &rkvm_data->userspace;

	bool preempt, record, replay, lock_step;
	EXTRACT_MODE(host);

	if (preempt)
		rkvm_preemption_userspace_entry(host, userspace, out_userspace);
	else
		out_userspace->quantum = 0;
}
EXPORT_SYMBOL_GPL(rkvm_userspace_entry);

void rkvm_userspace_exit(rkvm_host *host,
			 struct rkvm_userspace_data *userspace_in)
{
	struct rkvm_data *rkvm_data = RKVM_DATA(host);
	struct rkvm_userspace_data *userspace = &rkvm_data->userspace;

	bool preempt, record, replay, lock_step;
	EXTRACT_MODE(host);

	if (preempt)
		rkvm_preemption_userspace_exit(host, userspace, userspace_in);
}
EXPORT_SYMBOL_GPL(rkvm_userspace_exit);

int rkvm_set_timer_quantum(rkvm_host *host, u32 preemption_timer_quantum)
{
	int ret;

	bool preempt, record, replay, lock_step;
	EXTRACT_MODE(host);

	ret = rkvm_preemption_set_timer_quantum(host, preemption_timer_quantum);
	if (ret < 0)
		return ret;

	preempt = (rkvm_get_timer_quantum(host) > 0);
	UPDATE_MODE(host);

	return ret;
}
EXPORT_SYMBOL_GPL(rkvm_set_timer_quantum);

int rkvm_on_preemption_timer_exit(rkvm_vcpu_host *vcpu)
{
	int ret = 0;

	bool preempt, record, replay, lock_step;
	EXTRACT_VCPU_MODE(vcpu);

	if (record) {
		struct rkvm_vcpu_recording *vcpu_recording = RKVM_VCPU_RECORDING(vcpu);
		RKVM_DEBUG_PRINT(vcpu, "Will make one more step.\n");
		vcpu_recording->make_one_more_step = true;
		rkvm_preemption_run_free(vcpu, true);
		ret = 1;
	}
	return ret;
}
EXPORT_SYMBOL_GPL(rkvm_on_preemption_timer_exit);

static inline bool rkvm_execution_mode_valid(rkvm_host *host, u32 execution_mode)
{
	u32 permitted_execution_modes =
		RKVM_EXECUTION_MODE_LOCKSTEP |
		RKVM_EXECUTION_MODE_RECORD |
		RKVM_EXECUTION_MODE_REPLAY;
	return (execution_mode & ~permitted_execution_modes) == 0;
}

static inline bool flag_value_set(u32 flag, u32 value)
{
	return (flag & value) == value;
}

static void get_record_stream_name(char buffer[48],
				   enum rkvm_stream_index id)
{
	sprintf(buffer, "rkvm-record-%s", stream_suffixes[id]);
}

static void get_replay_stream_name(char buffer[48],
				   enum rkvm_stream_index id)
{
	sprintf(buffer, "rkvm-replay-%s", stream_suffixes[id]);
}

static void init_record_streams(rkvm_vcpu_host *vcpu)
{
	struct rkvm_vcpu_data *vcpu_data = RKVM_VCPU_DATA(vcpu);
	int i;
	u32 num_pages = 2;
	u32 page_size_order = 4;
	char buffer[48];
	for (i = 0; i < RKVM_NUM_STREAMS; ++i) {
		get_record_stream_name(buffer, i);
		create_bstream_file(buffer, O_RDONLY,
				    num_pages, page_size_order,
				    &vcpu_data->record_stream_data[i]);
	}
}

static void init_replay_streams(rkvm_vcpu_host *vcpu)
{
	struct rkvm_vcpu_data *vcpu_data = RKVM_VCPU_DATA(vcpu);
	int i;
	u32 num_pages = 2;
	u32 page_size_order = 4;
	char buffer[48];
	for (i = 0; i < RKVM_NUM_STREAMS; ++i) {
		get_replay_stream_name(buffer, i);
		create_bstream_file(buffer, O_WRONLY,
				    num_pages, page_size_order,
				    &vcpu_data->replay_stream_data[i]);
	}
}

static void close_record_streams(rkvm_vcpu_host *vcpu)
{
	struct rkvm_vcpu_data *vcpu_data = RKVM_VCPU_DATA(vcpu);
	int i;
	for (i = 0; i < RKVM_NUM_STREAMS; ++i)
		close_bstream_file(&vcpu_data->record_stream_data[i]);
}

static void close_debug_stream(rkvm_vcpu_host *vcpu)
{
	struct rkvm_vcpu_data *vcpu_data = RKVM_VCPU_DATA(vcpu);
	close_bstream_file(&vcpu_data->debug_stream_data);
}

static void close_replay_streams(rkvm_vcpu_host *vcpu)
{
	struct rkvm_vcpu_data *vcpu_data = RKVM_VCPU_DATA(vcpu);
	int i;
	for (i = 0; i < RKVM_NUM_STREAMS; ++i)
		close_bstream_file(&vcpu_data->replay_stream_data[i]);
}

int rkvm_set_execution_flag(rkvm_host *host, u32 flag)
{
	int vcpu_index;
	rkvm_vcpu_host *vcpu;
	bool do_lock_step = flag_value_set(flag, RKVM_EXECUTION_MODE_LOCKSTEP);
	bool do_preempt = flag_value_set(flag, RKVM_EXECUTION_MODE_PREEMPT);
	bool do_record = flag_value_set(flag, RKVM_EXECUTION_MODE_RECORD);
	bool do_replay = flag_value_set(flag, RKVM_EXECUTION_MODE_REPLAY);
	bool start_record, start_replay;

	bool preempt, record, replay, lock_step;
	EXTRACT_MODE(host);

	start_record = do_record && !record;
	start_replay = do_replay && !replay;

	kvm_for_each_vcpu(vcpu_index, vcpu, host) {
		if (start_record)
			init_record_streams(vcpu);
		if (start_replay)
			init_replay_streams(vcpu);
	}

	record = record || do_record;
	replay = replay || do_replay;
	preempt = preempt || do_preempt;
	lock_step = lock_step || do_lock_step || replay || record;

	UPDATE_MODE(host);

	return 0;
}
EXPORT_SYMBOL_GPL(rkvm_set_execution_flag);

int rkvm_clear_execution_flag(rkvm_host *host, u32 flag)
{
	int vcpu_index;
	rkvm_vcpu_host *vcpu;
	bool do_lock_step = flag_value_set(~flag, RKVM_EXECUTION_MODE_LOCKSTEP);
	bool do_preempt = flag_value_set(~flag, RKVM_EXECUTION_MODE_PREEMPT);
	bool do_record = flag_value_set(~flag, RKVM_EXECUTION_MODE_RECORD);
	bool do_replay = flag_value_set(~flag, RKVM_EXECUTION_MODE_REPLAY);
	bool stop_record, stop_replay;

	bool preempt, record, replay, lock_step;
	EXTRACT_MODE(host);

	stop_record = !do_record && record;
	stop_replay = !do_replay && replay;

	kvm_for_each_vcpu(vcpu_index, vcpu, host) {
		if (stop_record)
			close_record_streams(vcpu);
		if (stop_replay)
			close_replay_streams(vcpu);
	}

	record = record && do_record;
	replay = replay && do_replay;
	preempt = preempt && do_preempt;
	lock_step = lock_step && do_lock_step && !record && !replay;

	UPDATE_MODE(host);

	return 0;
}
EXPORT_SYMBOL_GPL(rkvm_clear_execution_flag);

int rkvm_get_execution_mode(rkvm_host *host, u32 *out_execution_mode)
{
	bool preempt, record, replay, lock_step;
	EXTRACT_MODE(host);

	*out_execution_mode =
		(lock_step ? RKVM_EXECUTION_MODE_LOCKSTEP : 0) |
		(record ? RKVM_EXECUTION_MODE_RECORD : 0) |
		(replay ? RKVM_EXECUTION_MODE_REPLAY : 0);
	return 0;
}
EXPORT_SYMBOL_GPL(rkvm_get_execution_mode);

int rkvm_vcpu_init(rkvm_vcpu_host *vcpu)
{
	int rc = 0;
	RKVM_STATIC_CHECK(kvm_run_size,
			  sizeof(struct kvm_run) <= PAGE_SIZE);

	bool preempt, record, replay, lock_step;
	EXTRACT_VCPU_MODE(vcpu);

	vcpu->rkvm_vcpu_data = (struct rkvm_vcpu_data *)kzalloc(sizeof(*vcpu->rkvm_vcpu_data), GFP_KERNEL);
	if (!vcpu->rkvm_vcpu_data)
		return -ENOMEM;

	rc = rkvm_vcpu_preemption_init(vcpu);
	if (rc < 0) {
		rkvm_vcpu_uninit(vcpu);
		return rc;
	}

	if (record)
		init_record_streams(vcpu);
	if (replay)
		init_replay_streams(vcpu);

	return 0;
}
EXPORT_SYMBOL_GPL(rkvm_vcpu_init);

void rkvm_vcpu_uninit(rkvm_vcpu_host *vcpu)
{
	rkvm_vcpu_preemption_destroy(vcpu);
	if (!vcpu->rkvm_vcpu_data)
		return;
	close_record_streams(vcpu);
	close_replay_streams(vcpu);
	close_debug_stream(vcpu);
	kfree(vcpu->rkvm_vcpu_data);
	vcpu->rkvm_vcpu_data = NULL;
}
EXPORT_SYMBOL_GPL(rkvm_vcpu_uninit);

bool rkvm_record_tsc(rkvm_vcpu_host *vcpu, u64 tsc_value)
{
	struct rkvm_vcpu_recording *vcpu_recording = RKVM_VCPU_RECORDING(vcpu);
	if (!RKVM_RECORD_VALUE(vcpu, u64, RKVM_TSC_STREAM, tsc_value - vcpu_recording->recorded_tsc))
		return false;
	vcpu_recording->recorded_tsc = tsc_value;
	return true;
}
EXPORT_SYMBOL_GPL(rkvm_record_tsc);

bool rkvm_replay_tsc(rkvm_vcpu_host *vcpu, u64 *out_tsc_value)
{
	struct rkvm_vcpu_replaying *vcpu_replaying = RKVM_VCPU_REPLAYING(vcpu);
	u64 tsc_value;
	if (!RKVM_READ_REPLAY_VALUE(vcpu, u64, RKVM_TSC_STREAM, &tsc_value))
		return false;
	*out_tsc_value = (vcpu_replaying->replayed_tsc += tsc_value);
	return true;
}
EXPORT_SYMBOL_GPL(rkvm_replay_tsc);

bool rkvm_retrieve_preemption_tsc(rkvm_vcpu_host *vcpu, u64 *out_tsc_value)
{
	bool preempt, record, replay, lock_step;
	EXTRACT_VCPU_MODE(vcpu);

	if (preempt) {
		RKVM_VCPU_DEBUG_DATA(vcpu)->last_read_tsc = 
			*out_tsc_value = rkvm_preemption_get_tsc(vcpu);
		return true;
	}

	return false;
}
EXPORT_SYMBOL_GPL(rkvm_retrieve_preemption_tsc);

void rkvm_record_irq(rkvm_vcpu_host *vcpu, u32 irq)
{
	/* TODO */
}
EXPORT_SYMBOL_GPL(rkvm_record_irq);

long rkvm_arch_vm_ioctl(struct kvm *kvm,
			unsigned int ioctl, unsigned long arg, bool *phandled)
{
	void __user *argp = (void __user *)arg;
	int r = -ENOTTY;
	switch (ioctl) {
	default:
		*phandled = false;
		return r;
	case RKVM_SET_TIMER_QUANTUM: {
		u32 preemption_timer_quantum;
		
		r = -EFAULT;
		if (copy_from_user(&preemption_timer_quantum, argp, sizeof preemption_timer_quantum))
			goto out;
		r = rkvm_set_timer_quantum(kvm, preemption_timer_quantum);
		break;
	}
	case RKVM_GET_TIMER_QUANTUM: {
		u32 preemption_timer_quantum = rkvm_get_timer_quantum(kvm);
		r = -EFAULT;
		if (copy_to_user(argp, &preemption_timer_quantum, sizeof preemption_timer_quantum))
			goto out;
		r = 0;
	}
	case RKVM_SET_EXECUTION_FLAG: {
		u32 execution_mode;

		r = -EFAULT;
		if (copy_from_user(&execution_mode, argp, sizeof execution_mode))
			goto out;
		r = rkvm_set_execution_flag(kvm, execution_mode);
		break;		
	}
	case RKVM_CLEAR_EXECUTION_FLAG: {
		u32 execution_mode;

		r = -EFAULT;
		if (copy_from_user(&execution_mode, argp, sizeof execution_mode))
			goto out;
		r = rkvm_clear_execution_flag(kvm, execution_mode);
		break;		
	}
	case RKVM_GET_EXECUTION_MODE: {
		u32 execution_mode;
		r = rkvm_get_execution_mode(kvm, &execution_mode);
		if (r != 0)
			goto out;
		r = -EFAULT;
		if (copy_to_user(argp, &execution_mode, sizeof execution_mode))
			goto out;
		r = 0;
		break;
	}
	case RKVM_USERSPACE_ENTRY: {
		struct rkvm_userspace_data rkvm_us_data;
		rkvm_userspace_entry(kvm, &rkvm_us_data);
		r = -EFAULT;
		if (copy_to_user(argp, &rkvm_us_data, sizeof rkvm_us_data))
			goto out;
		r = 0;
		break;
	}
	case RKVM_USERSPACE_EXIT: {
		struct rkvm_userspace_data rkvm_us_data;
		r = -EFAULT;
		if (copy_from_user(&rkvm_us_data, argp, sizeof rkvm_us_data))
			goto out;
		rkvm_userspace_exit(kvm, &rkvm_us_data);
		r = 0;
		break;
	}
	case RKVM_XFER: {
		struct rkvm_xfer rkvm_xfer;
		r = -EFAULT;
		if (copy_from_user(&rkvm_xfer, argp, sizeof rkvm_xfer))
			goto out;
		r = on_rkvm_xfer(kvm, &rkvm_xfer);
		break;
	}
	}
 out:
	*phandled = true;
	return r;
}
EXPORT_SYMBOL_GPL(rkvm_arch_vm_ioctl);

long rkvm_vcpu_ioctl(rkvm_vcpu_host *vcpu,
		     unsigned int ioctl, unsigned long arg, bool *phandled)
{
	void __user *argp = (void __user *)arg;
	struct rkvm_vcpu_data *vcpu_data = RKVM_VCPU_DATA(vcpu);
	struct rkvm_stream_fds stream_fds;
	u32 num_pages = 2;
	u32 page_size_order = 4;
	u32 num_pages_debug = 2;
	u32 page_size_order_debug = 4;
	int r, i;
	char buffer[48];

	switch (ioctl) {
	case RKVM_OPEN_DEBUG_STREAM:
		*phandled = true;
		return open_bstream_file("rkvm-debug",
					 O_RDONLY,
					 num_pages_debug,
					 page_size_order_debug,
					 &vcpu_data->debug_stream_data);
	case RKVM_OPEN_RECORD_STREAMS:
		*phandled = true;
		memset(&stream_fds, 0, sizeof(stream_fds));
		for (i = 0; i < RKVM_NUM_STREAMS; ++i) {
			get_record_stream_name(buffer, i);
			r = open_bstream_file(buffer,
					      O_RDONLY,
					      num_pages,
					      page_size_order,
					      &vcpu_data->record_stream_data[i]);
			if (r < 0)
				goto record_out;
			stream_fds.fd[stream_fds.count++] = r;
			memcpy(stream_fds.name[i], stream_suffixes[i], sizeof(stream_suffixes[i]));
		}
		r = -EFAULT;
		if (copy_to_user(argp, &stream_fds, sizeof stream_fds))
			goto record_out;
		return 0;
	record_out:
		close_record_streams(vcpu);
		return r;
	case RKVM_OPEN_REPLAY_STREAMS:
		*phandled = true;
		memset(&stream_fds, 0, sizeof(stream_fds));
		for (i = 0; i < RKVM_NUM_STREAMS; ++i) {
			get_replay_stream_name(buffer, i);
			r = open_bstream_file(buffer,
					      O_WRONLY,
					      num_pages,
					      page_size_order,
					      &vcpu_data->replay_stream_data[i]);
			if (r < 0)
				goto replay_out;
			stream_fds.fd[stream_fds.count++] = r;
			memcpy(stream_fds.name[i], stream_suffixes[i], sizeof(stream_suffixes[i]));
		}
		r = -EFAULT;
		if (copy_to_user(argp, &stream_fds, sizeof stream_fds))
			goto replay_out;
		return 0;
	replay_out:
		close_replay_streams(vcpu);
		return r;
	}
	*phandled = false;
	return -ENOTTY;
}
EXPORT_SYMBOL_GPL(rkvm_vcpu_ioctl);
