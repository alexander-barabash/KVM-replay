#ifndef __RKVM_INTERNAL_H
#define __RKVM_INTERNAL_H

#include <linux/rkvm_host.h>

enum rkvm_stream_index {
	RKVM_RID_STREAM,
	RKVM_RSN_STREAM,
	RKVM_RBC_STREAM,
	RKVM_PC_STREAM,
	RKVM_ECX_STREAM,
	RKVM_TSC_STREAM,
	RKVM_IRQ_STREAM,
	RKVM_IRQCNT_STREAM,
	RKVM_PIO_STREAM,
	RKVM_REGS_STREAM,
	RKVM_SREGS_STREAM,
	RKVM_XSAVE_STREAM,
	RKVM_XCRS_STREAM,
	RKVM_MCE_STREAM,
	RKVM_EVENTS_STREAM,
	RKVM_DREGS_STREAM,
	RKVM_EXITRSN_STREAM,
	RKVM_INSIZE_STREAM,
	RKVM_OUTSIZE_STREAM,
	RKVM_INPORT_STREAM,
	RKVM_OUTPORT_STREAM,
	RKVM_MMIOSIZ_STREAM,
	RKVM_MMIOADR_STREAM,
	RKVM_DMA_STREAM,
	RKVM_NUM_STREAMS
};

enum rkvm_sync_reason {
	RKVM_NO_RSN,
	RKVM_RSN_VCPU_EXIT,
	RKVM_RSN_PROTECTED_MOD_IRQ,
	RKVM_RSN_PROTECTED_MOD_NMI,
	RKVM_RSN_REAL_MOD_IRQ,
};

enum rkvm_replay_state {
	REPLAY_UNINITIALIZED,
	REPLAY_WAIT_FOR_PMI,
	REPLAY_HIT_EVENT,
	REPLAY_NEW_TARGET,
};

struct rkvm_delta {
	u64 rbc_delta;
	s64 pc_delta;
	s32 ecx_delta;
};

struct rkvm_point {
	u64 rbc;
	s64 pc;
	s32 ecx;
};

struct rkvm_vcpu_data {
	bool vcpu_entered;
	bool lockstep_owner;
	bool must_exit;
	bool process_exit;
	bool exit_immediately;
	bool make_one_more_step;
	bool launched;

	struct rkvm_vcpu_recording {
		atomic_long_t record_stream_data[RKVM_NUM_STREAMS];
		struct rkvm_point recorded_point;
		struct rkvm_point pending_point;
		enum rkvm_sync_reason pending_sync_reason;
		u64 record_write_counter;
		u8 pending_irq;
		u8 pending_irqcnt;
		u32 pending_exitrsn;
		u64 recorded_rid;
		u64 recorded_tsc;
		bool vcpu_halted;
		bool has_internal_exit_reason;
	} recording;

	struct rkvm_vcpu_replaying {
		atomic_long_t replay_stream_data[RKVM_NUM_STREAMS];
		bool replay_disabled;
		bool need_replay_cleanup;
		enum rkvm_replay_state replay_state;
		struct rkvm_point replay_target_point;
		u8 pending_irq;
		u8 pending_irqcnt;
		u32 pending_exitrsn;
		u64 replayed_rid;
		u64 next_rid;
		u64 replayed_tsc;
		enum rkvm_sync_reason replay_sync_reason;
		u64 replay_read_counter;
		bool vcpu_halted;
		bool has_internal_exit_reason;
		s64 accumulate_rbc_delta;
		bool has_breakpoint;
		u64 old_bp_value;
	} replaying;

	u64 vmentry_guest_pc;
	u64 vmexit_guest_pc;

	u32 vmentry_guest_ecx;
	u32 vmexit_guest_ecx;

	u64 accumulate_rbc;
	bool single_stepping;

	int in_counter;
	int out_counter;

	u64 entry_rbc;
	u64 exit_rbc;

	atomic_t irq_counts[KVM_NR_INTERRUPTS];

	atomic_long_t debug_stream_data;
};

struct rkvm_data {
	struct rkvm_ops *ops;
	u32 unavailable_regs[8];

	spinlock_t lockstep_spinlock;

	atomic_t mode;

	struct rkvm_userspace_data userspace;

	struct rkvm_recording {
		u64 recorded_rid;
	} recording;
	struct rkvm_replaying {
		u64 replayed_rid;
	} replaying;

	rkvm_vcpu_host *dma_vcpu;
	spinlock_t dma_vcpu_spinlock;
};

#endif /* __RKVM_INTERNAL_H */
