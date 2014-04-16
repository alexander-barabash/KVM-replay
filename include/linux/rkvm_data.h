#ifndef __KVM_PREEMPTION_H
#define __KVM_PREEMPTION_H

/*
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 */

#include <asm/types.h>
#include <linux/spinlock.h>
#include <linux/rkvm.h>

struct kvm;
struct kvm_vcpu;
struct module;

/* guest preemption timer supported? */
extern bool kvm_has_preemption_timer;
/* guest preemption timer (logarithmic) rate */
extern int kvm_preemption_timer_rate;

typedef void (*KVMSetFlag)(struct kvm_vcpu *vcpu, bool on);
typedef u64 (*KVMRead64BitValue)(struct kvm_vcpu *vcpu);
typedef u32 (*KVMRead32BitValue)(struct kvm_vcpu *vcpu);
typedef void (*KVMWrite32BitValue)(struct kvm_vcpu *vcpu, u32 value);
typedef void (*KVMWrite64BitValue)(struct kvm_vcpu *vcpu, u64 value);
typedef bool (*KVMCheckCondition)(struct kvm_vcpu *vcpu);

struct rkvm_ops {
	KVMSetFlag setup_preemption_timer;
	KVMSetFlag save_preemption_timer_on_exit;
	KVMRead32BitValue read_hw_intr_info;
	KVMWrite32BitValue set_intr_info;
	KVMRead64BitValue read_retired_branch_counter;
	KVMWrite64BitValue set_retired_branch_counter;
	KVMRead32BitValue read_preemption_timer_value;
	KVMWrite32BitValue write_preemption_timer_value;
	KVMRead64BitValue read_guest_program_counter;
	KVMRead32BitValue read_guest_ecx;
	KVMCheckCondition guest_halted;
};

#define RKVM_DATA_SIZE 512
#define KVM_VCPU_PREEMPTION_DATA_SIZE 128

extern bool kvm_enable_preemption_timer(struct kvm_vcpu *vcpu);
extern bool rkvm_on(struct kvm *kvm);

extern int kvm_init_preemption_data(struct kvm *kvm,
				    struct rkvm_ops *ops);
extern void kvm_destroy_preemption_data(struct kvm *kvm);

extern void kvm_vcpu_uninit_preemption_data(struct kvm_vcpu *vcpu);

extern void rkvm_on_vmentry(struct kvm_vcpu *vcpu);
extern void rkvm_on_vmexit(struct kvm_vcpu *vcpu);
extern void rkvm_lock_vcpu(struct kvm_vcpu *vcpu);
extern void rkvm_unlock_vcpu(struct kvm_vcpu *vcpu);
extern void rkvm_vcpu_halted(struct kvm_vcpu *vcpu);

extern void rkvm_userspace_entry(struct kvm *kvm,
					   struct kvm_userspace_preemption_data *out_userspace);
extern void rkvm_userspace_exit(struct kvm *kvm,
					  struct kvm_userspace_preemption_data *out_userspace);
extern bool rkvm_retrieve_rdtsc_value(struct kvm_vcpu *vcpu,
				      u64 *out_tsc_value,
				      bool *out_do_record);

extern int kvm_set_preemption_timer_quantum(struct kvm *kvm, u32 preemption_timer_quantum);
extern int kvm_get_preemption_timer_quantum(struct kvm *kvm, u32 *preemption_timer_quantum);

extern int kvm_on_preemption_timer_exit(struct kvm_vcpu *vcpu);

extern int kvm_set_execution_flag(struct kvm *kvm, u32 execution_mode);
extern int kvm_clear_execution_flag(struct kvm *kvm, u32 execution_mode);
extern int kvm_get_execution_mode(struct kvm *kvm, u32 *execution_mode);

extern int kvm_open_record_stream(struct kvm_vcpu *vcpu);
extern int kvm_open_replay_stream(struct kvm_vcpu *vcpu);
extern void kvm_register_bstream_ops(struct module *module);

extern void kvm_record_tsc(struct kvm_vcpu *vcpu, u64 tsc_value);

#endif
