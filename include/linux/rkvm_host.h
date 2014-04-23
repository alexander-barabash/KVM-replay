#ifndef __RKVM_HOST_H
#define __RKVM_HOST_H

/*
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 */

#include <asm/types.h>
#include <linux/spinlock.h>
#include <linux/rkvm.h>

struct kvm;
typedef struct kvm rkvm_host;
struct kvm_vcpu;
typedef struct kvm_vcpu rkvm_vcpu_host;
struct module;

/* guest preemption timer supported? */
extern bool kvm_has_preemption_timer;
/* guest preemption timer (logarithmic) rate */
extern int kvm_preemption_timer_rate;

typedef void (*KVMSetFlag)(rkvm_vcpu_host *vcpu, bool on);
typedef u64 (*KVMRead64BitValue)(rkvm_vcpu_host *vcpu);
typedef u32 (*KVMRead32BitValue)(rkvm_vcpu_host *vcpu);
typedef void (*KVMWrite32BitValue)(rkvm_vcpu_host *vcpu, u32 value);
typedef void (*KVMWrite64BitValue)(rkvm_vcpu_host *vcpu, u64 value);
typedef bool (*KVMCheckCondition)(rkvm_vcpu_host *vcpu);

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
#define RKVM_VCPU_DATA_SIZE 128

extern bool kvm_enable_preemption_timer(rkvm_vcpu_host *vcpu);
extern bool rkvm_on(rkvm_host *host);

extern int rkvm_init(rkvm_host *host,
		     struct rkvm_ops *ops);
extern void rkvm_destroy(rkvm_host *host);

extern void rkvm_uninit(rkvm_vcpu_host *vcpu);

extern void rkvm_on_vmentry(rkvm_vcpu_host *vcpu);
extern void rkvm_on_vmexit(rkvm_vcpu_host *vcpu);
extern void rkvm_lock_vcpu(rkvm_vcpu_host *vcpu);
extern void rkvm_unlock_vcpu(rkvm_vcpu_host *vcpu);
extern void rkvm_vcpu_halted(rkvm_vcpu_host *vcpu);

extern void rkvm_userspace_entry(rkvm_host *host,
				 struct rkvm_userspace_data *out_userspace);
extern void rkvm_userspace_exit(rkvm_host *host,
				struct rkvm_userspace_data *out_userspace);
extern bool rkvm_retrieve_rdtsc_value(rkvm_vcpu_host *vcpu, u64 *out_tsc_value);

extern int rkvm_set_timer_quantum(rkvm_host *host, u32 preemption_timer_quantum);
extern int rkvm_get_timer_quantum(rkvm_host *host, u32 *preemption_timer_quantum);

extern int rkvm_on_preemption_timer_exit(rkvm_vcpu_host *vcpu);

extern int rkvm_set_execution_flag(rkvm_host *host, u32 execution_mode);
extern int rkvm_clear_execution_flag(rkvm_host *host, u32 execution_mode);
extern int rkvm_get_execution_mode(rkvm_host *host, u32 *execution_mode);

extern int rkvm_open_record_stream(rkvm_vcpu_host *vcpu);
extern int rkvm_open_replay_stream(rkvm_vcpu_host *vcpu);
extern void rkvm_register_bstream_ops(struct module *module);

extern void rkvm_record_irq(rkvm_vcpu_host *vcpu, u32 irq);

extern long rkvm_arch_vm_ioctl(rkvm_host *host,
			       unsigned int ioctl, unsigned long arg, bool *phandled);

#endif
