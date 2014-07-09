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

struct rkvm_local_ops {
	void (*enable_single_step)(bool on);
	bool (*mov_ss_blocks_interrupts)(void);
	void (*ensure_rdtsc_exiting)(void);
	void (*disable_pending_virtual_intr)(void);
	void (*disable_host_pmc_counters)(void);
	bool (*read_hw_intr_info)(int *int_vec);
	void (*set_hw_intr_info)(int int_vec);
	bool (*read_nmi_intr_info)(int *int_vec);
	void (*set_nmi_intr_info)(int int_vec);
	bool (*inject_immediate_exit)(void);
	void (*clear_immediate_exit)(void);
	bool (*clear_ucc_pmi)(void);
	bool (*clear_rbc_pmi)(void);
	bool (*has_ucc_pmi)(void);
	bool (*has_rbc_pmi)(void);
	void (*make_apic_deliver_nmi_on_pmi)(void);

	void (*set_rkvm_breakpoint)(rkvm_vcpu_host *vcpu, u64 pc, u64 *old);
	void (*clear_rkvm_breakpoint)(rkvm_vcpu_host *vcpu, u64 old);
};

struct rkvm_ops {
	int (*rkvm_host_init)(rkvm_host *host);
	void (*inject_external_realmod_int)(rkvm_vcpu_host *vcpu, int int_vec);
	u64 (*read_ucc)(rkvm_vcpu_host *vcpu);
	u64 (*read_rbc)(rkvm_vcpu_host *vcpu);
	void (*set_ucc)(rkvm_vcpu_host *vcpu, u64 value);
	void (*set_rbc)(rkvm_vcpu_host *vcpu, u64 value);
	u64 (*read_guest_pc)(rkvm_vcpu_host *vcpu);
	u32 (*read_guest_ecx)(rkvm_vcpu_host *vcpu);
	bool (*guest_halted)(rkvm_vcpu_host *vcpu);
	u32 (*exit_reason)(rkvm_vcpu_host *vcpu);
	bool (*has_internal_exit_reason)(rkvm_vcpu_host *vcpu);
	u32 (*userspace_exit_reason)(rkvm_vcpu_host *vcpu);
};

struct rkvm_data;
struct rkvm_preemption;
struct rkvm_vcpu_data;
struct rkvm_vcpu_preemption;

#define RKVM_HOST(vcpu) ((vcpu)->kvm)

extern void rkvm_debug_output(rkvm_vcpu_host *vcpu, const char *s);

extern bool rkvm_preempting(rkvm_host *host);
extern bool rkvm_recording(rkvm_host *host);
extern bool rkvm_replaying(rkvm_host *host);
extern bool rkvm_recording_or_replaying(rkvm_host *host);
extern bool rkvm_vcpu_recording_or_replaying(rkvm_vcpu_host *vcpu);

extern int rkvm_init(rkvm_host *host,
		     struct rkvm_ops *ops);
extern void rkvm_destroy(rkvm_host *host);

extern int rkvm_vcpu_init(rkvm_vcpu_host *vcpu);
extern void rkvm_vcpu_uninit(rkvm_vcpu_host *vcpu);

extern bool rkvm_on_vcpu_entry(rkvm_vcpu_host *vcpu);
extern void rkvm_on_vcpu_exit(rkvm_vcpu_host *vcpu, bool internal);
extern bool rkvm_can_reschedule(rkvm_vcpu_host *vcpu);

extern void rkvm_on_vmentry(rkvm_vcpu_host *vcpu, struct rkvm_local_ops *lops);
extern void rkvm_on_vmexit(rkvm_vcpu_host *vcpu,
			   bool reinject_external_interrupt, u32 exit_reason,
			   struct rkvm_local_ops *lops);
extern void rkvm_on_update_vmexit_state(rkvm_vcpu_host *vcpu);

extern bool rkvm_before_inject_rmod_irq(rkvm_vcpu_host *vcpu, int irq);
extern bool rkvm_after_inject_irq(rkvm_vcpu_host *vcpu, int irq);
extern bool rkvm_after_inject_nmi(rkvm_vcpu_host *vcpu, int irq);

extern bool rkvm_handle_nmi(rkvm_vcpu_host *vcpu, struct rkvm_local_ops *lops);

extern bool rkvm_on_pio_in_data_avail(rkvm_vcpu_host *vcpu,
				      void *target, const void *src, int size);

extern void rkvm_on_set_regs(rkvm_vcpu_host *vcpu, void *src, unsigned size);
extern void rkvm_on_set_sregs(rkvm_vcpu_host *vcpu, void *src, unsigned size);
extern void rkvm_on_set_xsave(rkvm_vcpu_host *vcpu, void *src, unsigned size);
extern void rkvm_on_set_xcrs(rkvm_vcpu_host *vcpu, void *src, unsigned size);
extern void rkvm_on_set_mce(rkvm_vcpu_host *vcpu, void *src, unsigned size);
extern void rkvm_on_set_events(rkvm_vcpu_host *vcpu, void *src, unsigned size);
extern void rkvm_on_set_dregs(rkvm_vcpu_host *vcpu, void *src, unsigned size);

extern bool rkvm_handle_halt(rkvm_vcpu_host *vcpu);

extern void rkvm_vcpu_halted(rkvm_vcpu_host *vcpu);
extern bool rkvm_must_exit(rkvm_vcpu_host *vcpu);

extern void rkvm_userspace_entry(rkvm_host *host,
				 struct rkvm_userspace_data *out_userspace);
extern void rkvm_userspace_exit(rkvm_host *host,
				struct rkvm_userspace_data *out_userspace);
extern bool rkvm_retrieve_tsc(rkvm_vcpu_host *vcpu, u64 *out_tsc_value);
extern bool rkvm_record_tsc(rkvm_vcpu_host *vcpu, u64 tsc_value);
extern bool rkvm_replay_tsc(rkvm_vcpu_host *vcpu, u64 *out_tsc_value);

extern int rkvm_set_quantum(rkvm_host *host, u64 quantum);
extern u64 rkvm_get_quantum(rkvm_host *host);

extern int rkvm_set_execution_flag(rkvm_host *host, u32 execution_mode);
extern int rkvm_clear_execution_flag(rkvm_host *host, u32 execution_mode);
extern int rkvm_get_execution_mode(rkvm_host *host, u32 *execution_mode);

extern void rkvm_record_irq(rkvm_vcpu_host *vcpu, u32 irq);

extern long rkvm_arch_vm_ioctl(rkvm_host *host,
			       unsigned int ioctl, unsigned long arg, bool *phandled);
extern long rkvm_vcpu_ioctl(rkvm_vcpu_host *vcpu,
			    unsigned int ioctl, unsigned long arg, bool *phandled);

extern void rkvm_mark_guest_reg_unavailable(rkvm_host *host, u32 reg);
extern bool rkvm_guest_reg_available(rkvm_host *host, u32 reg);

#endif
