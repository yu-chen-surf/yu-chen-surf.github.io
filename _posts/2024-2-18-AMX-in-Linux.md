# AMX in a nutshell
AMX is part of SIMD, which is used to improve the throughput by issuing one command and launches multiple data transfer in parallel. Like other float point data type, only the user space is supposed to use these data type, not the kernel. During context switch, the kernel is responsible to save/restore the AMX registers,

# How Linux supports AMX
As stated above, the kernel saves and restores the AMX registers across context switch. This includes the task switch, signal handling, etc. However, the AMX registers to be saved/restored are quite large in size, each Tile register is up 16 * 64 = 1024 bytes, and there are 8 Tiles. That is to say, each task mush allocate 8K for AMX save/restore, no matter whether the task runs AMX or not, this is a waste of space.
To solve this space problem, one important design is introduced, that is on-demond allocation. This idea is used in COW(Copy-On-Write) in page fault. For AMX, a similar exception is required if the task runs the AMX for the first time. This is a hardware named XFD(eXtended Feature Disabling). The kernel arms XFD to provide an #NM exception upon a tasks' first access to TILE state. The kernel exception handler allocates and installs the appropriate XSAVE context switch buffer, and the task behaves as if the kernel had done that for all tasks. Chang S. Bae from Intel is the author to implement this.

There are mainly three aspects to support AMX in Linux:
* prctl interface for the userspace to enable the AMX support for the specific task
* XFD MSR setting save/restore across context switch 
* On-demand fpstate allocation

Let's talk about them one-by-one.

Commit db8268df0983 ("x86/arch_prctl: Add controls for dynamic XSTATE components") Introduced the user interface to indicate whether the current task wants the one-demand AMX allocation. 

Commit dae1bd583896 ("x86/msr-index: Add MSRs for XFD") introduces two MSR:
* IA32_XFD to enable/disable a feature controlled by XFD
* IA32_XFD_ERR to expose to the #NM trap handler which feature was tried to be used for the first time.

Both use the same xstate-component bitmap format, used by XCR0. 
Commit 672365477ae8 ("x86/fpu: Update XFD state where required")  mainly initialize the XFD perf CPU:
```
if (cpu_feature_enabled(X86_FEATURE_XFD))
	wrmsrl(MSR_IA32_XFD, init_fpstate.xfd);
```
Besides, since XFD attribute is per task wide, we need to save/restore XFD value across task context switch. In theory, this save/restore of XFD should be in \_\_switch_to -> switch_fpu_finish, like the original patch did [here](https://lore.kernel.org/lkml/20210825155413.19673-14-chang.seok.bae@intel.com/):
```
-static inline void switch_fpu_finish(struct fpu *new_fpu)
+static inline void switch_fpu_finish(struct fpu *old_fpu, struct fpu *new_fpu)
 {
-	if (cpu_feature_enabled(X86_FEATURE_FPU))
+	if (cpu_feature_enabled(X86_FEATURE_FPU)) {
 		set_thread_flag(TIF_NEED_FPU_LOAD);
+		xfd_switch(old_fpu, new_fpu);
+	}
 }
 
 +/**
+ * xfd_switch - Switches the MSR IA32_XFD context if needed.
+ * @prev:	The previous task's struct fpu pointer
+ * @next:	The next task's struct fpu pointer
+ */
+static inline void xfd_switch(struct fpu *prev, struct fpu *next)
+{
+	u64 prev_xfd_mask, next_xfd_mask;
+
+	if (!cpu_feature_enabled(X86_FEATURE_XFD) || !xfeatures_mask_user_dynamic)
+		return;
+
+	prev_xfd_mask = prev->state_mask & xfeatures_mask_user_dynamic;
+	next_xfd_mask = next->state_mask & xfeatures_mask_user_dynamic;
+
+	if (unlikely(prev_xfd_mask != next_xfd_mask))
+		wrmsrl_safe(MSR_IA32_XFD, xfeatures_mask_user_dynamic ^ next_xfd_mask);
+}
```
But Thomas said this is not needed, just restore the XFD when returning to user space is more efficient, that would save 2 MSR writes, and MSR write is costly:
```
How does that matter? The point is that if the FPU registers are
unmodified then a task can return to user space without doing anything
even if it went through five context switches. So how is XFD any
different?

So what's the win?

No wrmsrl() on context switch, which means for the user -> kthread ->
user context switch scenario for which the register preserving is
optimized you spare two wrmsrl() invocations, run less code with less
conditionals.

What's the price?

A few trivial XFD sanity checks for debug enabled kernels to ensure that
XFD is correct on XSAVE[S] and XRSTOR[S], which have no runtime overhead
on production systems.

Even if we decide that these checks should be permanent then they happen
in code pathes which are doing a slow X* operation anyway.
```
Finally Commit 672365477ae8 loads the XFD when retuning to user space:
```
fpregs_restore_userregs() ->
restore_fpregs_from_fpstate(fpu->fpstate, XFEATURE_MASK_FPSTATE) -> xfd_update_state(fpstate);
```

After XFD has been taken care of, #NM exception handler need to be created. Commit 783e87b40495 ("x86/fpu/xstate: Add XFD #NM handler").  In the #NM handler exc_device_not_available(),  added a hook handle_xfd_event():
```
rdmsrl(MSR_IA32_XFD_ERR, xfd_err);
//confirm it is a XFD error
if (!xfd_err)
	return false;
	
//clear the reason
wrmsrl(MSR_IA32_XFD_ERR, 0);

//get the current old fpu
fpu = &current->group_leader->thread.fpu;
//get the size of the new fpu(which is set by perm)
ksize = fpu->perm.__state_size;
usize = fpu->perm.__user_state_size;

fpstate_realloc(xfd_event, ksize, usize)
```
Commit 500afbf645a0 ("x86/fpu/xstate: Add fpstate_realloc()/free()") is the patch to vzalloc the new fpstate based on the ksize, in fpstate_realloc(). Then
```
fpsize = ksize + ALIGN(offsetof(struct fpstate, regs), 64);
struct fpstate *newfps = vzalloc(fpsize);
current->thread.fpu->fpstate = newfps;
```
Later commit db3e7321b4b8 ("x86/fpu: Add XFD handling for dynamic states") set the initial value of init_fpstate.xfd:
```
_init fpu__init_system_xstate(unsigned int legacy_size)
{
	init_fpstate.xfd = fpu_user_cfg.max_features & XFEATURE_MASK_USER_DYNAMIC;
}
```
Finally enabled the AMX feature bits for XFD in commit 2308ee57d93d ("x86/fpu/amx: Enable the AMX feature in 64-bit mode")
# How KVM supports AMX
Liu Jing from Intel proposed the original idea to support AMX in KVM in this thread, titled with [Thoughts of AMX KVM support based on latest kernel](https://www.spinics.net/lists/kvm/msg259015.html).  To be honest, I could not catch up with what this article is talking about, so let's look at the first patch instead. The patch set is posted by Zhong Yong, [AMX Support in KVM](https://lore.kernel.org/lkml/20211208000359.2853257-1-yang.zhong@intel.com/) and involved to version 5 [[PATCH v5 00/21] AMX Support in KVM](https://lore.kernel.org/lkml/20220105123532.12586-1-yang.zhong@intel.com/)
The same as native AMX support, the task in vm guest has to request permission to run AMX. It is still prctl, and the guest relies on the qemu to invoke prctl(ARCH_REQ_XCOMP_GUEST_PERM) for the qemu process. This has to be invoked before the vm guest runs. The idea is to set guest_permit of the vm:
```
perm = guest ? &fpu->guest_perm : &fpu->perm;
WRITE_ONCE(perm->__state_perm, requested);
```
The calltrace is:
```
[  153.195759] CPU: 1 PID: 4367 Comm: genvm Not tainted #61
[  153.195787] Hardware name: Quanta Cloud Technology Inc. QuantaGrid D54Q-2U/S6Q-MB-MPS, BIOS 3B03.TEL0P1 06/09/2023
[  153.195812] Call Trace:
[  153.195826]  <TASK>
[  153.195838]  dump_stack_lvl+0x36/0x50
[  153.195861]  fpu_xstate_prctl+0x5d/0x250
[  153.195884]  do_syscall_64+0x4b/0xf0
[  153.195905]  entry_SYSCALL_64_after_hwframe+0x6e/0x76
```
We can see that, the genvm is the qemu process, and the whole process is granted the ARCH_REQ_XCOMP_GUEST_PERM, so any vCPU created by qemu will inherit the permission.
After the permission has been implemented, before vCPU runs, qemu needs to expand the fpstate buffer for AMX. Unlike the native fpstate buffer allocation, which is allocated on-demand in #NM exception handler, the qemu allocate the fpstate buffer statically. The qemu leverage KVM ioctl kvm_vcpu_ioctl_set_cpuid2() to do it:
```
[  153.197451] CPU: 5 PID: 4371 Comm: CPU 0/KVM Not tainted #61
[  153.197491] Hardware name: Quanta Cloud Technology Inc. QuantaGrid D54Q-2U/S6Q-MB-MPS, BIOS 3B03.TEL0P1 06/09/2023
[  153.197527] Call Trace:
[  153.197546]  <TASK>
[  153.197563]  dump_stack_lvl+0x36/0x50
[  153.197591]  fpstate_realloc+0x148/0x300
[  153.197619]  ? vmemdup_user+0x25/0x90
[  153.197650]  __xfd_enable_feature+0x99/0x110
[  153.197678]  kvm_set_cpuid+0x26e/0x2a0 [kvm]
[  153.197997]  kvm_vcpu_ioctl_set_cpuid2+0x4f/0xa0 [kvm]
[  153.198232]  kvm_arch_vcpu_ioctl+0x909/0x1130 [kvm]
[  153.198500]  ? sgx_set_attribute+0x46/0x60
[  153.198527]  ? kvm_vm_ioctl_enable_cap+0x544/0x620 [kvm]
[  153.198782]  ? kvm_vm_ioctl+0x7ba/0x950 [kvm]
[  153.198996]  kvm_vcpu_ioctl+0x3a0/0x690 [kvm]
[  153.199199]  ? __mod_memcg_state+0x72/0xe0
[  153.199227]  ? kvm_arch_dev_ioctl+0x274/0x3b0 [kvm]
[  153.199480]  __x64_sys_ioctl+0x94/0xd0
[  153.199506]  do_syscall_64+0x4b/0xf0
[  153.199536]  entry_SYSCALL_64_after_hwframe+0x6e/0x76

```
The code looks like below:
```
static int kvm_check_cpuid(struct kvm_vcpu *vcpu,
															struct kvm_cpuid_entry2 *entries,
															int nent)
{
	struct kvm_cpuid_entry2 *best;
	best = cpuid_entry2_find(entries, nent, 0xd, 0);
	if (best) {
		xfeatures = best->eax | ((u64)best->edx << 32);
		xfeatures &= XFEATURE_MASK_USER_DYNAMIC;
		if (xfeatures) {
			//free 
			fpu_enable_guest_xfd_features(&vcpu->arch.guest_fpu,
																			xfeatures);
		}
	}
}

int fpu_enable_guest_xfd_features(struct fpu_guest *guest_fpu, u64 xfeatures)
{
	xfeatures &= ~guest_fpu->xfeatures;
	//all features have been enabled, nothing to do
	if (!xfeatures)
		return 0;

	//enable the features(usually acompany with fpstate re-allocation)
	return __xfd_enable_feature(xfeatures, guest_fpu);
}

//check the permission of current task, and re-allocate fpstate buffer
int __xfd_enable_feature(u64 xfd_err, struct fpu_guest *guest_fpu)
{
	//check the permisson
	if ((xstate_get_group_perm(!!guest_fpu) & xfd_event) != xfd_event) {
		return -EPERM;
	}
	//re-allocate the buffer of either guest_fpu's(not NULL)
	//or the current task's fpstate.
	//For the kvm_vcpu_ioctl_set_cpuid2 call path,
	//it is re-allocate the buffer of &vcpu->arch.guest_fpu
	fpstate_realloc(xfd_event, ksize, usize, guest_fpu)
}
```
Then the fpstate_realloc is defined as:
```
static int fpstate_realloc(u64 xfeatures, unsigned int ksize,
														unsigned int usize, struct fpu_guest *guest_fpu)
{
	//get current fpu in used
	struct fpu *fpu = &current->thread.fpu;

	fpsize = ksize + ALIGN(offsetof(struct fpstate, regs), 64);
	newfps = vzalloc(fpsize);

	curfps = guest_fpu ? guest_fpu->fpstate : fpu->fpstate;
	//if guest_fpu == NULL, in_use is true
	in_use = fpu->fpstate == curfps;

	if (guest_fpu) {
		guest_fpu->fpstate = newfps;
		if (in_use)
			fpu->fpstate = newfps;
	} else {
		fpu->fpstate = newfps;
	}
	
	if (in_use)
		xfd_update_state(fpu->fpstate);
		
	//free the old fpstate
	if (curfps && curfps->is_valloc)
		vfree(curfps);
}
```
So the code is actually:
```
curfps = guest_fpu->fpstate;
&vcpu->arch.guest_fpu->fpstate = vzalloc();
vfree(curfps)
```
Later when vCPU switches in, the guest_fpu->fpstate will be loaded. See below.

After the buffer allocation, the KVM checks if it can let the vm guest read directly from MSR_IA32_XFD_ERR:
```
[  153.199992] CPU: 5 PID: 4371 Comm: CPU 0/KVM Not tainted #61
[  153.200029] Hardware name: Quanta Cloud Technology Inc. QuantaGrid D54Q-2U/S6Q-MB-MPS, BIOS 3B03.TEL0P1 06/09/2023
[  153.200064] Call Trace:
[  153.200080]  <TASK>
[  153.200096]  dump_stack_lvl+0x36/0x50
[  153.200120]  vmx_vcpu_after_set_cpuid+0x33f/0x4e0 [kvm_intel]
[  153.200210]  kvm_vcpu_after_set_cpuid+0x34c/0x530 [kvm]
[  153.200481]  kvm_set_cpuid+0x1eb/0x2a0 [kvm]
[  153.200736]  kvm_vcpu_ioctl_set_cpuid2+0x4f/0xa0 [kvm]
[  153.200993]  kvm_arch_vcpu_ioctl+0x909/0x1130 [kvm]
[  153.201251]  ? sgx_set_attribute+0x46/0x60
[  153.201277]  ? kvm_vm_ioctl_enable_cap+0x544/0x620 [kvm]
[  153.201527]  ? kvm_vm_ioctl+0x7ba/0x950 [kvm]
[  153.203571]  kvm_vcpu_ioctl+0x3a0/0x690 [kvm]
[  153.205616]  ? __mod_memcg_state+0x72/0xe0
[  153.207399]  ? kvm_arch_dev_ioctl+0x274/0x3b0 [kvm]
[  153.209403]  __x64_sys_ioctl+0x94/0xd0
[  153.210746]  do_syscall_64+0x4b/0xf0
[  153.211961]  entry_SYSCALL_64_after_hwframe+0x6e/0x76

```

```
void vmx_vcpu_after_set_cpuid(struct kvm_vcpu *vcpu)
{
	if (kvm_cpu_cap_has(X86_FEATURE_XFD))
		vmx_set_intercept_for_msr(vcpu, MSR_IA32_XFD_ERR, MSR_TYPE_R,
															!guest_cpuid_has(vcpu, X86_FEATURE_XFD));
}
```
What vmx_set_intercept_for_msr() does is to allow/disallow the guest from reading MSR_IA32_XFD_ERR without vm_exit:
```
static inline void vmx_set_intercept_for_msr(struct kvm_vcpu *vcpu, u32 msr,
																								int type, bool value)
{
	if (value)
		vmx_enable_intercept_for_msr(vcpu, msr, type);
	else
		vmx_disable_intercept_for_msr(vcpu, msr, type);
}
```
Since !guest_cpuid_has(vcpu, X86_FEATURE_XFD) is false, it invokes vmx_disable_intercept_for_msr(vcpu, msr, type);
```
//actually clear the bit in VMCS
void vmx_disable_intercept_for_msr(struct kvm_vcpu *vcpu, u32 msr, int type)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	unsigned long *msr_bitmap = vmx->vmcs01.msr_bitmap;
	
	if (type & MSR_TYPE_R)
		vmx_clear_msr_bitmap_read(msr_bitmap, msr);
}
```
Any read of X86_FEATURE_XFD from vCPU will be passed through without vm_exit.
After that, for some reason the kvm clears the value of MSR_IA32_XFD and MSR_IA32_XFD_ERR:
```
[  156.017353] kvm_set_msr_common set MSR_IA32_XFD to 0x0 on vcpu1 cpu1
[  156.018867] CPU: 1 PID: 4371 Comm: CPU 0/KVM Not tainted #61
[  156.020521] Hardware name: Quanta Cloud Technology Inc. QuantaGrid D54Q-2U/S6Q-MB-MPS, BIOS 3B03.TEL0P1 06/09/2023
[  156.022294] Call Trace:
[  156.024059]  <TASK>
[  156.025811]  dump_stack_lvl+0x36/0x50
[  156.027578]  kvm_set_msr_common+0x7bd/0x11d0 [kvm]
[  156.029559]  vmx_set_msr+0x207/0xff0 [kvm_intel]
[  156.031263]  __kvm_set_msr+0x7f/0x1d0 [kvm]
[  156.032996]  do_set_msr+0x67/0x100 [kvm]
[  156.034367]  ? memdup_user+0x49/0x80
[  156.035557]  kvm_arch_vcpu_ioctl+0xa6d/0x1130 [kvm]
[  156.036919]  ? __kmem_cache_free+0x225/0x2d0
[  156.038122]  kvm_vcpu_ioctl+0x3a0/0x690 [kvm]
[  156.039439]  __x64_sys_ioctl+0x94/0xd0
[  156.040621]  do_syscall_64+0x4b/0xf0


[  156.050641] kvm_set_msr_common set MSR_XFD_ERR to 0x0 on vcpu1 cpu1
[  156.051324] CPU: 1 PID: 4371 Comm: CPU 0/KVM Not tainted #61
[  156.051953] Hardware name: Quanta Cloud Technology Inc. QuantaGrid D54Q-2U/S6Q-MB-MPS, BIOS 3B03.TEL0P1 06/09/2023
[  156.052769] Call Trace:
[  156.053660]  <TASK>
[  156.054448]  dump_stack_lvl+0x36/0x50
[  156.055170]  kvm_set_msr_common+0xc64/0x11d0 [kvm]
[  156.055989]  vmx_set_msr+0x55b/0xff0 [kvm_intel]
[  156.056734]  __kvm_set_msr+0x7f/0x1d0 [kvm]
[  156.057553]  do_set_msr+0x67/0x100 [kvm]
[  156.058366]  ? memdup_user+0x49/0x80
[  156.059088]  kvm_arch_vcpu_ioctl+0xa6d/0x1130 [kvm]
[  156.059878]  ? __kmem_cache_free+0x225/0x2d0
[  156.060554]  kvm_vcpu_ioctl+0x3a0/0x690 [kvm]
[  156.061305]  __x64_sys_ioctl+0x94/0xd0
[  156.061972]  do_syscall_64+0x4b/0xf0

```

Then launches the vCPU. During vm guest boot up, the vm guest would initialize the MSR_IA32_XFD register to the default 0x40000(just like native), based on the cpuid value. The 0x40000 indicates that it supports AMX. The calltrace on the vm guest looks like below:
```
[    0.637404] write xfd to cpu0 with 0x40000
[    0.637404] CPU: 0 PID: 0 Comm: swapper/0 Not tainted #61
[    0.637404] Hardware name: QEMU Standard PC (Q35 + ICH9, 2009), BIOS unknown 2/2/2022
[    0.637404] Call Trace:
[    0.637404]  <TASK>
[    0.637404]  dump_stack_lvl+0x36/0x50
[    0.637404]  fpu__init_cpu_xstate.part.0+0x3f/0xd0
[    0.637404]  arch_cpu_finalize_init+0x2f/0x60
[    0.637404]  start_kernel+0x30a/0x5d0
[    0.637404]  x86_64_start_reservations+0x21/0x40
[    0.637404]  x86_64_start_kernel+0x91/0xa0

```
The write to MSR_IA32_XFD triggeres the vm_exit, which will be intercept(emulated) by the KVM host:
```
[  158.501017] kvm_set_msr_common set MSR_IA32_XFD to 0x40000 on vcpu1 cpu1
[  158.501887] CPU: 1 PID: 4371 Comm: CPU 0/KVM Not tainted #61
[  158.502636] Hardware name: Quanta Cloud Technology Inc. QuantaGrid D54Q-2U/S6Q-MB-MPS, BIOS 3B03.TEL0P1 06/09/2023
[  158.503388] Call Trace:
[  158.504135]  <TASK>
[  158.504867]  dump_stack_lvl+0x36/0x50
[  158.505620]  kvm_set_msr_common+0x7bd/0x11d0 [kvm]
[  158.506503]  vmx_set_msr+0x207/0xff0 [kvm_intel]
[  158.507264]  __kvm_set_msr+0x7f/0x1d0 [kvm]
[  158.508132]  kvm_emulate_wrmsr+0x51/0x1c0 [kvm]
[  158.508962]  vmx_handle_exit+0x13/0x90 [kvm_intel]
[  158.509725]  vcpu_enter_guest.constprop.0+0x32c/0xf20 [kvm]
[  158.510576]  ? vmx_get_cs_db_l_bits+0x53/0x80 [kvm_intel]
[  158.511336]  vcpu_run+0x3a/0x230 [kvm]
[  158.512164]  kvm_arch_vcpu_ioctl_run+0xe8/0x3e0 [kvm]
[  158.512975]  kvm_vcpu_ioctl+0x225/0x690 [kvm]
[  158.513729]  ? __hrtimer_run_queues+0x15c/0x2d0
[  158.514408]  ? ktime_get+0x39/0xa0
[  158.515079]  ? clockevents_program_event+0x96/0x100
[  158.515750]  ? __fget_light+0x85/0x100
[  158.516423]  __x64_sys_ioctl+0x94/0xd0
[  158.517097]  do_syscall_64+0x4b/0xf0
[  158.517765]  entry_SYSCALL_64_after_hwframe+0x6e/0x76

```
After the intercept of MSR_IA32_XFD, the KVM disable the read/write intercept of MSR_IA32_XFD immediately:
```
int vmx_set_msr(struct kvm_vcpu *vcpu, struct msr_data *msr_info)
{
	case MSR_IA32_XFD:
		ret = kvm_set_msr_common(vcpu, msr_info);
		if (!ret && data) {
			//clear vmcs bits in MSR map for MSR_IA32_XFD
			vmx_disable_intercept_for_msr(vcpu, MSR_IA32_XFD, MSR_TYPE_RW);
			//flag to indicate write to XFD will not cause vm_exit
			vcpu->arch.xfd_no_write_intercept = true;
			//after disable intercept, need to tell the exception bitmap to 
			//trigger vm_exit when #NM happens on the guest
			vmx_update_exception_bitmap(vcpu);
		}
}

```
Why vmx_update_exception_bitmap(vcpu) above is needed to let the KVM trap the #NM of the guest? This is because the KVM side wants to know the xfd_err value. The code of vmx_update_exception_bitmap() looks like below:
```
void vmx_update_exception_bitmap(struct kvm_vcpu *vcpu)
{
	# if write to MSR XDF is passthrough, then the #NM of running AMX
	# will cause vm_exit and traped by KVM
	if (vcpu->arch.xfd_no_write_intercept)
		eb |= (1u << NM_VECTOR);

	vmcs_write32(EXCEPTION_BITMAP, eb);
}
```

After the vCPU has began to run, it is possible that the vCPU switches out and in. This involves the context switch. If the vCPU switches to a normal task, the XFD value needs to be save/restored. When the vCPU is switched in, the XFD needs to be loaded:
```
kvm_arch_vcpu_ioctl_run()
{
	kvm_load_guest_fpu(vcpu) ->
		fpu_swap_kvm_fpstate(&vcpu->arch.guest_fpu, true)
	vcpu_run(vcpu);
	...
}

```
The core logic is in fpu_swap_kvm_fpstate:
```
int fpu_swap_kvm_fpstate(struct fpu_guest *guest_fpu, bool enter_guest)
{
	struct fpu *fpu = &current->thread.fpu;

	if (enter_guest) {
		fpu->fpstate = guest_fps;
	} else {
		fpu->fpstate = fpu->__task_fpstate;
	}
	//either guest_fps->fpstate or host's __task_fpstate->fpstate
	//if entering guest, it is the former
	cur_fps = fpu->fpstate;
	
	restore_fpregs_from_fpstate(cur_fps, XFEATURE_MASK_FPSTATE);
}
```
restore_fpregs_from_fpstate() uses os_xrstor() to restore the fpstate stored in fpstate, and update the XFD MSR according to the value in cur_fps:
```
void restore_fpregs_from_fpstate(struct fpstate *fpstate, u64 mask)
{
	if (use_xsave()) {
		xfd_update_state(fpstate);
		os_xrstor(fpstate, mask);
	}
}

static inline void xfd_update_state(struct fpstate *fpstate)
{
        if (fpu_state_size_dynamic()) {
                u64 xfd = fpstate->xfd;

                if (__this_cpu_read(xfd_state) != xfd) {
                        wrmsrl(MSR_IA32_XFD, xfd);
                        __this_cpu_write(xfd_state, xfd);
                }
        }       
}


```
Similarly, consider the vCPU switches out, kvm_arch_vcpu_ioctl_run() becomes:
```
kvm_arch_vcpu_ioctl_run()
{
	kvm_load_guest_fpu(vcpu) ->
		fpu_swap_kvm_fpstate(&vcpu->arch.guest_fpu, true)
	vcpu_run(vcpu);
	kvm_put_guest_fpu(vcpu) ->
		fpu_swap_kvm_fpstate(&vcpu->arch.guest_fpu, false);
}
```
fpu_swap_kvm_fpstate(&vcpu->arch.guest_fpu, false) loads the fpstate(including the XFD) of the host.

Suppose there is a task on the vm guest, without prctl(ARCH_REQ_XCOMP_PERM), trying to run AMX instruction. It will get the following error:
```
/amx-test -d 10 -t 1 -i 1
Illegal instruction (core dumped)
```
As the running of AMX will trigger #NM, because the XFD value is 0x40000 by default. Then it will cause vm_exit() because KVM has set the NM bit in EXCEPTION_BITMAP. In vm_exit(), the KVM first checks the XDF_ERR:
```
vmx_handle_nm_fault_irqoff read XFD_ERR as 0x40000
[37606.449168] CPU: 5 PID: 4371 Comm: CPU 0/KVM Not tainted #61
[37606.450072] Hardware name: Quanta Cloud Technology Inc. QuantaGrid D54Q-2U/S6Q-MB-MPS, BIOS 3B03.TEL0P1 06/09/2023
[37606.450828] Call Trace:
[37606.451548]  <TASK>
[37606.452242]  dump_stack_lvl+0x36/0x50
[37606.452946]  vcpu_enter_guest.constprop.0+0x2a6/0xf20 [kvm]
[37606.453824]  ? hrtimer_try_to_cancel.part.0+0x50/0xf0
[37606.454522]  ? __rseq_handle_notify_resume+0x36/0x60
[37606.455215]  vcpu_run+0x3a/0x230 [kvm]
[37606.456078]  kvm_arch_vcpu_ioctl_run+0xe8/0x3e0 [kvm]
[37606.456892]  kvm_vcpu_ioctl+0x225/0x690 [kvm]
[37606.457662]  ? vfs_write+0xe7/0x3a0
[37606.458338]  ? rseq_ip_fixup+0x6d/0x1c0
[37606.459005]  ? task_mm_cid_work+0x1a1/0x220
[37606.459658]  ? __fget_light+0x85/0x100
[37606.460314]  __x64_sys_ioctl+0x94/0xd0
[37606.460969]  do_syscall_64+0x4b/0xf0
[37606.461625]  entry_SYSCALL_64_after_hwframe+0x6e/0x76

```
The code path looks like:
```
static int vcpu_enter_guest(struct kvm_vcpu *vcpu)
{
	for (;;) {
		static_call(kvm_x86_vcpu_run)(vcpu);
	}
	//read the guest's XDF and cached it in percpu XDF
	if (vcpu->arch.xfd_no_write_intercept)
		fpu_sync_guest_vmexit_xfd_state();
			rdmsrl(MSR_IA32_XFD, fps->xfd)
			__this_cpu_write(xfd_state, fps->xfd)
	
	//save the XDF_ERR to vcpu->arch.guest_fpu.xfd_err for later use(re-enter vm guest)
	static_call(kvm_x86_handle_exit_irqoff)(vcpu);
	
	if (vcpu->arch.guest_fpu.xfd_err)
		wrmsrl(MSR_IA32_XFD_ERR, 0);
		
}
```
The handler of #NM in KVM is in kvm_x86_handle_exit_irqoff() -> vt_handle_exit_irqoff
```
vt_handle_exit_irqoff->
	vmx_handle_exit_irqoff(vcpu)->
		if (vmx->exit_reason.basic == EXIT_REASON_EXCEPTION_NMI)
			vmx_handle_exception_irqoff(vcpu)->
				if (is_nm_fault(intr_info))
					vmx_handle_nm_fault_irqoff(vcpu)
						//Save xfd_err to guest_fpu before interrupt is enabled, to avoid
						//interrupt scribble the xfd_err register
						if (vcpu->arch.guest_fpu.fpstate->xfd)
							rdmsrl(MSR_IA32_XFD_ERR, vcpu->arch.guest_fpu.xfd_err)

```
After the kvm_x86_handle_exit_irqoff() has been done with irq disabled, the local irq / preemption is enabled, then the main exit handler is invoked. Thus vcpu_enter_guest() becomes:
```
static int vcpu_enter_guest(struct kvm_vcpu *vcpu)
{
	for (;;) {
		static_call(kvm_x86_vcpu_run)(vcpu);
	}
	//read the guest's XDF and cached it in percpu XDF
	if (vcpu->arch.xfd_no_write_intercept)
		fpu_sync_guest_vmexit_xfd_state();
			rdmsrl(MSR_IA32_XFD, fps->xfd)
			__this_cpu_write(xfd_state, fps->xfd)
	
	//save the XDF_ERR to vcpu->arch.guest_fpu.xfd_err with irq disabled,
	//for later use(re-enter vm guest)
	static_call(kvm_x86_handle_exit_irqoff)(vcpu);
	
	if (vcpu->arch.guest_fpu.xfd_err)
		wrmsrl(MSR_IA32_XFD_ERR, 0);
		
		local_irq_enable();
		preempt_enable();
		
		static_call(kvm_x86_handle_exit)(vcpu, exit_fastpath);
}
```
kvm_x86_handle_exit() callback is vmx_handle_exit():
```
[37606.468613] handle_exception_nmi queue #nm exception to vcpu5
[37606.469130] CPU: 5 PID: 4371 Comm: CPU 0/KVM Not tainted #61
[37606.469838] Hardware name: Quanta Cloud Technology Inc. QuantaGrid D54Q-2U/S6Q-MB-MPS, BIOS 3B03.TEL0P1 06/09/2023
[37606.470567] Call Trace:
[37606.471288]  <TASK>
[37606.472002]  dump_stack_lvl+0x36/0x50
[37606.472722]  handle_exception_nmi+0x4a9/0x7e0 [kvm_intel]
[37606.473477]  vmx_handle_exit+0x13/0x90 [kvm_intel]
[37606.474205]  vcpu_enter_guest.constprop.0+0x32c/0xf20 [kvm]
[37606.474989]  ? hrtimer_try_to_cancel.part.0+0x50/0xf0
[37606.475672]  ? __rseq_handle_notify_resume+0x36/0x60
[37606.476348]  vcpu_run+0x3a/0x230 [kvm]
[37606.477124]  kvm_arch_vcpu_ioctl_run+0xe8/0x3e0 [kvm]
[37606.477900]  kvm_vcpu_ioctl+0x225/0x690 [kvm]
[37606.478661]  ? vfs_write+0xe7/0x3a0
[37606.479337]  ? rseq_ip_fixup+0x6d/0x1c0
[37606.480005]  ? task_mm_cid_work+0x1a1/0x220
[37606.480668]  ? __fget_light+0x85/0x100
[37606.481318]  __x64_sys_ioctl+0x94/0xd0
[37606.481959]  do_syscall_64+0x4b/0xf0
[37606.482602]  entry_SYSCALL_64_after_hwframe+0x6e/0x76
```

In handle_exception_nmi, it mainly inject the NM exception back to the vm guest:
```
static int handle_exception_nmi(struct kvm_vcpu *vcpu)
{
	if (is_nm_fault(intr_info)) {
		kvm_queue_exception(vcpu, NM_VECTOR);
		return 1;
	}
}
```
Although not having dig into the kvm_queue_exception(), my guess is that this function manipulates on VMCS thus trigger the #NM when vm guest is entered again.
After the vm guest is running again, it triggers the #NM, and falls into the #NM handler:
```
static bool handle_xfd_event(struct pt_regs *regs)
{
	rdmsrl(MSR_IA32_XFD_ERR, xfd_err)
	wrmsrl(MSR_IA32_XFD_ERR, 0)

	//__xfd_enable_feature(xfd_err, NULL)
	err = xfd_enable_feature(xfd_err);
	switch (err) {
		case -EPERM:
			force_sig_fault(SIGILL, ILL_ILLOPC, error_get_trap_addr(regs));
			break;
		case -EFAULT:
			force_sig(SIGSEGV);
			break;
	}
}
```
The core is in xfd_enable_feature(), it is supposed to check the permisson of current task, and allocate xfd buffer on-demand:
```
int __xfd_enable_feature(u64 xfd_err, struct fpu_guest *guest_fpu)
{
	//check the permisson
	if ((xstate_get_group_perm(!!guest_fpu) & xfd_event) != xfd_event) {
		return -EPERM;
	}
	
	fpstate_realloc(xfd_event, ksize, usize, guest_fpu)
}
```
As discussed previously, the kvm_vcpu_ioctl_set_cpuid2 has already re-allocated the buffer of &vcpu->arch.guest_fpu. Here in vm guest's #NM handler, the current task's fpstate is re-allocated again:
```
static int fpstate_realloc(u64 xfeatures, unsigned int ksize,
														unsigned int usize, struct fpu_guest *guest_fpu)
{
	//get current fpu in used
	struct fpu *fpu = &current->thread.fpu;

	fpsize = ksize + ALIGN(offsetof(struct fpstate, regs), 64);
	newfps = vzalloc(fpsize);

	curfps = guest_fpu ? guest_fpu->fpstate : fpu->fpstate;
	//if guest_fpu == NULL, in_use is true
	in_use = fpu->fpstate == curfps;

	if (guest_fpu) {
		guest_fpu->fpstate = newfps;
		if (in_use)
			fpu->fpstate = newfps;
	} else {
		fpu->fpstate = newfps;
	}
	
	if (in_use)
		xfd_update_state(fpu->fpstate);
		
	//free the old fpstate
	if (curfps && curfps->is_valloc)
		vfree(curfps);
}
```

**Here comes the question,  the kvm_vcpu_ioctl_set_cpuid2 has already re-allocated the buffer of &vcpu->arch.guest_fpu, and once vCPU is switched in, the vm guest should use the re-allocated buffer, why here in vm guest's #NM handler, the fpstate buffer is re-allocated again?**

# How TDX supports AMX
Before looking into TDX's support, check the definition of MSR write under TDX. According to the TDX module spec 1.5, the MSR virtualization is done by the TDX module:
```
IA32_XFD			

Inject_GP(~(virt.
CPUID(0xD,0x1).EAX[4]))
```
Above means that, if the result of CPUID(0xD,0x1) on the vm guest is stored in EAX, and if EAX's bit4 is not set, TDX module injects a #GP to the TDX vm guest. Otherwise, it behaves like a native IA32_XFD read and write.  According to the SDM CPUID(0xD,ecx=0x1), bit4 of result EAX indicates:
```
Bit 04: Supports extended feature disable (XFD) if set.
```
The reason why CPU(0xD,0x1) does not have bit4 in EAX set might be that, the Intel TDX module does not enable XFD in its CPUID virtualization. In summary, on TDX vm guest, a read/write to XFD is transparant to the KVM, but will be assited(emulated) by the TDX module.
During the TDX vm bootup, we can see from the host side dmesg, there are only prctl permission enabling, and cpuid set to trigger the fpstate reallocation, while the XFD/XFD_ERR MSR settings are gone, although we can see the TDX vm guest has explictly set the XFD MSR to 0x40000. This is expected, because as we discussed previously, the write to XFD MSR will be taken over by the TDX module.
```
[  562.182167] Guest ARCH_REQ_XCOMP_GUEST_PERM calltrace
[  562.182197] CPU: 1 PID: 4357 Comm: tdxvm Not tainted #61
[  562.182220] Hardware name: Quanta Cloud Technology Inc. QuantaGrid D54Q-2U/S6Q-MB-MPS, BIOS 3B03.TEL0P1 06/09/2023
[  562.182241] Call Trace:
[  562.182251]  <TASK>
[  562.182259]  dump_stack_lvl+0x36/0x50
[  562.182281]  fpu_xstate_prctl+0x5d/0x250
[  562.182303]  do_syscall_64+0x4b/0xf0
[  562.182322]  entry_SYSCALL_64_after_hwframe+0x6e/0x76
[  562.182340] RIP: 0033:0x7ff02271e88d
[  562.182354] Code: 5b 41 5c c3 66 0f 1f 84 00 00 00 00 00 f3 0f 1e fa 48 89 f8 48 89 f7 48 89 d6 48 89 ca 4d 89 c2 4d 89 c8 4c 8b 4c 24 08 0f 05 <48> 3d 01 f0 ff ff 73 01 c3 48 8b 0d 73 b5 0f 00 f7 d8 64 89 01 48
[  562.182395] RSP: 002b:00007ffd7d458588 EFLAGS: 00000202 ORIG_RAX: 000000000000009e
[  562.182420] RAX: ffffffffffffffda RBX: 0000000000040000 RCX: 00007ff02271e88d
[  562.182442] RDX: 000055bd52a61e58 RSI: 0000000000000012 RDI: 0000000000001025
[  562.182462] RBP: 0000000000000012 R08: 0000000000000000 R09: 00007ffd7d458600
[  562.182482] R10: 000000000000000c R11: 0000000000000202 R12: 00000000000602e7
[  562.182502] R13: 000055bd51c980f0 R14: ffffffffffffffdf R15: 000055bd51ca99e0
[  562.182523]  </TASK>
[  562.182546] Before xstate_request_perm.
[  562.184975] fpstate_realloc (4361 CPU 0/KVM) dynamic on-demand allocate fpstate
[  562.185023] CPU: 126 PID: 4361 Comm: CPU 0/KVM Not tainted 6.7.0-rc1-tdx-fix-test-g34e60203b79e-dirty #61
[  562.185061] Hardware name: Quanta Cloud Technology Inc. QuantaGrid D54Q-2U/S6Q-MB-MPS, BIOS 3B03.TEL0P1 06/09/2023
[  562.185098] Call Trace:
[  562.185116]  <TASK>
[  562.185133]  dump_stack_lvl+0x36/0x50
[  562.185162]  fpstate_realloc+0x148/0x300
[  562.185191]  ? vmemdup_user+0x25/0x90
[  562.185225]  __xfd_enable_feature+0x99/0x110
[  562.185254]  kvm_set_cpuid+0x26e/0x2a0 [kvm]
[  562.185557]  kvm_vcpu_ioctl_set_cpuid2+0x4f/0xa0 [kvm]
[  562.185818]  kvm_arch_vcpu_ioctl+0x909/0x1130 [kvm]
[  562.186082]  ? do_anonymous_page+0x1a5/0x3d0
[  562.186111]  ? __handle_mm_fault+0x31e/0x600
[  562.186143]  kvm_vcpu_ioctl+0x3a0/0x690 [kvm]
[  562.186348]  ? __count_memcg_events+0x52/0xa0
[  562.186379]  ? handle_mm_fault+0xc1/0x370
[  562.186405]  ? kvm_vm_ioctl_check_extension+0x32e/0x4f0 [kvm]
[  562.186661]  ? kvm_arch_dev_ioctl+0x274/0x3b0 [kvm]
[  562.186907]  __x64_sys_ioctl+0x94/0xd0
[  562.186935]  do_syscall_64+0x4b/0xf0
[  562.186964]  entry_SYSCALL_64_after_hwframe+0x6e/0x76

```
When we ran the amx test without prctl permission:
```
./amx-test-no -d 10 -t 1 -i 1
Illegal instruction (core dumped)
```
And there is no dmesg printed on the host, while there is one message on the TDX guest:
```
[ 5905.771721] handle_xfd_event on CPU0
```
This indicates that, the #NM has been traped by the TDX module and inject an #NM to the TDX guest.
Then run the amx test with prctl permission enabled:
```
./amx-test-ok -d 10 -t 1 -i 1
Throughput thread0: 744 bytes per second
```
Still there is no message printed on the host, but there are many message on the TDX guest:
```
[ 6073.811797] Normal ARCH_REQ_XCOMP_PERM calltrace
[ 6073.812333] CPU: 0 PID: 2292 Comm: amx-test-ok Not tainted #61
[ 6073.812904] Hardware name: QEMU Standard PC (Q35 + ICH9, 2009), BIOS unknown 2/2/2022
[ 6073.813533] Call Trace:
[ 6073.813650]  <TASK>
[ 6073.813768]  dump_stack_lvl+0x36/0x50
[ 6073.813984]  fpu_xstate_prctl+0x1ee/0x250
[ 6073.814486]  do_syscall_64+0x4b/0xf0
[ 6073.814661]  entry_SYSCALL_64_after_hwframe+0x6e/0x76
[ 6073.814916] RIP: 0033:0x7f2ea0b1e88d
[ 6073.815161] Code: 5b 41 5c c3 66 0f 1f 84 00 00 00 00 00 f3 0f 1e fa 48 89 f8 48 89 f7 48 89 d6 48 89 ca 4d 89 c2 4d 89 c8 4c 8b 4c 24 08 0f 05 <48> 3d 01 f0 ff ff 73 01 c3 48 8b 0d 73 b5 0f 00 f7 d8 64 89 01 48
[ 6073.815954] RSP: 002b:00007f2ea09fed68 EFLAGS: 00000246 ORIG_RAX: 000000000000009e
[ 6073.816346] RAX: ffffffffffffffda RBX: 000055d8368932a0 RCX: 00007f2ea0b1e88d
[ 6073.816736] RDX: 0000000000000000 RSI: 0000000000000012 RDI: 0000000000001023
[ 6073.817107] RBP: 00007f2ea09fee20 R08: 00007ffd7049939f R09: 0000000000000000
[ 6073.817453] R10: 0000000000000000 R11: 0000000000000246 R12: 000055d8368932a0
[ 6073.817787] R13: 0000000000000000 R14: 00007f2ea0a947d0 R15: 00007ffd704993e0
[ 6073.818140]  </TASK>
[ 6073.818315] Before xstate_request_perm.
[ 6073.845833] handle_xfd_event on CPU0
[ 6073.846298] fpstate_realloc (2292 amx-test-ok) dynamic on-demand allocate fpstate
[ 6073.846754] CPU: 0 PID: 2292 Comm: amx-test-ok Not tainted 6.7.0-rc1-tdx-fix-test-g34e60203b79e-dirty #61
[ 6073.847109] Hardware name: QEMU Standard PC (Q35 + ICH9, 2009), BIOS unknown 2/2/2022
[ 6073.847386] Call Trace:
[ 6073.847478]  <TASK>
[ 6073.847571]  dump_stack_lvl+0x36/0x50
[ 6073.847710]  fpstate_realloc+0x148/0x300
[ 6073.847850]  __xfd_enable_feature+0x99/0x110
[ 6073.848040]  handle_xfd_event+0x7d/0x100
[ 6073.848178]  exc_device_not_available+0x1e/0x70
[ 6073.848360]  asm_exc_device_not_available+0x1a/0x20
[ 6073.848543] RIP: 0033:0x55d83688fa32
[ 6073.848678] Code: 0f 1f 84 00 00 00 00 00 85 c0 0f 8e b8 00 00 00 31 d2 66 0f 1f 44 00 00 48 89 d0 48 c1 e0 0d 49 03 04 24 48 8d 88 00 08 00 00 <c4> e2 7b 4b 14 19 c4 e2 7b 4b 04 18 48 8d b0 00 04 00 00 c4 e2 7b
[ 6073.849327] RSP: 002b:00007f2ea09fee30 EFLAGS: 00010206
[ 6073.849511] RAX: 000055d8368932c0 RBX: 0000000000000040 RCX: 000055d836893ac0
[ 6073.849786] RDX: 0000000000000000 RSI: 0000000000000000 RDI: 0000000000000100
[ 6073.850066] RBP: 0000000065d0cf65 R08: 00007f2e9c000b70 R09: 0000000000000000
[ 6073.850342] R10: 00007f2e9c000d40 R11: f8a16ab89c55a11f R12: 000055d8368932a0
[ 6073.850616] R13: 0000000065d0cf66 R14: 000000000000000a R15: 00007ffd704993e0
[ 6073.850893]  </TASK>

```
Which is exactly the same on the generic VM guest when running AMX.
Next, let's dig into the TDX module code to check how it deals with MSR XFD write, and #NM exception. The TDX module code can be downloaded [here](https://github.com/intel/tdx-module.git) When the TDX vm writes msr, the CPU exits from TDX nonroot mode to TDX root mode, in TDX module. The code path of TDX module looks like:
1. set the host RIP when TDX vm exit:
```
./common/data_structures/td_vmcs_init.c:248:
ia32_vmwrite(VMX_HOST_RIP_ENCODE, (uint64_t)td_entry_func_ptr);

save_guest_td_state_before_td_exit

```
The td_entry_func_ptr hook is the function pointer to deal with TDX vm exit, and its implementation is:
```
./common/data_structures/td_vmcs_init.c:247:
oid (*td_entry_func_ptr)(void) = tdx_tdexit_entry_point;
```
```
./td_dispatcher/tdx_td_transitions.S:33
//TDX exit and entry to the TDX module
.globl tdx_tdexit_entry_point
	//check if we have nest TD
	movq %gs:TDX_LOCAL_DATA_CURRENT_TD_VM_ID_OFFSET, %rax
	test %rax, %rax
	jnz l2_dispatcher
	
	//not nest TD
	callq tdx_td_dispatcher
	
l2_dispatcher:
	callq tdx_td_l2_dispatcher

./td_dispatcher/tdx_td_dispatcher.c:712:
void tdx_td_dispatcher(void)
{
	//get the TDX exit reason in vm_exit_reason
	vmexit_stepping_result = 
	tdx_td_l1_l2_dispatcher_common_prologue(tdx_local_data_ptr, 0, &vm_exit_reason,
					&vm_exit_qualification, &vm_exit_inter_info);
	
	//check if the exit is due to  MSR read/write, if yes,
	//simulate it.
	switch (vm_exit_reason.basic_reason)
		case VMEXIT_REASON_MSR_READ:
		case VMEXIT_REASON_MSR_WRITE:
			td_msr_access_status_t status = 
			(vm_exit_reason.basic_reason == VMEXIT_REASON_MSR_READ) ?
			td_rdmsr_exit() : td_wrmsr_exit();
}

./td_dispatcher/vm_exits/td_msr_access.c:348:
td_msr_access_status_t td_wrmsr_exit(void)
{
	uint32_t msr_addr = (uint32_t)tdvps_p->guest_state.gpr_state.rcx;
	status = rd_wr_msr_generic_checks(msr_addr, true, tdvps_p, vm_id);
	switch (msr_addr) {
		case IA32_XSS_MSR_ADDR:
			status = wrmsr_ia32_xss(tdvps_p);
			break
		default:
			rd_wr_msr_generic_case(msr_addr, true, tdcs_p);
			break;
	}
}
```
When the TDX vm writes to the XFD MSR, it should fall into rd_wr_msr_generic_case. As we mentioned previously,  the MSR virtualization in TDX module 1.5 should be:
```
IA32_XFD			

Inject_GP(~(virt.
CPUID(0xD,0x1).EAX[4]))
```
Normally it should write to CPU directly. However according to the implementation of rd_wr_msr_generic_case(), it only returns TD_MSR_ACCESS_GP for XFD write:
```
static td_msr_access_status_t rd_wr_msr_generic_case(uint32_t msr_addr, 
					bool_t wr, tdcs_t* tdcs_p)
{
	const msr_lookup_t* msr_lookup_ptr = find_msr_entry(msr_addr);
	
	//Inject_GP(~(virt.CPUID(0xD,0x1).EAX[4]))
	msr_bitmap_action action = wr ? msr_lookup_ptr->wr_action : msr_lookup_ptr->rd_action;
	
	else if (action == MSR_ACTION_GP)
		return TD_MSR_ACCESS_GP;
}
```
So what's wrong here? The reason is that, actually the write to XFD MSR will not cause TDX vm exit, but will be writen to the CPU directly:
```
./src/common/helpers/helpers.c:1754:
void set_msr_bitmaps(tdcs_t * tdcs_ptr)
{
	for (uint32_t i = 0; i < MAX_NUM_MSR_LOOKUP; i++) {
		uint32_t msr_addr = msr_lookup[i].start_address;
		bool_t clear_wr_bit = is_msr_dynamic_bit_cleared(tdcs_ptr, msr_addr, msr_lookup[i].wr_bit_meaning) ||
	
		for (; msr_addr <= msr_lookup[i].end_address; msr_addr++) {
			//maybe something like the VMCS->MSR_BITMAP
			uint32_t* byte_addr_wr = (uint32_t*)&tdcs_ptr->MSR_BITMAPS[byte_offset + (MSR_BITMAP_SIZE * 2)];
			if (clear_wr_bit)
				btr_32b(byte_addr_wr, bit_offset);
		}
	}
}
```
So it is possible the MSR_BITMAP for XFD is set. To confirm, check:
```

bool_t is_msr_dynamic_bit_cleared(tdcs_t* tdcs_ptr, uint32_t msr_addr, msr_bitmap_bit_type bit_meaning)
{
    // Common dynamic cases
    if (((bit_meaning == MSR_BITMAP_DYN_PERFMON)  && is_perfmon_supported_in_tdcs(tdcs_ptr)) ||
        ((bit_meaning == MSR_BITMAP_DYN_XFAM_CET) && is_cet_supported_in_tdcs(tdcs_ptr))     ||
        ((bit_meaning == MSR_BITMAP_DYN_XFAM_PT)  && is_pt_supported_in_tdcs(tdcs_ptr))      ||
        ((bit_meaning == MSR_BITMAP_DYN_XFAM_ULI) && is_uli_supported_in_tdcs(tdcs_ptr))     ||
        ((bit_meaning == MSR_BITMAP_DYN_XFAM_LBR) && is_lbr_supported_in_tdcs(tdcs_ptr))     ||
        ((bit_meaning == MSR_BITMAP_DYN_UMWAIT)   && is_waitpkg_supported_in_tdcs(tdcs_ptr)) ||
        ((bit_meaning == MSR_BITMAP_DYN_PKS)      && is_pks_supported_in_tdcs(tdcs_ptr))     ||
        ((bit_meaning == MSR_BITMAP_DYN_XFD)      && is_xfd_supported_in_tdcs(tdcs_ptr))     ||
        ((bit_meaning == MSR_BITMAP_DYN_TSX)      && is_tsx_supported_in_tdcs(tdcs_ptr)))
    {
        return true;
    }

}
```
We can see the XFD is in the dynamic list. And this dynamic list is generated in:
```
./include/auto_gen/msr_config_lookup.c:
const msr_lookup_t msr_lookup[MAX_NUM_MSR_LOOKUP] = {

 {
  // 24 - IA32_XFD 
  .start_address  = 0x1c4, .end_address = 0x1c4,
  .rd_bit_meaning = MSR_BITMAP_DYN_XFD, .rd_action = MSR_ACTION_GP,
  .wr_bit_meaning = MSR_BITMAP_DYN_XFD, .wr_action = MSR_ACTION_GP
 },

}
```
# Why AMX performs much worse on TDX than non-TDX
Finally we come the tough question, why AMX performance much worse on TDX than non-TDX guest. 
