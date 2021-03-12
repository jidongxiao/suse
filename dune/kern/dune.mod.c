#include <linux/module.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

MODULE_INFO(vermagic, VERMAGIC_STRING);

__visible struct module __this_module
__attribute__((section(".gnu.linkonce.this_module"))) = {
	.name = KBUILD_MODNAME,
	.init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
	.exit = cleanup_module,
#endif
	.arch = MODULE_ARCH_INIT,
};

#ifdef RETPOLINE
MODULE_INFO(retpoline, "Y");
#endif

static const struct modversion_info ____versions[]
__used
__attribute__((section("__versions"))) = {
	{ 0x8febb783, __VMLINUX_SYMBOL_STR(module_layout) },
	{ 0xde16dc16, __VMLINUX_SYMBOL_STR(tboot) },
	{ 0xbdc6b187, __VMLINUX_SYMBOL_STR(cpu_tss) },
	{ 0xc68b28fd, __VMLINUX_SYMBOL_STR(kmalloc_caches) },
	{ 0xd2b09ce5, __VMLINUX_SYMBOL_STR(__kmalloc) },
	{ 0x7b6533ff, __VMLINUX_SYMBOL_STR(up_read) },
	{ 0xda3e43d1, __VMLINUX_SYMBOL_STR(_raw_spin_unlock) },
	{ 0xd066c74c, __VMLINUX_SYMBOL_STR(preempt_notifier_unregister) },
	{ 0xae987a66, __VMLINUX_SYMBOL_STR(node_data) },
	{ 0x75f2ad62, __VMLINUX_SYMBOL_STR(boot_cpu_data) },
	{ 0x9ab66ba3, __VMLINUX_SYMBOL_STR(fpu__restore) },
	{ 0x1000de14, __VMLINUX_SYMBOL_STR(mmu_notifier_register) },
	{ 0x836db7e8, __VMLINUX_SYMBOL_STR(set_page_dirty_lock) },
	{ 0xc0a3d105, __VMLINUX_SYMBOL_STR(find_next_bit) },
	{ 0x44b1d426, __VMLINUX_SYMBOL_STR(__dynamic_pr_debug) },
	{ 0x7a2af7b4, __VMLINUX_SYMBOL_STR(cpu_number) },
	{ 0x69563540, __VMLINUX_SYMBOL_STR(__alloc_pages_nodemask) },
	{ 0x392927aa, __VMLINUX_SYMBOL_STR(set_page_dirty) },
	{ 0x4c71e863, __VMLINUX_SYMBOL_STR(down_read) },
	{ 0x4f8b5ddb, __VMLINUX_SYMBOL_STR(_copy_to_user) },
	{ 0xfe7c4287, __VMLINUX_SYMBOL_STR(nr_cpu_ids) },
	{ 0xde62d845, __VMLINUX_SYMBOL_STR(misc_register) },
	{ 0x21716978, __VMLINUX_SYMBOL_STR(follow_pfn) },
	{ 0xfb578fc5, __VMLINUX_SYMBOL_STR(memset) },
	{ 0xb5fe70d, __VMLINUX_SYMBOL_STR(current_task) },
	{ 0x75bc549a, __VMLINUX_SYMBOL_STR(x86_cpu_to_apicid) },
	{ 0xb5f17edf, __VMLINUX_SYMBOL_STR(perf_register_guest_info_callbacks) },
	{ 0x27e1a049, __VMLINUX_SYMBOL_STR(printk) },
	{ 0x478ec2ce, __VMLINUX_SYMBOL_STR(mmu_notifier_unregister) },
	{ 0x4c9d28b0, __VMLINUX_SYMBOL_STR(phys_base) },
	{ 0xa1c76e0a, __VMLINUX_SYMBOL_STR(_cond_resched) },
	{ 0xcee70bb5, __VMLINUX_SYMBOL_STR(preempt_notifier_register) },
	{ 0x50f754, __VMLINUX_SYMBOL_STR(noop_llseek) },
	{ 0x83e91998, __VMLINUX_SYMBOL_STR(__get_page_tail) },
	{ 0xf11543ff, __VMLINUX_SYMBOL_STR(find_first_zero_bit) },
	{ 0x16289e31, __VMLINUX_SYMBOL_STR(find_vma) },
	{ 0x78764f4e, __VMLINUX_SYMBOL_STR(pv_irq_ops) },
	{ 0x618911fc, __VMLINUX_SYMBOL_STR(numa_node) },
	{ 0xdb96fae8, __VMLINUX_SYMBOL_STR(cpu_tlbstate) },
	{ 0x93fca811, __VMLINUX_SYMBOL_STR(__get_free_pages) },
	{ 0xdb7305a1, __VMLINUX_SYMBOL_STR(__stack_chk_fail) },
	{ 0xd9b2e30e, __VMLINUX_SYMBOL_STR(cpu_possible_mask) },
	{ 0xbb038ce4, __VMLINUX_SYMBOL_STR(perf_unregister_guest_info_callbacks) },
	{ 0x6d334118, __VMLINUX_SYMBOL_STR(__get_user_8) },
	{ 0x6b2dc060, __VMLINUX_SYMBOL_STR(dump_stack) },
	{ 0x2ea2c95c, __VMLINUX_SYMBOL_STR(__x86_indirect_thunk_rax) },
	{ 0x493ba0e5, __VMLINUX_SYMBOL_STR(pv_cpu_ops) },
	{ 0xbdfb6dbb, __VMLINUX_SYMBOL_STR(__fentry__) },
	{ 0xf80bf7a8, __VMLINUX_SYMBOL_STR(kmem_cache_alloc_trace) },
	{ 0xd52bf1ce, __VMLINUX_SYMBOL_STR(_raw_spin_lock) },
	{ 0x5ecfeec6, __VMLINUX_SYMBOL_STR(__per_cpu_offset) },
	{ 0x4302d0eb, __VMLINUX_SYMBOL_STR(free_pages) },
	{ 0xcc838223, __VMLINUX_SYMBOL_STR(__pte2cachemode_tbl) },
	{ 0x37a0cba, __VMLINUX_SYMBOL_STR(kfree) },
	{ 0x30a4de62, __VMLINUX_SYMBOL_STR(pv_mmu_ops) },
	{ 0x53569707, __VMLINUX_SYMBOL_STR(this_cpu_off) },
	{ 0x952f1d44, __VMLINUX_SYMBOL_STR(put_page) },
	{ 0xad722085, __VMLINUX_SYMBOL_STR(apic) },
	{ 0x5541ea93, __VMLINUX_SYMBOL_STR(on_each_cpu) },
	{ 0x4f6b400b, __VMLINUX_SYMBOL_STR(_copy_from_user) },
	{ 0x48682db9, __VMLINUX_SYMBOL_STR(perf_guest_get_msrs) },
	{ 0x5b97b332, __VMLINUX_SYMBOL_STR(misc_deregister) },
	{ 0x6228c21f, __VMLINUX_SYMBOL_STR(smp_call_function_single) },
	{ 0x9ea5dca0, __VMLINUX_SYMBOL_STR(get_user_pages_fast) },
};

static const char __module_depends[]
__used
__attribute__((section(".modinfo"))) =
"depends=";


MODULE_INFO(srcversion, "362BC897B1E93C7DA5B3DD7");
