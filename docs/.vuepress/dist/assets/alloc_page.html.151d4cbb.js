import{c as n}from"./app.b183bda1.js";import{_ as s}from"./plugin-vue_export-helper.21dcd24c.js";const a={},p=n(`<h1 id="alloc-page" tabindex="-1"><a class="header-anchor" href="#alloc-page" aria-hidden="true">#</a> alloc_page</h1><ol><li>do_user_addr_fault</li></ol><div class="language-c ext-c line-numbers-mode"><pre class="language-c"><code>
<span class="token comment">/*
 * Handle faults in the user portion of the address space.  Nothing in here
 * should check X86_PF_USER without a specific justification: for almost
 * all purposes, we should treat a normal kernel access to user memory
 * (e.g. get_user(), put_user(), etc.) the same as the WRUSS instruction.
 * The one exception is AC flag handling, which is, per the x86
 * architecture, special for WRUSS.
 */</span>
<span class="token keyword">static</span> <span class="token keyword">inline</span>
<span class="token keyword">void</span> <span class="token function">do_user_addr_fault</span><span class="token punctuation">(</span><span class="token keyword">struct</span> <span class="token class-name">pt_regs</span> <span class="token operator">*</span>regs<span class="token punctuation">,</span>
			<span class="token keyword">unsigned</span> <span class="token keyword">long</span> error_code<span class="token punctuation">,</span>
			<span class="token keyword">unsigned</span> <span class="token keyword">long</span> address<span class="token punctuation">)</span>
<span class="token punctuation">{</span>
	<span class="token keyword">struct</span> <span class="token class-name">vm_area_struct</span> <span class="token operator">*</span>vma<span class="token punctuation">;</span>
	<span class="token keyword">struct</span> <span class="token class-name">task_struct</span> <span class="token operator">*</span>tsk<span class="token punctuation">;</span>
	<span class="token keyword">struct</span> <span class="token class-name">mm_struct</span> <span class="token operator">*</span>mm<span class="token punctuation">;</span>
	<span class="token class-name">vm_fault_t</span> fault<span class="token punctuation">;</span>
	<span class="token keyword">unsigned</span> <span class="token keyword">int</span> flags <span class="token operator">=</span> FAULT_FLAG_DEFAULT<span class="token punctuation">;</span>

	tsk <span class="token operator">=</span> current<span class="token punctuation">;</span>
	mm <span class="token operator">=</span> tsk<span class="token operator">-&gt;</span>mm<span class="token punctuation">;</span>

	<span class="token keyword">if</span> <span class="token punctuation">(</span><span class="token function">unlikely</span><span class="token punctuation">(</span><span class="token punctuation">(</span>error_code <span class="token operator">&amp;</span> <span class="token punctuation">(</span>X86_PF_USER <span class="token operator">|</span> X86_PF_INSTR<span class="token punctuation">)</span><span class="token punctuation">)</span> <span class="token operator">==</span> X86_PF_INSTR<span class="token punctuation">)</span><span class="token punctuation">)</span> <span class="token punctuation">{</span>
		<span class="token comment">/*
		 * Whoops, this is kernel mode code trying to execute from
		 * user memory.  Unless this is AMD erratum #93, which
		 * corrupts RIP such that it looks like a user address,
		 * this is unrecoverable.  Don&#39;t even try to look up the
		 * VMA or look for extable entries.
		 */</span>
		<span class="token keyword">if</span> <span class="token punctuation">(</span><span class="token function">is_errata93</span><span class="token punctuation">(</span>regs<span class="token punctuation">,</span> address<span class="token punctuation">)</span><span class="token punctuation">)</span>
			<span class="token keyword">return</span><span class="token punctuation">;</span>

		<span class="token function">page_fault_oops</span><span class="token punctuation">(</span>regs<span class="token punctuation">,</span> error_code<span class="token punctuation">,</span> address<span class="token punctuation">)</span><span class="token punctuation">;</span>
		<span class="token keyword">return</span><span class="token punctuation">;</span>
	<span class="token punctuation">}</span>

	<span class="token comment">/* kprobes don&#39;t want to hook the spurious faults: */</span>
	<span class="token keyword">if</span> <span class="token punctuation">(</span><span class="token function">WARN_ON_ONCE</span><span class="token punctuation">(</span><span class="token function">kprobe_page_fault</span><span class="token punctuation">(</span>regs<span class="token punctuation">,</span> X86_TRAP_PF<span class="token punctuation">)</span><span class="token punctuation">)</span><span class="token punctuation">)</span>
		<span class="token keyword">return</span><span class="token punctuation">;</span>

	<span class="token comment">/*
	 * Reserved bits are never expected to be set on
	 * entries in the user portion of the page tables.
	 */</span>
	<span class="token keyword">if</span> <span class="token punctuation">(</span><span class="token function">unlikely</span><span class="token punctuation">(</span>error_code <span class="token operator">&amp;</span> X86_PF_RSVD<span class="token punctuation">)</span><span class="token punctuation">)</span>
		<span class="token function">pgtable_bad</span><span class="token punctuation">(</span>regs<span class="token punctuation">,</span> error_code<span class="token punctuation">,</span> address<span class="token punctuation">)</span><span class="token punctuation">;</span>

	<span class="token comment">/*
	 * If SMAP is on, check for invalid kernel (supervisor) access to user
	 * pages in the user address space.  The odd case here is WRUSS,
	 * which, according to the preliminary documentation, does not respect
	 * SMAP and will have the USER bit set so, in all cases, SMAP
	 * enforcement appears to be consistent with the USER bit.
	 */</span>
	<span class="token keyword">if</span> <span class="token punctuation">(</span><span class="token function">unlikely</span><span class="token punctuation">(</span><span class="token function">cpu_feature_enabled</span><span class="token punctuation">(</span>X86_FEATURE_SMAP<span class="token punctuation">)</span> <span class="token operator">&amp;&amp;</span>
		     <span class="token operator">!</span><span class="token punctuation">(</span>error_code <span class="token operator">&amp;</span> X86_PF_USER<span class="token punctuation">)</span> <span class="token operator">&amp;&amp;</span>
		     <span class="token operator">!</span><span class="token punctuation">(</span>regs<span class="token operator">-&gt;</span>flags <span class="token operator">&amp;</span> X86_EFLAGS_AC<span class="token punctuation">)</span><span class="token punctuation">)</span><span class="token punctuation">)</span> <span class="token punctuation">{</span>
		<span class="token comment">/*
		 * No extable entry here.  This was a kernel access to an
		 * invalid pointer.  get_kernel_nofault() will not get here.
		 */</span>
		<span class="token function">page_fault_oops</span><span class="token punctuation">(</span>regs<span class="token punctuation">,</span> error_code<span class="token punctuation">,</span> address<span class="token punctuation">)</span><span class="token punctuation">;</span>
		<span class="token keyword">return</span><span class="token punctuation">;</span>
	<span class="token punctuation">}</span>

	<span class="token comment">/*
	 * If we&#39;re in an interrupt, have no user context or are running
	 * in a region with pagefaults disabled then we must not take the fault
	 */</span>
	<span class="token keyword">if</span> <span class="token punctuation">(</span><span class="token function">unlikely</span><span class="token punctuation">(</span><span class="token function">faulthandler_disabled</span><span class="token punctuation">(</span><span class="token punctuation">)</span> <span class="token operator">||</span> <span class="token operator">!</span>mm<span class="token punctuation">)</span><span class="token punctuation">)</span> <span class="token punctuation">{</span>
		<span class="token function">bad_area_nosemaphore</span><span class="token punctuation">(</span>regs<span class="token punctuation">,</span> error_code<span class="token punctuation">,</span> address<span class="token punctuation">)</span><span class="token punctuation">;</span>
		<span class="token keyword">return</span><span class="token punctuation">;</span>
	<span class="token punctuation">}</span>

	<span class="token comment">/*
	 * It&#39;s safe to allow irq&#39;s after cr2 has been saved and the
	 * vmalloc fault has been handled.
	 *
	 * User-mode registers count as a user access even for any
	 * potential system fault or CPU buglet:
	 */</span>
	<span class="token keyword">if</span> <span class="token punctuation">(</span><span class="token function">user_mode</span><span class="token punctuation">(</span>regs<span class="token punctuation">)</span><span class="token punctuation">)</span> <span class="token punctuation">{</span>
		<span class="token function">local_irq_enable</span><span class="token punctuation">(</span><span class="token punctuation">)</span><span class="token punctuation">;</span>
		flags <span class="token operator">|=</span> FAULT_FLAG_USER<span class="token punctuation">;</span>
	<span class="token punctuation">}</span> <span class="token keyword">else</span> <span class="token punctuation">{</span>
		<span class="token keyword">if</span> <span class="token punctuation">(</span>regs<span class="token operator">-&gt;</span>flags <span class="token operator">&amp;</span> X86_EFLAGS_IF<span class="token punctuation">)</span>
			<span class="token function">local_irq_enable</span><span class="token punctuation">(</span><span class="token punctuation">)</span><span class="token punctuation">;</span>
	<span class="token punctuation">}</span>

	<span class="token function">perf_sw_event</span><span class="token punctuation">(</span>PERF_COUNT_SW_PAGE_FAULTS<span class="token punctuation">,</span> <span class="token number">1</span><span class="token punctuation">,</span> regs<span class="token punctuation">,</span> address<span class="token punctuation">)</span><span class="token punctuation">;</span>

	<span class="token keyword">if</span> <span class="token punctuation">(</span>error_code <span class="token operator">&amp;</span> X86_PF_WRITE<span class="token punctuation">)</span>
		flags <span class="token operator">|=</span> FAULT_FLAG_WRITE<span class="token punctuation">;</span>
	<span class="token keyword">if</span> <span class="token punctuation">(</span>error_code <span class="token operator">&amp;</span> X86_PF_INSTR<span class="token punctuation">)</span>
		flags <span class="token operator">|=</span> FAULT_FLAG_INSTRUCTION<span class="token punctuation">;</span>

<span class="token macro property"><span class="token directive-hash">#</span><span class="token directive keyword">ifdef</span> <span class="token expression">CONFIG_X86_64</span></span>
	<span class="token comment">/*
	 * Faults in the vsyscall page might need emulation.  The
	 * vsyscall page is at a high address (&gt;PAGE_OFFSET), but is
	 * considered to be part of the user address space.
	 *
	 * The vsyscall page does not have a &quot;real&quot; VMA, so do this
	 * emulation before we go searching for VMAs.
	 *
	 * PKRU never rejects instruction fetches, so we don&#39;t need
	 * to consider the PF_PK bit.
	 */</span>
	<span class="token keyword">if</span> <span class="token punctuation">(</span><span class="token function">is_vsyscall_vaddr</span><span class="token punctuation">(</span>address<span class="token punctuation">)</span><span class="token punctuation">)</span> <span class="token punctuation">{</span>
		<span class="token keyword">if</span> <span class="token punctuation">(</span><span class="token function">emulate_vsyscall</span><span class="token punctuation">(</span>error_code<span class="token punctuation">,</span> regs<span class="token punctuation">,</span> address<span class="token punctuation">)</span><span class="token punctuation">)</span>
			<span class="token keyword">return</span><span class="token punctuation">;</span>
	<span class="token punctuation">}</span>
<span class="token macro property"><span class="token directive-hash">#</span><span class="token directive keyword">endif</span></span>

	<span class="token comment">/*
	 * Kernel-mode access to the user address space should only occur
	 * on well-defined single instructions listed in the exception
	 * tables.  But, an erroneous kernel fault occurring outside one of
	 * those areas which also holds mmap_lock might deadlock attempting
	 * to validate the fault against the address space.
	 *
	 * Only do the expensive exception table search when we might be at
	 * risk of a deadlock.  This happens if we
	 * 1. Failed to acquire mmap_lock, and
	 * 2. The access did not originate in userspace.
	 */</span>
	<span class="token keyword">if</span> <span class="token punctuation">(</span><span class="token function">unlikely</span><span class="token punctuation">(</span><span class="token operator">!</span><span class="token function">mmap_read_trylock</span><span class="token punctuation">(</span>mm<span class="token punctuation">)</span><span class="token punctuation">)</span><span class="token punctuation">)</span> <span class="token punctuation">{</span>
		<span class="token keyword">if</span> <span class="token punctuation">(</span><span class="token operator">!</span><span class="token function">user_mode</span><span class="token punctuation">(</span>regs<span class="token punctuation">)</span> <span class="token operator">&amp;&amp;</span> <span class="token operator">!</span><span class="token function">search_exception_tables</span><span class="token punctuation">(</span>regs<span class="token operator">-&gt;</span>ip<span class="token punctuation">)</span><span class="token punctuation">)</span> <span class="token punctuation">{</span>
			<span class="token comment">/*
			 * Fault from code in kernel from
			 * which we do not expect faults.
			 */</span>
			<span class="token function">bad_area_nosemaphore</span><span class="token punctuation">(</span>regs<span class="token punctuation">,</span> error_code<span class="token punctuation">,</span> address<span class="token punctuation">)</span><span class="token punctuation">;</span>
			<span class="token keyword">return</span><span class="token punctuation">;</span>
		<span class="token punctuation">}</span>
retry<span class="token operator">:</span>
		<span class="token function">mmap_read_lock</span><span class="token punctuation">(</span>mm<span class="token punctuation">)</span><span class="token punctuation">;</span>
	<span class="token punctuation">}</span> <span class="token keyword">else</span> <span class="token punctuation">{</span>
		<span class="token comment">/*
		 * The above down_read_trylock() might have succeeded in
		 * which case we&#39;ll have missed the might_sleep() from
		 * down_read():
		 */</span>
		<span class="token function">might_sleep</span><span class="token punctuation">(</span><span class="token punctuation">)</span><span class="token punctuation">;</span>
	<span class="token punctuation">}</span>

	vma <span class="token operator">=</span> <span class="token function">find_vma</span><span class="token punctuation">(</span>mm<span class="token punctuation">,</span> address<span class="token punctuation">)</span><span class="token punctuation">;</span>
	<span class="token keyword">if</span> <span class="token punctuation">(</span><span class="token function">unlikely</span><span class="token punctuation">(</span><span class="token operator">!</span>vma<span class="token punctuation">)</span><span class="token punctuation">)</span> <span class="token punctuation">{</span>
		<span class="token function">bad_area</span><span class="token punctuation">(</span>regs<span class="token punctuation">,</span> error_code<span class="token punctuation">,</span> address<span class="token punctuation">)</span><span class="token punctuation">;</span>
		<span class="token keyword">return</span><span class="token punctuation">;</span>
	<span class="token punctuation">}</span>
	<span class="token keyword">if</span> <span class="token punctuation">(</span><span class="token function">likely</span><span class="token punctuation">(</span>vma<span class="token operator">-&gt;</span>vm_start <span class="token operator">&lt;=</span> address<span class="token punctuation">)</span><span class="token punctuation">)</span>
		<span class="token keyword">goto</span> good_area<span class="token punctuation">;</span>
	<span class="token keyword">if</span> <span class="token punctuation">(</span><span class="token function">unlikely</span><span class="token punctuation">(</span><span class="token operator">!</span><span class="token punctuation">(</span>vma<span class="token operator">-&gt;</span>vm_flags <span class="token operator">&amp;</span> VM_GROWSDOWN<span class="token punctuation">)</span><span class="token punctuation">)</span><span class="token punctuation">)</span> <span class="token punctuation">{</span>
		<span class="token function">bad_area</span><span class="token punctuation">(</span>regs<span class="token punctuation">,</span> error_code<span class="token punctuation">,</span> address<span class="token punctuation">)</span><span class="token punctuation">;</span>
		<span class="token keyword">return</span><span class="token punctuation">;</span>
	<span class="token punctuation">}</span>
	<span class="token keyword">if</span> <span class="token punctuation">(</span><span class="token function">unlikely</span><span class="token punctuation">(</span><span class="token function">expand_stack</span><span class="token punctuation">(</span>vma<span class="token punctuation">,</span> address<span class="token punctuation">)</span><span class="token punctuation">)</span><span class="token punctuation">)</span> <span class="token punctuation">{</span>
		<span class="token function">bad_area</span><span class="token punctuation">(</span>regs<span class="token punctuation">,</span> error_code<span class="token punctuation">,</span> address<span class="token punctuation">)</span><span class="token punctuation">;</span>
		<span class="token keyword">return</span><span class="token punctuation">;</span>
	<span class="token punctuation">}</span>

	<span class="token comment">/*
	 * Ok, we have a good vm_area for this memory access, so
	 * we can handle it..
	 */</span>
good_area<span class="token operator">:</span>
	<span class="token keyword">if</span> <span class="token punctuation">(</span><span class="token function">unlikely</span><span class="token punctuation">(</span><span class="token function">access_error</span><span class="token punctuation">(</span>error_code<span class="token punctuation">,</span> vma<span class="token punctuation">)</span><span class="token punctuation">)</span><span class="token punctuation">)</span> <span class="token punctuation">{</span>
		<span class="token function">bad_area_access_error</span><span class="token punctuation">(</span>regs<span class="token punctuation">,</span> error_code<span class="token punctuation">,</span> address<span class="token punctuation">,</span> vma<span class="token punctuation">)</span><span class="token punctuation">;</span>
		<span class="token keyword">return</span><span class="token punctuation">;</span>
	<span class="token punctuation">}</span>

	<span class="token comment">/*
	 * If for any reason at all we couldn&#39;t handle the fault,
	 * make sure we exit gracefully rather than endlessly redo
	 * the fault.  Since we never set FAULT_FLAG_RETRY_NOWAIT, if
	 * we get VM_FAULT_RETRY back, the mmap_lock has been unlocked.
	 *
	 * Note that handle_userfault() may also release and reacquire mmap_lock
	 * (and not return with VM_FAULT_RETRY), when returning to userland to
	 * repeat the page fault later with a VM_FAULT_NOPAGE retval
	 * (potentially after handling any pending signal during the return to
	 * userland). The return to userland is identified whenever
	 * FAULT_FLAG_USER|FAULT_FLAG_KILLABLE are both set in flags.
	 */</span>
	fault <span class="token operator">=</span> <span class="token function">handle_mm_fault</span><span class="token punctuation">(</span>vma<span class="token punctuation">,</span> address<span class="token punctuation">,</span> flags<span class="token punctuation">,</span> regs<span class="token punctuation">)</span><span class="token punctuation">;</span>

	<span class="token keyword">if</span> <span class="token punctuation">(</span><span class="token function">fault_signal_pending</span><span class="token punctuation">(</span>fault<span class="token punctuation">,</span> regs<span class="token punctuation">)</span><span class="token punctuation">)</span> <span class="token punctuation">{</span>
		<span class="token comment">/*
		 * Quick path to respond to signals.  The core mm code
		 * has unlocked the mm for us if we get here.
		 */</span>
		<span class="token keyword">if</span> <span class="token punctuation">(</span><span class="token operator">!</span><span class="token function">user_mode</span><span class="token punctuation">(</span>regs<span class="token punctuation">)</span><span class="token punctuation">)</span>
			<span class="token function">kernelmode_fixup_or_oops</span><span class="token punctuation">(</span>regs<span class="token punctuation">,</span> error_code<span class="token punctuation">,</span> address<span class="token punctuation">,</span>
						 SIGBUS<span class="token punctuation">,</span> BUS_ADRERR<span class="token punctuation">,</span>
						 ARCH_DEFAULT_PKEY<span class="token punctuation">)</span><span class="token punctuation">;</span>
		<span class="token keyword">return</span><span class="token punctuation">;</span>
	<span class="token punctuation">}</span>

	<span class="token comment">/*
	 * If we need to retry the mmap_lock has already been released,
	 * and if there is a fatal signal pending there is no guarantee
	 * that we made any progress. Handle this case first.
	 */</span>
	<span class="token keyword">if</span> <span class="token punctuation">(</span><span class="token function">unlikely</span><span class="token punctuation">(</span><span class="token punctuation">(</span>fault <span class="token operator">&amp;</span> VM_FAULT_RETRY<span class="token punctuation">)</span> <span class="token operator">&amp;&amp;</span>
		     <span class="token punctuation">(</span>flags <span class="token operator">&amp;</span> FAULT_FLAG_ALLOW_RETRY<span class="token punctuation">)</span><span class="token punctuation">)</span><span class="token punctuation">)</span> <span class="token punctuation">{</span>
		flags <span class="token operator">|=</span> FAULT_FLAG_TRIED<span class="token punctuation">;</span>
		<span class="token keyword">goto</span> retry<span class="token punctuation">;</span>
	<span class="token punctuation">}</span>

	<span class="token function">mmap_read_unlock</span><span class="token punctuation">(</span>mm<span class="token punctuation">)</span><span class="token punctuation">;</span>
	<span class="token keyword">if</span> <span class="token punctuation">(</span><span class="token function">likely</span><span class="token punctuation">(</span><span class="token operator">!</span><span class="token punctuation">(</span>fault <span class="token operator">&amp;</span> VM_FAULT_ERROR<span class="token punctuation">)</span><span class="token punctuation">)</span><span class="token punctuation">)</span>
		<span class="token keyword">return</span><span class="token punctuation">;</span>

	<span class="token keyword">if</span> <span class="token punctuation">(</span><span class="token function">fatal_signal_pending</span><span class="token punctuation">(</span>current<span class="token punctuation">)</span> <span class="token operator">&amp;&amp;</span> <span class="token operator">!</span><span class="token function">user_mode</span><span class="token punctuation">(</span>regs<span class="token punctuation">)</span><span class="token punctuation">)</span> <span class="token punctuation">{</span>
		<span class="token function">kernelmode_fixup_or_oops</span><span class="token punctuation">(</span>regs<span class="token punctuation">,</span> error_code<span class="token punctuation">,</span> address<span class="token punctuation">,</span>
					 <span class="token number">0</span><span class="token punctuation">,</span> <span class="token number">0</span><span class="token punctuation">,</span> ARCH_DEFAULT_PKEY<span class="token punctuation">)</span><span class="token punctuation">;</span>
		<span class="token keyword">return</span><span class="token punctuation">;</span>
	<span class="token punctuation">}</span>

	<span class="token keyword">if</span> <span class="token punctuation">(</span>fault <span class="token operator">&amp;</span> VM_FAULT_OOM<span class="token punctuation">)</span> <span class="token punctuation">{</span>
		<span class="token comment">/* Kernel mode? Handle exceptions or die: */</span>
		<span class="token keyword">if</span> <span class="token punctuation">(</span><span class="token operator">!</span><span class="token function">user_mode</span><span class="token punctuation">(</span>regs<span class="token punctuation">)</span><span class="token punctuation">)</span> <span class="token punctuation">{</span>
			<span class="token function">kernelmode_fixup_or_oops</span><span class="token punctuation">(</span>regs<span class="token punctuation">,</span> error_code<span class="token punctuation">,</span> address<span class="token punctuation">,</span>
						 SIGSEGV<span class="token punctuation">,</span> SEGV_MAPERR<span class="token punctuation">,</span>
						 ARCH_DEFAULT_PKEY<span class="token punctuation">)</span><span class="token punctuation">;</span>
			<span class="token keyword">return</span><span class="token punctuation">;</span>
		<span class="token punctuation">}</span>

		<span class="token comment">/*
		 * We ran out of memory, call the OOM killer, and return the
		 * userspace (which will retry the fault, or kill us if we got
		 * oom-killed):
		 */</span>
		<span class="token function">pagefault_out_of_memory</span><span class="token punctuation">(</span><span class="token punctuation">)</span><span class="token punctuation">;</span>
	<span class="token punctuation">}</span> <span class="token keyword">else</span> <span class="token punctuation">{</span>
		<span class="token keyword">if</span> <span class="token punctuation">(</span>fault <span class="token operator">&amp;</span> <span class="token punctuation">(</span>VM_FAULT_SIGBUS<span class="token operator">|</span>VM_FAULT_HWPOISON<span class="token operator">|</span>
			     VM_FAULT_HWPOISON_LARGE<span class="token punctuation">)</span><span class="token punctuation">)</span>
			<span class="token function">do_sigbus</span><span class="token punctuation">(</span>regs<span class="token punctuation">,</span> error_code<span class="token punctuation">,</span> address<span class="token punctuation">,</span> fault<span class="token punctuation">)</span><span class="token punctuation">;</span>
		<span class="token keyword">else</span> <span class="token keyword">if</span> <span class="token punctuation">(</span>fault <span class="token operator">&amp;</span> VM_FAULT_SIGSEGV<span class="token punctuation">)</span>
			<span class="token function">bad_area_nosemaphore</span><span class="token punctuation">(</span>regs<span class="token punctuation">,</span> error_code<span class="token punctuation">,</span> address<span class="token punctuation">)</span><span class="token punctuation">;</span>
		<span class="token keyword">else</span>
			<span class="token function">BUG</span><span class="token punctuation">(</span><span class="token punctuation">)</span><span class="token punctuation">;</span>
	<span class="token punctuation">}</span>
<span class="token punctuation">}</span>
<span class="token function">NOKPROBE_SYMBOL</span><span class="token punctuation">(</span>do_user_addr_fault<span class="token punctuation">)</span><span class="token punctuation">;</span>
</code></pre><div class="line-numbers" aria-hidden="true"><span class="line-number">1</span><br><span class="line-number">2</span><br><span class="line-number">3</span><br><span class="line-number">4</span><br><span class="line-number">5</span><br><span class="line-number">6</span><br><span class="line-number">7</span><br><span class="line-number">8</span><br><span class="line-number">9</span><br><span class="line-number">10</span><br><span class="line-number">11</span><br><span class="line-number">12</span><br><span class="line-number">13</span><br><span class="line-number">14</span><br><span class="line-number">15</span><br><span class="line-number">16</span><br><span class="line-number">17</span><br><span class="line-number">18</span><br><span class="line-number">19</span><br><span class="line-number">20</span><br><span class="line-number">21</span><br><span class="line-number">22</span><br><span class="line-number">23</span><br><span class="line-number">24</span><br><span class="line-number">25</span><br><span class="line-number">26</span><br><span class="line-number">27</span><br><span class="line-number">28</span><br><span class="line-number">29</span><br><span class="line-number">30</span><br><span class="line-number">31</span><br><span class="line-number">32</span><br><span class="line-number">33</span><br><span class="line-number">34</span><br><span class="line-number">35</span><br><span class="line-number">36</span><br><span class="line-number">37</span><br><span class="line-number">38</span><br><span class="line-number">39</span><br><span class="line-number">40</span><br><span class="line-number">41</span><br><span class="line-number">42</span><br><span class="line-number">43</span><br><span class="line-number">44</span><br><span class="line-number">45</span><br><span class="line-number">46</span><br><span class="line-number">47</span><br><span class="line-number">48</span><br><span class="line-number">49</span><br><span class="line-number">50</span><br><span class="line-number">51</span><br><span class="line-number">52</span><br><span class="line-number">53</span><br><span class="line-number">54</span><br><span class="line-number">55</span><br><span class="line-number">56</span><br><span class="line-number">57</span><br><span class="line-number">58</span><br><span class="line-number">59</span><br><span class="line-number">60</span><br><span class="line-number">61</span><br><span class="line-number">62</span><br><span class="line-number">63</span><br><span class="line-number">64</span><br><span class="line-number">65</span><br><span class="line-number">66</span><br><span class="line-number">67</span><br><span class="line-number">68</span><br><span class="line-number">69</span><br><span class="line-number">70</span><br><span class="line-number">71</span><br><span class="line-number">72</span><br><span class="line-number">73</span><br><span class="line-number">74</span><br><span class="line-number">75</span><br><span class="line-number">76</span><br><span class="line-number">77</span><br><span class="line-number">78</span><br><span class="line-number">79</span><br><span class="line-number">80</span><br><span class="line-number">81</span><br><span class="line-number">82</span><br><span class="line-number">83</span><br><span class="line-number">84</span><br><span class="line-number">85</span><br><span class="line-number">86</span><br><span class="line-number">87</span><br><span class="line-number">88</span><br><span class="line-number">89</span><br><span class="line-number">90</span><br><span class="line-number">91</span><br><span class="line-number">92</span><br><span class="line-number">93</span><br><span class="line-number">94</span><br><span class="line-number">95</span><br><span class="line-number">96</span><br><span class="line-number">97</span><br><span class="line-number">98</span><br><span class="line-number">99</span><br><span class="line-number">100</span><br><span class="line-number">101</span><br><span class="line-number">102</span><br><span class="line-number">103</span><br><span class="line-number">104</span><br><span class="line-number">105</span><br><span class="line-number">106</span><br><span class="line-number">107</span><br><span class="line-number">108</span><br><span class="line-number">109</span><br><span class="line-number">110</span><br><span class="line-number">111</span><br><span class="line-number">112</span><br><span class="line-number">113</span><br><span class="line-number">114</span><br><span class="line-number">115</span><br><span class="line-number">116</span><br><span class="line-number">117</span><br><span class="line-number">118</span><br><span class="line-number">119</span><br><span class="line-number">120</span><br><span class="line-number">121</span><br><span class="line-number">122</span><br><span class="line-number">123</span><br><span class="line-number">124</span><br><span class="line-number">125</span><br><span class="line-number">126</span><br><span class="line-number">127</span><br><span class="line-number">128</span><br><span class="line-number">129</span><br><span class="line-number">130</span><br><span class="line-number">131</span><br><span class="line-number">132</span><br><span class="line-number">133</span><br><span class="line-number">134</span><br><span class="line-number">135</span><br><span class="line-number">136</span><br><span class="line-number">137</span><br><span class="line-number">138</span><br><span class="line-number">139</span><br><span class="line-number">140</span><br><span class="line-number">141</span><br><span class="line-number">142</span><br><span class="line-number">143</span><br><span class="line-number">144</span><br><span class="line-number">145</span><br><span class="line-number">146</span><br><span class="line-number">147</span><br><span class="line-number">148</span><br><span class="line-number">149</span><br><span class="line-number">150</span><br><span class="line-number">151</span><br><span class="line-number">152</span><br><span class="line-number">153</span><br><span class="line-number">154</span><br><span class="line-number">155</span><br><span class="line-number">156</span><br><span class="line-number">157</span><br><span class="line-number">158</span><br><span class="line-number">159</span><br><span class="line-number">160</span><br><span class="line-number">161</span><br><span class="line-number">162</span><br><span class="line-number">163</span><br><span class="line-number">164</span><br><span class="line-number">165</span><br><span class="line-number">166</span><br><span class="line-number">167</span><br><span class="line-number">168</span><br><span class="line-number">169</span><br><span class="line-number">170</span><br><span class="line-number">171</span><br><span class="line-number">172</span><br><span class="line-number">173</span><br><span class="line-number">174</span><br><span class="line-number">175</span><br><span class="line-number">176</span><br><span class="line-number">177</span><br><span class="line-number">178</span><br><span class="line-number">179</span><br><span class="line-number">180</span><br><span class="line-number">181</span><br><span class="line-number">182</span><br><span class="line-number">183</span><br><span class="line-number">184</span><br><span class="line-number">185</span><br><span class="line-number">186</span><br><span class="line-number">187</span><br><span class="line-number">188</span><br><span class="line-number">189</span><br><span class="line-number">190</span><br><span class="line-number">191</span><br><span class="line-number">192</span><br><span class="line-number">193</span><br><span class="line-number">194</span><br><span class="line-number">195</span><br><span class="line-number">196</span><br><span class="line-number">197</span><br><span class="line-number">198</span><br><span class="line-number">199</span><br><span class="line-number">200</span><br><span class="line-number">201</span><br><span class="line-number">202</span><br><span class="line-number">203</span><br><span class="line-number">204</span><br><span class="line-number">205</span><br><span class="line-number">206</span><br><span class="line-number">207</span><br><span class="line-number">208</span><br><span class="line-number">209</span><br><span class="line-number">210</span><br><span class="line-number">211</span><br><span class="line-number">212</span><br><span class="line-number">213</span><br><span class="line-number">214</span><br><span class="line-number">215</span><br><span class="line-number">216</span><br><span class="line-number">217</span><br><span class="line-number">218</span><br><span class="line-number">219</span><br><span class="line-number">220</span><br><span class="line-number">221</span><br><span class="line-number">222</span><br><span class="line-number">223</span><br><span class="line-number">224</span><br><span class="line-number">225</span><br><span class="line-number">226</span><br><span class="line-number">227</span><br><span class="line-number">228</span><br><span class="line-number">229</span><br><span class="line-number">230</span><br><span class="line-number">231</span><br><span class="line-number">232</span><br><span class="line-number">233</span><br><span class="line-number">234</span><br><span class="line-number">235</span><br><span class="line-number">236</span><br><span class="line-number">237</span><br><span class="line-number">238</span><br><span class="line-number">239</span><br><span class="line-number">240</span><br><span class="line-number">241</span><br><span class="line-number">242</span><br><span class="line-number">243</span><br><span class="line-number">244</span><br><span class="line-number">245</span><br><span class="line-number">246</span><br><span class="line-number">247</span><br><span class="line-number">248</span><br></div></div><div class="language-c ext-c line-numbers-mode"><pre class="language-c"><code>do_user_addr_fault <span class="token punctuation">{</span>
	vma <span class="token operator">=</span> <span class="token function">find_vma</span><span class="token punctuation">(</span>mm<span class="token punctuation">,</span> address<span class="token punctuation">)</span><span class="token punctuation">;</span>
	<span class="token keyword">if</span> <span class="token punctuation">(</span>vma<span class="token operator">-&gt;</span>vm_start <span class="token operator">&lt;=</span> address<span class="token punctuation">)</span> <span class="token punctuation">{</span>
		good_area<span class="token punctuation">;</span>
	<span class="token punctuation">}</span>
good_area<span class="token operator">:</span>
	fault <span class="token operator">=</span> <span class="token function">handle_mm_fault</span><span class="token punctuation">(</span>vma<span class="token punctuation">,</span> address<span class="token punctuation">,</span> flags<span class="token punctuation">,</span> regs<span class="token punctuation">)</span><span class="token punctuation">;</span>
<span class="token punctuation">}</span>
</code></pre><div class="line-numbers" aria-hidden="true"><span class="line-number">1</span><br><span class="line-number">2</span><br><span class="line-number">3</span><br><span class="line-number">4</span><br><span class="line-number">5</span><br><span class="line-number">6</span><br><span class="line-number">7</span><br><span class="line-number">8</span><br></div></div><ol start="2"><li><p>handle_mm_fault</p><div class="language-c ext-c line-numbers-mode"><pre class="language-c"><code>
<span class="token comment">/*
 * By the time we get here, we already hold the mm semaphore
 *
 * The mmap_lock may have been released depending on flags and our
 * return value.  See filemap_fault() and __lock_page_or_retry().
 */</span>
<span class="token class-name">vm_fault_t</span> <span class="token function">handle_mm_fault</span><span class="token punctuation">(</span><span class="token keyword">struct</span> <span class="token class-name">vm_area_struct</span> <span class="token operator">*</span>vma<span class="token punctuation">,</span> <span class="token keyword">unsigned</span> <span class="token keyword">long</span> address<span class="token punctuation">,</span>
			   <span class="token keyword">unsigned</span> <span class="token keyword">int</span> flags<span class="token punctuation">,</span> <span class="token keyword">struct</span> <span class="token class-name">pt_regs</span> <span class="token operator">*</span>regs<span class="token punctuation">)</span>
<span class="token punctuation">{</span>
	<span class="token class-name">vm_fault_t</span> ret<span class="token punctuation">;</span>

	<span class="token function">__set_current_state</span><span class="token punctuation">(</span>TASK_RUNNING<span class="token punctuation">)</span><span class="token punctuation">;</span>

	<span class="token function">count_vm_event</span><span class="token punctuation">(</span>PGFAULT<span class="token punctuation">)</span><span class="token punctuation">;</span>
	<span class="token function">count_memcg_event_mm</span><span class="token punctuation">(</span>vma<span class="token operator">-&gt;</span>vm_mm<span class="token punctuation">,</span> PGFAULT<span class="token punctuation">)</span><span class="token punctuation">;</span>

	<span class="token comment">/* do counter updates before entering really critical section. */</span>
	<span class="token function">check_sync_rss_stat</span><span class="token punctuation">(</span>current<span class="token punctuation">)</span><span class="token punctuation">;</span>

	<span class="token keyword">if</span> <span class="token punctuation">(</span><span class="token operator">!</span><span class="token function">arch_vma_access_permitted</span><span class="token punctuation">(</span>vma<span class="token punctuation">,</span> flags <span class="token operator">&amp;</span> FAULT_FLAG_WRITE<span class="token punctuation">,</span>
					    flags <span class="token operator">&amp;</span> FAULT_FLAG_INSTRUCTION<span class="token punctuation">,</span>
					    flags <span class="token operator">&amp;</span> FAULT_FLAG_REMOTE<span class="token punctuation">)</span><span class="token punctuation">)</span>
		<span class="token keyword">return</span> VM_FAULT_SIGSEGV<span class="token punctuation">;</span>

	<span class="token comment">/*
	 * Enable the memcg OOM handling for faults triggered in user
	 * space.  Kernel faults are handled more gracefully.
	 */</span>
	<span class="token keyword">if</span> <span class="token punctuation">(</span>flags <span class="token operator">&amp;</span> FAULT_FLAG_USER<span class="token punctuation">)</span>
		<span class="token function">mem_cgroup_enter_user_fault</span><span class="token punctuation">(</span><span class="token punctuation">)</span><span class="token punctuation">;</span>

	<span class="token keyword">if</span> <span class="token punctuation">(</span><span class="token function">unlikely</span><span class="token punctuation">(</span><span class="token function">is_vm_hugetlb_page</span><span class="token punctuation">(</span>vma<span class="token punctuation">)</span><span class="token punctuation">)</span><span class="token punctuation">)</span>
		ret <span class="token operator">=</span> <span class="token function">hugetlb_fault</span><span class="token punctuation">(</span>vma<span class="token operator">-&gt;</span>vm_mm<span class="token punctuation">,</span> vma<span class="token punctuation">,</span> address<span class="token punctuation">,</span> flags<span class="token punctuation">)</span><span class="token punctuation">;</span>
	<span class="token keyword">else</span>
		ret <span class="token operator">=</span> <span class="token function">__handle_mm_fault</span><span class="token punctuation">(</span>vma<span class="token punctuation">,</span> address<span class="token punctuation">,</span> flags<span class="token punctuation">)</span><span class="token punctuation">;</span>

	<span class="token keyword">if</span> <span class="token punctuation">(</span>flags <span class="token operator">&amp;</span> FAULT_FLAG_USER<span class="token punctuation">)</span> <span class="token punctuation">{</span>
		<span class="token function">mem_cgroup_exit_user_fault</span><span class="token punctuation">(</span><span class="token punctuation">)</span><span class="token punctuation">;</span>
		<span class="token comment">/*
		 * The task may have entered a memcg OOM situation but
		 * if the allocation error was handled gracefully (no
		 * VM_FAULT_OOM), there is no need to kill anything.
		 * Just clean up the OOM state peacefully.
		 */</span>
		<span class="token keyword">if</span> <span class="token punctuation">(</span><span class="token function">task_in_memcg_oom</span><span class="token punctuation">(</span>current<span class="token punctuation">)</span> <span class="token operator">&amp;&amp;</span> <span class="token operator">!</span><span class="token punctuation">(</span>ret <span class="token operator">&amp;</span> VM_FAULT_OOM<span class="token punctuation">)</span><span class="token punctuation">)</span>
			<span class="token function">mem_cgroup_oom_synchronize</span><span class="token punctuation">(</span>false<span class="token punctuation">)</span><span class="token punctuation">;</span>
	<span class="token punctuation">}</span>

	<span class="token function">mm_account_fault</span><span class="token punctuation">(</span>regs<span class="token punctuation">,</span> address<span class="token punctuation">,</span> flags<span class="token punctuation">,</span> ret<span class="token punctuation">)</span><span class="token punctuation">;</span>

	<span class="token keyword">return</span> ret<span class="token punctuation">;</span>
<span class="token punctuation">}</span>
<span class="token function">EXPORT_SYMBOL_GPL</span><span class="token punctuation">(</span>handle_mm_fault<span class="token punctuation">)</span><span class="token punctuation">;</span>
</code></pre><div class="line-numbers" aria-hidden="true"><span class="line-number">1</span><br><span class="line-number">2</span><br><span class="line-number">3</span><br><span class="line-number">4</span><br><span class="line-number">5</span><br><span class="line-number">6</span><br><span class="line-number">7</span><br><span class="line-number">8</span><br><span class="line-number">9</span><br><span class="line-number">10</span><br><span class="line-number">11</span><br><span class="line-number">12</span><br><span class="line-number">13</span><br><span class="line-number">14</span><br><span class="line-number">15</span><br><span class="line-number">16</span><br><span class="line-number">17</span><br><span class="line-number">18</span><br><span class="line-number">19</span><br><span class="line-number">20</span><br><span class="line-number">21</span><br><span class="line-number">22</span><br><span class="line-number">23</span><br><span class="line-number">24</span><br><span class="line-number">25</span><br><span class="line-number">26</span><br><span class="line-number">27</span><br><span class="line-number">28</span><br><span class="line-number">29</span><br><span class="line-number">30</span><br><span class="line-number">31</span><br><span class="line-number">32</span><br><span class="line-number">33</span><br><span class="line-number">34</span><br><span class="line-number">35</span><br><span class="line-number">36</span><br><span class="line-number">37</span><br><span class="line-number">38</span><br><span class="line-number">39</span><br><span class="line-number">40</span><br><span class="line-number">41</span><br><span class="line-number">42</span><br><span class="line-number">43</span><br><span class="line-number">44</span><br><span class="line-number">45</span><br><span class="line-number">46</span><br><span class="line-number">47</span><br><span class="line-number">48</span><br><span class="line-number">49</span><br><span class="line-number">50</span><br><span class="line-number">51</span><br><span class="line-number">52</span><br><span class="line-number">53</span><br><span class="line-number">54</span><br></div></div></li><li><p>__handle_mm_fault</p><div class="language-c ext-c line-numbers-mode"><pre class="language-c"><code>
<span class="token comment">/*
 * By the time we get here, we already hold the mm semaphore
 *
 * The mmap_lock may have been released depending on flags and our
 * return value.  See filemap_fault() and __lock_page_or_retry().
 */</span>
<span class="token keyword">static</span> <span class="token class-name">vm_fault_t</span> <span class="token function">__handle_mm_fault</span><span class="token punctuation">(</span><span class="token keyword">struct</span> <span class="token class-name">vm_area_struct</span> <span class="token operator">*</span>vma<span class="token punctuation">,</span>
		<span class="token keyword">unsigned</span> <span class="token keyword">long</span> address<span class="token punctuation">,</span> <span class="token keyword">unsigned</span> <span class="token keyword">int</span> flags<span class="token punctuation">)</span>
<span class="token punctuation">{</span>
	<span class="token keyword">struct</span> <span class="token class-name">vm_fault</span> vmf <span class="token operator">=</span> <span class="token punctuation">{</span>
		<span class="token punctuation">.</span>vma <span class="token operator">=</span> vma<span class="token punctuation">,</span>
		<span class="token punctuation">.</span>address <span class="token operator">=</span> address <span class="token operator">&amp;</span> PAGE_MASK<span class="token punctuation">,</span>
		<span class="token punctuation">.</span>flags <span class="token operator">=</span> flags<span class="token punctuation">,</span>
		<span class="token punctuation">.</span>pgoff <span class="token operator">=</span> <span class="token function">linear_page_index</span><span class="token punctuation">(</span>vma<span class="token punctuation">,</span> address<span class="token punctuation">)</span><span class="token punctuation">,</span>
		<span class="token punctuation">.</span>gfp_mask <span class="token operator">=</span> <span class="token function">__get_fault_gfp_mask</span><span class="token punctuation">(</span>vma<span class="token punctuation">)</span><span class="token punctuation">,</span>
	<span class="token punctuation">}</span><span class="token punctuation">;</span>
	<span class="token keyword">unsigned</span> <span class="token keyword">int</span> dirty <span class="token operator">=</span> flags <span class="token operator">&amp;</span> FAULT_FLAG_WRITE<span class="token punctuation">;</span>
	<span class="token keyword">struct</span> <span class="token class-name">mm_struct</span> <span class="token operator">*</span>mm <span class="token operator">=</span> vma<span class="token operator">-&gt;</span>vm_mm<span class="token punctuation">;</span>
	<span class="token class-name">pgd_t</span> <span class="token operator">*</span>pgd<span class="token punctuation">;</span>
	<span class="token class-name">p4d_t</span> <span class="token operator">*</span>p4d<span class="token punctuation">;</span>
	<span class="token class-name">vm_fault_t</span> ret<span class="token punctuation">;</span>

	pgd <span class="token operator">=</span> <span class="token function">pgd_offset</span><span class="token punctuation">(</span>mm<span class="token punctuation">,</span> address<span class="token punctuation">)</span><span class="token punctuation">;</span>
	p4d <span class="token operator">=</span> <span class="token function">p4d_alloc</span><span class="token punctuation">(</span>mm<span class="token punctuation">,</span> pgd<span class="token punctuation">,</span> address<span class="token punctuation">)</span><span class="token punctuation">;</span>
	<span class="token keyword">if</span> <span class="token punctuation">(</span><span class="token operator">!</span>p4d<span class="token punctuation">)</span>
		<span class="token keyword">return</span> VM_FAULT_OOM<span class="token punctuation">;</span>

	vmf<span class="token punctuation">.</span>pud <span class="token operator">=</span> <span class="token function">pud_alloc</span><span class="token punctuation">(</span>mm<span class="token punctuation">,</span> p4d<span class="token punctuation">,</span> address<span class="token punctuation">)</span><span class="token punctuation">;</span>
	<span class="token keyword">if</span> <span class="token punctuation">(</span><span class="token operator">!</span>vmf<span class="token punctuation">.</span>pud<span class="token punctuation">)</span>
		<span class="token keyword">return</span> VM_FAULT_OOM<span class="token punctuation">;</span>
retry_pud<span class="token operator">:</span>
	<span class="token keyword">if</span> <span class="token punctuation">(</span><span class="token function">pud_none</span><span class="token punctuation">(</span><span class="token operator">*</span>vmf<span class="token punctuation">.</span>pud<span class="token punctuation">)</span> <span class="token operator">&amp;&amp;</span> <span class="token function">__transparent_hugepage_enabled</span><span class="token punctuation">(</span>vma<span class="token punctuation">)</span><span class="token punctuation">)</span> <span class="token punctuation">{</span>
		ret <span class="token operator">=</span> <span class="token function">create_huge_pud</span><span class="token punctuation">(</span><span class="token operator">&amp;</span>vmf<span class="token punctuation">)</span><span class="token punctuation">;</span>
		<span class="token keyword">if</span> <span class="token punctuation">(</span><span class="token operator">!</span><span class="token punctuation">(</span>ret <span class="token operator">&amp;</span> VM_FAULT_FALLBACK<span class="token punctuation">)</span><span class="token punctuation">)</span>
			<span class="token keyword">return</span> ret<span class="token punctuation">;</span>
	<span class="token punctuation">}</span> <span class="token keyword">else</span> <span class="token punctuation">{</span>
		<span class="token class-name">pud_t</span> orig_pud <span class="token operator">=</span> <span class="token operator">*</span>vmf<span class="token punctuation">.</span>pud<span class="token punctuation">;</span>

		<span class="token function">barrier</span><span class="token punctuation">(</span><span class="token punctuation">)</span><span class="token punctuation">;</span>
		<span class="token keyword">if</span> <span class="token punctuation">(</span><span class="token function">pud_trans_huge</span><span class="token punctuation">(</span>orig_pud<span class="token punctuation">)</span> <span class="token operator">||</span> <span class="token function">pud_devmap</span><span class="token punctuation">(</span>orig_pud<span class="token punctuation">)</span><span class="token punctuation">)</span> <span class="token punctuation">{</span>

			<span class="token comment">/* NUMA case for anonymous PUDs would go here */</span>

			<span class="token keyword">if</span> <span class="token punctuation">(</span>dirty <span class="token operator">&amp;&amp;</span> <span class="token operator">!</span><span class="token function">pud_write</span><span class="token punctuation">(</span>orig_pud<span class="token punctuation">)</span><span class="token punctuation">)</span> <span class="token punctuation">{</span>
				ret <span class="token operator">=</span> <span class="token function">wp_huge_pud</span><span class="token punctuation">(</span><span class="token operator">&amp;</span>vmf<span class="token punctuation">,</span> orig_pud<span class="token punctuation">)</span><span class="token punctuation">;</span>
				<span class="token keyword">if</span> <span class="token punctuation">(</span><span class="token operator">!</span><span class="token punctuation">(</span>ret <span class="token operator">&amp;</span> VM_FAULT_FALLBACK<span class="token punctuation">)</span><span class="token punctuation">)</span>
					<span class="token keyword">return</span> ret<span class="token punctuation">;</span>
			<span class="token punctuation">}</span> <span class="token keyword">else</span> <span class="token punctuation">{</span>
				<span class="token function">huge_pud_set_accessed</span><span class="token punctuation">(</span><span class="token operator">&amp;</span>vmf<span class="token punctuation">,</span> orig_pud<span class="token punctuation">)</span><span class="token punctuation">;</span>
				<span class="token keyword">return</span> <span class="token number">0</span><span class="token punctuation">;</span>
			<span class="token punctuation">}</span>
		<span class="token punctuation">}</span>
	<span class="token punctuation">}</span>

	vmf<span class="token punctuation">.</span>pmd <span class="token operator">=</span> <span class="token function">pmd_alloc</span><span class="token punctuation">(</span>mm<span class="token punctuation">,</span> vmf<span class="token punctuation">.</span>pud<span class="token punctuation">,</span> address<span class="token punctuation">)</span><span class="token punctuation">;</span>
	<span class="token keyword">if</span> <span class="token punctuation">(</span><span class="token operator">!</span>vmf<span class="token punctuation">.</span>pmd<span class="token punctuation">)</span>
		<span class="token keyword">return</span> VM_FAULT_OOM<span class="token punctuation">;</span>

	<span class="token comment">/* Huge pud page fault raced with pmd_alloc? */</span>
	<span class="token keyword">if</span> <span class="token punctuation">(</span><span class="token function">pud_trans_unstable</span><span class="token punctuation">(</span>vmf<span class="token punctuation">.</span>pud<span class="token punctuation">)</span><span class="token punctuation">)</span>
		<span class="token keyword">goto</span> retry_pud<span class="token punctuation">;</span>

	<span class="token keyword">if</span> <span class="token punctuation">(</span><span class="token function">pmd_none</span><span class="token punctuation">(</span><span class="token operator">*</span>vmf<span class="token punctuation">.</span>pmd<span class="token punctuation">)</span> <span class="token operator">&amp;&amp;</span> <span class="token function">__transparent_hugepage_enabled</span><span class="token punctuation">(</span>vma<span class="token punctuation">)</span><span class="token punctuation">)</span> <span class="token punctuation">{</span>
		ret <span class="token operator">=</span> <span class="token function">create_huge_pmd</span><span class="token punctuation">(</span><span class="token operator">&amp;</span>vmf<span class="token punctuation">)</span><span class="token punctuation">;</span>
		<span class="token keyword">if</span> <span class="token punctuation">(</span><span class="token operator">!</span><span class="token punctuation">(</span>ret <span class="token operator">&amp;</span> VM_FAULT_FALLBACK<span class="token punctuation">)</span><span class="token punctuation">)</span>
			<span class="token keyword">return</span> ret<span class="token punctuation">;</span>
	<span class="token punctuation">}</span> <span class="token keyword">else</span> <span class="token punctuation">{</span>
		vmf<span class="token punctuation">.</span>orig_pmd <span class="token operator">=</span> <span class="token operator">*</span>vmf<span class="token punctuation">.</span>pmd<span class="token punctuation">;</span>

		<span class="token function">barrier</span><span class="token punctuation">(</span><span class="token punctuation">)</span><span class="token punctuation">;</span>
		<span class="token keyword">if</span> <span class="token punctuation">(</span><span class="token function">unlikely</span><span class="token punctuation">(</span><span class="token function">is_swap_pmd</span><span class="token punctuation">(</span>vmf<span class="token punctuation">.</span>orig_pmd<span class="token punctuation">)</span><span class="token punctuation">)</span><span class="token punctuation">)</span> <span class="token punctuation">{</span>
			<span class="token function">VM_BUG_ON</span><span class="token punctuation">(</span><span class="token function">thp_migration_supported</span><span class="token punctuation">(</span><span class="token punctuation">)</span> <span class="token operator">&amp;&amp;</span>
					  <span class="token operator">!</span><span class="token function">is_pmd_migration_entry</span><span class="token punctuation">(</span>vmf<span class="token punctuation">.</span>orig_pmd<span class="token punctuation">)</span><span class="token punctuation">)</span><span class="token punctuation">;</span>
			<span class="token keyword">if</span> <span class="token punctuation">(</span><span class="token function">is_pmd_migration_entry</span><span class="token punctuation">(</span>vmf<span class="token punctuation">.</span>orig_pmd<span class="token punctuation">)</span><span class="token punctuation">)</span>
				<span class="token function">pmd_migration_entry_wait</span><span class="token punctuation">(</span>mm<span class="token punctuation">,</span> vmf<span class="token punctuation">.</span>pmd<span class="token punctuation">)</span><span class="token punctuation">;</span>
			<span class="token keyword">return</span> <span class="token number">0</span><span class="token punctuation">;</span>
		<span class="token punctuation">}</span>
		<span class="token keyword">if</span> <span class="token punctuation">(</span><span class="token function">pmd_trans_huge</span><span class="token punctuation">(</span>vmf<span class="token punctuation">.</span>orig_pmd<span class="token punctuation">)</span> <span class="token operator">||</span> <span class="token function">pmd_devmap</span><span class="token punctuation">(</span>vmf<span class="token punctuation">.</span>orig_pmd<span class="token punctuation">)</span><span class="token punctuation">)</span> <span class="token punctuation">{</span>
			<span class="token keyword">if</span> <span class="token punctuation">(</span><span class="token function">pmd_protnone</span><span class="token punctuation">(</span>vmf<span class="token punctuation">.</span>orig_pmd<span class="token punctuation">)</span> <span class="token operator">&amp;&amp;</span> <span class="token function">vma_is_accessible</span><span class="token punctuation">(</span>vma<span class="token punctuation">)</span><span class="token punctuation">)</span>
				<span class="token keyword">return</span> <span class="token function">do_huge_pmd_numa_page</span><span class="token punctuation">(</span><span class="token operator">&amp;</span>vmf<span class="token punctuation">)</span><span class="token punctuation">;</span>

			<span class="token keyword">if</span> <span class="token punctuation">(</span>dirty <span class="token operator">&amp;&amp;</span> <span class="token operator">!</span><span class="token function">pmd_write</span><span class="token punctuation">(</span>vmf<span class="token punctuation">.</span>orig_pmd<span class="token punctuation">)</span><span class="token punctuation">)</span> <span class="token punctuation">{</span>
				ret <span class="token operator">=</span> <span class="token function">wp_huge_pmd</span><span class="token punctuation">(</span><span class="token operator">&amp;</span>vmf<span class="token punctuation">)</span><span class="token punctuation">;</span>
				<span class="token keyword">if</span> <span class="token punctuation">(</span><span class="token operator">!</span><span class="token punctuation">(</span>ret <span class="token operator">&amp;</span> VM_FAULT_FALLBACK<span class="token punctuation">)</span><span class="token punctuation">)</span>
					<span class="token keyword">return</span> ret<span class="token punctuation">;</span>
			<span class="token punctuation">}</span> <span class="token keyword">else</span> <span class="token punctuation">{</span>
				<span class="token function">huge_pmd_set_accessed</span><span class="token punctuation">(</span><span class="token operator">&amp;</span>vmf<span class="token punctuation">)</span><span class="token punctuation">;</span>
				<span class="token keyword">return</span> <span class="token number">0</span><span class="token punctuation">;</span>
			<span class="token punctuation">}</span>
		<span class="token punctuation">}</span>
	<span class="token punctuation">}</span>

	<span class="token keyword">return</span> <span class="token function">handle_pte_fault</span><span class="token punctuation">(</span><span class="token operator">&amp;</span>vmf<span class="token punctuation">)</span><span class="token punctuation">;</span>
<span class="token punctuation">}</span>
</code></pre><div class="line-numbers" aria-hidden="true"><span class="line-number">1</span><br><span class="line-number">2</span><br><span class="line-number">3</span><br><span class="line-number">4</span><br><span class="line-number">5</span><br><span class="line-number">6</span><br><span class="line-number">7</span><br><span class="line-number">8</span><br><span class="line-number">9</span><br><span class="line-number">10</span><br><span class="line-number">11</span><br><span class="line-number">12</span><br><span class="line-number">13</span><br><span class="line-number">14</span><br><span class="line-number">15</span><br><span class="line-number">16</span><br><span class="line-number">17</span><br><span class="line-number">18</span><br><span class="line-number">19</span><br><span class="line-number">20</span><br><span class="line-number">21</span><br><span class="line-number">22</span><br><span class="line-number">23</span><br><span class="line-number">24</span><br><span class="line-number">25</span><br><span class="line-number">26</span><br><span class="line-number">27</span><br><span class="line-number">28</span><br><span class="line-number">29</span><br><span class="line-number">30</span><br><span class="line-number">31</span><br><span class="line-number">32</span><br><span class="line-number">33</span><br><span class="line-number">34</span><br><span class="line-number">35</span><br><span class="line-number">36</span><br><span class="line-number">37</span><br><span class="line-number">38</span><br><span class="line-number">39</span><br><span class="line-number">40</span><br><span class="line-number">41</span><br><span class="line-number">42</span><br><span class="line-number">43</span><br><span class="line-number">44</span><br><span class="line-number">45</span><br><span class="line-number">46</span><br><span class="line-number">47</span><br><span class="line-number">48</span><br><span class="line-number">49</span><br><span class="line-number">50</span><br><span class="line-number">51</span><br><span class="line-number">52</span><br><span class="line-number">53</span><br><span class="line-number">54</span><br><span class="line-number">55</span><br><span class="line-number">56</span><br><span class="line-number">57</span><br><span class="line-number">58</span><br><span class="line-number">59</span><br><span class="line-number">60</span><br><span class="line-number">61</span><br><span class="line-number">62</span><br><span class="line-number">63</span><br><span class="line-number">64</span><br><span class="line-number">65</span><br><span class="line-number">66</span><br><span class="line-number">67</span><br><span class="line-number">68</span><br><span class="line-number">69</span><br><span class="line-number">70</span><br><span class="line-number">71</span><br><span class="line-number">72</span><br><span class="line-number">73</span><br><span class="line-number">74</span><br><span class="line-number">75</span><br><span class="line-number">76</span><br><span class="line-number">77</span><br><span class="line-number">78</span><br><span class="line-number">79</span><br><span class="line-number">80</span><br><span class="line-number">81</span><br><span class="line-number">82</span><br><span class="line-number">83</span><br><span class="line-number">84</span><br><span class="line-number">85</span><br><span class="line-number">86</span><br><span class="line-number">87</span><br><span class="line-number">88</span><br><span class="line-number">89</span><br><span class="line-number">90</span><br><span class="line-number">91</span><br><span class="line-number">92</span><br><span class="line-number">93</span><br><span class="line-number">94</span><br><span class="line-number">95</span><br></div></div></li><li><p>handle_pte_fault</p><div class="language-c ext-c line-numbers-mode"><pre class="language-c"><code>
<span class="token comment">/*
 * These routines also need to handle stuff like marking pages dirty
 * and/or accessed for architectures that don&#39;t do it in hardware (most
 * RISC architectures).  The early dirtying is also good on the i386.
 *
 * There is also a hook called &quot;update_mmu_cache()&quot; that architectures
 * with external mmu caches can use to update those (ie the Sparc or
 * PowerPC hashed page tables that act as extended TLBs).
 *
 * We enter with non-exclusive mmap_lock (to exclude vma changes, but allow
 * concurrent faults).
 *
 * The mmap_lock may have been released depending on flags and our return value.
 * See filemap_fault() and __lock_page_or_retry().
 */</span>
<span class="token keyword">static</span> <span class="token class-name">vm_fault_t</span> <span class="token function">handle_pte_fault</span><span class="token punctuation">(</span><span class="token keyword">struct</span> <span class="token class-name">vm_fault</span> <span class="token operator">*</span>vmf<span class="token punctuation">)</span>
<span class="token punctuation">{</span>
	<span class="token class-name">pte_t</span> entry<span class="token punctuation">;</span>

	<span class="token keyword">if</span> <span class="token punctuation">(</span><span class="token function">unlikely</span><span class="token punctuation">(</span><span class="token function">pmd_none</span><span class="token punctuation">(</span><span class="token operator">*</span>vmf<span class="token operator">-&gt;</span>pmd<span class="token punctuation">)</span><span class="token punctuation">)</span><span class="token punctuation">)</span> <span class="token punctuation">{</span>
		<span class="token comment">/*
		 * Leave __pte_alloc() until later: because vm_ops-&gt;fault may
		 * want to allocate huge page, and if we expose page table
		 * for an instant, it will be difficult to retract from
		 * concurrent faults and from rmap lookups.
		 */</span>
		vmf<span class="token operator">-&gt;</span>pte <span class="token operator">=</span> <span class="token constant">NULL</span><span class="token punctuation">;</span>
	<span class="token punctuation">}</span> <span class="token keyword">else</span> <span class="token punctuation">{</span>
		<span class="token comment">/*
		 * If a huge pmd materialized under us just retry later.  Use
		 * pmd_trans_unstable() via pmd_devmap_trans_unstable() instead
		 * of pmd_trans_huge() to ensure the pmd didn&#39;t become
		 * pmd_trans_huge under us and then back to pmd_none, as a
		 * result of MADV_DONTNEED running immediately after a huge pmd
		 * fault in a different thread of this mm, in turn leading to a
		 * misleading pmd_trans_huge() retval. All we have to ensure is
		 * that it is a regular pmd that we can walk with
		 * pte_offset_map() and we can do that through an atomic read
		 * in C, which is what pmd_trans_unstable() provides.
		 */</span>
		<span class="token keyword">if</span> <span class="token punctuation">(</span><span class="token function">pmd_devmap_trans_unstable</span><span class="token punctuation">(</span>vmf<span class="token operator">-&gt;</span>pmd<span class="token punctuation">)</span><span class="token punctuation">)</span>
			<span class="token keyword">return</span> <span class="token number">0</span><span class="token punctuation">;</span>
		<span class="token comment">/*
		 * A regular pmd is established and it can&#39;t morph into a huge
		 * pmd from under us anymore at this point because we hold the
		 * mmap_lock read mode and khugepaged takes it in write mode.
		 * So now it&#39;s safe to run pte_offset_map().
		 */</span>
		vmf<span class="token operator">-&gt;</span>pte <span class="token operator">=</span> <span class="token function">pte_offset_map</span><span class="token punctuation">(</span>vmf<span class="token operator">-&gt;</span>pmd<span class="token punctuation">,</span> vmf<span class="token operator">-&gt;</span>address<span class="token punctuation">)</span><span class="token punctuation">;</span>
		vmf<span class="token operator">-&gt;</span>orig_pte <span class="token operator">=</span> <span class="token operator">*</span>vmf<span class="token operator">-&gt;</span>pte<span class="token punctuation">;</span>

		<span class="token comment">/*
		 * some architectures can have larger ptes than wordsize,
		 * e.g.ppc44x-defconfig has CONFIG_PTE_64BIT=y and
		 * CONFIG_32BIT=y, so READ_ONCE cannot guarantee atomic
		 * accesses.  The code below just needs a consistent view
		 * for the ifs and we later double check anyway with the
		 * ptl lock held. So here a barrier will do.
		 */</span>
		<span class="token function">barrier</span><span class="token punctuation">(</span><span class="token punctuation">)</span><span class="token punctuation">;</span>
		<span class="token keyword">if</span> <span class="token punctuation">(</span><span class="token function">pte_none</span><span class="token punctuation">(</span>vmf<span class="token operator">-&gt;</span>orig_pte<span class="token punctuation">)</span><span class="token punctuation">)</span> <span class="token punctuation">{</span>
			<span class="token function">pte_unmap</span><span class="token punctuation">(</span>vmf<span class="token operator">-&gt;</span>pte<span class="token punctuation">)</span><span class="token punctuation">;</span>
			vmf<span class="token operator">-&gt;</span>pte <span class="token operator">=</span> <span class="token constant">NULL</span><span class="token punctuation">;</span>
		<span class="token punctuation">}</span>
	<span class="token punctuation">}</span>

	<span class="token keyword">if</span> <span class="token punctuation">(</span><span class="token operator">!</span>vmf<span class="token operator">-&gt;</span>pte<span class="token punctuation">)</span> <span class="token punctuation">{</span>
		<span class="token keyword">if</span> <span class="token punctuation">(</span><span class="token function">vma_is_anonymous</span><span class="token punctuation">(</span>vmf<span class="token operator">-&gt;</span>vma<span class="token punctuation">)</span><span class="token punctuation">)</span>
			<span class="token keyword">return</span> <span class="token function">do_anonymous_page</span><span class="token punctuation">(</span>vmf<span class="token punctuation">)</span><span class="token punctuation">;</span>
		<span class="token keyword">else</span>
			<span class="token keyword">return</span> <span class="token function">do_fault</span><span class="token punctuation">(</span>vmf<span class="token punctuation">)</span><span class="token punctuation">;</span>
	<span class="token punctuation">}</span>

	<span class="token keyword">if</span> <span class="token punctuation">(</span><span class="token operator">!</span><span class="token function">pte_present</span><span class="token punctuation">(</span>vmf<span class="token operator">-&gt;</span>orig_pte<span class="token punctuation">)</span><span class="token punctuation">)</span>
		<span class="token keyword">return</span> <span class="token function">do_swap_page</span><span class="token punctuation">(</span>vmf<span class="token punctuation">)</span><span class="token punctuation">;</span>

	<span class="token keyword">if</span> <span class="token punctuation">(</span><span class="token function">pte_protnone</span><span class="token punctuation">(</span>vmf<span class="token operator">-&gt;</span>orig_pte<span class="token punctuation">)</span> <span class="token operator">&amp;&amp;</span> <span class="token function">vma_is_accessible</span><span class="token punctuation">(</span>vmf<span class="token operator">-&gt;</span>vma<span class="token punctuation">)</span><span class="token punctuation">)</span>
		<span class="token keyword">return</span> <span class="token function">do_numa_page</span><span class="token punctuation">(</span>vmf<span class="token punctuation">)</span><span class="token punctuation">;</span>

	vmf<span class="token operator">-&gt;</span>ptl <span class="token operator">=</span> <span class="token function">pte_lockptr</span><span class="token punctuation">(</span>vmf<span class="token operator">-&gt;</span>vma<span class="token operator">-&gt;</span>vm_mm<span class="token punctuation">,</span> vmf<span class="token operator">-&gt;</span>pmd<span class="token punctuation">)</span><span class="token punctuation">;</span>
	<span class="token function">spin_lock</span><span class="token punctuation">(</span>vmf<span class="token operator">-&gt;</span>ptl<span class="token punctuation">)</span><span class="token punctuation">;</span>
	entry <span class="token operator">=</span> vmf<span class="token operator">-&gt;</span>orig_pte<span class="token punctuation">;</span>
	<span class="token keyword">if</span> <span class="token punctuation">(</span><span class="token function">unlikely</span><span class="token punctuation">(</span><span class="token operator">!</span><span class="token function">pte_same</span><span class="token punctuation">(</span><span class="token operator">*</span>vmf<span class="token operator">-&gt;</span>pte<span class="token punctuation">,</span> entry<span class="token punctuation">)</span><span class="token punctuation">)</span><span class="token punctuation">)</span> <span class="token punctuation">{</span>
		<span class="token function">update_mmu_tlb</span><span class="token punctuation">(</span>vmf<span class="token operator">-&gt;</span>vma<span class="token punctuation">,</span> vmf<span class="token operator">-&gt;</span>address<span class="token punctuation">,</span> vmf<span class="token operator">-&gt;</span>pte<span class="token punctuation">)</span><span class="token punctuation">;</span>
		<span class="token keyword">goto</span> unlock<span class="token punctuation">;</span>
	<span class="token punctuation">}</span>
	<span class="token keyword">if</span> <span class="token punctuation">(</span>vmf<span class="token operator">-&gt;</span>flags <span class="token operator">&amp;</span> FAULT_FLAG_WRITE<span class="token punctuation">)</span> <span class="token punctuation">{</span>
		<span class="token keyword">if</span> <span class="token punctuation">(</span><span class="token operator">!</span><span class="token function">pte_write</span><span class="token punctuation">(</span>entry<span class="token punctuation">)</span><span class="token punctuation">)</span>
			<span class="token keyword">return</span> <span class="token function">do_wp_page</span><span class="token punctuation">(</span>vmf<span class="token punctuation">)</span><span class="token punctuation">;</span>
		entry <span class="token operator">=</span> <span class="token function">pte_mkdirty</span><span class="token punctuation">(</span>entry<span class="token punctuation">)</span><span class="token punctuation">;</span>
	<span class="token punctuation">}</span>
	entry <span class="token operator">=</span> <span class="token function">pte_mkyoung</span><span class="token punctuation">(</span>entry<span class="token punctuation">)</span><span class="token punctuation">;</span>
	<span class="token keyword">if</span> <span class="token punctuation">(</span><span class="token function">ptep_set_access_flags</span><span class="token punctuation">(</span>vmf<span class="token operator">-&gt;</span>vma<span class="token punctuation">,</span> vmf<span class="token operator">-&gt;</span>address<span class="token punctuation">,</span> vmf<span class="token operator">-&gt;</span>pte<span class="token punctuation">,</span> entry<span class="token punctuation">,</span>
				vmf<span class="token operator">-&gt;</span>flags <span class="token operator">&amp;</span> FAULT_FLAG_WRITE<span class="token punctuation">)</span><span class="token punctuation">)</span> <span class="token punctuation">{</span>
		<span class="token function">update_mmu_cache</span><span class="token punctuation">(</span>vmf<span class="token operator">-&gt;</span>vma<span class="token punctuation">,</span> vmf<span class="token operator">-&gt;</span>address<span class="token punctuation">,</span> vmf<span class="token operator">-&gt;</span>pte<span class="token punctuation">)</span><span class="token punctuation">;</span>
	<span class="token punctuation">}</span> <span class="token keyword">else</span> <span class="token punctuation">{</span>
		<span class="token comment">/* Skip spurious TLB flush for retried page fault */</span>
		<span class="token keyword">if</span> <span class="token punctuation">(</span>vmf<span class="token operator">-&gt;</span>flags <span class="token operator">&amp;</span> FAULT_FLAG_TRIED<span class="token punctuation">)</span>
			<span class="token keyword">goto</span> unlock<span class="token punctuation">;</span>
		<span class="token comment">/*
		 * This is needed only for protection faults but the arch code
		 * is not yet telling us if this is a protection fault or not.
		 * This still avoids useless tlb flushes for .text page faults
		 * with threads.
		 */</span>
		<span class="token keyword">if</span> <span class="token punctuation">(</span>vmf<span class="token operator">-&gt;</span>flags <span class="token operator">&amp;</span> FAULT_FLAG_WRITE<span class="token punctuation">)</span>
			<span class="token function">flush_tlb_fix_spurious_fault</span><span class="token punctuation">(</span>vmf<span class="token operator">-&gt;</span>vma<span class="token punctuation">,</span> vmf<span class="token operator">-&gt;</span>address<span class="token punctuation">)</span><span class="token punctuation">;</span>
	<span class="token punctuation">}</span>
unlock<span class="token operator">:</span>
	<span class="token function">pte_unmap_unlock</span><span class="token punctuation">(</span>vmf<span class="token operator">-&gt;</span>pte<span class="token punctuation">,</span> vmf<span class="token operator">-&gt;</span>ptl<span class="token punctuation">)</span><span class="token punctuation">;</span>
	<span class="token keyword">return</span> <span class="token number">0</span><span class="token punctuation">;</span>
<span class="token punctuation">}</span>
</code></pre><div class="line-numbers" aria-hidden="true"><span class="line-number">1</span><br><span class="line-number">2</span><br><span class="line-number">3</span><br><span class="line-number">4</span><br><span class="line-number">5</span><br><span class="line-number">6</span><br><span class="line-number">7</span><br><span class="line-number">8</span><br><span class="line-number">9</span><br><span class="line-number">10</span><br><span class="line-number">11</span><br><span class="line-number">12</span><br><span class="line-number">13</span><br><span class="line-number">14</span><br><span class="line-number">15</span><br><span class="line-number">16</span><br><span class="line-number">17</span><br><span class="line-number">18</span><br><span class="line-number">19</span><br><span class="line-number">20</span><br><span class="line-number">21</span><br><span class="line-number">22</span><br><span class="line-number">23</span><br><span class="line-number">24</span><br><span class="line-number">25</span><br><span class="line-number">26</span><br><span class="line-number">27</span><br><span class="line-number">28</span><br><span class="line-number">29</span><br><span class="line-number">30</span><br><span class="line-number">31</span><br><span class="line-number">32</span><br><span class="line-number">33</span><br><span class="line-number">34</span><br><span class="line-number">35</span><br><span class="line-number">36</span><br><span class="line-number">37</span><br><span class="line-number">38</span><br><span class="line-number">39</span><br><span class="line-number">40</span><br><span class="line-number">41</span><br><span class="line-number">42</span><br><span class="line-number">43</span><br><span class="line-number">44</span><br><span class="line-number">45</span><br><span class="line-number">46</span><br><span class="line-number">47</span><br><span class="line-number">48</span><br><span class="line-number">49</span><br><span class="line-number">50</span><br><span class="line-number">51</span><br><span class="line-number">52</span><br><span class="line-number">53</span><br><span class="line-number">54</span><br><span class="line-number">55</span><br><span class="line-number">56</span><br><span class="line-number">57</span><br><span class="line-number">58</span><br><span class="line-number">59</span><br><span class="line-number">60</span><br><span class="line-number">61</span><br><span class="line-number">62</span><br><span class="line-number">63</span><br><span class="line-number">64</span><br><span class="line-number">65</span><br><span class="line-number">66</span><br><span class="line-number">67</span><br><span class="line-number">68</span><br><span class="line-number">69</span><br><span class="line-number">70</span><br><span class="line-number">71</span><br><span class="line-number">72</span><br><span class="line-number">73</span><br><span class="line-number">74</span><br><span class="line-number">75</span><br><span class="line-number">76</span><br><span class="line-number">77</span><br><span class="line-number">78</span><br><span class="line-number">79</span><br><span class="line-number">80</span><br><span class="line-number">81</span><br><span class="line-number">82</span><br><span class="line-number">83</span><br><span class="line-number">84</span><br><span class="line-number">85</span><br><span class="line-number">86</span><br><span class="line-number">87</span><br><span class="line-number">88</span><br><span class="line-number">89</span><br><span class="line-number">90</span><br><span class="line-number">91</span><br><span class="line-number">92</span><br><span class="line-number">93</span><br><span class="line-number">94</span><br><span class="line-number">95</span><br><span class="line-number">96</span><br><span class="line-number">97</span><br><span class="line-number">98</span><br><span class="line-number">99</span><br><span class="line-number">100</span><br><span class="line-number">101</span><br><span class="line-number">102</span><br><span class="line-number">103</span><br><span class="line-number">104</span><br><span class="line-number">105</span><br><span class="line-number">106</span><br><span class="line-number">107</span><br><span class="line-number">108</span><br><span class="line-number">109</span><br><span class="line-number">110</span><br><span class="line-number">111</span><br><span class="line-number">112</span><br><span class="line-number">113</span><br></div></div></li><li><p>do_anonymous_page</p><div class="language-c ext-c line-numbers-mode"><pre class="language-c"><code>
<span class="token comment">/*
 * We enter with non-exclusive mmap_lock (to exclude vma changes,
 * but allow concurrent faults), and pte mapped but not yet locked.
 * We return with mmap_lock still held, but pte unmapped and unlocked.
 */</span>
<span class="token keyword">static</span> <span class="token class-name">vm_fault_t</span> <span class="token function">do_anonymous_page</span><span class="token punctuation">(</span><span class="token keyword">struct</span> <span class="token class-name">vm_fault</span> <span class="token operator">*</span>vmf<span class="token punctuation">)</span>
<span class="token punctuation">{</span>
	<span class="token keyword">struct</span> <span class="token class-name">vm_area_struct</span> <span class="token operator">*</span>vma <span class="token operator">=</span> vmf<span class="token operator">-&gt;</span>vma<span class="token punctuation">;</span>
	<span class="token keyword">struct</span> <span class="token class-name">page</span> <span class="token operator">*</span>page<span class="token punctuation">;</span>
	<span class="token class-name">vm_fault_t</span> ret <span class="token operator">=</span> <span class="token number">0</span><span class="token punctuation">;</span>
	<span class="token class-name">pte_t</span> entry<span class="token punctuation">;</span>

	<span class="token comment">/* File mapping without -&gt;vm_ops ? */</span>
	<span class="token keyword">if</span> <span class="token punctuation">(</span>vma<span class="token operator">-&gt;</span>vm_flags <span class="token operator">&amp;</span> VM_SHARED<span class="token punctuation">)</span>
		<span class="token keyword">return</span> VM_FAULT_SIGBUS<span class="token punctuation">;</span>

	<span class="token comment">/*
	 * Use pte_alloc() instead of pte_alloc_map().  We can&#39;t run
	 * pte_offset_map() on pmds where a huge pmd might be created
	 * from a different thread.
	 *
	 * pte_alloc_map() is safe to use under mmap_write_lock(mm) or when
	 * parallel threads are excluded by other means.
	 *
	 * Here we only have mmap_read_lock(mm).
	 */</span>
	<span class="token keyword">if</span> <span class="token punctuation">(</span><span class="token function">pte_alloc</span><span class="token punctuation">(</span>vma<span class="token operator">-&gt;</span>vm_mm<span class="token punctuation">,</span> vmf<span class="token operator">-&gt;</span>pmd<span class="token punctuation">)</span><span class="token punctuation">)</span>
		<span class="token keyword">return</span> VM_FAULT_OOM<span class="token punctuation">;</span>

	<span class="token comment">/* See comment in handle_pte_fault() */</span>
	<span class="token keyword">if</span> <span class="token punctuation">(</span><span class="token function">unlikely</span><span class="token punctuation">(</span><span class="token function">pmd_trans_unstable</span><span class="token punctuation">(</span>vmf<span class="token operator">-&gt;</span>pmd<span class="token punctuation">)</span><span class="token punctuation">)</span><span class="token punctuation">)</span>
		<span class="token keyword">return</span> <span class="token number">0</span><span class="token punctuation">;</span>

	<span class="token comment">/* Use the zero-page for reads */</span>
	<span class="token keyword">if</span> <span class="token punctuation">(</span><span class="token operator">!</span><span class="token punctuation">(</span>vmf<span class="token operator">-&gt;</span>flags <span class="token operator">&amp;</span> FAULT_FLAG_WRITE<span class="token punctuation">)</span> <span class="token operator">&amp;&amp;</span>
			<span class="token operator">!</span><span class="token function">mm_forbids_zeropage</span><span class="token punctuation">(</span>vma<span class="token operator">-&gt;</span>vm_mm<span class="token punctuation">)</span><span class="token punctuation">)</span> <span class="token punctuation">{</span>
		entry <span class="token operator">=</span> <span class="token function">pte_mkspecial</span><span class="token punctuation">(</span><span class="token function">pfn_pte</span><span class="token punctuation">(</span><span class="token function">my_zero_pfn</span><span class="token punctuation">(</span>vmf<span class="token operator">-&gt;</span>address<span class="token punctuation">)</span><span class="token punctuation">,</span>
						vma<span class="token operator">-&gt;</span>vm_page_prot<span class="token punctuation">)</span><span class="token punctuation">)</span><span class="token punctuation">;</span>
		vmf<span class="token operator">-&gt;</span>pte <span class="token operator">=</span> <span class="token function">pte_offset_map_lock</span><span class="token punctuation">(</span>vma<span class="token operator">-&gt;</span>vm_mm<span class="token punctuation">,</span> vmf<span class="token operator">-&gt;</span>pmd<span class="token punctuation">,</span>
				vmf<span class="token operator">-&gt;</span>address<span class="token punctuation">,</span> <span class="token operator">&amp;</span>vmf<span class="token operator">-&gt;</span>ptl<span class="token punctuation">)</span><span class="token punctuation">;</span>
		<span class="token keyword">if</span> <span class="token punctuation">(</span><span class="token operator">!</span><span class="token function">pte_none</span><span class="token punctuation">(</span><span class="token operator">*</span>vmf<span class="token operator">-&gt;</span>pte<span class="token punctuation">)</span><span class="token punctuation">)</span> <span class="token punctuation">{</span>
			<span class="token function">update_mmu_tlb</span><span class="token punctuation">(</span>vma<span class="token punctuation">,</span> vmf<span class="token operator">-&gt;</span>address<span class="token punctuation">,</span> vmf<span class="token operator">-&gt;</span>pte<span class="token punctuation">)</span><span class="token punctuation">;</span>
			<span class="token keyword">goto</span> unlock<span class="token punctuation">;</span>
		<span class="token punctuation">}</span>
		ret <span class="token operator">=</span> <span class="token function">check_stable_address_space</span><span class="token punctuation">(</span>vma<span class="token operator">-&gt;</span>vm_mm<span class="token punctuation">)</span><span class="token punctuation">;</span>
		<span class="token keyword">if</span> <span class="token punctuation">(</span>ret<span class="token punctuation">)</span>
			<span class="token keyword">goto</span> unlock<span class="token punctuation">;</span>
		<span class="token comment">/* Deliver the page fault to userland, check inside PT lock */</span>
		<span class="token keyword">if</span> <span class="token punctuation">(</span><span class="token function">userfaultfd_missing</span><span class="token punctuation">(</span>vma<span class="token punctuation">)</span><span class="token punctuation">)</span> <span class="token punctuation">{</span>
			<span class="token function">pte_unmap_unlock</span><span class="token punctuation">(</span>vmf<span class="token operator">-&gt;</span>pte<span class="token punctuation">,</span> vmf<span class="token operator">-&gt;</span>ptl<span class="token punctuation">)</span><span class="token punctuation">;</span>
			<span class="token keyword">return</span> <span class="token function">handle_userfault</span><span class="token punctuation">(</span>vmf<span class="token punctuation">,</span> VM_UFFD_MISSING<span class="token punctuation">)</span><span class="token punctuation">;</span>
		<span class="token punctuation">}</span>
		<span class="token keyword">goto</span> setpte<span class="token punctuation">;</span>
	<span class="token punctuation">}</span>

	<span class="token comment">/* Allocate our own private page. */</span>
	<span class="token keyword">if</span> <span class="token punctuation">(</span><span class="token function">unlikely</span><span class="token punctuation">(</span><span class="token function">anon_vma_prepare</span><span class="token punctuation">(</span>vma<span class="token punctuation">)</span><span class="token punctuation">)</span><span class="token punctuation">)</span>
		<span class="token keyword">goto</span> oom<span class="token punctuation">;</span>
	page <span class="token operator">=</span> <span class="token function">alloc_zeroed_user_highpage_movable</span><span class="token punctuation">(</span>vma<span class="token punctuation">,</span> vmf<span class="token operator">-&gt;</span>address<span class="token punctuation">)</span><span class="token punctuation">;</span>
	<span class="token keyword">if</span> <span class="token punctuation">(</span><span class="token operator">!</span>page<span class="token punctuation">)</span>
		<span class="token keyword">goto</span> oom<span class="token punctuation">;</span>

	<span class="token keyword">if</span> <span class="token punctuation">(</span><span class="token function">mem_cgroup_charge</span><span class="token punctuation">(</span>page<span class="token punctuation">,</span> vma<span class="token operator">-&gt;</span>vm_mm<span class="token punctuation">,</span> GFP_KERNEL<span class="token punctuation">)</span><span class="token punctuation">)</span>
		<span class="token keyword">goto</span> oom_free_page<span class="token punctuation">;</span>
	<span class="token function">cgroup_throttle_swaprate</span><span class="token punctuation">(</span>page<span class="token punctuation">,</span> GFP_KERNEL<span class="token punctuation">)</span><span class="token punctuation">;</span>

	<span class="token comment">/*
	 * The memory barrier inside __SetPageUptodate makes sure that
	 * preceding stores to the page contents become visible before
	 * the set_pte_at() write.
	 */</span>
	<span class="token function">__SetPageUptodate</span><span class="token punctuation">(</span>page<span class="token punctuation">)</span><span class="token punctuation">;</span>

	entry <span class="token operator">=</span> <span class="token function">mk_pte</span><span class="token punctuation">(</span>page<span class="token punctuation">,</span> vma<span class="token operator">-&gt;</span>vm_page_prot<span class="token punctuation">)</span><span class="token punctuation">;</span>
	entry <span class="token operator">=</span> <span class="token function">pte_sw_mkyoung</span><span class="token punctuation">(</span>entry<span class="token punctuation">)</span><span class="token punctuation">;</span>
	<span class="token keyword">if</span> <span class="token punctuation">(</span>vma<span class="token operator">-&gt;</span>vm_flags <span class="token operator">&amp;</span> VM_WRITE<span class="token punctuation">)</span>
		entry <span class="token operator">=</span> <span class="token function">pte_mkwrite</span><span class="token punctuation">(</span><span class="token function">pte_mkdirty</span><span class="token punctuation">(</span>entry<span class="token punctuation">)</span><span class="token punctuation">)</span><span class="token punctuation">;</span>

	vmf<span class="token operator">-&gt;</span>pte <span class="token operator">=</span> <span class="token function">pte_offset_map_lock</span><span class="token punctuation">(</span>vma<span class="token operator">-&gt;</span>vm_mm<span class="token punctuation">,</span> vmf<span class="token operator">-&gt;</span>pmd<span class="token punctuation">,</span> vmf<span class="token operator">-&gt;</span>address<span class="token punctuation">,</span>
			<span class="token operator">&amp;</span>vmf<span class="token operator">-&gt;</span>ptl<span class="token punctuation">)</span><span class="token punctuation">;</span>
	<span class="token keyword">if</span> <span class="token punctuation">(</span><span class="token operator">!</span><span class="token function">pte_none</span><span class="token punctuation">(</span><span class="token operator">*</span>vmf<span class="token operator">-&gt;</span>pte<span class="token punctuation">)</span><span class="token punctuation">)</span> <span class="token punctuation">{</span>
		<span class="token function">update_mmu_cache</span><span class="token punctuation">(</span>vma<span class="token punctuation">,</span> vmf<span class="token operator">-&gt;</span>address<span class="token punctuation">,</span> vmf<span class="token operator">-&gt;</span>pte<span class="token punctuation">)</span><span class="token punctuation">;</span>
		<span class="token keyword">goto</span> release<span class="token punctuation">;</span>
	<span class="token punctuation">}</span>

	ret <span class="token operator">=</span> <span class="token function">check_stable_address_space</span><span class="token punctuation">(</span>vma<span class="token operator">-&gt;</span>vm_mm<span class="token punctuation">)</span><span class="token punctuation">;</span>
	<span class="token keyword">if</span> <span class="token punctuation">(</span>ret<span class="token punctuation">)</span>
		<span class="token keyword">goto</span> release<span class="token punctuation">;</span>

	<span class="token comment">/* Deliver the page fault to userland, check inside PT lock */</span>
	<span class="token keyword">if</span> <span class="token punctuation">(</span><span class="token function">userfaultfd_missing</span><span class="token punctuation">(</span>vma<span class="token punctuation">)</span><span class="token punctuation">)</span> <span class="token punctuation">{</span>
		<span class="token function">pte_unmap_unlock</span><span class="token punctuation">(</span>vmf<span class="token operator">-&gt;</span>pte<span class="token punctuation">,</span> vmf<span class="token operator">-&gt;</span>ptl<span class="token punctuation">)</span><span class="token punctuation">;</span>
		<span class="token function">put_page</span><span class="token punctuation">(</span>page<span class="token punctuation">)</span><span class="token punctuation">;</span>
		<span class="token keyword">return</span> <span class="token function">handle_userfault</span><span class="token punctuation">(</span>vmf<span class="token punctuation">,</span> VM_UFFD_MISSING<span class="token punctuation">)</span><span class="token punctuation">;</span>
	<span class="token punctuation">}</span>

	<span class="token function">inc_mm_counter_fast</span><span class="token punctuation">(</span>vma<span class="token operator">-&gt;</span>vm_mm<span class="token punctuation">,</span> MM_ANONPAGES<span class="token punctuation">)</span><span class="token punctuation">;</span>
	<span class="token function">page_add_new_anon_rmap</span><span class="token punctuation">(</span>page<span class="token punctuation">,</span> vma<span class="token punctuation">,</span> vmf<span class="token operator">-&gt;</span>address<span class="token punctuation">,</span> false<span class="token punctuation">)</span><span class="token punctuation">;</span>
	<span class="token function">lru_cache_add_inactive_or_unevictable</span><span class="token punctuation">(</span>page<span class="token punctuation">,</span> vma<span class="token punctuation">)</span><span class="token punctuation">;</span>
setpte<span class="token operator">:</span>
	<span class="token function">set_pte_at</span><span class="token punctuation">(</span>vma<span class="token operator">-&gt;</span>vm_mm<span class="token punctuation">,</span> vmf<span class="token operator">-&gt;</span>address<span class="token punctuation">,</span> vmf<span class="token operator">-&gt;</span>pte<span class="token punctuation">,</span> entry<span class="token punctuation">)</span><span class="token punctuation">;</span>

	<span class="token comment">/* No need to invalidate - it was non-present before */</span>
	<span class="token function">update_mmu_cache</span><span class="token punctuation">(</span>vma<span class="token punctuation">,</span> vmf<span class="token operator">-&gt;</span>address<span class="token punctuation">,</span> vmf<span class="token operator">-&gt;</span>pte<span class="token punctuation">)</span><span class="token punctuation">;</span>
unlock<span class="token operator">:</span>
	<span class="token function">pte_unmap_unlock</span><span class="token punctuation">(</span>vmf<span class="token operator">-&gt;</span>pte<span class="token punctuation">,</span> vmf<span class="token operator">-&gt;</span>ptl<span class="token punctuation">)</span><span class="token punctuation">;</span>
	<span class="token keyword">return</span> ret<span class="token punctuation">;</span>
release<span class="token operator">:</span>
	<span class="token function">put_page</span><span class="token punctuation">(</span>page<span class="token punctuation">)</span><span class="token punctuation">;</span>
	<span class="token keyword">goto</span> unlock<span class="token punctuation">;</span>
oom_free_page<span class="token operator">:</span>
	<span class="token function">put_page</span><span class="token punctuation">(</span>page<span class="token punctuation">)</span><span class="token punctuation">;</span>
oom<span class="token operator">:</span>
	<span class="token keyword">return</span> VM_FAULT_OOM<span class="token punctuation">;</span>
<span class="token punctuation">}</span>
</code></pre><div class="line-numbers" aria-hidden="true"><span class="line-number">1</span><br><span class="line-number">2</span><br><span class="line-number">3</span><br><span class="line-number">4</span><br><span class="line-number">5</span><br><span class="line-number">6</span><br><span class="line-number">7</span><br><span class="line-number">8</span><br><span class="line-number">9</span><br><span class="line-number">10</span><br><span class="line-number">11</span><br><span class="line-number">12</span><br><span class="line-number">13</span><br><span class="line-number">14</span><br><span class="line-number">15</span><br><span class="line-number">16</span><br><span class="line-number">17</span><br><span class="line-number">18</span><br><span class="line-number">19</span><br><span class="line-number">20</span><br><span class="line-number">21</span><br><span class="line-number">22</span><br><span class="line-number">23</span><br><span class="line-number">24</span><br><span class="line-number">25</span><br><span class="line-number">26</span><br><span class="line-number">27</span><br><span class="line-number">28</span><br><span class="line-number">29</span><br><span class="line-number">30</span><br><span class="line-number">31</span><br><span class="line-number">32</span><br><span class="line-number">33</span><br><span class="line-number">34</span><br><span class="line-number">35</span><br><span class="line-number">36</span><br><span class="line-number">37</span><br><span class="line-number">38</span><br><span class="line-number">39</span><br><span class="line-number">40</span><br><span class="line-number">41</span><br><span class="line-number">42</span><br><span class="line-number">43</span><br><span class="line-number">44</span><br><span class="line-number">45</span><br><span class="line-number">46</span><br><span class="line-number">47</span><br><span class="line-number">48</span><br><span class="line-number">49</span><br><span class="line-number">50</span><br><span class="line-number">51</span><br><span class="line-number">52</span><br><span class="line-number">53</span><br><span class="line-number">54</span><br><span class="line-number">55</span><br><span class="line-number">56</span><br><span class="line-number">57</span><br><span class="line-number">58</span><br><span class="line-number">59</span><br><span class="line-number">60</span><br><span class="line-number">61</span><br><span class="line-number">62</span><br><span class="line-number">63</span><br><span class="line-number">64</span><br><span class="line-number">65</span><br><span class="line-number">66</span><br><span class="line-number">67</span><br><span class="line-number">68</span><br><span class="line-number">69</span><br><span class="line-number">70</span><br><span class="line-number">71</span><br><span class="line-number">72</span><br><span class="line-number">73</span><br><span class="line-number">74</span><br><span class="line-number">75</span><br><span class="line-number">76</span><br><span class="line-number">77</span><br><span class="line-number">78</span><br><span class="line-number">79</span><br><span class="line-number">80</span><br><span class="line-number">81</span><br><span class="line-number">82</span><br><span class="line-number">83</span><br><span class="line-number">84</span><br><span class="line-number">85</span><br><span class="line-number">86</span><br><span class="line-number">87</span><br><span class="line-number">88</span><br><span class="line-number">89</span><br><span class="line-number">90</span><br><span class="line-number">91</span><br><span class="line-number">92</span><br><span class="line-number">93</span><br><span class="line-number">94</span><br><span class="line-number">95</span><br><span class="line-number">96</span><br><span class="line-number">97</span><br><span class="line-number">98</span><br><span class="line-number">99</span><br><span class="line-number">100</span><br><span class="line-number">101</span><br><span class="line-number">102</span><br><span class="line-number">103</span><br><span class="line-number">104</span><br><span class="line-number">105</span><br><span class="line-number">106</span><br><span class="line-number">107</span><br><span class="line-number">108</span><br><span class="line-number">109</span><br><span class="line-number">110</span><br><span class="line-number">111</span><br><span class="line-number">112</span><br><span class="line-number">113</span><br><span class="line-number">114</span><br><span class="line-number">115</span><br><span class="line-number">116</span><br></div></div></li><li><p>alloc_zeroed_user_highpage_movable</p><div class="language-c ext-c line-numbers-mode"><pre class="language-c"><code>
<span class="token comment">/**
 * alloc_zeroed_user_highpage_movable - Allocate a zeroed HIGHMEM page for a VMA that the caller knows can move
 * @vma: The VMA the page is to be allocated for
 * @vaddr: The virtual address the page will be inserted into
 *
 * This function will allocate a page for a VMA that the caller knows will
 * be able to migrate in the future using move_pages() or reclaimed
 *
 * An architecture may override this function by defining
 * __HAVE_ARCH_ALLOC_ZEROED_USER_HIGHPAGE_MOVABLE and providing their own
 * implementation.
 */</span>
<span class="token keyword">static</span> <span class="token keyword">inline</span> <span class="token keyword">struct</span> <span class="token class-name">page</span> <span class="token operator">*</span>
<span class="token function">alloc_zeroed_user_highpage_movable</span><span class="token punctuation">(</span><span class="token keyword">struct</span> <span class="token class-name">vm_area_struct</span> <span class="token operator">*</span>vma<span class="token punctuation">,</span>
				   <span class="token keyword">unsigned</span> <span class="token keyword">long</span> vaddr<span class="token punctuation">)</span>
<span class="token punctuation">{</span>
	<span class="token keyword">struct</span> <span class="token class-name">page</span> <span class="token operator">*</span>page <span class="token operator">=</span> <span class="token function">alloc_page_vma</span><span class="token punctuation">(</span>GFP_HIGHUSER_MOVABLE<span class="token punctuation">,</span> vma<span class="token punctuation">,</span> vaddr<span class="token punctuation">)</span><span class="token punctuation">;</span>

	<span class="token keyword">if</span> <span class="token punctuation">(</span>page<span class="token punctuation">)</span>
		<span class="token function">clear_user_highpage</span><span class="token punctuation">(</span>page<span class="token punctuation">,</span> vaddr<span class="token punctuation">)</span><span class="token punctuation">;</span>

	<span class="token keyword">return</span> page<span class="token punctuation">;</span>
<span class="token punctuation">}</span>
</code></pre><div class="line-numbers" aria-hidden="true"><span class="line-number">1</span><br><span class="line-number">2</span><br><span class="line-number">3</span><br><span class="line-number">4</span><br><span class="line-number">5</span><br><span class="line-number">6</span><br><span class="line-number">7</span><br><span class="line-number">8</span><br><span class="line-number">9</span><br><span class="line-number">10</span><br><span class="line-number">11</span><br><span class="line-number">12</span><br><span class="line-number">13</span><br><span class="line-number">14</span><br><span class="line-number">15</span><br><span class="line-number">16</span><br><span class="line-number">17</span><br><span class="line-number">18</span><br><span class="line-number">19</span><br><span class="line-number">20</span><br><span class="line-number">21</span><br><span class="line-number">22</span><br><span class="line-number">23</span><br><span class="line-number">24</span><br></div></div></li><li><p>alloc_page_vma</p><div class="language-c ext-c line-numbers-mode"><pre class="language-c"><code>
<span class="token comment">/**
 * alloc_pages_vma - Allocate a page for a VMA.
 * @gfp: GFP flags.
 * @order: Order of the GFP allocation.
 * @vma: Pointer to VMA or NULL if not available.
 * @addr: Virtual address of the allocation.  Must be inside @vma.
 * @node: Which node to prefer for allocation (modulo policy).
 * @hugepage: For hugepages try only the preferred node if possible.
 *
 * Allocate a page for a specific address in @vma, using the appropriate
 * NUMA policy.  When @vma is not NULL the caller must hold the mmap_lock
 * of the mm_struct of the VMA to prevent it from going away.  Should be
 * used for all allocations for pages that will be mapped into user space.
 *
 * Return: The page on success or NULL if allocation fails.
 */</span>
<span class="token keyword">struct</span> <span class="token class-name">page</span> <span class="token operator">*</span><span class="token function">alloc_pages_vma</span><span class="token punctuation">(</span><span class="token class-name">gfp_t</span> gfp<span class="token punctuation">,</span> <span class="token keyword">int</span> order<span class="token punctuation">,</span> <span class="token keyword">struct</span> <span class="token class-name">vm_area_struct</span> <span class="token operator">*</span>vma<span class="token punctuation">,</span>
		<span class="token keyword">unsigned</span> <span class="token keyword">long</span> addr<span class="token punctuation">,</span> <span class="token keyword">int</span> node<span class="token punctuation">,</span> bool hugepage<span class="token punctuation">)</span>
<span class="token punctuation">{</span>
	<span class="token keyword">struct</span> <span class="token class-name">mempolicy</span> <span class="token operator">*</span>pol<span class="token punctuation">;</span>
	<span class="token keyword">struct</span> <span class="token class-name">page</span> <span class="token operator">*</span>page<span class="token punctuation">;</span>
	<span class="token keyword">int</span> preferred_nid<span class="token punctuation">;</span>
	<span class="token class-name">nodemask_t</span> <span class="token operator">*</span>nmask<span class="token punctuation">;</span>

	pol <span class="token operator">=</span> <span class="token function">get_vma_policy</span><span class="token punctuation">(</span>vma<span class="token punctuation">,</span> addr<span class="token punctuation">)</span><span class="token punctuation">;</span>

	<span class="token keyword">if</span> <span class="token punctuation">(</span>pol<span class="token operator">-&gt;</span>mode <span class="token operator">==</span> MPOL_INTERLEAVE<span class="token punctuation">)</span> <span class="token punctuation">{</span>
		<span class="token keyword">unsigned</span> nid<span class="token punctuation">;</span>

		nid <span class="token operator">=</span> <span class="token function">interleave_nid</span><span class="token punctuation">(</span>pol<span class="token punctuation">,</span> vma<span class="token punctuation">,</span> addr<span class="token punctuation">,</span> PAGE_SHIFT <span class="token operator">+</span> order<span class="token punctuation">)</span><span class="token punctuation">;</span>
		<span class="token function">mpol_cond_put</span><span class="token punctuation">(</span>pol<span class="token punctuation">)</span><span class="token punctuation">;</span>
		page <span class="token operator">=</span> <span class="token function">alloc_page_interleave</span><span class="token punctuation">(</span>gfp<span class="token punctuation">,</span> order<span class="token punctuation">,</span> nid<span class="token punctuation">)</span><span class="token punctuation">;</span>
		<span class="token keyword">goto</span> out<span class="token punctuation">;</span>
	<span class="token punctuation">}</span>

	<span class="token keyword">if</span> <span class="token punctuation">(</span>pol<span class="token operator">-&gt;</span>mode <span class="token operator">==</span> MPOL_PREFERRED_MANY<span class="token punctuation">)</span> <span class="token punctuation">{</span>
		page <span class="token operator">=</span> <span class="token function">alloc_pages_preferred_many</span><span class="token punctuation">(</span>gfp<span class="token punctuation">,</span> order<span class="token punctuation">,</span> node<span class="token punctuation">,</span> pol<span class="token punctuation">)</span><span class="token punctuation">;</span>
		<span class="token function">mpol_cond_put</span><span class="token punctuation">(</span>pol<span class="token punctuation">)</span><span class="token punctuation">;</span>
		<span class="token keyword">goto</span> out<span class="token punctuation">;</span>
	<span class="token punctuation">}</span>

	<span class="token keyword">if</span> <span class="token punctuation">(</span><span class="token function">unlikely</span><span class="token punctuation">(</span><span class="token function">IS_ENABLED</span><span class="token punctuation">(</span>CONFIG_TRANSPARENT_HUGEPAGE<span class="token punctuation">)</span> <span class="token operator">&amp;&amp;</span> hugepage<span class="token punctuation">)</span><span class="token punctuation">)</span> <span class="token punctuation">{</span>
		<span class="token keyword">int</span> hpage_node <span class="token operator">=</span> node<span class="token punctuation">;</span>

		<span class="token comment">/*
		 * For hugepage allocation and non-interleave policy which
		 * allows the current node (or other explicitly preferred
		 * node) we only try to allocate from the current/preferred
		 * node and don&#39;t fall back to other nodes, as the cost of
		 * remote accesses would likely offset THP benefits.
		 *
		 * If the policy is interleave or does not allow the current
		 * node in its nodemask, we allocate the standard way.
		 */</span>
		<span class="token keyword">if</span> <span class="token punctuation">(</span>pol<span class="token operator">-&gt;</span>mode <span class="token operator">==</span> MPOL_PREFERRED<span class="token punctuation">)</span>
			hpage_node <span class="token operator">=</span> <span class="token function">first_node</span><span class="token punctuation">(</span>pol<span class="token operator">-&gt;</span>nodes<span class="token punctuation">)</span><span class="token punctuation">;</span>

		nmask <span class="token operator">=</span> <span class="token function">policy_nodemask</span><span class="token punctuation">(</span>gfp<span class="token punctuation">,</span> pol<span class="token punctuation">)</span><span class="token punctuation">;</span>
		<span class="token keyword">if</span> <span class="token punctuation">(</span><span class="token operator">!</span>nmask <span class="token operator">||</span> <span class="token function">node_isset</span><span class="token punctuation">(</span>hpage_node<span class="token punctuation">,</span> <span class="token operator">*</span>nmask<span class="token punctuation">)</span><span class="token punctuation">)</span> <span class="token punctuation">{</span>
			<span class="token function">mpol_cond_put</span><span class="token punctuation">(</span>pol<span class="token punctuation">)</span><span class="token punctuation">;</span>
			<span class="token comment">/*
			 * First, try to allocate THP only on local node, but
			 * don&#39;t reclaim unnecessarily, just compact.
			 */</span>
			page <span class="token operator">=</span> <span class="token function">__alloc_pages_node</span><span class="token punctuation">(</span>hpage_node<span class="token punctuation">,</span>
				gfp <span class="token operator">|</span> __GFP_THISNODE <span class="token operator">|</span> __GFP_NORETRY<span class="token punctuation">,</span> order<span class="token punctuation">)</span><span class="token punctuation">;</span>

			<span class="token comment">/*
			 * If hugepage allocations are configured to always
			 * synchronous compact or the vma has been madvised
			 * to prefer hugepage backing, retry allowing remote
			 * memory with both reclaim and compact as well.
			 */</span>
			<span class="token keyword">if</span> <span class="token punctuation">(</span><span class="token operator">!</span>page <span class="token operator">&amp;&amp;</span> <span class="token punctuation">(</span>gfp <span class="token operator">&amp;</span> __GFP_DIRECT_RECLAIM<span class="token punctuation">)</span><span class="token punctuation">)</span>
				page <span class="token operator">=</span> <span class="token function">__alloc_pages_node</span><span class="token punctuation">(</span>hpage_node<span class="token punctuation">,</span>
								gfp<span class="token punctuation">,</span> order<span class="token punctuation">)</span><span class="token punctuation">;</span>

			<span class="token keyword">goto</span> out<span class="token punctuation">;</span>
		<span class="token punctuation">}</span>
	<span class="token punctuation">}</span>

	nmask <span class="token operator">=</span> <span class="token function">policy_nodemask</span><span class="token punctuation">(</span>gfp<span class="token punctuation">,</span> pol<span class="token punctuation">)</span><span class="token punctuation">;</span>
	preferred_nid <span class="token operator">=</span> <span class="token function">policy_node</span><span class="token punctuation">(</span>gfp<span class="token punctuation">,</span> pol<span class="token punctuation">,</span> node<span class="token punctuation">)</span><span class="token punctuation">;</span>
	page <span class="token operator">=</span> <span class="token function">__alloc_pages</span><span class="token punctuation">(</span>gfp<span class="token punctuation">,</span> order<span class="token punctuation">,</span> preferred_nid<span class="token punctuation">,</span> nmask<span class="token punctuation">)</span><span class="token punctuation">;</span>
	<span class="token function">mpol_cond_put</span><span class="token punctuation">(</span>pol<span class="token punctuation">)</span><span class="token punctuation">;</span>
out<span class="token operator">:</span>
	<span class="token keyword">return</span> page<span class="token punctuation">;</span>
<span class="token punctuation">}</span>
<span class="token function">EXPORT_SYMBOL</span><span class="token punctuation">(</span>alloc_pages_vma<span class="token punctuation">)</span><span class="token punctuation">;</span>
</code></pre><div class="line-numbers" aria-hidden="true"><span class="line-number">1</span><br><span class="line-number">2</span><br><span class="line-number">3</span><br><span class="line-number">4</span><br><span class="line-number">5</span><br><span class="line-number">6</span><br><span class="line-number">7</span><br><span class="line-number">8</span><br><span class="line-number">9</span><br><span class="line-number">10</span><br><span class="line-number">11</span><br><span class="line-number">12</span><br><span class="line-number">13</span><br><span class="line-number">14</span><br><span class="line-number">15</span><br><span class="line-number">16</span><br><span class="line-number">17</span><br><span class="line-number">18</span><br><span class="line-number">19</span><br><span class="line-number">20</span><br><span class="line-number">21</span><br><span class="line-number">22</span><br><span class="line-number">23</span><br><span class="line-number">24</span><br><span class="line-number">25</span><br><span class="line-number">26</span><br><span class="line-number">27</span><br><span class="line-number">28</span><br><span class="line-number">29</span><br><span class="line-number">30</span><br><span class="line-number">31</span><br><span class="line-number">32</span><br><span class="line-number">33</span><br><span class="line-number">34</span><br><span class="line-number">35</span><br><span class="line-number">36</span><br><span class="line-number">37</span><br><span class="line-number">38</span><br><span class="line-number">39</span><br><span class="line-number">40</span><br><span class="line-number">41</span><br><span class="line-number">42</span><br><span class="line-number">43</span><br><span class="line-number">44</span><br><span class="line-number">45</span><br><span class="line-number">46</span><br><span class="line-number">47</span><br><span class="line-number">48</span><br><span class="line-number">49</span><br><span class="line-number">50</span><br><span class="line-number">51</span><br><span class="line-number">52</span><br><span class="line-number">53</span><br><span class="line-number">54</span><br><span class="line-number">55</span><br><span class="line-number">56</span><br><span class="line-number">57</span><br><span class="line-number">58</span><br><span class="line-number">59</span><br><span class="line-number">60</span><br><span class="line-number">61</span><br><span class="line-number">62</span><br><span class="line-number">63</span><br><span class="line-number">64</span><br><span class="line-number">65</span><br><span class="line-number">66</span><br><span class="line-number">67</span><br><span class="line-number">68</span><br><span class="line-number">69</span><br><span class="line-number">70</span><br><span class="line-number">71</span><br><span class="line-number">72</span><br><span class="line-number">73</span><br><span class="line-number">74</span><br><span class="line-number">75</span><br><span class="line-number">76</span><br><span class="line-number">77</span><br><span class="line-number">78</span><br><span class="line-number">79</span><br><span class="line-number">80</span><br><span class="line-number">81</span><br><span class="line-number">82</span><br><span class="line-number">83</span><br><span class="line-number">84</span><br><span class="line-number">85</span><br><span class="line-number">86</span><br><span class="line-number">87</span><br><span class="line-number">88</span><br><span class="line-number">89</span><br><span class="line-number">90</span><br></div></div></li><li><p>__alloc_pages</p><div class="language-c ext-c line-numbers-mode"><pre class="language-c"><code>
<span class="token comment">/*
 * This is the &#39;heart&#39; of the zoned buddy allocator.
 */</span>
<span class="token keyword">struct</span> <span class="token class-name">page</span> <span class="token operator">*</span><span class="token function">__alloc_pages</span><span class="token punctuation">(</span><span class="token class-name">gfp_t</span> gfp<span class="token punctuation">,</span> <span class="token keyword">unsigned</span> <span class="token keyword">int</span> order<span class="token punctuation">,</span> <span class="token keyword">int</span> preferred_nid<span class="token punctuation">,</span>
							<span class="token class-name">nodemask_t</span> <span class="token operator">*</span>nodemask<span class="token punctuation">)</span>
<span class="token punctuation">{</span>
	<span class="token keyword">struct</span> <span class="token class-name">page</span> <span class="token operator">*</span>page<span class="token punctuation">;</span>
	<span class="token keyword">unsigned</span> <span class="token keyword">int</span> alloc_flags <span class="token operator">=</span> ALLOC_WMARK_LOW<span class="token punctuation">;</span>
	<span class="token class-name">gfp_t</span> alloc_gfp<span class="token punctuation">;</span> <span class="token comment">/* The gfp_t that was actually used for allocation */</span>
	<span class="token keyword">struct</span> <span class="token class-name">alloc_context</span> ac <span class="token operator">=</span> <span class="token punctuation">{</span> <span class="token punctuation">}</span><span class="token punctuation">;</span>

	<span class="token comment">/*
	 * There are several places where we assume that the order value is sane
	 * so bail out early if the request is out of bound.
	 */</span>
	<span class="token keyword">if</span> <span class="token punctuation">(</span><span class="token function">unlikely</span><span class="token punctuation">(</span>order <span class="token operator">&gt;=</span> MAX_ORDER<span class="token punctuation">)</span><span class="token punctuation">)</span> <span class="token punctuation">{</span>
		<span class="token function">WARN_ON_ONCE</span><span class="token punctuation">(</span><span class="token operator">!</span><span class="token punctuation">(</span>gfp <span class="token operator">&amp;</span> __GFP_NOWARN<span class="token punctuation">)</span><span class="token punctuation">)</span><span class="token punctuation">;</span>
		<span class="token keyword">return</span> <span class="token constant">NULL</span><span class="token punctuation">;</span>
	<span class="token punctuation">}</span>

	gfp <span class="token operator">&amp;=</span> gfp_allowed_mask<span class="token punctuation">;</span>
	<span class="token comment">/*
	 * Apply scoped allocation constraints. This is mainly about GFP_NOFS
	 * resp. GFP_NOIO which has to be inherited for all allocation requests
	 * from a particular context which has been marked by
	 * memalloc_no{fs,io}_{save,restore}. And PF_MEMALLOC_PIN which ensures
	 * movable zones are not used during allocation.
	 */</span>
	gfp <span class="token operator">=</span> <span class="token function">current_gfp_context</span><span class="token punctuation">(</span>gfp<span class="token punctuation">)</span><span class="token punctuation">;</span>
	alloc_gfp <span class="token operator">=</span> gfp<span class="token punctuation">;</span>
	<span class="token keyword">if</span> <span class="token punctuation">(</span><span class="token operator">!</span><span class="token function">prepare_alloc_pages</span><span class="token punctuation">(</span>gfp<span class="token punctuation">,</span> order<span class="token punctuation">,</span> preferred_nid<span class="token punctuation">,</span> nodemask<span class="token punctuation">,</span> <span class="token operator">&amp;</span>ac<span class="token punctuation">,</span>
			<span class="token operator">&amp;</span>alloc_gfp<span class="token punctuation">,</span> <span class="token operator">&amp;</span>alloc_flags<span class="token punctuation">)</span><span class="token punctuation">)</span>
		<span class="token keyword">return</span> <span class="token constant">NULL</span><span class="token punctuation">;</span>

	<span class="token comment">/*
	 * Forbid the first pass from falling back to types that fragment
	 * memory until all local zones are considered.
	 */</span>
	alloc_flags <span class="token operator">|=</span> <span class="token function">alloc_flags_nofragment</span><span class="token punctuation">(</span>ac<span class="token punctuation">.</span>preferred_zoneref<span class="token operator">-&gt;</span>zone<span class="token punctuation">,</span> gfp<span class="token punctuation">)</span><span class="token punctuation">;</span>

	<span class="token comment">/* First allocation attempt */</span>
	page <span class="token operator">=</span> <span class="token function">get_page_from_freelist</span><span class="token punctuation">(</span>alloc_gfp<span class="token punctuation">,</span> order<span class="token punctuation">,</span> alloc_flags<span class="token punctuation">,</span> <span class="token operator">&amp;</span>ac<span class="token punctuation">)</span><span class="token punctuation">;</span>
	<span class="token keyword">if</span> <span class="token punctuation">(</span><span class="token function">likely</span><span class="token punctuation">(</span>page<span class="token punctuation">)</span><span class="token punctuation">)</span>
		<span class="token keyword">goto</span> out<span class="token punctuation">;</span>

	alloc_gfp <span class="token operator">=</span> gfp<span class="token punctuation">;</span>
	ac<span class="token punctuation">.</span>spread_dirty_pages <span class="token operator">=</span> false<span class="token punctuation">;</span>

	<span class="token comment">/*
	 * Restore the original nodemask if it was potentially replaced with
	 * &amp;cpuset_current_mems_allowed to optimize the fast-path attempt.
	 */</span>
	ac<span class="token punctuation">.</span>nodemask <span class="token operator">=</span> nodemask<span class="token punctuation">;</span>

	page <span class="token operator">=</span> <span class="token function">__alloc_pages_slowpath</span><span class="token punctuation">(</span>alloc_gfp<span class="token punctuation">,</span> order<span class="token punctuation">,</span> <span class="token operator">&amp;</span>ac<span class="token punctuation">)</span><span class="token punctuation">;</span>

out<span class="token operator">:</span>
	<span class="token keyword">if</span> <span class="token punctuation">(</span><span class="token function">memcg_kmem_enabled</span><span class="token punctuation">(</span><span class="token punctuation">)</span> <span class="token operator">&amp;&amp;</span> <span class="token punctuation">(</span>gfp <span class="token operator">&amp;</span> __GFP_ACCOUNT<span class="token punctuation">)</span> <span class="token operator">&amp;&amp;</span> page <span class="token operator">&amp;&amp;</span>
	    <span class="token function">unlikely</span><span class="token punctuation">(</span><span class="token function">__memcg_kmem_charge_page</span><span class="token punctuation">(</span>page<span class="token punctuation">,</span> gfp<span class="token punctuation">,</span> order<span class="token punctuation">)</span> <span class="token operator">!=</span> <span class="token number">0</span><span class="token punctuation">)</span><span class="token punctuation">)</span> <span class="token punctuation">{</span>
		<span class="token function">__free_pages</span><span class="token punctuation">(</span>page<span class="token punctuation">,</span> order<span class="token punctuation">)</span><span class="token punctuation">;</span>
		page <span class="token operator">=</span> <span class="token constant">NULL</span><span class="token punctuation">;</span>
	<span class="token punctuation">}</span>

	<span class="token function">trace_mm_page_alloc</span><span class="token punctuation">(</span>page<span class="token punctuation">,</span> order<span class="token punctuation">,</span> alloc_gfp<span class="token punctuation">,</span> ac<span class="token punctuation">.</span>migratetype<span class="token punctuation">)</span><span class="token punctuation">;</span>

	<span class="token keyword">return</span> page<span class="token punctuation">;</span>
<span class="token punctuation">}</span>
<span class="token function">EXPORT_SYMBOL</span><span class="token punctuation">(</span>__alloc_pages<span class="token punctuation">)</span><span class="token punctuation">;</span>
</code></pre><div class="line-numbers" aria-hidden="true"><span class="line-number">1</span><br><span class="line-number">2</span><br><span class="line-number">3</span><br><span class="line-number">4</span><br><span class="line-number">5</span><br><span class="line-number">6</span><br><span class="line-number">7</span><br><span class="line-number">8</span><br><span class="line-number">9</span><br><span class="line-number">10</span><br><span class="line-number">11</span><br><span class="line-number">12</span><br><span class="line-number">13</span><br><span class="line-number">14</span><br><span class="line-number">15</span><br><span class="line-number">16</span><br><span class="line-number">17</span><br><span class="line-number">18</span><br><span class="line-number">19</span><br><span class="line-number">20</span><br><span class="line-number">21</span><br><span class="line-number">22</span><br><span class="line-number">23</span><br><span class="line-number">24</span><br><span class="line-number">25</span><br><span class="line-number">26</span><br><span class="line-number">27</span><br><span class="line-number">28</span><br><span class="line-number">29</span><br><span class="line-number">30</span><br><span class="line-number">31</span><br><span class="line-number">32</span><br><span class="line-number">33</span><br><span class="line-number">34</span><br><span class="line-number">35</span><br><span class="line-number">36</span><br><span class="line-number">37</span><br><span class="line-number">38</span><br><span class="line-number">39</span><br><span class="line-number">40</span><br><span class="line-number">41</span><br><span class="line-number">42</span><br><span class="line-number">43</span><br><span class="line-number">44</span><br><span class="line-number">45</span><br><span class="line-number">46</span><br><span class="line-number">47</span><br><span class="line-number">48</span><br><span class="line-number">49</span><br><span class="line-number">50</span><br><span class="line-number">51</span><br><span class="line-number">52</span><br><span class="line-number">53</span><br><span class="line-number">54</span><br><span class="line-number">55</span><br><span class="line-number">56</span><br><span class="line-number">57</span><br><span class="line-number">58</span><br><span class="line-number">59</span><br><span class="line-number">60</span><br><span class="line-number">61</span><br><span class="line-number">62</span><br><span class="line-number">63</span><br><span class="line-number">64</span><br><span class="line-number">65</span><br><span class="line-number">66</span><br><span class="line-number">67</span><br><span class="line-number">68</span><br><span class="line-number">69</span><br></div></div></li><li><p>get_page_from_freelist</p><div class="language-c ext-c line-numbers-mode"><pre class="language-c"><code>
<span class="token comment">/*
 * get_page_from_freelist goes through the zonelist trying to allocate
 * a page.
 */</span>
<span class="token keyword">static</span> <span class="token keyword">struct</span> <span class="token class-name">page</span> <span class="token operator">*</span>
<span class="token function">get_page_from_freelist</span><span class="token punctuation">(</span><span class="token class-name">gfp_t</span> gfp_mask<span class="token punctuation">,</span> <span class="token keyword">unsigned</span> <span class="token keyword">int</span> order<span class="token punctuation">,</span> <span class="token keyword">int</span> alloc_flags<span class="token punctuation">,</span>
						<span class="token keyword">const</span> <span class="token keyword">struct</span> <span class="token class-name">alloc_context</span> <span class="token operator">*</span>ac<span class="token punctuation">)</span>
<span class="token punctuation">{</span>
	<span class="token keyword">struct</span> <span class="token class-name">zoneref</span> <span class="token operator">*</span>z<span class="token punctuation">;</span>
	<span class="token keyword">struct</span> <span class="token class-name">zone</span> <span class="token operator">*</span>zone<span class="token punctuation">;</span>
	<span class="token keyword">struct</span> <span class="token class-name">pglist_data</span> <span class="token operator">*</span>last_pgdat_dirty_limit <span class="token operator">=</span> <span class="token constant">NULL</span><span class="token punctuation">;</span>
	bool no_fallback<span class="token punctuation">;</span>

retry<span class="token operator">:</span>
	<span class="token comment">/*
	 * Scan zonelist, looking for a zone with enough free.
	 * See also __cpuset_node_allowed() comment in kernel/cpuset.c.
	 */</span>
	no_fallback <span class="token operator">=</span> alloc_flags <span class="token operator">&amp;</span> ALLOC_NOFRAGMENT<span class="token punctuation">;</span>
	z <span class="token operator">=</span> ac<span class="token operator">-&gt;</span>preferred_zoneref<span class="token punctuation">;</span>
	<span class="token function">for_next_zone_zonelist_nodemask</span><span class="token punctuation">(</span>zone<span class="token punctuation">,</span> z<span class="token punctuation">,</span> ac<span class="token operator">-&gt;</span>highest_zoneidx<span class="token punctuation">,</span>
					ac<span class="token operator">-&gt;</span>nodemask<span class="token punctuation">)</span> <span class="token punctuation">{</span>
		<span class="token keyword">struct</span> <span class="token class-name">page</span> <span class="token operator">*</span>page<span class="token punctuation">;</span>
		<span class="token keyword">unsigned</span> <span class="token keyword">long</span> mark<span class="token punctuation">;</span>

		<span class="token keyword">if</span> <span class="token punctuation">(</span><span class="token function">cpusets_enabled</span><span class="token punctuation">(</span><span class="token punctuation">)</span> <span class="token operator">&amp;&amp;</span>
			<span class="token punctuation">(</span>alloc_flags <span class="token operator">&amp;</span> ALLOC_CPUSET<span class="token punctuation">)</span> <span class="token operator">&amp;&amp;</span>
			<span class="token operator">!</span><span class="token function">__cpuset_zone_allowed</span><span class="token punctuation">(</span>zone<span class="token punctuation">,</span> gfp_mask<span class="token punctuation">)</span><span class="token punctuation">)</span>
				<span class="token keyword">continue</span><span class="token punctuation">;</span>
		<span class="token comment">/*
		 * When allocating a page cache page for writing, we
		 * want to get it from a node that is within its dirty
		 * limit, such that no single node holds more than its
		 * proportional share of globally allowed dirty pages.
		 * The dirty limits take into account the node&#39;s
		 * lowmem reserves and high watermark so that kswapd
		 * should be able to balance it without having to
		 * write pages from its LRU list.
		 *
		 * XXX: For now, allow allocations to potentially
		 * exceed the per-node dirty limit in the slowpath
		 * (spread_dirty_pages unset) before going into reclaim,
		 * which is important when on a NUMA setup the allowed
		 * nodes are together not big enough to reach the
		 * global limit.  The proper fix for these situations
		 * will require awareness of nodes in the
		 * dirty-throttling and the flusher threads.
		 */</span>
		<span class="token keyword">if</span> <span class="token punctuation">(</span>ac<span class="token operator">-&gt;</span>spread_dirty_pages<span class="token punctuation">)</span> <span class="token punctuation">{</span>
			<span class="token keyword">if</span> <span class="token punctuation">(</span>last_pgdat_dirty_limit <span class="token operator">==</span> zone<span class="token operator">-&gt;</span>zone_pgdat<span class="token punctuation">)</span>
				<span class="token keyword">continue</span><span class="token punctuation">;</span>

			<span class="token keyword">if</span> <span class="token punctuation">(</span><span class="token operator">!</span><span class="token function">node_dirty_ok</span><span class="token punctuation">(</span>zone<span class="token operator">-&gt;</span>zone_pgdat<span class="token punctuation">)</span><span class="token punctuation">)</span> <span class="token punctuation">{</span>
				last_pgdat_dirty_limit <span class="token operator">=</span> zone<span class="token operator">-&gt;</span>zone_pgdat<span class="token punctuation">;</span>
				<span class="token keyword">continue</span><span class="token punctuation">;</span>
			<span class="token punctuation">}</span>
		<span class="token punctuation">}</span>

		<span class="token keyword">if</span> <span class="token punctuation">(</span>no_fallback <span class="token operator">&amp;&amp;</span> nr_online_nodes <span class="token operator">&gt;</span> <span class="token number">1</span> <span class="token operator">&amp;&amp;</span>
		    zone <span class="token operator">!=</span> ac<span class="token operator">-&gt;</span>preferred_zoneref<span class="token operator">-&gt;</span>zone<span class="token punctuation">)</span> <span class="token punctuation">{</span>
			<span class="token keyword">int</span> local_nid<span class="token punctuation">;</span>

			<span class="token comment">/*
			 * If moving to a remote node, retry but allow
			 * fragmenting fallbacks. Locality is more important
			 * than fragmentation avoidance.
			 */</span>
			local_nid <span class="token operator">=</span> <span class="token function">zone_to_nid</span><span class="token punctuation">(</span>ac<span class="token operator">-&gt;</span>preferred_zoneref<span class="token operator">-&gt;</span>zone<span class="token punctuation">)</span><span class="token punctuation">;</span>
			<span class="token keyword">if</span> <span class="token punctuation">(</span><span class="token function">zone_to_nid</span><span class="token punctuation">(</span>zone<span class="token punctuation">)</span> <span class="token operator">!=</span> local_nid<span class="token punctuation">)</span> <span class="token punctuation">{</span>
				alloc_flags <span class="token operator">&amp;=</span> <span class="token operator">~</span>ALLOC_NOFRAGMENT<span class="token punctuation">;</span>
				<span class="token keyword">goto</span> retry<span class="token punctuation">;</span>
			<span class="token punctuation">}</span>
		<span class="token punctuation">}</span>

		mark <span class="token operator">=</span> <span class="token function">wmark_pages</span><span class="token punctuation">(</span>zone<span class="token punctuation">,</span> alloc_flags <span class="token operator">&amp;</span> ALLOC_WMARK_MASK<span class="token punctuation">)</span><span class="token punctuation">;</span>
		<span class="token keyword">if</span> <span class="token punctuation">(</span><span class="token operator">!</span><span class="token function">zone_watermark_fast</span><span class="token punctuation">(</span>zone<span class="token punctuation">,</span> order<span class="token punctuation">,</span> mark<span class="token punctuation">,</span>
				       ac<span class="token operator">-&gt;</span>highest_zoneidx<span class="token punctuation">,</span> alloc_flags<span class="token punctuation">,</span>
				       gfp_mask<span class="token punctuation">)</span><span class="token punctuation">)</span> <span class="token punctuation">{</span>
			<span class="token keyword">int</span> ret<span class="token punctuation">;</span>

<span class="token macro property"><span class="token directive-hash">#</span><span class="token directive keyword">ifdef</span> <span class="token expression">CONFIG_DEFERRED_STRUCT_PAGE_INIT</span></span>
			<span class="token comment">/*
			 * Watermark failed for this zone, but see if we can
			 * grow this zone if it contains deferred pages.
			 */</span>
			<span class="token keyword">if</span> <span class="token punctuation">(</span><span class="token function">static_branch_unlikely</span><span class="token punctuation">(</span><span class="token operator">&amp;</span>deferred_pages<span class="token punctuation">)</span><span class="token punctuation">)</span> <span class="token punctuation">{</span>
				<span class="token keyword">if</span> <span class="token punctuation">(</span><span class="token function">_deferred_grow_zone</span><span class="token punctuation">(</span>zone<span class="token punctuation">,</span> order<span class="token punctuation">)</span><span class="token punctuation">)</span>
					<span class="token keyword">goto</span> try_this_zone<span class="token punctuation">;</span>
			<span class="token punctuation">}</span>
<span class="token macro property"><span class="token directive-hash">#</span><span class="token directive keyword">endif</span></span>
			<span class="token comment">/* Checked here to keep the fast path fast */</span>
			<span class="token function">BUILD_BUG_ON</span><span class="token punctuation">(</span>ALLOC_NO_WATERMARKS <span class="token operator">&lt;</span> NR_WMARK<span class="token punctuation">)</span><span class="token punctuation">;</span>
			<span class="token keyword">if</span> <span class="token punctuation">(</span>alloc_flags <span class="token operator">&amp;</span> ALLOC_NO_WATERMARKS<span class="token punctuation">)</span>
				<span class="token keyword">goto</span> try_this_zone<span class="token punctuation">;</span>

			<span class="token keyword">if</span> <span class="token punctuation">(</span><span class="token operator">!</span><span class="token function">node_reclaim_enabled</span><span class="token punctuation">(</span><span class="token punctuation">)</span> <span class="token operator">||</span>
			    <span class="token operator">!</span><span class="token function">zone_allows_reclaim</span><span class="token punctuation">(</span>ac<span class="token operator">-&gt;</span>preferred_zoneref<span class="token operator">-&gt;</span>zone<span class="token punctuation">,</span> zone<span class="token punctuation">)</span><span class="token punctuation">)</span>
				<span class="token keyword">continue</span><span class="token punctuation">;</span>

			ret <span class="token operator">=</span> <span class="token function">node_reclaim</span><span class="token punctuation">(</span>zone<span class="token operator">-&gt;</span>zone_pgdat<span class="token punctuation">,</span> gfp_mask<span class="token punctuation">,</span> order<span class="token punctuation">)</span><span class="token punctuation">;</span>
			<span class="token keyword">switch</span> <span class="token punctuation">(</span>ret<span class="token punctuation">)</span> <span class="token punctuation">{</span>
			<span class="token keyword">case</span> NODE_RECLAIM_NOSCAN<span class="token operator">:</span>
				<span class="token comment">/* did not scan */</span>
				<span class="token keyword">continue</span><span class="token punctuation">;</span>
			<span class="token keyword">case</span> NODE_RECLAIM_FULL<span class="token operator">:</span>
				<span class="token comment">/* scanned but unreclaimable */</span>
				<span class="token keyword">continue</span><span class="token punctuation">;</span>
			<span class="token keyword">default</span><span class="token operator">:</span>
				<span class="token comment">/* did we reclaim enough */</span>
				<span class="token keyword">if</span> <span class="token punctuation">(</span><span class="token function">zone_watermark_ok</span><span class="token punctuation">(</span>zone<span class="token punctuation">,</span> order<span class="token punctuation">,</span> mark<span class="token punctuation">,</span>
					ac<span class="token operator">-&gt;</span>highest_zoneidx<span class="token punctuation">,</span> alloc_flags<span class="token punctuation">)</span><span class="token punctuation">)</span>
					<span class="token keyword">goto</span> try_this_zone<span class="token punctuation">;</span>

				<span class="token keyword">continue</span><span class="token punctuation">;</span>
			<span class="token punctuation">}</span>
		<span class="token punctuation">}</span>

try_this_zone<span class="token operator">:</span>
		page <span class="token operator">=</span> <span class="token function">rmqueue</span><span class="token punctuation">(</span>ac<span class="token operator">-&gt;</span>preferred_zoneref<span class="token operator">-&gt;</span>zone<span class="token punctuation">,</span> zone<span class="token punctuation">,</span> order<span class="token punctuation">,</span>
				gfp_mask<span class="token punctuation">,</span> alloc_flags<span class="token punctuation">,</span> ac<span class="token operator">-&gt;</span>migratetype<span class="token punctuation">)</span><span class="token punctuation">;</span>
		<span class="token keyword">if</span> <span class="token punctuation">(</span>page<span class="token punctuation">)</span> <span class="token punctuation">{</span>
			<span class="token function">prep_new_page</span><span class="token punctuation">(</span>page<span class="token punctuation">,</span> order<span class="token punctuation">,</span> gfp_mask<span class="token punctuation">,</span> alloc_flags<span class="token punctuation">)</span><span class="token punctuation">;</span>

			<span class="token comment">/*
			 * If this is a high-order atomic allocation then check
			 * if the pageblock should be reserved for the future
			 */</span>
			<span class="token keyword">if</span> <span class="token punctuation">(</span><span class="token function">unlikely</span><span class="token punctuation">(</span>order <span class="token operator">&amp;&amp;</span> <span class="token punctuation">(</span>alloc_flags <span class="token operator">&amp;</span> ALLOC_HARDER<span class="token punctuation">)</span><span class="token punctuation">)</span><span class="token punctuation">)</span>
				<span class="token function">reserve_highatomic_pageblock</span><span class="token punctuation">(</span>page<span class="token punctuation">,</span> zone<span class="token punctuation">,</span> order<span class="token punctuation">)</span><span class="token punctuation">;</span>

			<span class="token keyword">return</span> page<span class="token punctuation">;</span>
		<span class="token punctuation">}</span> <span class="token keyword">else</span> <span class="token punctuation">{</span>
<span class="token macro property"><span class="token directive-hash">#</span><span class="token directive keyword">ifdef</span> <span class="token expression">CONFIG_DEFERRED_STRUCT_PAGE_INIT</span></span>
			<span class="token comment">/* Try again if zone has deferred pages */</span>
			<span class="token keyword">if</span> <span class="token punctuation">(</span><span class="token function">static_branch_unlikely</span><span class="token punctuation">(</span><span class="token operator">&amp;</span>deferred_pages<span class="token punctuation">)</span><span class="token punctuation">)</span> <span class="token punctuation">{</span>
				<span class="token keyword">if</span> <span class="token punctuation">(</span><span class="token function">_deferred_grow_zone</span><span class="token punctuation">(</span>zone<span class="token punctuation">,</span> order<span class="token punctuation">)</span><span class="token punctuation">)</span>
					<span class="token keyword">goto</span> try_this_zone<span class="token punctuation">;</span>
			<span class="token punctuation">}</span>
<span class="token macro property"><span class="token directive-hash">#</span><span class="token directive keyword">endif</span></span>
		<span class="token punctuation">}</span>
	<span class="token punctuation">}</span>

	<span class="token comment">/*
	 * It&#39;s possible on a UMA machine to get through all zones that are
	 * fragmented. If avoiding fragmentation, reset and try again.
	 */</span>
	<span class="token keyword">if</span> <span class="token punctuation">(</span>no_fallback<span class="token punctuation">)</span> <span class="token punctuation">{</span>
		alloc_flags <span class="token operator">&amp;=</span> <span class="token operator">~</span>ALLOC_NOFRAGMENT<span class="token punctuation">;</span>
		<span class="token keyword">goto</span> retry<span class="token punctuation">;</span>
	<span class="token punctuation">}</span>

	<span class="token keyword">return</span> <span class="token constant">NULL</span><span class="token punctuation">;</span>
<span class="token punctuation">}</span>
</code></pre><div class="line-numbers" aria-hidden="true"><span class="line-number">1</span><br><span class="line-number">2</span><br><span class="line-number">3</span><br><span class="line-number">4</span><br><span class="line-number">5</span><br><span class="line-number">6</span><br><span class="line-number">7</span><br><span class="line-number">8</span><br><span class="line-number">9</span><br><span class="line-number">10</span><br><span class="line-number">11</span><br><span class="line-number">12</span><br><span class="line-number">13</span><br><span class="line-number">14</span><br><span class="line-number">15</span><br><span class="line-number">16</span><br><span class="line-number">17</span><br><span class="line-number">18</span><br><span class="line-number">19</span><br><span class="line-number">20</span><br><span class="line-number">21</span><br><span class="line-number">22</span><br><span class="line-number">23</span><br><span class="line-number">24</span><br><span class="line-number">25</span><br><span class="line-number">26</span><br><span class="line-number">27</span><br><span class="line-number">28</span><br><span class="line-number">29</span><br><span class="line-number">30</span><br><span class="line-number">31</span><br><span class="line-number">32</span><br><span class="line-number">33</span><br><span class="line-number">34</span><br><span class="line-number">35</span><br><span class="line-number">36</span><br><span class="line-number">37</span><br><span class="line-number">38</span><br><span class="line-number">39</span><br><span class="line-number">40</span><br><span class="line-number">41</span><br><span class="line-number">42</span><br><span class="line-number">43</span><br><span class="line-number">44</span><br><span class="line-number">45</span><br><span class="line-number">46</span><br><span class="line-number">47</span><br><span class="line-number">48</span><br><span class="line-number">49</span><br><span class="line-number">50</span><br><span class="line-number">51</span><br><span class="line-number">52</span><br><span class="line-number">53</span><br><span class="line-number">54</span><br><span class="line-number">55</span><br><span class="line-number">56</span><br><span class="line-number">57</span><br><span class="line-number">58</span><br><span class="line-number">59</span><br><span class="line-number">60</span><br><span class="line-number">61</span><br><span class="line-number">62</span><br><span class="line-number">63</span><br><span class="line-number">64</span><br><span class="line-number">65</span><br><span class="line-number">66</span><br><span class="line-number">67</span><br><span class="line-number">68</span><br><span class="line-number">69</span><br><span class="line-number">70</span><br><span class="line-number">71</span><br><span class="line-number">72</span><br><span class="line-number">73</span><br><span class="line-number">74</span><br><span class="line-number">75</span><br><span class="line-number">76</span><br><span class="line-number">77</span><br><span class="line-number">78</span><br><span class="line-number">79</span><br><span class="line-number">80</span><br><span class="line-number">81</span><br><span class="line-number">82</span><br><span class="line-number">83</span><br><span class="line-number">84</span><br><span class="line-number">85</span><br><span class="line-number">86</span><br><span class="line-number">87</span><br><span class="line-number">88</span><br><span class="line-number">89</span><br><span class="line-number">90</span><br><span class="line-number">91</span><br><span class="line-number">92</span><br><span class="line-number">93</span><br><span class="line-number">94</span><br><span class="line-number">95</span><br><span class="line-number">96</span><br><span class="line-number">97</span><br><span class="line-number">98</span><br><span class="line-number">99</span><br><span class="line-number">100</span><br><span class="line-number">101</span><br><span class="line-number">102</span><br><span class="line-number">103</span><br><span class="line-number">104</span><br><span class="line-number">105</span><br><span class="line-number">106</span><br><span class="line-number">107</span><br><span class="line-number">108</span><br><span class="line-number">109</span><br><span class="line-number">110</span><br><span class="line-number">111</span><br><span class="line-number">112</span><br><span class="line-number">113</span><br><span class="line-number">114</span><br><span class="line-number">115</span><br><span class="line-number">116</span><br><span class="line-number">117</span><br><span class="line-number">118</span><br><span class="line-number">119</span><br><span class="line-number">120</span><br><span class="line-number">121</span><br><span class="line-number">122</span><br><span class="line-number">123</span><br><span class="line-number">124</span><br><span class="line-number">125</span><br><span class="line-number">126</span><br><span class="line-number">127</span><br><span class="line-number">128</span><br><span class="line-number">129</span><br><span class="line-number">130</span><br><span class="line-number">131</span><br><span class="line-number">132</span><br><span class="line-number">133</span><br><span class="line-number">134</span><br><span class="line-number">135</span><br><span class="line-number">136</span><br><span class="line-number">137</span><br><span class="line-number">138</span><br><span class="line-number">139</span><br><span class="line-number">140</span><br><span class="line-number">141</span><br><span class="line-number">142</span><br><span class="line-number">143</span><br><span class="line-number">144</span><br><span class="line-number">145</span><br><span class="line-number">146</span><br><span class="line-number">147</span><br><span class="line-number">148</span><br><span class="line-number">149</span><br><span class="line-number">150</span><br><span class="line-number">151</span><br><span class="line-number">152</span><br><span class="line-number">153</span><br><span class="line-number">154</span><br></div></div></li><li><p>rmqueue</p><div class="language-c ext-c line-numbers-mode"><pre class="language-c"><code>
<span class="token comment">/*
 * Allocate a page from the given zone. Use pcplists for order-0 allocations.
 */</span>
<span class="token keyword">static</span> <span class="token keyword">inline</span>
<span class="token keyword">struct</span> <span class="token class-name">page</span> <span class="token operator">*</span><span class="token function">rmqueue</span><span class="token punctuation">(</span><span class="token keyword">struct</span> <span class="token class-name">zone</span> <span class="token operator">*</span>preferred_zone<span class="token punctuation">,</span>
			<span class="token keyword">struct</span> <span class="token class-name">zone</span> <span class="token operator">*</span>zone<span class="token punctuation">,</span> <span class="token keyword">unsigned</span> <span class="token keyword">int</span> order<span class="token punctuation">,</span>
			<span class="token class-name">gfp_t</span> gfp_flags<span class="token punctuation">,</span> <span class="token keyword">unsigned</span> <span class="token keyword">int</span> alloc_flags<span class="token punctuation">,</span>
			<span class="token keyword">int</span> migratetype<span class="token punctuation">)</span>
<span class="token punctuation">{</span>
	<span class="token keyword">unsigned</span> <span class="token keyword">long</span> flags<span class="token punctuation">;</span>
	<span class="token keyword">struct</span> <span class="token class-name">page</span> <span class="token operator">*</span>page<span class="token punctuation">;</span>

	<span class="token keyword">if</span> <span class="token punctuation">(</span><span class="token function">likely</span><span class="token punctuation">(</span><span class="token function">pcp_allowed_order</span><span class="token punctuation">(</span>order<span class="token punctuation">)</span><span class="token punctuation">)</span><span class="token punctuation">)</span> <span class="token punctuation">{</span>
		<span class="token comment">/*
		 * MIGRATE_MOVABLE pcplist could have the pages on CMA area and
		 * we need to skip it when CMA area isn&#39;t allowed.
		 */</span>
		<span class="token keyword">if</span> <span class="token punctuation">(</span><span class="token operator">!</span><span class="token function">IS_ENABLED</span><span class="token punctuation">(</span>CONFIG_CMA<span class="token punctuation">)</span> <span class="token operator">||</span> alloc_flags <span class="token operator">&amp;</span> ALLOC_CMA <span class="token operator">||</span>
				migratetype <span class="token operator">!=</span> MIGRATE_MOVABLE<span class="token punctuation">)</span> <span class="token punctuation">{</span>
			page <span class="token operator">=</span> <span class="token function">rmqueue_pcplist</span><span class="token punctuation">(</span>preferred_zone<span class="token punctuation">,</span> zone<span class="token punctuation">,</span> order<span class="token punctuation">,</span>
					gfp_flags<span class="token punctuation">,</span> migratetype<span class="token punctuation">,</span> alloc_flags<span class="token punctuation">)</span><span class="token punctuation">;</span>
			<span class="token keyword">goto</span> out<span class="token punctuation">;</span>
		<span class="token punctuation">}</span>
	<span class="token punctuation">}</span>

	<span class="token comment">/*
	 * We most definitely don&#39;t want callers attempting to
	 * allocate greater than order-1 page units with __GFP_NOFAIL.
	 */</span>
	<span class="token function">WARN_ON_ONCE</span><span class="token punctuation">(</span><span class="token punctuation">(</span>gfp_flags <span class="token operator">&amp;</span> __GFP_NOFAIL<span class="token punctuation">)</span> <span class="token operator">&amp;&amp;</span> <span class="token punctuation">(</span>order <span class="token operator">&gt;</span> <span class="token number">1</span><span class="token punctuation">)</span><span class="token punctuation">)</span><span class="token punctuation">;</span>
	<span class="token function">spin_lock_irqsave</span><span class="token punctuation">(</span><span class="token operator">&amp;</span>zone<span class="token operator">-&gt;</span>lock<span class="token punctuation">,</span> flags<span class="token punctuation">)</span><span class="token punctuation">;</span>

	<span class="token keyword">do</span> <span class="token punctuation">{</span>
		page <span class="token operator">=</span> <span class="token constant">NULL</span><span class="token punctuation">;</span>
		<span class="token comment">/*
		 * order-0 request can reach here when the pcplist is skipped
		 * due to non-CMA allocation context. HIGHATOMIC area is
		 * reserved for high-order atomic allocation, so order-0
		 * request should skip it.
		 */</span>
		<span class="token keyword">if</span> <span class="token punctuation">(</span>order <span class="token operator">&gt;</span> <span class="token number">0</span> <span class="token operator">&amp;&amp;</span> alloc_flags <span class="token operator">&amp;</span> ALLOC_HARDER<span class="token punctuation">)</span> <span class="token punctuation">{</span>
			page <span class="token operator">=</span> <span class="token function">__rmqueue_smallest</span><span class="token punctuation">(</span>zone<span class="token punctuation">,</span> order<span class="token punctuation">,</span> MIGRATE_HIGHATOMIC<span class="token punctuation">)</span><span class="token punctuation">;</span>
			<span class="token keyword">if</span> <span class="token punctuation">(</span>page<span class="token punctuation">)</span>
				<span class="token function">trace_mm_page_alloc_zone_locked</span><span class="token punctuation">(</span>page<span class="token punctuation">,</span> order<span class="token punctuation">,</span> migratetype<span class="token punctuation">)</span><span class="token punctuation">;</span>
		<span class="token punctuation">}</span>
		<span class="token keyword">if</span> <span class="token punctuation">(</span><span class="token operator">!</span>page<span class="token punctuation">)</span>
			page <span class="token operator">=</span> <span class="token function">__rmqueue</span><span class="token punctuation">(</span>zone<span class="token punctuation">,</span> order<span class="token punctuation">,</span> migratetype<span class="token punctuation">,</span> alloc_flags<span class="token punctuation">)</span><span class="token punctuation">;</span>
	<span class="token punctuation">}</span> <span class="token keyword">while</span> <span class="token punctuation">(</span>page <span class="token operator">&amp;&amp;</span> <span class="token function">check_new_pages</span><span class="token punctuation">(</span>page<span class="token punctuation">,</span> order<span class="token punctuation">)</span><span class="token punctuation">)</span><span class="token punctuation">;</span>
	<span class="token keyword">if</span> <span class="token punctuation">(</span><span class="token operator">!</span>page<span class="token punctuation">)</span>
		<span class="token keyword">goto</span> failed<span class="token punctuation">;</span>

	<span class="token function">__mod_zone_freepage_state</span><span class="token punctuation">(</span>zone<span class="token punctuation">,</span> <span class="token operator">-</span><span class="token punctuation">(</span><span class="token number">1</span> <span class="token operator">&lt;&lt;</span> order<span class="token punctuation">)</span><span class="token punctuation">,</span>
				  <span class="token function">get_pcppage_migratetype</span><span class="token punctuation">(</span>page<span class="token punctuation">)</span><span class="token punctuation">)</span><span class="token punctuation">;</span>
	<span class="token function">spin_unlock_irqrestore</span><span class="token punctuation">(</span><span class="token operator">&amp;</span>zone<span class="token operator">-&gt;</span>lock<span class="token punctuation">,</span> flags<span class="token punctuation">)</span><span class="token punctuation">;</span>

	<span class="token function">__count_zid_vm_events</span><span class="token punctuation">(</span>PGALLOC<span class="token punctuation">,</span> <span class="token function">page_zonenum</span><span class="token punctuation">(</span>page<span class="token punctuation">)</span><span class="token punctuation">,</span> <span class="token number">1</span> <span class="token operator">&lt;&lt;</span> order<span class="token punctuation">)</span><span class="token punctuation">;</span>
	<span class="token function">zone_statistics</span><span class="token punctuation">(</span>preferred_zone<span class="token punctuation">,</span> zone<span class="token punctuation">,</span> <span class="token number">1</span><span class="token punctuation">)</span><span class="token punctuation">;</span>

out<span class="token operator">:</span>
	<span class="token comment">/* Separate test+clear to avoid unnecessary atomics */</span>
	<span class="token keyword">if</span> <span class="token punctuation">(</span><span class="token function">test_bit</span><span class="token punctuation">(</span>ZONE_BOOSTED_WATERMARK<span class="token punctuation">,</span> <span class="token operator">&amp;</span>zone<span class="token operator">-&gt;</span>flags<span class="token punctuation">)</span><span class="token punctuation">)</span> <span class="token punctuation">{</span>
		<span class="token function">clear_bit</span><span class="token punctuation">(</span>ZONE_BOOSTED_WATERMARK<span class="token punctuation">,</span> <span class="token operator">&amp;</span>zone<span class="token operator">-&gt;</span>flags<span class="token punctuation">)</span><span class="token punctuation">;</span>
		<span class="token function">wakeup_kswapd</span><span class="token punctuation">(</span>zone<span class="token punctuation">,</span> <span class="token number">0</span><span class="token punctuation">,</span> <span class="token number">0</span><span class="token punctuation">,</span> <span class="token function">zone_idx</span><span class="token punctuation">(</span>zone<span class="token punctuation">)</span><span class="token punctuation">)</span><span class="token punctuation">;</span>
	<span class="token punctuation">}</span>

	<span class="token function">VM_BUG_ON_PAGE</span><span class="token punctuation">(</span>page <span class="token operator">&amp;&amp;</span> <span class="token function">bad_range</span><span class="token punctuation">(</span>zone<span class="token punctuation">,</span> page<span class="token punctuation">)</span><span class="token punctuation">,</span> page<span class="token punctuation">)</span><span class="token punctuation">;</span>
	<span class="token keyword">return</span> page<span class="token punctuation">;</span>

failed<span class="token operator">:</span>
	<span class="token function">spin_unlock_irqrestore</span><span class="token punctuation">(</span><span class="token operator">&amp;</span>zone<span class="token operator">-&gt;</span>lock<span class="token punctuation">,</span> flags<span class="token punctuation">)</span><span class="token punctuation">;</span>
	<span class="token keyword">return</span> <span class="token constant">NULL</span><span class="token punctuation">;</span>
<span class="token punctuation">}</span>
</code></pre><div class="line-numbers" aria-hidden="true"><span class="line-number">1</span><br><span class="line-number">2</span><br><span class="line-number">3</span><br><span class="line-number">4</span><br><span class="line-number">5</span><br><span class="line-number">6</span><br><span class="line-number">7</span><br><span class="line-number">8</span><br><span class="line-number">9</span><br><span class="line-number">10</span><br><span class="line-number">11</span><br><span class="line-number">12</span><br><span class="line-number">13</span><br><span class="line-number">14</span><br><span class="line-number">15</span><br><span class="line-number">16</span><br><span class="line-number">17</span><br><span class="line-number">18</span><br><span class="line-number">19</span><br><span class="line-number">20</span><br><span class="line-number">21</span><br><span class="line-number">22</span><br><span class="line-number">23</span><br><span class="line-number">24</span><br><span class="line-number">25</span><br><span class="line-number">26</span><br><span class="line-number">27</span><br><span class="line-number">28</span><br><span class="line-number">29</span><br><span class="line-number">30</span><br><span class="line-number">31</span><br><span class="line-number">32</span><br><span class="line-number">33</span><br><span class="line-number">34</span><br><span class="line-number">35</span><br><span class="line-number">36</span><br><span class="line-number">37</span><br><span class="line-number">38</span><br><span class="line-number">39</span><br><span class="line-number">40</span><br><span class="line-number">41</span><br><span class="line-number">42</span><br><span class="line-number">43</span><br><span class="line-number">44</span><br><span class="line-number">45</span><br><span class="line-number">46</span><br><span class="line-number">47</span><br><span class="line-number">48</span><br><span class="line-number">49</span><br><span class="line-number">50</span><br><span class="line-number">51</span><br><span class="line-number">52</span><br><span class="line-number">53</span><br><span class="line-number">54</span><br><span class="line-number">55</span><br><span class="line-number">56</span><br><span class="line-number">57</span><br><span class="line-number">58</span><br><span class="line-number">59</span><br><span class="line-number">60</span><br><span class="line-number">61</span><br><span class="line-number">62</span><br><span class="line-number">63</span><br><span class="line-number">64</span><br><span class="line-number">65</span><br><span class="line-number">66</span><br><span class="line-number">67</span><br><span class="line-number">68</span><br><span class="line-number">69</span><br><span class="line-number">70</span><br><span class="line-number">71</span><br><span class="line-number">72</span><br><span class="line-number">73</span><br></div></div></li><li><p>__rmqueue</p><div class="language-c ext-c line-numbers-mode"><pre class="language-c"><code>
<span class="token comment">/*
 * Do the hard work of removing an element from the buddy allocator.
 * Call me with the zone-&gt;lock already held.
 */</span>
<span class="token keyword">static</span> __always_inline <span class="token keyword">struct</span> <span class="token class-name">page</span> <span class="token operator">*</span>
<span class="token function">__rmqueue</span><span class="token punctuation">(</span><span class="token keyword">struct</span> <span class="token class-name">zone</span> <span class="token operator">*</span>zone<span class="token punctuation">,</span> <span class="token keyword">unsigned</span> <span class="token keyword">int</span> order<span class="token punctuation">,</span> <span class="token keyword">int</span> migratetype<span class="token punctuation">,</span>
						<span class="token keyword">unsigned</span> <span class="token keyword">int</span> alloc_flags<span class="token punctuation">)</span>
<span class="token punctuation">{</span>
	<span class="token keyword">struct</span> <span class="token class-name">page</span> <span class="token operator">*</span>page<span class="token punctuation">;</span>

	<span class="token keyword">if</span> <span class="token punctuation">(</span><span class="token function">IS_ENABLED</span><span class="token punctuation">(</span>CONFIG_CMA<span class="token punctuation">)</span><span class="token punctuation">)</span> <span class="token punctuation">{</span>
		<span class="token comment">/*
		 * Balance movable allocations between regular and CMA areas by
		 * allocating from CMA when over half of the zone&#39;s free memory
		 * is in the CMA area.
		 */</span>
		<span class="token keyword">if</span> <span class="token punctuation">(</span>alloc_flags <span class="token operator">&amp;</span> ALLOC_CMA <span class="token operator">&amp;&amp;</span>
		    <span class="token function">zone_page_state</span><span class="token punctuation">(</span>zone<span class="token punctuation">,</span> NR_FREE_CMA_PAGES<span class="token punctuation">)</span> <span class="token operator">&gt;</span>
		    <span class="token function">zone_page_state</span><span class="token punctuation">(</span>zone<span class="token punctuation">,</span> NR_FREE_PAGES<span class="token punctuation">)</span> <span class="token operator">/</span> <span class="token number">2</span><span class="token punctuation">)</span> <span class="token punctuation">{</span>
			page <span class="token operator">=</span> <span class="token function">__rmqueue_cma_fallback</span><span class="token punctuation">(</span>zone<span class="token punctuation">,</span> order<span class="token punctuation">)</span><span class="token punctuation">;</span>
			<span class="token keyword">if</span> <span class="token punctuation">(</span>page<span class="token punctuation">)</span>
				<span class="token keyword">goto</span> out<span class="token punctuation">;</span>
		<span class="token punctuation">}</span>
	<span class="token punctuation">}</span>
retry<span class="token operator">:</span>
	page <span class="token operator">=</span> <span class="token function">__rmqueue_smallest</span><span class="token punctuation">(</span>zone<span class="token punctuation">,</span> order<span class="token punctuation">,</span> migratetype<span class="token punctuation">)</span><span class="token punctuation">;</span>
	<span class="token keyword">if</span> <span class="token punctuation">(</span><span class="token function">unlikely</span><span class="token punctuation">(</span><span class="token operator">!</span>page<span class="token punctuation">)</span><span class="token punctuation">)</span> <span class="token punctuation">{</span>
		<span class="token keyword">if</span> <span class="token punctuation">(</span>alloc_flags <span class="token operator">&amp;</span> ALLOC_CMA<span class="token punctuation">)</span>
			page <span class="token operator">=</span> <span class="token function">__rmqueue_cma_fallback</span><span class="token punctuation">(</span>zone<span class="token punctuation">,</span> order<span class="token punctuation">)</span><span class="token punctuation">;</span>

		<span class="token keyword">if</span> <span class="token punctuation">(</span><span class="token operator">!</span>page <span class="token operator">&amp;&amp;</span> <span class="token function">__rmqueue_fallback</span><span class="token punctuation">(</span>zone<span class="token punctuation">,</span> order<span class="token punctuation">,</span> migratetype<span class="token punctuation">,</span>
								alloc_flags<span class="token punctuation">)</span><span class="token punctuation">)</span>
			<span class="token keyword">goto</span> retry<span class="token punctuation">;</span>
	<span class="token punctuation">}</span>
out<span class="token operator">:</span>
	<span class="token keyword">if</span> <span class="token punctuation">(</span>page<span class="token punctuation">)</span>
		<span class="token function">trace_mm_page_alloc_zone_locked</span><span class="token punctuation">(</span>page<span class="token punctuation">,</span> order<span class="token punctuation">,</span> migratetype<span class="token punctuation">)</span><span class="token punctuation">;</span>
	<span class="token keyword">return</span> page<span class="token punctuation">;</span>
<span class="token punctuation">}</span>

</code></pre><div class="line-numbers" aria-hidden="true"><span class="line-number">1</span><br><span class="line-number">2</span><br><span class="line-number">3</span><br><span class="line-number">4</span><br><span class="line-number">5</span><br><span class="line-number">6</span><br><span class="line-number">7</span><br><span class="line-number">8</span><br><span class="line-number">9</span><br><span class="line-number">10</span><br><span class="line-number">11</span><br><span class="line-number">12</span><br><span class="line-number">13</span><br><span class="line-number">14</span><br><span class="line-number">15</span><br><span class="line-number">16</span><br><span class="line-number">17</span><br><span class="line-number">18</span><br><span class="line-number">19</span><br><span class="line-number">20</span><br><span class="line-number">21</span><br><span class="line-number">22</span><br><span class="line-number">23</span><br><span class="line-number">24</span><br><span class="line-number">25</span><br><span class="line-number">26</span><br><span class="line-number">27</span><br><span class="line-number">28</span><br><span class="line-number">29</span><br><span class="line-number">30</span><br><span class="line-number">31</span><br><span class="line-number">32</span><br><span class="line-number">33</span><br><span class="line-number">34</span><br><span class="line-number">35</span><br><span class="line-number">36</span><br><span class="line-number">37</span><br><span class="line-number">38</span><br><span class="line-number">39</span><br><span class="line-number">40</span><br><span class="line-number">41</span><br></div></div></li><li><p>__rmqueue_smallest</p><div class="language-c ext-c line-numbers-mode"><pre class="language-c"><code>
<span class="token comment">/*
 * Go through the free lists for the given migratetype and remove
 * the smallest available page from the freelists
 */</span>
<span class="token keyword">static</span> __always_inline
<span class="token keyword">struct</span> <span class="token class-name">page</span> <span class="token operator">*</span><span class="token function">__rmqueue_smallest</span><span class="token punctuation">(</span><span class="token keyword">struct</span> <span class="token class-name">zone</span> <span class="token operator">*</span>zone<span class="token punctuation">,</span> <span class="token keyword">unsigned</span> <span class="token keyword">int</span> order<span class="token punctuation">,</span>
						<span class="token keyword">int</span> migratetype<span class="token punctuation">)</span>
<span class="token punctuation">{</span>
	<span class="token keyword">unsigned</span> <span class="token keyword">int</span> current_order<span class="token punctuation">;</span>
	<span class="token keyword">struct</span> <span class="token class-name">free_area</span> <span class="token operator">*</span>area<span class="token punctuation">;</span>
	<span class="token keyword">struct</span> <span class="token class-name">page</span> <span class="token operator">*</span>page<span class="token punctuation">;</span>

	<span class="token comment">/* Find a page of the appropriate size in the preferred list */</span>
	<span class="token keyword">for</span> <span class="token punctuation">(</span>current_order <span class="token operator">=</span> order<span class="token punctuation">;</span> current_order <span class="token operator">&lt;</span> MAX_ORDER<span class="token punctuation">;</span> <span class="token operator">++</span>current_order<span class="token punctuation">)</span> <span class="token punctuation">{</span>
		area <span class="token operator">=</span> <span class="token operator">&amp;</span><span class="token punctuation">(</span>zone<span class="token operator">-&gt;</span>free_area<span class="token punctuation">[</span>current_order<span class="token punctuation">]</span><span class="token punctuation">)</span><span class="token punctuation">;</span>
		page <span class="token operator">=</span> <span class="token function">get_page_from_free_area</span><span class="token punctuation">(</span>area<span class="token punctuation">,</span> migratetype<span class="token punctuation">)</span><span class="token punctuation">;</span>
		<span class="token keyword">if</span> <span class="token punctuation">(</span><span class="token operator">!</span>page<span class="token punctuation">)</span>
			<span class="token keyword">continue</span><span class="token punctuation">;</span>
		<span class="token function">del_page_from_free_list</span><span class="token punctuation">(</span>page<span class="token punctuation">,</span> zone<span class="token punctuation">,</span> current_order<span class="token punctuation">)</span><span class="token punctuation">;</span>
		<span class="token function">expand</span><span class="token punctuation">(</span>zone<span class="token punctuation">,</span> page<span class="token punctuation">,</span> order<span class="token punctuation">,</span> current_order<span class="token punctuation">,</span> migratetype<span class="token punctuation">)</span><span class="token punctuation">;</span>
		<span class="token function">set_pcppage_migratetype</span><span class="token punctuation">(</span>page<span class="token punctuation">,</span> migratetype<span class="token punctuation">)</span><span class="token punctuation">;</span>
		<span class="token keyword">return</span> page<span class="token punctuation">;</span>
	<span class="token punctuation">}</span>

	<span class="token keyword">return</span> <span class="token constant">NULL</span><span class="token punctuation">;</span>
<span class="token punctuation">}</span>


</code></pre><div class="line-numbers" aria-hidden="true"><span class="line-number">1</span><br><span class="line-number">2</span><br><span class="line-number">3</span><br><span class="line-number">4</span><br><span class="line-number">5</span><br><span class="line-number">6</span><br><span class="line-number">7</span><br><span class="line-number">8</span><br><span class="line-number">9</span><br><span class="line-number">10</span><br><span class="line-number">11</span><br><span class="line-number">12</span><br><span class="line-number">13</span><br><span class="line-number">14</span><br><span class="line-number">15</span><br><span class="line-number">16</span><br><span class="line-number">17</span><br><span class="line-number">18</span><br><span class="line-number">19</span><br><span class="line-number">20</span><br><span class="line-number">21</span><br><span class="line-number">22</span><br><span class="line-number">23</span><br><span class="line-number">24</span><br><span class="line-number">25</span><br><span class="line-number">26</span><br><span class="line-number">27</span><br><span class="line-number">28</span><br><span class="line-number">29</span><br></div></div></li><li><p>get_page_from_free_area</p><div class="language-c ext-c line-numbers-mode"><pre class="language-c"><code>
<span class="token keyword">static</span> <span class="token keyword">inline</span> <span class="token keyword">struct</span> <span class="token class-name">page</span> <span class="token operator">*</span><span class="token function">get_page_from_free_area</span><span class="token punctuation">(</span><span class="token keyword">struct</span> <span class="token class-name">free_area</span> <span class="token operator">*</span>area<span class="token punctuation">,</span>
					    <span class="token keyword">int</span> migratetype<span class="token punctuation">)</span>
<span class="token punctuation">{</span>
	<span class="token keyword">return</span> <span class="token function">list_first_entry_or_null</span><span class="token punctuation">(</span><span class="token operator">&amp;</span>area<span class="token operator">-&gt;</span>free_list<span class="token punctuation">[</span>migratetype<span class="token punctuation">]</span><span class="token punctuation">,</span>
					<span class="token keyword">struct</span> <span class="token class-name">page</span><span class="token punctuation">,</span> lru<span class="token punctuation">)</span><span class="token punctuation">;</span>
<span class="token punctuation">}</span>
</code></pre><div class="line-numbers" aria-hidden="true"><span class="line-number">1</span><br><span class="line-number">2</span><br><span class="line-number">3</span><br><span class="line-number">4</span><br><span class="line-number">5</span><br><span class="line-number">6</span><br><span class="line-number">7</span><br></div></div></li><li><p>list_first_entry_or_null</p><div class="language-c ext-c line-numbers-mode"><pre class="language-c"><code><span class="token comment">/**
 * list_first_entry_or_null - get the first element from a list
 * @ptr:	the list head to take the element from.
 * @type:	the type of the struct this is embedded in.
 * @member:	the name of the list_head within the struct.
 *
 * Note that if the list is empty, it returns NULL.
 */</span>
<span class="token macro property"><span class="token directive-hash">#</span><span class="token directive keyword">define</span> <span class="token macro-name function">list_first_entry_or_null</span><span class="token expression"><span class="token punctuation">(</span>ptr<span class="token punctuation">,</span> type<span class="token punctuation">,</span> member<span class="token punctuation">)</span> <span class="token punctuation">(</span><span class="token punctuation">{</span> </span><span class="token punctuation">\\</span>
	<span class="token expression"><span class="token keyword">struct</span> <span class="token class-name">list_head</span> <span class="token operator">*</span>head__ <span class="token operator">=</span> <span class="token punctuation">(</span>ptr<span class="token punctuation">)</span><span class="token punctuation">;</span> </span><span class="token punctuation">\\</span>
	<span class="token expression"><span class="token keyword">struct</span> <span class="token class-name">list_head</span> <span class="token operator">*</span>pos__ <span class="token operator">=</span> <span class="token function">READ_ONCE</span><span class="token punctuation">(</span>head__<span class="token operator">-&gt;</span>next<span class="token punctuation">)</span><span class="token punctuation">;</span> </span><span class="token punctuation">\\</span>
	<span class="token expression">pos__ <span class="token operator">!=</span> head__ <span class="token operator">?</span> <span class="token function">list_entry</span><span class="token punctuation">(</span>pos__<span class="token punctuation">,</span> type<span class="token punctuation">,</span> member<span class="token punctuation">)</span> <span class="token operator">:</span> <span class="token constant">NULL</span><span class="token punctuation">;</span> </span><span class="token punctuation">\\</span>
<span class="token expression"><span class="token punctuation">}</span><span class="token punctuation">)</span></span></span>

</code></pre><div class="line-numbers" aria-hidden="true"><span class="line-number">1</span><br><span class="line-number">2</span><br><span class="line-number">3</span><br><span class="line-number">4</span><br><span class="line-number">5</span><br><span class="line-number">6</span><br><span class="line-number">7</span><br><span class="line-number">8</span><br><span class="line-number">9</span><br><span class="line-number">10</span><br><span class="line-number">11</span><br><span class="line-number">12</span><br><span class="line-number">13</span><br><span class="line-number">14</span><br></div></div></li><li><p>data structure</p></li></ol><div class="language-c ext-c line-numbers-mode"><pre class="language-c"><code>
<span class="token comment">/*
 * On NUMA machines, each NUMA node would have a pg_data_t to describe
 * it&#39;s memory layout. On UMA machines there is a single pglist_data which
 * describes the whole memory.
 *
 * Memory statistics and page replacement data structures are maintained on a
 * per-zone basis.
 */</span>
<span class="token keyword">typedef</span> <span class="token keyword">struct</span> <span class="token class-name">pglist_data</span> <span class="token punctuation">{</span>
	<span class="token comment">/*
	 * node_zones contains just the zones for THIS node. Not all of the
	 * zones may be populated, but it is the full list. It is referenced by
	 * this node&#39;s node_zonelists as well as other node&#39;s node_zonelists.
	 */</span>
	<span class="token keyword">struct</span> <span class="token class-name">zone</span> node_zones<span class="token punctuation">[</span>MAX_NR_ZONES<span class="token punctuation">]</span><span class="token punctuation">;</span>

	<span class="token comment">/*
	 * node_zonelists contains references to all zones in all nodes.
	 * Generally the first zones will be references to this node&#39;s
	 * node_zones.
	 */</span>
	<span class="token keyword">struct</span> <span class="token class-name">zonelist</span> node_zonelists<span class="token punctuation">[</span>MAX_ZONELISTS<span class="token punctuation">]</span><span class="token punctuation">;</span>

	<span class="token keyword">int</span> nr_zones<span class="token punctuation">;</span> <span class="token comment">/* number of populated zones in this node */</span>
<span class="token macro property"><span class="token directive-hash">#</span><span class="token directive keyword">ifdef</span> <span class="token expression">CONFIG_FLATMEM	</span><span class="token comment">/* means !SPARSEMEM */</span></span>
	<span class="token keyword">struct</span> <span class="token class-name">page</span> <span class="token operator">*</span>node_mem_map<span class="token punctuation">;</span>
<span class="token macro property"><span class="token directive-hash">#</span><span class="token directive keyword">ifdef</span> <span class="token expression">CONFIG_PAGE_EXTENSION</span></span>
	<span class="token keyword">struct</span> <span class="token class-name">page_ext</span> <span class="token operator">*</span>node_page_ext<span class="token punctuation">;</span>
<span class="token macro property"><span class="token directive-hash">#</span><span class="token directive keyword">endif</span></span>
<span class="token macro property"><span class="token directive-hash">#</span><span class="token directive keyword">endif</span></span>
<span class="token macro property"><span class="token directive-hash">#</span><span class="token directive keyword">if</span> <span class="token expression"><span class="token function">defined</span><span class="token punctuation">(</span>CONFIG_MEMORY_HOTPLUG<span class="token punctuation">)</span> <span class="token operator">||</span> <span class="token function">defined</span><span class="token punctuation">(</span>CONFIG_DEFERRED_STRUCT_PAGE_INIT<span class="token punctuation">)</span></span></span>
	<span class="token comment">/*
	 * Must be held any time you expect node_start_pfn,
	 * node_present_pages, node_spanned_pages or nr_zones to stay constant.
	 * Also synchronizes pgdat-&gt;first_deferred_pfn during deferred page
	 * init.
	 *
	 * pgdat_resize_lock() and pgdat_resize_unlock() are provided to
	 * manipulate node_size_lock without checking for CONFIG_MEMORY_HOTPLUG
	 * or CONFIG_DEFERRED_STRUCT_PAGE_INIT.
	 *
	 * Nests above zone-&gt;lock and zone-&gt;span_seqlock
	 */</span>
	<span class="token class-name">spinlock_t</span> node_size_lock<span class="token punctuation">;</span>
<span class="token macro property"><span class="token directive-hash">#</span><span class="token directive keyword">endif</span></span>
	<span class="token keyword">unsigned</span> <span class="token keyword">long</span> node_start_pfn<span class="token punctuation">;</span>
	<span class="token keyword">unsigned</span> <span class="token keyword">long</span> node_present_pages<span class="token punctuation">;</span> <span class="token comment">/* total number of physical pages */</span>
	<span class="token keyword">unsigned</span> <span class="token keyword">long</span> node_spanned_pages<span class="token punctuation">;</span> <span class="token comment">/* total size of physical page
					     range, including holes */</span>
	<span class="token keyword">int</span> node_id<span class="token punctuation">;</span>
	<span class="token class-name">wait_queue_head_t</span> kswapd_wait<span class="token punctuation">;</span>
	<span class="token class-name">wait_queue_head_t</span> pfmemalloc_wait<span class="token punctuation">;</span>
	<span class="token keyword">struct</span> <span class="token class-name">task_struct</span> <span class="token operator">*</span>kswapd<span class="token punctuation">;</span>	<span class="token comment">/* Protected by
					   mem_hotplug_begin/end() */</span>
	<span class="token keyword">int</span> kswapd_order<span class="token punctuation">;</span>
	<span class="token keyword">enum</span> <span class="token class-name">zone_type</span> kswapd_highest_zoneidx<span class="token punctuation">;</span>

	<span class="token keyword">int</span> kswapd_failures<span class="token punctuation">;</span>		<span class="token comment">/* Number of &#39;reclaimed == 0&#39; runs */</span>

<span class="token macro property"><span class="token directive-hash">#</span><span class="token directive keyword">ifdef</span> <span class="token expression">CONFIG_COMPACTION</span></span>
	<span class="token keyword">int</span> kcompactd_max_order<span class="token punctuation">;</span>
	<span class="token keyword">enum</span> <span class="token class-name">zone_type</span> kcompactd_highest_zoneidx<span class="token punctuation">;</span>
	<span class="token class-name">wait_queue_head_t</span> kcompactd_wait<span class="token punctuation">;</span>
	<span class="token keyword">struct</span> <span class="token class-name">task_struct</span> <span class="token operator">*</span>kcompactd<span class="token punctuation">;</span>
	bool proactive_compact_trigger<span class="token punctuation">;</span>
<span class="token macro property"><span class="token directive-hash">#</span><span class="token directive keyword">endif</span></span>
	<span class="token comment">/*
	 * This is a per-node reserve of pages that are not available
	 * to userspace allocations.
	 */</span>
	<span class="token keyword">unsigned</span> <span class="token keyword">long</span>		totalreserve_pages<span class="token punctuation">;</span>

<span class="token macro property"><span class="token directive-hash">#</span><span class="token directive keyword">ifdef</span> <span class="token expression">CONFIG_NUMA</span></span>
	<span class="token comment">/*
	 * node reclaim becomes active if more unmapped pages exist.
	 */</span>
	<span class="token keyword">unsigned</span> <span class="token keyword">long</span>		min_unmapped_pages<span class="token punctuation">;</span>
	<span class="token keyword">unsigned</span> <span class="token keyword">long</span>		min_slab_pages<span class="token punctuation">;</span>
<span class="token macro property"><span class="token directive-hash">#</span><span class="token directive keyword">endif</span> <span class="token comment">/* CONFIG_NUMA */</span></span>

	<span class="token comment">/* Write-intensive fields used by page reclaim */</span>
	<span class="token function">ZONE_PADDING</span><span class="token punctuation">(</span>_pad1_<span class="token punctuation">)</span>

<span class="token macro property"><span class="token directive-hash">#</span><span class="token directive keyword">ifdef</span> <span class="token expression">CONFIG_DEFERRED_STRUCT_PAGE_INIT</span></span>
	<span class="token comment">/*
	 * If memory initialisation on large machines is deferred then this
	 * is the first PFN that needs to be initialised.
	 */</span>
	<span class="token keyword">unsigned</span> <span class="token keyword">long</span> first_deferred_pfn<span class="token punctuation">;</span>
<span class="token macro property"><span class="token directive-hash">#</span><span class="token directive keyword">endif</span> <span class="token comment">/* CONFIG_DEFERRED_STRUCT_PAGE_INIT */</span></span>

<span class="token macro property"><span class="token directive-hash">#</span><span class="token directive keyword">ifdef</span> <span class="token expression">CONFIG_TRANSPARENT_HUGEPAGE</span></span>
	<span class="token keyword">struct</span> <span class="token class-name">deferred_split</span> deferred_split_queue<span class="token punctuation">;</span>
<span class="token macro property"><span class="token directive-hash">#</span><span class="token directive keyword">endif</span></span>

	<span class="token comment">/* Fields commonly accessed by the page reclaim scanner */</span>

	<span class="token comment">/*
	 * NOTE: THIS IS UNUSED IF MEMCG IS ENABLED.
	 *
	 * Use mem_cgroup_lruvec() to look up lruvecs.
	 */</span>
	<span class="token keyword">struct</span> <span class="token class-name">lruvec</span>		__lruvec<span class="token punctuation">;</span>

	<span class="token keyword">unsigned</span> <span class="token keyword">long</span>		flags<span class="token punctuation">;</span>

	<span class="token function">ZONE_PADDING</span><span class="token punctuation">(</span>_pad2_<span class="token punctuation">)</span>

	<span class="token comment">/* Per-node vmstats */</span>
	<span class="token keyword">struct</span> <span class="token class-name">per_cpu_nodestat</span> __percpu <span class="token operator">*</span>per_cpu_nodestats<span class="token punctuation">;</span>
	<span class="token class-name">atomic_long_t</span>		vm_stat<span class="token punctuation">[</span>NR_VM_NODE_STAT_ITEMS<span class="token punctuation">]</span><span class="token punctuation">;</span>
<span class="token punctuation">}</span> <span class="token class-name">pg_data_t</span><span class="token punctuation">;</span>
</code></pre><div class="line-numbers" aria-hidden="true"><span class="line-number">1</span><br><span class="line-number">2</span><br><span class="line-number">3</span><br><span class="line-number">4</span><br><span class="line-number">5</span><br><span class="line-number">6</span><br><span class="line-number">7</span><br><span class="line-number">8</span><br><span class="line-number">9</span><br><span class="line-number">10</span><br><span class="line-number">11</span><br><span class="line-number">12</span><br><span class="line-number">13</span><br><span class="line-number">14</span><br><span class="line-number">15</span><br><span class="line-number">16</span><br><span class="line-number">17</span><br><span class="line-number">18</span><br><span class="line-number">19</span><br><span class="line-number">20</span><br><span class="line-number">21</span><br><span class="line-number">22</span><br><span class="line-number">23</span><br><span class="line-number">24</span><br><span class="line-number">25</span><br><span class="line-number">26</span><br><span class="line-number">27</span><br><span class="line-number">28</span><br><span class="line-number">29</span><br><span class="line-number">30</span><br><span class="line-number">31</span><br><span class="line-number">32</span><br><span class="line-number">33</span><br><span class="line-number">34</span><br><span class="line-number">35</span><br><span class="line-number">36</span><br><span class="line-number">37</span><br><span class="line-number">38</span><br><span class="line-number">39</span><br><span class="line-number">40</span><br><span class="line-number">41</span><br><span class="line-number">42</span><br><span class="line-number">43</span><br><span class="line-number">44</span><br><span class="line-number">45</span><br><span class="line-number">46</span><br><span class="line-number">47</span><br><span class="line-number">48</span><br><span class="line-number">49</span><br><span class="line-number">50</span><br><span class="line-number">51</span><br><span class="line-number">52</span><br><span class="line-number">53</span><br><span class="line-number">54</span><br><span class="line-number">55</span><br><span class="line-number">56</span><br><span class="line-number">57</span><br><span class="line-number">58</span><br><span class="line-number">59</span><br><span class="line-number">60</span><br><span class="line-number">61</span><br><span class="line-number">62</span><br><span class="line-number">63</span><br><span class="line-number">64</span><br><span class="line-number">65</span><br><span class="line-number">66</span><br><span class="line-number">67</span><br><span class="line-number">68</span><br><span class="line-number">69</span><br><span class="line-number">70</span><br><span class="line-number">71</span><br><span class="line-number">72</span><br><span class="line-number">73</span><br><span class="line-number">74</span><br><span class="line-number">75</span><br><span class="line-number">76</span><br><span class="line-number">77</span><br><span class="line-number">78</span><br><span class="line-number">79</span><br><span class="line-number">80</span><br><span class="line-number">81</span><br><span class="line-number">82</span><br><span class="line-number">83</span><br><span class="line-number">84</span><br><span class="line-number">85</span><br><span class="line-number">86</span><br><span class="line-number">87</span><br><span class="line-number">88</span><br><span class="line-number">89</span><br><span class="line-number">90</span><br><span class="line-number">91</span><br><span class="line-number">92</span><br><span class="line-number">93</span><br><span class="line-number">94</span><br><span class="line-number">95</span><br><span class="line-number">96</span><br><span class="line-number">97</span><br><span class="line-number">98</span><br><span class="line-number">99</span><br><span class="line-number">100</span><br><span class="line-number">101</span><br><span class="line-number">102</span><br><span class="line-number">103</span><br><span class="line-number">104</span><br><span class="line-number">105</span><br><span class="line-number">106</span><br><span class="line-number">107</span><br><span class="line-number">108</span><br><span class="line-number">109</span><br><span class="line-number">110</span><br><span class="line-number">111</span><br><span class="line-number">112</span><br><span class="line-number">113</span><br></div></div><div class="language-c ext-c line-numbers-mode"><pre class="language-c"><code>
<span class="token keyword">struct</span> <span class="token class-name">zone</span> <span class="token punctuation">{</span>
	<span class="token comment">/* Read-mostly fields */</span>

	<span class="token comment">/* zone watermarks, access with *_wmark_pages(zone) macros */</span>
	<span class="token keyword">unsigned</span> <span class="token keyword">long</span> _watermark<span class="token punctuation">[</span>NR_WMARK<span class="token punctuation">]</span><span class="token punctuation">;</span>
	<span class="token keyword">unsigned</span> <span class="token keyword">long</span> watermark_boost<span class="token punctuation">;</span>

	<span class="token keyword">unsigned</span> <span class="token keyword">long</span> nr_reserved_highatomic<span class="token punctuation">;</span>

	<span class="token comment">/*
	 * We don&#39;t know if the memory that we&#39;re going to allocate will be
	 * freeable or/and it will be released eventually, so to avoid totally
	 * wasting several GB of ram we must reserve some of the lower zone
	 * memory (otherwise we risk to run OOM on the lower zones despite
	 * there being tons of freeable ram on the higher zones).  This array is
	 * recalculated at runtime if the sysctl_lowmem_reserve_ratio sysctl
	 * changes.
	 */</span>
	<span class="token keyword">long</span> lowmem_reserve<span class="token punctuation">[</span>MAX_NR_ZONES<span class="token punctuation">]</span><span class="token punctuation">;</span>

<span class="token macro property"><span class="token directive-hash">#</span><span class="token directive keyword">ifdef</span> <span class="token expression">CONFIG_NUMA</span></span>
	<span class="token keyword">int</span> node<span class="token punctuation">;</span>
<span class="token macro property"><span class="token directive-hash">#</span><span class="token directive keyword">endif</span></span>
	<span class="token keyword">struct</span> <span class="token class-name">pglist_data</span>	<span class="token operator">*</span>zone_pgdat<span class="token punctuation">;</span>
	<span class="token keyword">struct</span> <span class="token class-name">per_cpu_pages</span>	__percpu <span class="token operator">*</span>per_cpu_pageset<span class="token punctuation">;</span>
	<span class="token keyword">struct</span> <span class="token class-name">per_cpu_zonestat</span>	__percpu <span class="token operator">*</span>per_cpu_zonestats<span class="token punctuation">;</span>
	<span class="token comment">/*
	 * the high and batch values are copied to individual pagesets for
	 * faster access
	 */</span>
	<span class="token keyword">int</span> pageset_high<span class="token punctuation">;</span>
	<span class="token keyword">int</span> pageset_batch<span class="token punctuation">;</span>

<span class="token macro property"><span class="token directive-hash">#</span><span class="token directive keyword">ifndef</span> <span class="token expression">CONFIG_SPARSEMEM</span></span>
	<span class="token comment">/*
	 * Flags for a pageblock_nr_pages block. See pageblock-flags.h.
	 * In SPARSEMEM, this map is stored in struct mem_section
	 */</span>
	<span class="token keyword">unsigned</span> <span class="token keyword">long</span>		<span class="token operator">*</span>pageblock_flags<span class="token punctuation">;</span>
<span class="token macro property"><span class="token directive-hash">#</span><span class="token directive keyword">endif</span> <span class="token comment">/* CONFIG_SPARSEMEM */</span></span>

	<span class="token comment">/* zone_start_pfn == zone_start_paddr &gt;&gt; PAGE_SHIFT */</span>
	<span class="token keyword">unsigned</span> <span class="token keyword">long</span>		zone_start_pfn<span class="token punctuation">;</span>

	<span class="token comment">/*
	 * spanned_pages is the total pages spanned by the zone, including
	 * holes, which is calculated as:
	 * 	spanned_pages = zone_end_pfn - zone_start_pfn;
	 *
	 * present_pages is physical pages existing within the zone, which
	 * is calculated as:
	 *	present_pages = spanned_pages - absent_pages(pages in holes);
	 *
	 * present_early_pages is present pages existing within the zone
	 * located on memory available since early boot, excluding hotplugged
	 * memory.
	 *
	 * managed_pages is present pages managed by the buddy system, which
	 * is calculated as (reserved_pages includes pages allocated by the
	 * bootmem allocator):
	 *	managed_pages = present_pages - reserved_pages;
	 *
	 * cma pages is present pages that are assigned for CMA use
	 * (MIGRATE_CMA).
	 *
	 * So present_pages may be used by memory hotplug or memory power
	 * management logic to figure out unmanaged pages by checking
	 * (present_pages - managed_pages). And managed_pages should be used
	 * by page allocator and vm scanner to calculate all kinds of watermarks
	 * and thresholds.
	 *
	 * Locking rules:
	 *
	 * zone_start_pfn and spanned_pages are protected by span_seqlock.
	 * It is a seqlock because it has to be read outside of zone-&gt;lock,
	 * and it is done in the main allocator path.  But, it is written
	 * quite infrequently.
	 *
	 * The span_seq lock is declared along with zone-&gt;lock because it is
	 * frequently read in proximity to zone-&gt;lock.  It&#39;s good to
	 * give them a chance of being in the same cacheline.
	 *
	 * Write access to present_pages at runtime should be protected by
	 * mem_hotplug_begin/end(). Any reader who can&#39;t tolerant drift of
	 * present_pages should get_online_mems() to get a stable value.
	 */</span>
	<span class="token class-name">atomic_long_t</span>		managed_pages<span class="token punctuation">;</span>
	<span class="token keyword">unsigned</span> <span class="token keyword">long</span>		spanned_pages<span class="token punctuation">;</span>
	<span class="token keyword">unsigned</span> <span class="token keyword">long</span>		present_pages<span class="token punctuation">;</span>
<span class="token macro property"><span class="token directive-hash">#</span><span class="token directive keyword">if</span> <span class="token expression"><span class="token function">defined</span><span class="token punctuation">(</span>CONFIG_MEMORY_HOTPLUG<span class="token punctuation">)</span></span></span>
	<span class="token keyword">unsigned</span> <span class="token keyword">long</span>		present_early_pages<span class="token punctuation">;</span>
<span class="token macro property"><span class="token directive-hash">#</span><span class="token directive keyword">endif</span></span>
<span class="token macro property"><span class="token directive-hash">#</span><span class="token directive keyword">ifdef</span> <span class="token expression">CONFIG_CMA</span></span>
	<span class="token keyword">unsigned</span> <span class="token keyword">long</span>		cma_pages<span class="token punctuation">;</span>
<span class="token macro property"><span class="token directive-hash">#</span><span class="token directive keyword">endif</span></span>

	<span class="token keyword">const</span> <span class="token keyword">char</span>		<span class="token operator">*</span>name<span class="token punctuation">;</span>

<span class="token macro property"><span class="token directive-hash">#</span><span class="token directive keyword">ifdef</span> <span class="token expression">CONFIG_MEMORY_ISOLATION</span></span>
	<span class="token comment">/*
	 * Number of isolated pageblock. It is used to solve incorrect
	 * freepage counting problem due to racy retrieving migratetype
	 * of pageblock. Protected by zone-&gt;lock.
	 */</span>
	<span class="token keyword">unsigned</span> <span class="token keyword">long</span>		nr_isolate_pageblock<span class="token punctuation">;</span>
<span class="token macro property"><span class="token directive-hash">#</span><span class="token directive keyword">endif</span></span>

<span class="token macro property"><span class="token directive-hash">#</span><span class="token directive keyword">ifdef</span> <span class="token expression">CONFIG_MEMORY_HOTPLUG</span></span>
	<span class="token comment">/* see spanned/present_pages for more description */</span>
	<span class="token class-name">seqlock_t</span>		span_seqlock<span class="token punctuation">;</span>
<span class="token macro property"><span class="token directive-hash">#</span><span class="token directive keyword">endif</span></span>

	<span class="token keyword">int</span> initialized<span class="token punctuation">;</span>

	<span class="token comment">/* Write-intensive fields used from the page allocator */</span>
	<span class="token function">ZONE_PADDING</span><span class="token punctuation">(</span>_pad1_<span class="token punctuation">)</span>

	<span class="token comment">/* free areas of different sizes */</span>
	<span class="token keyword">struct</span> <span class="token class-name">free_area</span>	free_area<span class="token punctuation">[</span>MAX_ORDER<span class="token punctuation">]</span><span class="token punctuation">;</span>

	<span class="token comment">/* zone flags, see below */</span>
	<span class="token keyword">unsigned</span> <span class="token keyword">long</span>		flags<span class="token punctuation">;</span>

	<span class="token comment">/* Primarily protects free_area */</span>
	<span class="token class-name">spinlock_t</span>		lock<span class="token punctuation">;</span>

	<span class="token comment">/* Write-intensive fields used by compaction and vmstats. */</span>
	<span class="token function">ZONE_PADDING</span><span class="token punctuation">(</span>_pad2_<span class="token punctuation">)</span>

	<span class="token comment">/*
	 * When free pages are below this point, additional steps are taken
	 * when reading the number of free pages to avoid per-cpu counter
	 * drift allowing watermarks to be breached
	 */</span>
	<span class="token keyword">unsigned</span> <span class="token keyword">long</span> percpu_drift_mark<span class="token punctuation">;</span>

<span class="token macro property"><span class="token directive-hash">#</span><span class="token directive keyword">if</span> <span class="token expression">defined CONFIG_COMPACTION <span class="token operator">||</span> defined CONFIG_CMA</span></span>
	<span class="token comment">/* pfn where compaction free scanner should start */</span>
	<span class="token keyword">unsigned</span> <span class="token keyword">long</span>		compact_cached_free_pfn<span class="token punctuation">;</span>
	<span class="token comment">/* pfn where compaction migration scanner should start */</span>
	<span class="token keyword">unsigned</span> <span class="token keyword">long</span>		compact_cached_migrate_pfn<span class="token punctuation">[</span>ASYNC_AND_SYNC<span class="token punctuation">]</span><span class="token punctuation">;</span>
	<span class="token keyword">unsigned</span> <span class="token keyword">long</span>		compact_init_migrate_pfn<span class="token punctuation">;</span>
	<span class="token keyword">unsigned</span> <span class="token keyword">long</span>		compact_init_free_pfn<span class="token punctuation">;</span>
<span class="token macro property"><span class="token directive-hash">#</span><span class="token directive keyword">endif</span></span>

<span class="token macro property"><span class="token directive-hash">#</span><span class="token directive keyword">ifdef</span> <span class="token expression">CONFIG_COMPACTION</span></span>
	<span class="token comment">/*
	 * On compaction failure, 1&lt;&lt;compact_defer_shift compactions
	 * are skipped before trying again. The number attempted since
	 * last failure is tracked with compact_considered.
	 * compact_order_failed is the minimum compaction failed order.
	 */</span>
	<span class="token keyword">unsigned</span> <span class="token keyword">int</span>		compact_considered<span class="token punctuation">;</span>
	<span class="token keyword">unsigned</span> <span class="token keyword">int</span>		compact_defer_shift<span class="token punctuation">;</span>
	<span class="token keyword">int</span>			compact_order_failed<span class="token punctuation">;</span>
<span class="token macro property"><span class="token directive-hash">#</span><span class="token directive keyword">endif</span></span>

<span class="token macro property"><span class="token directive-hash">#</span><span class="token directive keyword">if</span> <span class="token expression">defined CONFIG_COMPACTION <span class="token operator">||</span> defined CONFIG_CMA</span></span>
	<span class="token comment">/* Set to true when the PG_migrate_skip bits should be cleared */</span>
	bool			compact_blockskip_flush<span class="token punctuation">;</span>
<span class="token macro property"><span class="token directive-hash">#</span><span class="token directive keyword">endif</span></span>

	bool			contiguous<span class="token punctuation">;</span>

	<span class="token function">ZONE_PADDING</span><span class="token punctuation">(</span>_pad3_<span class="token punctuation">)</span>
	<span class="token comment">/* Zone statistics */</span>
	<span class="token class-name">atomic_long_t</span>		vm_stat<span class="token punctuation">[</span>NR_VM_ZONE_STAT_ITEMS<span class="token punctuation">]</span><span class="token punctuation">;</span>
	<span class="token class-name">atomic_long_t</span>		vm_numa_event<span class="token punctuation">[</span>NR_VM_NUMA_EVENT_ITEMS<span class="token punctuation">]</span><span class="token punctuation">;</span>
<span class="token punctuation">}</span> ____cacheline_internodealigned_in_smp<span class="token punctuation">;</span>
</code></pre><div class="line-numbers" aria-hidden="true"><span class="line-number">1</span><br><span class="line-number">2</span><br><span class="line-number">3</span><br><span class="line-number">4</span><br><span class="line-number">5</span><br><span class="line-number">6</span><br><span class="line-number">7</span><br><span class="line-number">8</span><br><span class="line-number">9</span><br><span class="line-number">10</span><br><span class="line-number">11</span><br><span class="line-number">12</span><br><span class="line-number">13</span><br><span class="line-number">14</span><br><span class="line-number">15</span><br><span class="line-number">16</span><br><span class="line-number">17</span><br><span class="line-number">18</span><br><span class="line-number">19</span><br><span class="line-number">20</span><br><span class="line-number">21</span><br><span class="line-number">22</span><br><span class="line-number">23</span><br><span class="line-number">24</span><br><span class="line-number">25</span><br><span class="line-number">26</span><br><span class="line-number">27</span><br><span class="line-number">28</span><br><span class="line-number">29</span><br><span class="line-number">30</span><br><span class="line-number">31</span><br><span class="line-number">32</span><br><span class="line-number">33</span><br><span class="line-number">34</span><br><span class="line-number">35</span><br><span class="line-number">36</span><br><span class="line-number">37</span><br><span class="line-number">38</span><br><span class="line-number">39</span><br><span class="line-number">40</span><br><span class="line-number">41</span><br><span class="line-number">42</span><br><span class="line-number">43</span><br><span class="line-number">44</span><br><span class="line-number">45</span><br><span class="line-number">46</span><br><span class="line-number">47</span><br><span class="line-number">48</span><br><span class="line-number">49</span><br><span class="line-number">50</span><br><span class="line-number">51</span><br><span class="line-number">52</span><br><span class="line-number">53</span><br><span class="line-number">54</span><br><span class="line-number">55</span><br><span class="line-number">56</span><br><span class="line-number">57</span><br><span class="line-number">58</span><br><span class="line-number">59</span><br><span class="line-number">60</span><br><span class="line-number">61</span><br><span class="line-number">62</span><br><span class="line-number">63</span><br><span class="line-number">64</span><br><span class="line-number">65</span><br><span class="line-number">66</span><br><span class="line-number">67</span><br><span class="line-number">68</span><br><span class="line-number">69</span><br><span class="line-number">70</span><br><span class="line-number">71</span><br><span class="line-number">72</span><br><span class="line-number">73</span><br><span class="line-number">74</span><br><span class="line-number">75</span><br><span class="line-number">76</span><br><span class="line-number">77</span><br><span class="line-number">78</span><br><span class="line-number">79</span><br><span class="line-number">80</span><br><span class="line-number">81</span><br><span class="line-number">82</span><br><span class="line-number">83</span><br><span class="line-number">84</span><br><span class="line-number">85</span><br><span class="line-number">86</span><br><span class="line-number">87</span><br><span class="line-number">88</span><br><span class="line-number">89</span><br><span class="line-number">90</span><br><span class="line-number">91</span><br><span class="line-number">92</span><br><span class="line-number">93</span><br><span class="line-number">94</span><br><span class="line-number">95</span><br><span class="line-number">96</span><br><span class="line-number">97</span><br><span class="line-number">98</span><br><span class="line-number">99</span><br><span class="line-number">100</span><br><span class="line-number">101</span><br><span class="line-number">102</span><br><span class="line-number">103</span><br><span class="line-number">104</span><br><span class="line-number">105</span><br><span class="line-number">106</span><br><span class="line-number">107</span><br><span class="line-number">108</span><br><span class="line-number">109</span><br><span class="line-number">110</span><br><span class="line-number">111</span><br><span class="line-number">112</span><br><span class="line-number">113</span><br><span class="line-number">114</span><br><span class="line-number">115</span><br><span class="line-number">116</span><br><span class="line-number">117</span><br><span class="line-number">118</span><br><span class="line-number">119</span><br><span class="line-number">120</span><br><span class="line-number">121</span><br><span class="line-number">122</span><br><span class="line-number">123</span><br><span class="line-number">124</span><br><span class="line-number">125</span><br><span class="line-number">126</span><br><span class="line-number">127</span><br><span class="line-number">128</span><br><span class="line-number">129</span><br><span class="line-number">130</span><br><span class="line-number">131</span><br><span class="line-number">132</span><br><span class="line-number">133</span><br><span class="line-number">134</span><br><span class="line-number">135</span><br><span class="line-number">136</span><br><span class="line-number">137</span><br><span class="line-number">138</span><br><span class="line-number">139</span><br><span class="line-number">140</span><br><span class="line-number">141</span><br><span class="line-number">142</span><br><span class="line-number">143</span><br><span class="line-number">144</span><br><span class="line-number">145</span><br><span class="line-number">146</span><br><span class="line-number">147</span><br><span class="line-number">148</span><br><span class="line-number">149</span><br><span class="line-number">150</span><br><span class="line-number">151</span><br><span class="line-number">152</span><br><span class="line-number">153</span><br><span class="line-number">154</span><br><span class="line-number">155</span><br><span class="line-number">156</span><br><span class="line-number">157</span><br><span class="line-number">158</span><br><span class="line-number">159</span><br><span class="line-number">160</span><br><span class="line-number">161</span><br><span class="line-number">162</span><br><span class="line-number">163</span><br><span class="line-number">164</span><br><span class="line-number">165</span><br><span class="line-number">166</span><br><span class="line-number">167</span><br><span class="line-number">168</span><br><span class="line-number">169</span><br><span class="line-number">170</span><br></div></div><div class="language-c ext-c line-numbers-mode"><pre class="language-c"><code>
<span class="token keyword">struct</span> <span class="token class-name">free_area</span> <span class="token punctuation">{</span>
	<span class="token keyword">struct</span> <span class="token class-name">list_head</span>	free_list<span class="token punctuation">[</span>MIGRATE_TYPES<span class="token punctuation">]</span><span class="token punctuation">;</span>
	<span class="token keyword">unsigned</span> <span class="token keyword">long</span>		nr_free<span class="token punctuation">;</span>
<span class="token punctuation">}</span><span class="token punctuation">;</span>
</code></pre><div class="line-numbers" aria-hidden="true"><span class="line-number">1</span><br><span class="line-number">2</span><br><span class="line-number">3</span><br><span class="line-number">4</span><br><span class="line-number">5</span><br></div></div><p>zonelist</p><div class="language-c ext-c line-numbers-mode"><pre class="language-c"><code>
<span class="token keyword">static</span> <span class="token keyword">inline</span> bool <span class="token function">prepare_alloc_pages</span><span class="token punctuation">(</span><span class="token class-name">gfp_t</span> gfp_mask<span class="token punctuation">,</span> <span class="token keyword">unsigned</span> <span class="token keyword">int</span> order<span class="token punctuation">,</span>
		<span class="token keyword">int</span> preferred_nid<span class="token punctuation">,</span> <span class="token class-name">nodemask_t</span> <span class="token operator">*</span>nodemask<span class="token punctuation">,</span>
		<span class="token keyword">struct</span> <span class="token class-name">alloc_context</span> <span class="token operator">*</span>ac<span class="token punctuation">,</span> <span class="token class-name">gfp_t</span> <span class="token operator">*</span>alloc_gfp<span class="token punctuation">,</span>
		<span class="token keyword">unsigned</span> <span class="token keyword">int</span> <span class="token operator">*</span>alloc_flags<span class="token punctuation">)</span>
<span class="token punctuation">{</span>
	ac<span class="token operator">-&gt;</span>highest_zoneidx <span class="token operator">=</span> <span class="token function">gfp_zone</span><span class="token punctuation">(</span>gfp_mask<span class="token punctuation">)</span><span class="token punctuation">;</span>
	ac<span class="token operator">-&gt;</span>zonelist <span class="token operator">=</span> <span class="token function">node_zonelist</span><span class="token punctuation">(</span>preferred_nid<span class="token punctuation">,</span> gfp_mask<span class="token punctuation">)</span><span class="token punctuation">;</span>
	ac<span class="token operator">-&gt;</span>nodemask <span class="token operator">=</span> nodemask<span class="token punctuation">;</span>
	ac<span class="token operator">-&gt;</span>migratetype <span class="token operator">=</span> <span class="token function">gfp_migratetype</span><span class="token punctuation">(</span>gfp_mask<span class="token punctuation">)</span><span class="token punctuation">;</span>

	<span class="token keyword">if</span> <span class="token punctuation">(</span><span class="token function">cpusets_enabled</span><span class="token punctuation">(</span><span class="token punctuation">)</span><span class="token punctuation">)</span> <span class="token punctuation">{</span>
		<span class="token operator">*</span>alloc_gfp <span class="token operator">|=</span> __GFP_HARDWALL<span class="token punctuation">;</span>
		<span class="token comment">/*
		 * When we are in the interrupt context, it is irrelevant
		 * to the current task context. It means that any node ok.
		 */</span>
		<span class="token keyword">if</span> <span class="token punctuation">(</span><span class="token function">in_task</span><span class="token punctuation">(</span><span class="token punctuation">)</span> <span class="token operator">&amp;&amp;</span> <span class="token operator">!</span>ac<span class="token operator">-&gt;</span>nodemask<span class="token punctuation">)</span>
			ac<span class="token operator">-&gt;</span>nodemask <span class="token operator">=</span> <span class="token operator">&amp;</span>cpuset_current_mems_allowed<span class="token punctuation">;</span>
		<span class="token keyword">else</span>
			<span class="token operator">*</span>alloc_flags <span class="token operator">|=</span> ALLOC_CPUSET<span class="token punctuation">;</span>
	<span class="token punctuation">}</span>

	<span class="token function">fs_reclaim_acquire</span><span class="token punctuation">(</span>gfp_mask<span class="token punctuation">)</span><span class="token punctuation">;</span>
	<span class="token function">fs_reclaim_release</span><span class="token punctuation">(</span>gfp_mask<span class="token punctuation">)</span><span class="token punctuation">;</span>

	<span class="token function">might_sleep_if</span><span class="token punctuation">(</span>gfp_mask <span class="token operator">&amp;</span> __GFP_DIRECT_RECLAIM<span class="token punctuation">)</span><span class="token punctuation">;</span>

	<span class="token keyword">if</span> <span class="token punctuation">(</span><span class="token function">should_fail_alloc_page</span><span class="token punctuation">(</span>gfp_mask<span class="token punctuation">,</span> order<span class="token punctuation">)</span><span class="token punctuation">)</span>
		<span class="token keyword">return</span> false<span class="token punctuation">;</span>

	<span class="token operator">*</span>alloc_flags <span class="token operator">=</span> <span class="token function">gfp_to_alloc_flags_cma</span><span class="token punctuation">(</span>gfp_mask<span class="token punctuation">,</span> <span class="token operator">*</span>alloc_flags<span class="token punctuation">)</span><span class="token punctuation">;</span>

	<span class="token comment">/* Dirty zone balancing only done in the fast path */</span>
	ac<span class="token operator">-&gt;</span>spread_dirty_pages <span class="token operator">=</span> <span class="token punctuation">(</span>gfp_mask <span class="token operator">&amp;</span> __GFP_WRITE<span class="token punctuation">)</span><span class="token punctuation">;</span>

	<span class="token comment">/*
	 * The preferred zone is used for statistics but crucially it is
	 * also used as the starting point for the zonelist iterator. It
	 * may get reset for allocations that ignore memory policies.
	 */</span>
	ac<span class="token operator">-&gt;</span>preferred_zoneref <span class="token operator">=</span> <span class="token function">first_zones_zonelist</span><span class="token punctuation">(</span>ac<span class="token operator">-&gt;</span>zonelist<span class="token punctuation">,</span>
					ac<span class="token operator">-&gt;</span>highest_zoneidx<span class="token punctuation">,</span> ac<span class="token operator">-&gt;</span>nodemask<span class="token punctuation">)</span><span class="token punctuation">;</span>

	<span class="token keyword">return</span> true<span class="token punctuation">;</span>
<span class="token punctuation">}</span>
</code></pre><div class="line-numbers" aria-hidden="true"><span class="line-number">1</span><br><span class="line-number">2</span><br><span class="line-number">3</span><br><span class="line-number">4</span><br><span class="line-number">5</span><br><span class="line-number">6</span><br><span class="line-number">7</span><br><span class="line-number">8</span><br><span class="line-number">9</span><br><span class="line-number">10</span><br><span class="line-number">11</span><br><span class="line-number">12</span><br><span class="line-number">13</span><br><span class="line-number">14</span><br><span class="line-number">15</span><br><span class="line-number">16</span><br><span class="line-number">17</span><br><span class="line-number">18</span><br><span class="line-number">19</span><br><span class="line-number">20</span><br><span class="line-number">21</span><br><span class="line-number">22</span><br><span class="line-number">23</span><br><span class="line-number">24</span><br><span class="line-number">25</span><br><span class="line-number">26</span><br><span class="line-number">27</span><br><span class="line-number">28</span><br><span class="line-number">29</span><br><span class="line-number">30</span><br><span class="line-number">31</span><br><span class="line-number">32</span><br><span class="line-number">33</span><br><span class="line-number">34</span><br><span class="line-number">35</span><br><span class="line-number">36</span><br><span class="line-number">37</span><br><span class="line-number">38</span><br><span class="line-number">39</span><br><span class="line-number">40</span><br><span class="line-number">41</span><br><span class="line-number">42</span><br><span class="line-number">43</span><br><span class="line-number">44</span><br><span class="line-number">45</span><br><span class="line-number">46</span><br></div></div><div class="language-c ext-c line-numbers-mode"><pre class="language-c"><code>
<span class="token comment">/*
 * We get the zone list from the current node and the gfp_mask.
 * This zone list contains a maximum of MAX_NUMNODES*MAX_NR_ZONES zones.
 * There are two zonelists per node, one for all zones with memory and
 * one containing just zones from the node the zonelist belongs to.
 *
 * For the case of non-NUMA systems the NODE_DATA() gets optimized to
 * &amp;contig_page_data at compile-time.
 */</span>
<span class="token keyword">static</span> <span class="token keyword">inline</span> <span class="token keyword">struct</span> <span class="token class-name">zonelist</span> <span class="token operator">*</span><span class="token function">node_zonelist</span><span class="token punctuation">(</span><span class="token keyword">int</span> nid<span class="token punctuation">,</span> <span class="token class-name">gfp_t</span> flags<span class="token punctuation">)</span>
<span class="token punctuation">{</span>
	<span class="token keyword">return</span> <span class="token function">NODE_DATA</span><span class="token punctuation">(</span>nid<span class="token punctuation">)</span><span class="token operator">-&gt;</span>node_zonelists <span class="token operator">+</span> <span class="token function">gfp_zonelist</span><span class="token punctuation">(</span>flags<span class="token punctuation">)</span><span class="token punctuation">;</span>
<span class="token punctuation">}</span>

</code></pre><div class="line-numbers" aria-hidden="true"><span class="line-number">1</span><br><span class="line-number">2</span><br><span class="line-number">3</span><br><span class="line-number">4</span><br><span class="line-number">5</span><br><span class="line-number">6</span><br><span class="line-number">7</span><br><span class="line-number">8</span><br><span class="line-number">9</span><br><span class="line-number">10</span><br><span class="line-number">11</span><br><span class="line-number">12</span><br><span class="line-number">13</span><br><span class="line-number">14</span><br><span class="line-number">15</span><br></div></div><p>NUMA:</p><div class="language-c ext-c line-numbers-mode"><pre class="language-c"><code>
<span class="token keyword">extern</span> <span class="token keyword">struct</span> <span class="token class-name">pglist_data</span> <span class="token operator">*</span>node_data<span class="token punctuation">[</span><span class="token punctuation">]</span><span class="token punctuation">;</span>

<span class="token macro property"><span class="token directive-hash">#</span><span class="token directive keyword">define</span> <span class="token macro-name function">NODE_DATA</span><span class="token expression"><span class="token punctuation">(</span>nid<span class="token punctuation">)</span>		<span class="token punctuation">(</span>node_data<span class="token punctuation">[</span>nid<span class="token punctuation">]</span><span class="token punctuation">)</span></span></span>

</code></pre><div class="line-numbers" aria-hidden="true"><span class="line-number">1</span><br><span class="line-number">2</span><br><span class="line-number">3</span><br><span class="line-number">4</span><br><span class="line-number">5</span><br></div></div><p>UMA:</p><div class="language-c ext-c line-numbers-mode"><pre class="language-c"><code>
<span class="token keyword">extern</span> <span class="token keyword">struct</span> <span class="token class-name">pglist_data</span> contig_page_data<span class="token punctuation">;</span>
<span class="token keyword">static</span> <span class="token keyword">inline</span> <span class="token keyword">struct</span> <span class="token class-name">pglist_data</span> <span class="token operator">*</span><span class="token function">NODE_DATA</span><span class="token punctuation">(</span><span class="token keyword">int</span> nid<span class="token punctuation">)</span>
<span class="token punctuation">{</span>
	<span class="token keyword">return</span> <span class="token operator">&amp;</span>contig_page_data<span class="token punctuation">;</span>
<span class="token punctuation">}</span>
</code></pre><div class="line-numbers" aria-hidden="true"><span class="line-number">1</span><br><span class="line-number">2</span><br><span class="line-number">3</span><br><span class="line-number">4</span><br><span class="line-number">5</span><br><span class="line-number">6</span><br></div></div><p>init</p><div class="language-c ext-c line-numbers-mode"><pre class="language-c"><code>
<span class="token comment">/*
 * Set up kernel memory allocators
 */</span>
<span class="token keyword">static</span> <span class="token keyword">void</span> __init <span class="token function">mm_init</span><span class="token punctuation">(</span><span class="token keyword">void</span><span class="token punctuation">)</span>
<span class="token punctuation">{</span>
	<span class="token comment">/*
	 * page_ext requires contiguous pages,
	 * bigger than MAX_ORDER unless SPARSEMEM.
	 */</span>
	<span class="token function">page_ext_init_flatmem</span><span class="token punctuation">(</span><span class="token punctuation">)</span><span class="token punctuation">;</span>
	<span class="token function">init_mem_debugging_and_hardening</span><span class="token punctuation">(</span><span class="token punctuation">)</span><span class="token punctuation">;</span>
	<span class="token function">kfence_alloc_pool</span><span class="token punctuation">(</span><span class="token punctuation">)</span><span class="token punctuation">;</span>
	<span class="token function">report_meminit</span><span class="token punctuation">(</span><span class="token punctuation">)</span><span class="token punctuation">;</span>
	<span class="token function">stack_depot_init</span><span class="token punctuation">(</span><span class="token punctuation">)</span><span class="token punctuation">;</span>
	<span class="token function">mem_init</span><span class="token punctuation">(</span><span class="token punctuation">)</span><span class="token punctuation">;</span>
	<span class="token function">mem_init_print_info</span><span class="token punctuation">(</span><span class="token punctuation">)</span><span class="token punctuation">;</span>
	<span class="token comment">/* page_owner must be initialized after buddy is ready */</span>
	<span class="token function">page_ext_init_flatmem_late</span><span class="token punctuation">(</span><span class="token punctuation">)</span><span class="token punctuation">;</span>
	<span class="token function">kmem_cache_init</span><span class="token punctuation">(</span><span class="token punctuation">)</span><span class="token punctuation">;</span>
	<span class="token function">kmemleak_init</span><span class="token punctuation">(</span><span class="token punctuation">)</span><span class="token punctuation">;</span>
	<span class="token function">pgtable_init</span><span class="token punctuation">(</span><span class="token punctuation">)</span><span class="token punctuation">;</span>
	<span class="token function">debug_objects_mem_init</span><span class="token punctuation">(</span><span class="token punctuation">)</span><span class="token punctuation">;</span>
	<span class="token function">vmalloc_init</span><span class="token punctuation">(</span><span class="token punctuation">)</span><span class="token punctuation">;</span>
	<span class="token comment">/* Should be run before the first non-init thread is created */</span>
	<span class="token function">init_espfix_bsp</span><span class="token punctuation">(</span><span class="token punctuation">)</span><span class="token punctuation">;</span>
	<span class="token comment">/* Should be run after espfix64 is set up. */</span>
	<span class="token function">pti_init</span><span class="token punctuation">(</span><span class="token punctuation">)</span><span class="token punctuation">;</span>
<span class="token punctuation">}</span>
</code></pre><div class="line-numbers" aria-hidden="true"><span class="line-number">1</span><br><span class="line-number">2</span><br><span class="line-number">3</span><br><span class="line-number">4</span><br><span class="line-number">5</span><br><span class="line-number">6</span><br><span class="line-number">7</span><br><span class="line-number">8</span><br><span class="line-number">9</span><br><span class="line-number">10</span><br><span class="line-number">11</span><br><span class="line-number">12</span><br><span class="line-number">13</span><br><span class="line-number">14</span><br><span class="line-number">15</span><br><span class="line-number">16</span><br><span class="line-number">17</span><br><span class="line-number">18</span><br><span class="line-number">19</span><br><span class="line-number">20</span><br><span class="line-number">21</span><br><span class="line-number">22</span><br><span class="line-number">23</span><br><span class="line-number">24</span><br><span class="line-number">25</span><br><span class="line-number">26</span><br><span class="line-number">27</span><br><span class="line-number">28</span><br><span class="line-number">29</span><br></div></div><div class="language-c ext-c line-numbers-mode"><pre class="language-c"><code>
<span class="token keyword">void</span> __init <span class="token function">mem_init</span><span class="token punctuation">(</span><span class="token keyword">void</span><span class="token punctuation">)</span>
<span class="token punctuation">{</span>
	<span class="token function">pci_iommu_alloc</span><span class="token punctuation">(</span><span class="token punctuation">)</span><span class="token punctuation">;</span>

	<span class="token comment">/* clear_bss() already clear the empty_zero_page */</span>

	<span class="token comment">/* this will put all memory onto the freelists */</span>
	<span class="token function">memblock_free_all</span><span class="token punctuation">(</span><span class="token punctuation">)</span><span class="token punctuation">;</span>
	after_bootmem <span class="token operator">=</span> <span class="token number">1</span><span class="token punctuation">;</span>
	x86_init<span class="token punctuation">.</span>hyper<span class="token punctuation">.</span><span class="token function">init_after_bootmem</span><span class="token punctuation">(</span><span class="token punctuation">)</span><span class="token punctuation">;</span>

	<span class="token comment">/*
	 * Must be done after boot memory is put on freelist, because here we
	 * might set fields in deferred struct pages that have not yet been
	 * initialized, and memblock_free_all() initializes all the reserved
	 * deferred pages for us.
	 */</span>
	<span class="token function">register_page_bootmem_info</span><span class="token punctuation">(</span><span class="token punctuation">)</span><span class="token punctuation">;</span>

	<span class="token comment">/* Register memory areas for /proc/kcore */</span>
	<span class="token keyword">if</span> <span class="token punctuation">(</span><span class="token function">get_gate_vma</span><span class="token punctuation">(</span><span class="token operator">&amp;</span>init_mm<span class="token punctuation">)</span><span class="token punctuation">)</span>
		<span class="token function">kclist_add</span><span class="token punctuation">(</span><span class="token operator">&amp;</span>kcore_vsyscall<span class="token punctuation">,</span> <span class="token punctuation">(</span><span class="token keyword">void</span> <span class="token operator">*</span><span class="token punctuation">)</span>VSYSCALL_ADDR<span class="token punctuation">,</span> PAGE_SIZE<span class="token punctuation">,</span> KCORE_USER<span class="token punctuation">)</span><span class="token punctuation">;</span>

	<span class="token function">preallocate_vmalloc_pages</span><span class="token punctuation">(</span><span class="token punctuation">)</span><span class="token punctuation">;</span>
<span class="token punctuation">}</span>
</code></pre><div class="line-numbers" aria-hidden="true"><span class="line-number">1</span><br><span class="line-number">2</span><br><span class="line-number">3</span><br><span class="line-number">4</span><br><span class="line-number">5</span><br><span class="line-number">6</span><br><span class="line-number">7</span><br><span class="line-number">8</span><br><span class="line-number">9</span><br><span class="line-number">10</span><br><span class="line-number">11</span><br><span class="line-number">12</span><br><span class="line-number">13</span><br><span class="line-number">14</span><br><span class="line-number">15</span><br><span class="line-number">16</span><br><span class="line-number">17</span><br><span class="line-number">18</span><br><span class="line-number">19</span><br><span class="line-number">20</span><br><span class="line-number">21</span><br><span class="line-number">22</span><br><span class="line-number">23</span><br><span class="line-number">24</span><br><span class="line-number">25</span><br><span class="line-number">26</span><br></div></div><div class="language-c ext-c line-numbers-mode"><pre class="language-c"><code>
<span class="token keyword">static</span> <span class="token keyword">void</span> __init <span class="token function">register_page_bootmem_info</span><span class="token punctuation">(</span><span class="token keyword">void</span><span class="token punctuation">)</span>
<span class="token punctuation">{</span>
<span class="token macro property"><span class="token directive-hash">#</span><span class="token directive keyword">if</span> <span class="token expression"><span class="token function">defined</span><span class="token punctuation">(</span>CONFIG_NUMA<span class="token punctuation">)</span> <span class="token operator">||</span> <span class="token function">defined</span><span class="token punctuation">(</span>CONFIG_HUGETLB_PAGE_FREE_VMEMMAP<span class="token punctuation">)</span></span></span>
	<span class="token keyword">int</span> i<span class="token punctuation">;</span>

	<span class="token function">for_each_online_node</span><span class="token punctuation">(</span>i<span class="token punctuation">)</span>
		<span class="token function">register_page_bootmem_info_node</span><span class="token punctuation">(</span><span class="token function">NODE_DATA</span><span class="token punctuation">(</span>i<span class="token punctuation">)</span><span class="token punctuation">)</span><span class="token punctuation">;</span>
<span class="token macro property"><span class="token directive-hash">#</span><span class="token directive keyword">endif</span></span>
<span class="token punctuation">}</span>
</code></pre><div class="line-numbers" aria-hidden="true"><span class="line-number">1</span><br><span class="line-number">2</span><br><span class="line-number">3</span><br><span class="line-number">4</span><br><span class="line-number">5</span><br><span class="line-number">6</span><br><span class="line-number">7</span><br><span class="line-number">8</span><br><span class="line-number">9</span><br><span class="line-number">10</span><br></div></div><div class="language-c ext-c line-numbers-mode"><pre class="language-c"><code>
<span class="token keyword">void</span> __init <span class="token function">register_page_bootmem_info_node</span><span class="token punctuation">(</span><span class="token keyword">struct</span> <span class="token class-name">pglist_data</span> <span class="token operator">*</span>pgdat<span class="token punctuation">)</span>
<span class="token punctuation">{</span>
	<span class="token keyword">unsigned</span> <span class="token keyword">long</span> i<span class="token punctuation">,</span> pfn<span class="token punctuation">,</span> end_pfn<span class="token punctuation">,</span> nr_pages<span class="token punctuation">;</span>
	<span class="token keyword">int</span> node <span class="token operator">=</span> pgdat<span class="token operator">-&gt;</span>node_id<span class="token punctuation">;</span>
	<span class="token keyword">struct</span> <span class="token class-name">page</span> <span class="token operator">*</span>page<span class="token punctuation">;</span>

	nr_pages <span class="token operator">=</span> <span class="token function">PAGE_ALIGN</span><span class="token punctuation">(</span><span class="token keyword">sizeof</span><span class="token punctuation">(</span><span class="token keyword">struct</span> <span class="token class-name">pglist_data</span><span class="token punctuation">)</span><span class="token punctuation">)</span> <span class="token operator">&gt;&gt;</span> PAGE_SHIFT<span class="token punctuation">;</span>
	page <span class="token operator">=</span> <span class="token function">virt_to_page</span><span class="token punctuation">(</span>pgdat<span class="token punctuation">)</span><span class="token punctuation">;</span>

	<span class="token keyword">for</span> <span class="token punctuation">(</span>i <span class="token operator">=</span> <span class="token number">0</span><span class="token punctuation">;</span> i <span class="token operator">&lt;</span> nr_pages<span class="token punctuation">;</span> i<span class="token operator">++</span><span class="token punctuation">,</span> page<span class="token operator">++</span><span class="token punctuation">)</span>
		<span class="token function">get_page_bootmem</span><span class="token punctuation">(</span>node<span class="token punctuation">,</span> page<span class="token punctuation">,</span> NODE_INFO<span class="token punctuation">)</span><span class="token punctuation">;</span>

	pfn <span class="token operator">=</span> pgdat<span class="token operator">-&gt;</span>node_start_pfn<span class="token punctuation">;</span>
	end_pfn <span class="token operator">=</span> <span class="token function">pgdat_end_pfn</span><span class="token punctuation">(</span>pgdat<span class="token punctuation">)</span><span class="token punctuation">;</span>

	<span class="token comment">/* register section info */</span>
	<span class="token keyword">for</span> <span class="token punctuation">(</span><span class="token punctuation">;</span> pfn <span class="token operator">&lt;</span> end_pfn<span class="token punctuation">;</span> pfn <span class="token operator">+=</span> PAGES_PER_SECTION<span class="token punctuation">)</span> <span class="token punctuation">{</span>
		<span class="token comment">/*
		 * Some platforms can assign the same pfn to multiple nodes - on
		 * node0 as well as nodeN.  To avoid registering a pfn against
		 * multiple nodes we check that this pfn does not already
		 * reside in some other nodes.
		 */</span>
		<span class="token keyword">if</span> <span class="token punctuation">(</span><span class="token function">pfn_valid</span><span class="token punctuation">(</span>pfn<span class="token punctuation">)</span> <span class="token operator">&amp;&amp;</span> <span class="token punctuation">(</span><span class="token function">early_pfn_to_nid</span><span class="token punctuation">(</span>pfn<span class="token punctuation">)</span> <span class="token operator">==</span> node<span class="token punctuation">)</span><span class="token punctuation">)</span>
			<span class="token function">register_page_bootmem_info_section</span><span class="token punctuation">(</span>pfn<span class="token punctuation">)</span><span class="token punctuation">;</span>
	<span class="token punctuation">}</span>
<span class="token punctuation">}</span>
</code></pre><div class="line-numbers" aria-hidden="true"><span class="line-number">1</span><br><span class="line-number">2</span><br><span class="line-number">3</span><br><span class="line-number">4</span><br><span class="line-number">5</span><br><span class="line-number">6</span><br><span class="line-number">7</span><br><span class="line-number">8</span><br><span class="line-number">9</span><br><span class="line-number">10</span><br><span class="line-number">11</span><br><span class="line-number">12</span><br><span class="line-number">13</span><br><span class="line-number">14</span><br><span class="line-number">15</span><br><span class="line-number">16</span><br><span class="line-number">17</span><br><span class="line-number">18</span><br><span class="line-number">19</span><br><span class="line-number">20</span><br><span class="line-number">21</span><br><span class="line-number">22</span><br><span class="line-number">23</span><br><span class="line-number">24</span><br><span class="line-number">25</span><br><span class="line-number">26</span><br><span class="line-number">27</span><br><span class="line-number">28</span><br></div></div>`,20);function t(e,o){return p}var r=s(a,[["render",t]]);export{r as default};
