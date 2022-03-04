# alloc_page

1. do_user_addr_fault

```c

/*
 * Handle faults in the user portion of the address space.  Nothing in here
 * should check X86_PF_USER without a specific justification: for almost
 * all purposes, we should treat a normal kernel access to user memory
 * (e.g. get_user(), put_user(), etc.) the same as the WRUSS instruction.
 * The one exception is AC flag handling, which is, per the x86
 * architecture, special for WRUSS.
 */
static inline
void do_user_addr_fault(struct pt_regs *regs,
			unsigned long error_code,
			unsigned long address)
{
	struct vm_area_struct *vma;
	struct task_struct *tsk;
	struct mm_struct *mm;
	vm_fault_t fault;
	unsigned int flags = FAULT_FLAG_DEFAULT;

	tsk = current;
	mm = tsk->mm;

	if (unlikely((error_code & (X86_PF_USER | X86_PF_INSTR)) == X86_PF_INSTR)) {
		/*
		 * Whoops, this is kernel mode code trying to execute from
		 * user memory.  Unless this is AMD erratum #93, which
		 * corrupts RIP such that it looks like a user address,
		 * this is unrecoverable.  Don't even try to look up the
		 * VMA or look for extable entries.
		 */
		if (is_errata93(regs, address))
			return;

		page_fault_oops(regs, error_code, address);
		return;
	}

	/* kprobes don't want to hook the spurious faults: */
	if (WARN_ON_ONCE(kprobe_page_fault(regs, X86_TRAP_PF)))
		return;

	/*
	 * Reserved bits are never expected to be set on
	 * entries in the user portion of the page tables.
	 */
	if (unlikely(error_code & X86_PF_RSVD))
		pgtable_bad(regs, error_code, address);

	/*
	 * If SMAP is on, check for invalid kernel (supervisor) access to user
	 * pages in the user address space.  The odd case here is WRUSS,
	 * which, according to the preliminary documentation, does not respect
	 * SMAP and will have the USER bit set so, in all cases, SMAP
	 * enforcement appears to be consistent with the USER bit.
	 */
	if (unlikely(cpu_feature_enabled(X86_FEATURE_SMAP) &&
		     !(error_code & X86_PF_USER) &&
		     !(regs->flags & X86_EFLAGS_AC))) {
		/*
		 * No extable entry here.  This was a kernel access to an
		 * invalid pointer.  get_kernel_nofault() will not get here.
		 */
		page_fault_oops(regs, error_code, address);
		return;
	}

	/*
	 * If we're in an interrupt, have no user context or are running
	 * in a region with pagefaults disabled then we must not take the fault
	 */
	if (unlikely(faulthandler_disabled() || !mm)) {
		bad_area_nosemaphore(regs, error_code, address);
		return;
	}

	/*
	 * It's safe to allow irq's after cr2 has been saved and the
	 * vmalloc fault has been handled.
	 *
	 * User-mode registers count as a user access even for any
	 * potential system fault or CPU buglet:
	 */
	if (user_mode(regs)) {
		local_irq_enable();
		flags |= FAULT_FLAG_USER;
	} else {
		if (regs->flags & X86_EFLAGS_IF)
			local_irq_enable();
	}

	perf_sw_event(PERF_COUNT_SW_PAGE_FAULTS, 1, regs, address);

	if (error_code & X86_PF_WRITE)
		flags |= FAULT_FLAG_WRITE;
	if (error_code & X86_PF_INSTR)
		flags |= FAULT_FLAG_INSTRUCTION;

#ifdef CONFIG_X86_64
	/*
	 * Faults in the vsyscall page might need emulation.  The
	 * vsyscall page is at a high address (>PAGE_OFFSET), but is
	 * considered to be part of the user address space.
	 *
	 * The vsyscall page does not have a "real" VMA, so do this
	 * emulation before we go searching for VMAs.
	 *
	 * PKRU never rejects instruction fetches, so we don't need
	 * to consider the PF_PK bit.
	 */
	if (is_vsyscall_vaddr(address)) {
		if (emulate_vsyscall(error_code, regs, address))
			return;
	}
#endif

	/*
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
	 */
	if (unlikely(!mmap_read_trylock(mm))) {
		if (!user_mode(regs) && !search_exception_tables(regs->ip)) {
			/*
			 * Fault from code in kernel from
			 * which we do not expect faults.
			 */
			bad_area_nosemaphore(regs, error_code, address);
			return;
		}
retry:
		mmap_read_lock(mm);
	} else {
		/*
		 * The above down_read_trylock() might have succeeded in
		 * which case we'll have missed the might_sleep() from
		 * down_read():
		 */
		might_sleep();
	}

	vma = find_vma(mm, address);
	if (unlikely(!vma)) {
		bad_area(regs, error_code, address);
		return;
	}
	if (likely(vma->vm_start <= address))
		goto good_area;
	if (unlikely(!(vma->vm_flags & VM_GROWSDOWN))) {
		bad_area(regs, error_code, address);
		return;
	}
	if (unlikely(expand_stack(vma, address))) {
		bad_area(regs, error_code, address);
		return;
	}

	/*
	 * Ok, we have a good vm_area for this memory access, so
	 * we can handle it..
	 */
good_area:
	if (unlikely(access_error(error_code, vma))) {
		bad_area_access_error(regs, error_code, address, vma);
		return;
	}

	/*
	 * If for any reason at all we couldn't handle the fault,
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
	 */
	fault = handle_mm_fault(vma, address, flags, regs);

	if (fault_signal_pending(fault, regs)) {
		/*
		 * Quick path to respond to signals.  The core mm code
		 * has unlocked the mm for us if we get here.
		 */
		if (!user_mode(regs))
			kernelmode_fixup_or_oops(regs, error_code, address,
						 SIGBUS, BUS_ADRERR,
						 ARCH_DEFAULT_PKEY);
		return;
	}

	/*
	 * If we need to retry the mmap_lock has already been released,
	 * and if there is a fatal signal pending there is no guarantee
	 * that we made any progress. Handle this case first.
	 */
	if (unlikely((fault & VM_FAULT_RETRY) &&
		     (flags & FAULT_FLAG_ALLOW_RETRY))) {
		flags |= FAULT_FLAG_TRIED;
		goto retry;
	}

	mmap_read_unlock(mm);
	if (likely(!(fault & VM_FAULT_ERROR)))
		return;

	if (fatal_signal_pending(current) && !user_mode(regs)) {
		kernelmode_fixup_or_oops(regs, error_code, address,
					 0, 0, ARCH_DEFAULT_PKEY);
		return;
	}

	if (fault & VM_FAULT_OOM) {
		/* Kernel mode? Handle exceptions or die: */
		if (!user_mode(regs)) {
			kernelmode_fixup_or_oops(regs, error_code, address,
						 SIGSEGV, SEGV_MAPERR,
						 ARCH_DEFAULT_PKEY);
			return;
		}

		/*
		 * We ran out of memory, call the OOM killer, and return the
		 * userspace (which will retry the fault, or kill us if we got
		 * oom-killed):
		 */
		pagefault_out_of_memory();
	} else {
		if (fault & (VM_FAULT_SIGBUS|VM_FAULT_HWPOISON|
			     VM_FAULT_HWPOISON_LARGE))
			do_sigbus(regs, error_code, address, fault);
		else if (fault & VM_FAULT_SIGSEGV)
			bad_area_nosemaphore(regs, error_code, address);
		else
			BUG();
	}
}
NOKPROBE_SYMBOL(do_user_addr_fault);
```

```c
do_user_addr_fault {
	vma = find_vma(mm, address);
	if (vma->vm_start <= address) {
		good_area;
	}
good_area:
	fault = handle_mm_fault(vma, address, flags, regs);
}
```



2. handle_mm_fault

   ```c
   
   /*
    * By the time we get here, we already hold the mm semaphore
    *
    * The mmap_lock may have been released depending on flags and our
    * return value.  See filemap_fault() and __lock_page_or_retry().
    */
   vm_fault_t handle_mm_fault(struct vm_area_struct *vma, unsigned long address,
   			   unsigned int flags, struct pt_regs *regs)
   {
   	vm_fault_t ret;
   
   	__set_current_state(TASK_RUNNING);
   
   	count_vm_event(PGFAULT);
   	count_memcg_event_mm(vma->vm_mm, PGFAULT);
   
   	/* do counter updates before entering really critical section. */
   	check_sync_rss_stat(current);
   
   	if (!arch_vma_access_permitted(vma, flags & FAULT_FLAG_WRITE,
   					    flags & FAULT_FLAG_INSTRUCTION,
   					    flags & FAULT_FLAG_REMOTE))
   		return VM_FAULT_SIGSEGV;
   
   	/*
   	 * Enable the memcg OOM handling for faults triggered in user
   	 * space.  Kernel faults are handled more gracefully.
   	 */
   	if (flags & FAULT_FLAG_USER)
   		mem_cgroup_enter_user_fault();
   
   	if (unlikely(is_vm_hugetlb_page(vma)))
   		ret = hugetlb_fault(vma->vm_mm, vma, address, flags);
   	else
   		ret = __handle_mm_fault(vma, address, flags);
   
   	if (flags & FAULT_FLAG_USER) {
   		mem_cgroup_exit_user_fault();
   		/*
   		 * The task may have entered a memcg OOM situation but
   		 * if the allocation error was handled gracefully (no
   		 * VM_FAULT_OOM), there is no need to kill anything.
   		 * Just clean up the OOM state peacefully.
   		 */
   		if (task_in_memcg_oom(current) && !(ret & VM_FAULT_OOM))
   			mem_cgroup_oom_synchronize(false);
   	}
   
   	mm_account_fault(regs, address, flags, ret);
   
   	return ret;
   }
   EXPORT_SYMBOL_GPL(handle_mm_fault);
   ```

3. __handle_mm_fault

   ```c
   
   /*
    * By the time we get here, we already hold the mm semaphore
    *
    * The mmap_lock may have been released depending on flags and our
    * return value.  See filemap_fault() and __lock_page_or_retry().
    */
   static vm_fault_t __handle_mm_fault(struct vm_area_struct *vma,
   		unsigned long address, unsigned int flags)
   {
   	struct vm_fault vmf = {
   		.vma = vma,
   		.address = address & PAGE_MASK,
   		.flags = flags,
   		.pgoff = linear_page_index(vma, address),
   		.gfp_mask = __get_fault_gfp_mask(vma),
   	};
   	unsigned int dirty = flags & FAULT_FLAG_WRITE;
   	struct mm_struct *mm = vma->vm_mm;
   	pgd_t *pgd;
   	p4d_t *p4d;
   	vm_fault_t ret;
   
   	pgd = pgd_offset(mm, address);
   	p4d = p4d_alloc(mm, pgd, address);
   	if (!p4d)
   		return VM_FAULT_OOM;
   
   	vmf.pud = pud_alloc(mm, p4d, address);
   	if (!vmf.pud)
   		return VM_FAULT_OOM;
   retry_pud:
   	if (pud_none(*vmf.pud) && __transparent_hugepage_enabled(vma)) {
   		ret = create_huge_pud(&vmf);
   		if (!(ret & VM_FAULT_FALLBACK))
   			return ret;
   	} else {
   		pud_t orig_pud = *vmf.pud;
   
   		barrier();
   		if (pud_trans_huge(orig_pud) || pud_devmap(orig_pud)) {
   
   			/* NUMA case for anonymous PUDs would go here */
   
   			if (dirty && !pud_write(orig_pud)) {
   				ret = wp_huge_pud(&vmf, orig_pud);
   				if (!(ret & VM_FAULT_FALLBACK))
   					return ret;
   			} else {
   				huge_pud_set_accessed(&vmf, orig_pud);
   				return 0;
   			}
   		}
   	}
   
   	vmf.pmd = pmd_alloc(mm, vmf.pud, address);
   	if (!vmf.pmd)
   		return VM_FAULT_OOM;
   
   	/* Huge pud page fault raced with pmd_alloc? */
   	if (pud_trans_unstable(vmf.pud))
   		goto retry_pud;
   
   	if (pmd_none(*vmf.pmd) && __transparent_hugepage_enabled(vma)) {
   		ret = create_huge_pmd(&vmf);
   		if (!(ret & VM_FAULT_FALLBACK))
   			return ret;
   	} else {
   		vmf.orig_pmd = *vmf.pmd;
   
   		barrier();
   		if (unlikely(is_swap_pmd(vmf.orig_pmd))) {
   			VM_BUG_ON(thp_migration_supported() &&
   					  !is_pmd_migration_entry(vmf.orig_pmd));
   			if (is_pmd_migration_entry(vmf.orig_pmd))
   				pmd_migration_entry_wait(mm, vmf.pmd);
   			return 0;
   		}
   		if (pmd_trans_huge(vmf.orig_pmd) || pmd_devmap(vmf.orig_pmd)) {
   			if (pmd_protnone(vmf.orig_pmd) && vma_is_accessible(vma))
   				return do_huge_pmd_numa_page(&vmf);
   
   			if (dirty && !pmd_write(vmf.orig_pmd)) {
   				ret = wp_huge_pmd(&vmf);
   				if (!(ret & VM_FAULT_FALLBACK))
   					return ret;
   			} else {
   				huge_pmd_set_accessed(&vmf);
   				return 0;
   			}
   		}
   	}
   
   	return handle_pte_fault(&vmf);
   }
   ```

4. handle_pte_fault

   ```c
   
   /*
    * These routines also need to handle stuff like marking pages dirty
    * and/or accessed for architectures that don't do it in hardware (most
    * RISC architectures).  The early dirtying is also good on the i386.
    *
    * There is also a hook called "update_mmu_cache()" that architectures
    * with external mmu caches can use to update those (ie the Sparc or
    * PowerPC hashed page tables that act as extended TLBs).
    *
    * We enter with non-exclusive mmap_lock (to exclude vma changes, but allow
    * concurrent faults).
    *
    * The mmap_lock may have been released depending on flags and our return value.
    * See filemap_fault() and __lock_page_or_retry().
    */
   static vm_fault_t handle_pte_fault(struct vm_fault *vmf)
   {
   	pte_t entry;
   
   	if (unlikely(pmd_none(*vmf->pmd))) {
   		/*
   		 * Leave __pte_alloc() until later: because vm_ops->fault may
   		 * want to allocate huge page, and if we expose page table
   		 * for an instant, it will be difficult to retract from
   		 * concurrent faults and from rmap lookups.
   		 */
   		vmf->pte = NULL;
   	} else {
   		/*
   		 * If a huge pmd materialized under us just retry later.  Use
   		 * pmd_trans_unstable() via pmd_devmap_trans_unstable() instead
   		 * of pmd_trans_huge() to ensure the pmd didn't become
   		 * pmd_trans_huge under us and then back to pmd_none, as a
   		 * result of MADV_DONTNEED running immediately after a huge pmd
   		 * fault in a different thread of this mm, in turn leading to a
   		 * misleading pmd_trans_huge() retval. All we have to ensure is
   		 * that it is a regular pmd that we can walk with
   		 * pte_offset_map() and we can do that through an atomic read
   		 * in C, which is what pmd_trans_unstable() provides.
   		 */
   		if (pmd_devmap_trans_unstable(vmf->pmd))
   			return 0;
   		/*
   		 * A regular pmd is established and it can't morph into a huge
   		 * pmd from under us anymore at this point because we hold the
   		 * mmap_lock read mode and khugepaged takes it in write mode.
   		 * So now it's safe to run pte_offset_map().
   		 */
   		vmf->pte = pte_offset_map(vmf->pmd, vmf->address);
   		vmf->orig_pte = *vmf->pte;
   
   		/*
   		 * some architectures can have larger ptes than wordsize,
   		 * e.g.ppc44x-defconfig has CONFIG_PTE_64BIT=y and
   		 * CONFIG_32BIT=y, so READ_ONCE cannot guarantee atomic
   		 * accesses.  The code below just needs a consistent view
   		 * for the ifs and we later double check anyway with the
   		 * ptl lock held. So here a barrier will do.
   		 */
   		barrier();
   		if (pte_none(vmf->orig_pte)) {
   			pte_unmap(vmf->pte);
   			vmf->pte = NULL;
   		}
   	}
   
   	if (!vmf->pte) {
   		if (vma_is_anonymous(vmf->vma))
   			return do_anonymous_page(vmf);
   		else
   			return do_fault(vmf);
   	}
   
   	if (!pte_present(vmf->orig_pte))
   		return do_swap_page(vmf);
   
   	if (pte_protnone(vmf->orig_pte) && vma_is_accessible(vmf->vma))
   		return do_numa_page(vmf);
   
   	vmf->ptl = pte_lockptr(vmf->vma->vm_mm, vmf->pmd);
   	spin_lock(vmf->ptl);
   	entry = vmf->orig_pte;
   	if (unlikely(!pte_same(*vmf->pte, entry))) {
   		update_mmu_tlb(vmf->vma, vmf->address, vmf->pte);
   		goto unlock;
   	}
   	if (vmf->flags & FAULT_FLAG_WRITE) {
   		if (!pte_write(entry))
   			return do_wp_page(vmf);
   		entry = pte_mkdirty(entry);
   	}
   	entry = pte_mkyoung(entry);
   	if (ptep_set_access_flags(vmf->vma, vmf->address, vmf->pte, entry,
   				vmf->flags & FAULT_FLAG_WRITE)) {
   		update_mmu_cache(vmf->vma, vmf->address, vmf->pte);
   	} else {
   		/* Skip spurious TLB flush for retried page fault */
   		if (vmf->flags & FAULT_FLAG_TRIED)
   			goto unlock;
   		/*
   		 * This is needed only for protection faults but the arch code
   		 * is not yet telling us if this is a protection fault or not.
   		 * This still avoids useless tlb flushes for .text page faults
   		 * with threads.
   		 */
   		if (vmf->flags & FAULT_FLAG_WRITE)
   			flush_tlb_fix_spurious_fault(vmf->vma, vmf->address);
   	}
   unlock:
   	pte_unmap_unlock(vmf->pte, vmf->ptl);
   	return 0;
   }
   ```

5. do_anonymous_page

   ```c
   
   /*
    * We enter with non-exclusive mmap_lock (to exclude vma changes,
    * but allow concurrent faults), and pte mapped but not yet locked.
    * We return with mmap_lock still held, but pte unmapped and unlocked.
    */
   static vm_fault_t do_anonymous_page(struct vm_fault *vmf)
   {
   	struct vm_area_struct *vma = vmf->vma;
   	struct page *page;
   	vm_fault_t ret = 0;
   	pte_t entry;
   
   	/* File mapping without ->vm_ops ? */
   	if (vma->vm_flags & VM_SHARED)
   		return VM_FAULT_SIGBUS;
   
   	/*
   	 * Use pte_alloc() instead of pte_alloc_map().  We can't run
   	 * pte_offset_map() on pmds where a huge pmd might be created
   	 * from a different thread.
   	 *
   	 * pte_alloc_map() is safe to use under mmap_write_lock(mm) or when
   	 * parallel threads are excluded by other means.
   	 *
   	 * Here we only have mmap_read_lock(mm).
   	 */
   	if (pte_alloc(vma->vm_mm, vmf->pmd))
   		return VM_FAULT_OOM;
   
   	/* See comment in handle_pte_fault() */
   	if (unlikely(pmd_trans_unstable(vmf->pmd)))
   		return 0;
   
   	/* Use the zero-page for reads */
   	if (!(vmf->flags & FAULT_FLAG_WRITE) &&
   			!mm_forbids_zeropage(vma->vm_mm)) {
   		entry = pte_mkspecial(pfn_pte(my_zero_pfn(vmf->address),
   						vma->vm_page_prot));
   		vmf->pte = pte_offset_map_lock(vma->vm_mm, vmf->pmd,
   				vmf->address, &vmf->ptl);
   		if (!pte_none(*vmf->pte)) {
   			update_mmu_tlb(vma, vmf->address, vmf->pte);
   			goto unlock;
   		}
   		ret = check_stable_address_space(vma->vm_mm);
   		if (ret)
   			goto unlock;
   		/* Deliver the page fault to userland, check inside PT lock */
   		if (userfaultfd_missing(vma)) {
   			pte_unmap_unlock(vmf->pte, vmf->ptl);
   			return handle_userfault(vmf, VM_UFFD_MISSING);
   		}
   		goto setpte;
   	}
   
   	/* Allocate our own private page. */
   	if (unlikely(anon_vma_prepare(vma)))
   		goto oom;
   	page = alloc_zeroed_user_highpage_movable(vma, vmf->address);
   	if (!page)
   		goto oom;
   
   	if (mem_cgroup_charge(page, vma->vm_mm, GFP_KERNEL))
   		goto oom_free_page;
   	cgroup_throttle_swaprate(page, GFP_KERNEL);
   
   	/*
   	 * The memory barrier inside __SetPageUptodate makes sure that
   	 * preceding stores to the page contents become visible before
   	 * the set_pte_at() write.
   	 */
   	__SetPageUptodate(page);
   
   	entry = mk_pte(page, vma->vm_page_prot);
   	entry = pte_sw_mkyoung(entry);
   	if (vma->vm_flags & VM_WRITE)
   		entry = pte_mkwrite(pte_mkdirty(entry));
   
   	vmf->pte = pte_offset_map_lock(vma->vm_mm, vmf->pmd, vmf->address,
   			&vmf->ptl);
   	if (!pte_none(*vmf->pte)) {
   		update_mmu_cache(vma, vmf->address, vmf->pte);
   		goto release;
   	}
   
   	ret = check_stable_address_space(vma->vm_mm);
   	if (ret)
   		goto release;
   
   	/* Deliver the page fault to userland, check inside PT lock */
   	if (userfaultfd_missing(vma)) {
   		pte_unmap_unlock(vmf->pte, vmf->ptl);
   		put_page(page);
   		return handle_userfault(vmf, VM_UFFD_MISSING);
   	}
   
   	inc_mm_counter_fast(vma->vm_mm, MM_ANONPAGES);
   	page_add_new_anon_rmap(page, vma, vmf->address, false);
   	lru_cache_add_inactive_or_unevictable(page, vma);
   setpte:
   	set_pte_at(vma->vm_mm, vmf->address, vmf->pte, entry);
   
   	/* No need to invalidate - it was non-present before */
   	update_mmu_cache(vma, vmf->address, vmf->pte);
   unlock:
   	pte_unmap_unlock(vmf->pte, vmf->ptl);
   	return ret;
   release:
   	put_page(page);
   	goto unlock;
   oom_free_page:
   	put_page(page);
   oom:
   	return VM_FAULT_OOM;
   }
   ```

6. alloc_zeroed_user_highpage_movable

   ```c
   
   /**
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
    */
   static inline struct page *
   alloc_zeroed_user_highpage_movable(struct vm_area_struct *vma,
   				   unsigned long vaddr)
   {
   	struct page *page = alloc_page_vma(GFP_HIGHUSER_MOVABLE, vma, vaddr);
   
   	if (page)
   		clear_user_highpage(page, vaddr);
   
   	return page;
   }
   ```

7. alloc_page_vma

   ```c
   
   /**
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
    */
   struct page *alloc_pages_vma(gfp_t gfp, int order, struct vm_area_struct *vma,
   		unsigned long addr, int node, bool hugepage)
   {
   	struct mempolicy *pol;
   	struct page *page;
   	int preferred_nid;
   	nodemask_t *nmask;
   
   	pol = get_vma_policy(vma, addr);
   
   	if (pol->mode == MPOL_INTERLEAVE) {
   		unsigned nid;
   
   		nid = interleave_nid(pol, vma, addr, PAGE_SHIFT + order);
   		mpol_cond_put(pol);
   		page = alloc_page_interleave(gfp, order, nid);
   		goto out;
   	}
   
   	if (pol->mode == MPOL_PREFERRED_MANY) {
   		page = alloc_pages_preferred_many(gfp, order, node, pol);
   		mpol_cond_put(pol);
   		goto out;
   	}
   
   	if (unlikely(IS_ENABLED(CONFIG_TRANSPARENT_HUGEPAGE) && hugepage)) {
   		int hpage_node = node;
   
   		/*
   		 * For hugepage allocation and non-interleave policy which
   		 * allows the current node (or other explicitly preferred
   		 * node) we only try to allocate from the current/preferred
   		 * node and don't fall back to other nodes, as the cost of
   		 * remote accesses would likely offset THP benefits.
   		 *
   		 * If the policy is interleave or does not allow the current
   		 * node in its nodemask, we allocate the standard way.
   		 */
   		if (pol->mode == MPOL_PREFERRED)
   			hpage_node = first_node(pol->nodes);
   
   		nmask = policy_nodemask(gfp, pol);
   		if (!nmask || node_isset(hpage_node, *nmask)) {
   			mpol_cond_put(pol);
   			/*
   			 * First, try to allocate THP only on local node, but
   			 * don't reclaim unnecessarily, just compact.
   			 */
   			page = __alloc_pages_node(hpage_node,
   				gfp | __GFP_THISNODE | __GFP_NORETRY, order);
   
   			/*
   			 * If hugepage allocations are configured to always
   			 * synchronous compact or the vma has been madvised
   			 * to prefer hugepage backing, retry allowing remote
   			 * memory with both reclaim and compact as well.
   			 */
   			if (!page && (gfp & __GFP_DIRECT_RECLAIM))
   				page = __alloc_pages_node(hpage_node,
   								gfp, order);
   
   			goto out;
   		}
   	}
   
   	nmask = policy_nodemask(gfp, pol);
   	preferred_nid = policy_node(gfp, pol, node);
   	page = __alloc_pages(gfp, order, preferred_nid, nmask);
   	mpol_cond_put(pol);
   out:
   	return page;
   }
   EXPORT_SYMBOL(alloc_pages_vma);
   ```

8. __alloc_pages

   ```c
   
   /*
    * This is the 'heart' of the zoned buddy allocator.
    */
   struct page *__alloc_pages(gfp_t gfp, unsigned int order, int preferred_nid,
   							nodemask_t *nodemask)
   {
   	struct page *page;
   	unsigned int alloc_flags = ALLOC_WMARK_LOW;
   	gfp_t alloc_gfp; /* The gfp_t that was actually used for allocation */
   	struct alloc_context ac = { };
   
   	/*
   	 * There are several places where we assume that the order value is sane
   	 * so bail out early if the request is out of bound.
   	 */
   	if (unlikely(order >= MAX_ORDER)) {
   		WARN_ON_ONCE(!(gfp & __GFP_NOWARN));
   		return NULL;
   	}
   
   	gfp &= gfp_allowed_mask;
   	/*
   	 * Apply scoped allocation constraints. This is mainly about GFP_NOFS
   	 * resp. GFP_NOIO which has to be inherited for all allocation requests
   	 * from a particular context which has been marked by
   	 * memalloc_no{fs,io}_{save,restore}. And PF_MEMALLOC_PIN which ensures
   	 * movable zones are not used during allocation.
   	 */
   	gfp = current_gfp_context(gfp);
   	alloc_gfp = gfp;
   	if (!prepare_alloc_pages(gfp, order, preferred_nid, nodemask, &ac,
   			&alloc_gfp, &alloc_flags))
   		return NULL;
   
   	/*
   	 * Forbid the first pass from falling back to types that fragment
   	 * memory until all local zones are considered.
   	 */
   	alloc_flags |= alloc_flags_nofragment(ac.preferred_zoneref->zone, gfp);
   
   	/* First allocation attempt */
   	page = get_page_from_freelist(alloc_gfp, order, alloc_flags, &ac);
   	if (likely(page))
   		goto out;
   
   	alloc_gfp = gfp;
   	ac.spread_dirty_pages = false;
   
   	/*
   	 * Restore the original nodemask if it was potentially replaced with
   	 * &cpuset_current_mems_allowed to optimize the fast-path attempt.
   	 */
   	ac.nodemask = nodemask;
   
   	page = __alloc_pages_slowpath(alloc_gfp, order, &ac);
   
   out:
   	if (memcg_kmem_enabled() && (gfp & __GFP_ACCOUNT) && page &&
   	    unlikely(__memcg_kmem_charge_page(page, gfp, order) != 0)) {
   		__free_pages(page, order);
   		page = NULL;
   	}
   
   	trace_mm_page_alloc(page, order, alloc_gfp, ac.migratetype);
   
   	return page;
   }
   EXPORT_SYMBOL(__alloc_pages);
   ```

9. get_page_from_freelist

   ```c
   
   /*
    * get_page_from_freelist goes through the zonelist trying to allocate
    * a page.
    */
   static struct page *
   get_page_from_freelist(gfp_t gfp_mask, unsigned int order, int alloc_flags,
   						const struct alloc_context *ac)
   {
   	struct zoneref *z;
   	struct zone *zone;
   	struct pglist_data *last_pgdat_dirty_limit = NULL;
   	bool no_fallback;
   
   retry:
   	/*
   	 * Scan zonelist, looking for a zone with enough free.
   	 * See also __cpuset_node_allowed() comment in kernel/cpuset.c.
   	 */
   	no_fallback = alloc_flags & ALLOC_NOFRAGMENT;
   	z = ac->preferred_zoneref;
   	for_next_zone_zonelist_nodemask(zone, z, ac->highest_zoneidx,
   					ac->nodemask) {
   		struct page *page;
   		unsigned long mark;
   
   		if (cpusets_enabled() &&
   			(alloc_flags & ALLOC_CPUSET) &&
   			!__cpuset_zone_allowed(zone, gfp_mask))
   				continue;
   		/*
   		 * When allocating a page cache page for writing, we
   		 * want to get it from a node that is within its dirty
   		 * limit, such that no single node holds more than its
   		 * proportional share of globally allowed dirty pages.
   		 * The dirty limits take into account the node's
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
   		 */
   		if (ac->spread_dirty_pages) {
   			if (last_pgdat_dirty_limit == zone->zone_pgdat)
   				continue;
   
   			if (!node_dirty_ok(zone->zone_pgdat)) {
   				last_pgdat_dirty_limit = zone->zone_pgdat;
   				continue;
   			}
   		}
   
   		if (no_fallback && nr_online_nodes > 1 &&
   		    zone != ac->preferred_zoneref->zone) {
   			int local_nid;
   
   			/*
   			 * If moving to a remote node, retry but allow
   			 * fragmenting fallbacks. Locality is more important
   			 * than fragmentation avoidance.
   			 */
   			local_nid = zone_to_nid(ac->preferred_zoneref->zone);
   			if (zone_to_nid(zone) != local_nid) {
   				alloc_flags &= ~ALLOC_NOFRAGMENT;
   				goto retry;
   			}
   		}
   
   		mark = wmark_pages(zone, alloc_flags & ALLOC_WMARK_MASK);
   		if (!zone_watermark_fast(zone, order, mark,
   				       ac->highest_zoneidx, alloc_flags,
   				       gfp_mask)) {
   			int ret;
   
   #ifdef CONFIG_DEFERRED_STRUCT_PAGE_INIT
   			/*
   			 * Watermark failed for this zone, but see if we can
   			 * grow this zone if it contains deferred pages.
   			 */
   			if (static_branch_unlikely(&deferred_pages)) {
   				if (_deferred_grow_zone(zone, order))
   					goto try_this_zone;
   			}
   #endif
   			/* Checked here to keep the fast path fast */
   			BUILD_BUG_ON(ALLOC_NO_WATERMARKS < NR_WMARK);
   			if (alloc_flags & ALLOC_NO_WATERMARKS)
   				goto try_this_zone;
   
   			if (!node_reclaim_enabled() ||
   			    !zone_allows_reclaim(ac->preferred_zoneref->zone, zone))
   				continue;
   
   			ret = node_reclaim(zone->zone_pgdat, gfp_mask, order);
   			switch (ret) {
   			case NODE_RECLAIM_NOSCAN:
   				/* did not scan */
   				continue;
   			case NODE_RECLAIM_FULL:
   				/* scanned but unreclaimable */
   				continue;
   			default:
   				/* did we reclaim enough */
   				if (zone_watermark_ok(zone, order, mark,
   					ac->highest_zoneidx, alloc_flags))
   					goto try_this_zone;
   
   				continue;
   			}
   		}
   
   try_this_zone:
   		page = rmqueue(ac->preferred_zoneref->zone, zone, order,
   				gfp_mask, alloc_flags, ac->migratetype);
   		if (page) {
   			prep_new_page(page, order, gfp_mask, alloc_flags);
   
   			/*
   			 * If this is a high-order atomic allocation then check
   			 * if the pageblock should be reserved for the future
   			 */
   			if (unlikely(order && (alloc_flags & ALLOC_HARDER)))
   				reserve_highatomic_pageblock(page, zone, order);
   
   			return page;
   		} else {
   #ifdef CONFIG_DEFERRED_STRUCT_PAGE_INIT
   			/* Try again if zone has deferred pages */
   			if (static_branch_unlikely(&deferred_pages)) {
   				if (_deferred_grow_zone(zone, order))
   					goto try_this_zone;
   			}
   #endif
   		}
   	}
   
   	/*
   	 * It's possible on a UMA machine to get through all zones that are
   	 * fragmented. If avoiding fragmentation, reset and try again.
   	 */
   	if (no_fallback) {
   		alloc_flags &= ~ALLOC_NOFRAGMENT;
   		goto retry;
   	}
   
   	return NULL;
   }
   ```

10. rmqueue

    ```c
    
    /*
     * Allocate a page from the given zone. Use pcplists for order-0 allocations.
     */
    static inline
    struct page *rmqueue(struct zone *preferred_zone,
    			struct zone *zone, unsigned int order,
    			gfp_t gfp_flags, unsigned int alloc_flags,
    			int migratetype)
    {
    	unsigned long flags;
    	struct page *page;
    
    	if (likely(pcp_allowed_order(order))) {
    		/*
    		 * MIGRATE_MOVABLE pcplist could have the pages on CMA area and
    		 * we need to skip it when CMA area isn't allowed.
    		 */
    		if (!IS_ENABLED(CONFIG_CMA) || alloc_flags & ALLOC_CMA ||
    				migratetype != MIGRATE_MOVABLE) {
    			page = rmqueue_pcplist(preferred_zone, zone, order,
    					gfp_flags, migratetype, alloc_flags);
    			goto out;
    		}
    	}
    
    	/*
    	 * We most definitely don't want callers attempting to
    	 * allocate greater than order-1 page units with __GFP_NOFAIL.
    	 */
    	WARN_ON_ONCE((gfp_flags & __GFP_NOFAIL) && (order > 1));
    	spin_lock_irqsave(&zone->lock, flags);
    
    	do {
    		page = NULL;
    		/*
    		 * order-0 request can reach here when the pcplist is skipped
    		 * due to non-CMA allocation context. HIGHATOMIC area is
    		 * reserved for high-order atomic allocation, so order-0
    		 * request should skip it.
    		 */
    		if (order > 0 && alloc_flags & ALLOC_HARDER) {
    			page = __rmqueue_smallest(zone, order, MIGRATE_HIGHATOMIC);
    			if (page)
    				trace_mm_page_alloc_zone_locked(page, order, migratetype);
    		}
    		if (!page)
    			page = __rmqueue(zone, order, migratetype, alloc_flags);
    	} while (page && check_new_pages(page, order));
    	if (!page)
    		goto failed;
    
    	__mod_zone_freepage_state(zone, -(1 << order),
    				  get_pcppage_migratetype(page));
    	spin_unlock_irqrestore(&zone->lock, flags);
    
    	__count_zid_vm_events(PGALLOC, page_zonenum(page), 1 << order);
    	zone_statistics(preferred_zone, zone, 1);
    
    out:
    	/* Separate test+clear to avoid unnecessary atomics */
    	if (test_bit(ZONE_BOOSTED_WATERMARK, &zone->flags)) {
    		clear_bit(ZONE_BOOSTED_WATERMARK, &zone->flags);
    		wakeup_kswapd(zone, 0, 0, zone_idx(zone));
    	}
    
    	VM_BUG_ON_PAGE(page && bad_range(zone, page), page);
    	return page;
    
    failed:
    	spin_unlock_irqrestore(&zone->lock, flags);
    	return NULL;
    }
    ```

11. __rmqueue

    ```c
    
    /*
     * Do the hard work of removing an element from the buddy allocator.
     * Call me with the zone->lock already held.
     */
    static __always_inline struct page *
    __rmqueue(struct zone *zone, unsigned int order, int migratetype,
    						unsigned int alloc_flags)
    {
    	struct page *page;
    
    	if (IS_ENABLED(CONFIG_CMA)) {
    		/*
    		 * Balance movable allocations between regular and CMA areas by
    		 * allocating from CMA when over half of the zone's free memory
    		 * is in the CMA area.
    		 */
    		if (alloc_flags & ALLOC_CMA &&
    		    zone_page_state(zone, NR_FREE_CMA_PAGES) >
    		    zone_page_state(zone, NR_FREE_PAGES) / 2) {
    			page = __rmqueue_cma_fallback(zone, order);
    			if (page)
    				goto out;
    		}
    	}
    retry:
    	page = __rmqueue_smallest(zone, order, migratetype);
    	if (unlikely(!page)) {
    		if (alloc_flags & ALLOC_CMA)
    			page = __rmqueue_cma_fallback(zone, order);
    
    		if (!page && __rmqueue_fallback(zone, order, migratetype,
    								alloc_flags))
    			goto retry;
    	}
    out:
    	if (page)
    		trace_mm_page_alloc_zone_locked(page, order, migratetype);
    	return page;
    }
    
    ```

12. __rmqueue_smallest

    ```c
    
    /*
     * Go through the free lists for the given migratetype and remove
     * the smallest available page from the freelists
     */
    static __always_inline
    struct page *__rmqueue_smallest(struct zone *zone, unsigned int order,
    						int migratetype)
    {
    	unsigned int current_order;
    	struct free_area *area;
    	struct page *page;
    
    	/* Find a page of the appropriate size in the preferred list */
    	for (current_order = order; current_order < MAX_ORDER; ++current_order) {
    		area = &(zone->free_area[current_order]);
    		page = get_page_from_free_area(area, migratetype);
    		if (!page)
    			continue;
    		del_page_from_free_list(page, zone, current_order);
    		expand(zone, page, order, current_order, migratetype);
    		set_pcppage_migratetype(page, migratetype);
    		return page;
    	}
    
    	return NULL;
    }
    
    
    ```

13. get_page_from_free_area

    ```c
    
    static inline struct page *get_page_from_free_area(struct free_area *area,
    					    int migratetype)
    {
    	return list_first_entry_or_null(&area->free_list[migratetype],
    					struct page, lru);
    }
    ```

14. list_first_entry_or_null

    ```c
    /**
     * list_first_entry_or_null - get the first element from a list
     * @ptr:	the list head to take the element from.
     * @type:	the type of the struct this is embedded in.
     * @member:	the name of the list_head within the struct.
     *
     * Note that if the list is empty, it returns NULL.
     */
    #define list_first_entry_or_null(ptr, type, member) ({ \
    	struct list_head *head__ = (ptr); \
    	struct list_head *pos__ = READ_ONCE(head__->next); \
    	pos__ != head__ ? list_entry(pos__, type, member) : NULL; \
    })
    
    ```

15. data structure



```c

/*
 * On NUMA machines, each NUMA node would have a pg_data_t to describe
 * it's memory layout. On UMA machines there is a single pglist_data which
 * describes the whole memory.
 *
 * Memory statistics and page replacement data structures are maintained on a
 * per-zone basis.
 */
typedef struct pglist_data {
	/*
	 * node_zones contains just the zones for THIS node. Not all of the
	 * zones may be populated, but it is the full list. It is referenced by
	 * this node's node_zonelists as well as other node's node_zonelists.
	 */
	struct zone node_zones[MAX_NR_ZONES];

	/*
	 * node_zonelists contains references to all zones in all nodes.
	 * Generally the first zones will be references to this node's
	 * node_zones.
	 */
	struct zonelist node_zonelists[MAX_ZONELISTS];

	int nr_zones; /* number of populated zones in this node */
#ifdef CONFIG_FLATMEM	/* means !SPARSEMEM */
	struct page *node_mem_map;
#ifdef CONFIG_PAGE_EXTENSION
	struct page_ext *node_page_ext;
#endif
#endif
#if defined(CONFIG_MEMORY_HOTPLUG) || defined(CONFIG_DEFERRED_STRUCT_PAGE_INIT)
	/*
	 * Must be held any time you expect node_start_pfn,
	 * node_present_pages, node_spanned_pages or nr_zones to stay constant.
	 * Also synchronizes pgdat->first_deferred_pfn during deferred page
	 * init.
	 *
	 * pgdat_resize_lock() and pgdat_resize_unlock() are provided to
	 * manipulate node_size_lock without checking for CONFIG_MEMORY_HOTPLUG
	 * or CONFIG_DEFERRED_STRUCT_PAGE_INIT.
	 *
	 * Nests above zone->lock and zone->span_seqlock
	 */
	spinlock_t node_size_lock;
#endif
	unsigned long node_start_pfn;
	unsigned long node_present_pages; /* total number of physical pages */
	unsigned long node_spanned_pages; /* total size of physical page
					     range, including holes */
	int node_id;
	wait_queue_head_t kswapd_wait;
	wait_queue_head_t pfmemalloc_wait;
	struct task_struct *kswapd;	/* Protected by
					   mem_hotplug_begin/end() */
	int kswapd_order;
	enum zone_type kswapd_highest_zoneidx;

	int kswapd_failures;		/* Number of 'reclaimed == 0' runs */

#ifdef CONFIG_COMPACTION
	int kcompactd_max_order;
	enum zone_type kcompactd_highest_zoneidx;
	wait_queue_head_t kcompactd_wait;
	struct task_struct *kcompactd;
	bool proactive_compact_trigger;
#endif
	/*
	 * This is a per-node reserve of pages that are not available
	 * to userspace allocations.
	 */
	unsigned long		totalreserve_pages;

#ifdef CONFIG_NUMA
	/*
	 * node reclaim becomes active if more unmapped pages exist.
	 */
	unsigned long		min_unmapped_pages;
	unsigned long		min_slab_pages;
#endif /* CONFIG_NUMA */

	/* Write-intensive fields used by page reclaim */
	ZONE_PADDING(_pad1_)

#ifdef CONFIG_DEFERRED_STRUCT_PAGE_INIT
	/*
	 * If memory initialisation on large machines is deferred then this
	 * is the first PFN that needs to be initialised.
	 */
	unsigned long first_deferred_pfn;
#endif /* CONFIG_DEFERRED_STRUCT_PAGE_INIT */

#ifdef CONFIG_TRANSPARENT_HUGEPAGE
	struct deferred_split deferred_split_queue;
#endif

	/* Fields commonly accessed by the page reclaim scanner */

	/*
	 * NOTE: THIS IS UNUSED IF MEMCG IS ENABLED.
	 *
	 * Use mem_cgroup_lruvec() to look up lruvecs.
	 */
	struct lruvec		__lruvec;

	unsigned long		flags;

	ZONE_PADDING(_pad2_)

	/* Per-node vmstats */
	struct per_cpu_nodestat __percpu *per_cpu_nodestats;
	atomic_long_t		vm_stat[NR_VM_NODE_STAT_ITEMS];
} pg_data_t;
```



```c

struct zone {
	/* Read-mostly fields */

	/* zone watermarks, access with *_wmark_pages(zone) macros */
	unsigned long _watermark[NR_WMARK];
	unsigned long watermark_boost;

	unsigned long nr_reserved_highatomic;

	/*
	 * We don't know if the memory that we're going to allocate will be
	 * freeable or/and it will be released eventually, so to avoid totally
	 * wasting several GB of ram we must reserve some of the lower zone
	 * memory (otherwise we risk to run OOM on the lower zones despite
	 * there being tons of freeable ram on the higher zones).  This array is
	 * recalculated at runtime if the sysctl_lowmem_reserve_ratio sysctl
	 * changes.
	 */
	long lowmem_reserve[MAX_NR_ZONES];

#ifdef CONFIG_NUMA
	int node;
#endif
	struct pglist_data	*zone_pgdat;
	struct per_cpu_pages	__percpu *per_cpu_pageset;
	struct per_cpu_zonestat	__percpu *per_cpu_zonestats;
	/*
	 * the high and batch values are copied to individual pagesets for
	 * faster access
	 */
	int pageset_high;
	int pageset_batch;

#ifndef CONFIG_SPARSEMEM
	/*
	 * Flags for a pageblock_nr_pages block. See pageblock-flags.h.
	 * In SPARSEMEM, this map is stored in struct mem_section
	 */
	unsigned long		*pageblock_flags;
#endif /* CONFIG_SPARSEMEM */

	/* zone_start_pfn == zone_start_paddr >> PAGE_SHIFT */
	unsigned long		zone_start_pfn;

	/*
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
	 * It is a seqlock because it has to be read outside of zone->lock,
	 * and it is done in the main allocator path.  But, it is written
	 * quite infrequently.
	 *
	 * The span_seq lock is declared along with zone->lock because it is
	 * frequently read in proximity to zone->lock.  It's good to
	 * give them a chance of being in the same cacheline.
	 *
	 * Write access to present_pages at runtime should be protected by
	 * mem_hotplug_begin/end(). Any reader who can't tolerant drift of
	 * present_pages should get_online_mems() to get a stable value.
	 */
	atomic_long_t		managed_pages;
	unsigned long		spanned_pages;
	unsigned long		present_pages;
#if defined(CONFIG_MEMORY_HOTPLUG)
	unsigned long		present_early_pages;
#endif
#ifdef CONFIG_CMA
	unsigned long		cma_pages;
#endif

	const char		*name;

#ifdef CONFIG_MEMORY_ISOLATION
	/*
	 * Number of isolated pageblock. It is used to solve incorrect
	 * freepage counting problem due to racy retrieving migratetype
	 * of pageblock. Protected by zone->lock.
	 */
	unsigned long		nr_isolate_pageblock;
#endif

#ifdef CONFIG_MEMORY_HOTPLUG
	/* see spanned/present_pages for more description */
	seqlock_t		span_seqlock;
#endif

	int initialized;

	/* Write-intensive fields used from the page allocator */
	ZONE_PADDING(_pad1_)

	/* free areas of different sizes */
	struct free_area	free_area[MAX_ORDER];

	/* zone flags, see below */
	unsigned long		flags;

	/* Primarily protects free_area */
	spinlock_t		lock;

	/* Write-intensive fields used by compaction and vmstats. */
	ZONE_PADDING(_pad2_)

	/*
	 * When free pages are below this point, additional steps are taken
	 * when reading the number of free pages to avoid per-cpu counter
	 * drift allowing watermarks to be breached
	 */
	unsigned long percpu_drift_mark;

#if defined CONFIG_COMPACTION || defined CONFIG_CMA
	/* pfn where compaction free scanner should start */
	unsigned long		compact_cached_free_pfn;
	/* pfn where compaction migration scanner should start */
	unsigned long		compact_cached_migrate_pfn[ASYNC_AND_SYNC];
	unsigned long		compact_init_migrate_pfn;
	unsigned long		compact_init_free_pfn;
#endif

#ifdef CONFIG_COMPACTION
	/*
	 * On compaction failure, 1<<compact_defer_shift compactions
	 * are skipped before trying again. The number attempted since
	 * last failure is tracked with compact_considered.
	 * compact_order_failed is the minimum compaction failed order.
	 */
	unsigned int		compact_considered;
	unsigned int		compact_defer_shift;
	int			compact_order_failed;
#endif

#if defined CONFIG_COMPACTION || defined CONFIG_CMA
	/* Set to true when the PG_migrate_skip bits should be cleared */
	bool			compact_blockskip_flush;
#endif

	bool			contiguous;

	ZONE_PADDING(_pad3_)
	/* Zone statistics */
	atomic_long_t		vm_stat[NR_VM_ZONE_STAT_ITEMS];
	atomic_long_t		vm_numa_event[NR_VM_NUMA_EVENT_ITEMS];
} ____cacheline_internodealigned_in_smp;
```



```c

struct free_area {
	struct list_head	free_list[MIGRATE_TYPES];
	unsigned long		nr_free;
};
```



zonelist

```c

static inline bool prepare_alloc_pages(gfp_t gfp_mask, unsigned int order,
		int preferred_nid, nodemask_t *nodemask,
		struct alloc_context *ac, gfp_t *alloc_gfp,
		unsigned int *alloc_flags)
{
	ac->highest_zoneidx = gfp_zone(gfp_mask);
	ac->zonelist = node_zonelist(preferred_nid, gfp_mask);
	ac->nodemask = nodemask;
	ac->migratetype = gfp_migratetype(gfp_mask);

	if (cpusets_enabled()) {
		*alloc_gfp |= __GFP_HARDWALL;
		/*
		 * When we are in the interrupt context, it is irrelevant
		 * to the current task context. It means that any node ok.
		 */
		if (in_task() && !ac->nodemask)
			ac->nodemask = &cpuset_current_mems_allowed;
		else
			*alloc_flags |= ALLOC_CPUSET;
	}

	fs_reclaim_acquire(gfp_mask);
	fs_reclaim_release(gfp_mask);

	might_sleep_if(gfp_mask & __GFP_DIRECT_RECLAIM);

	if (should_fail_alloc_page(gfp_mask, order))
		return false;

	*alloc_flags = gfp_to_alloc_flags_cma(gfp_mask, *alloc_flags);

	/* Dirty zone balancing only done in the fast path */
	ac->spread_dirty_pages = (gfp_mask & __GFP_WRITE);

	/*
	 * The preferred zone is used for statistics but crucially it is
	 * also used as the starting point for the zonelist iterator. It
	 * may get reset for allocations that ignore memory policies.
	 */
	ac->preferred_zoneref = first_zones_zonelist(ac->zonelist,
					ac->highest_zoneidx, ac->nodemask);

	return true;
}
```



```c

/*
 * We get the zone list from the current node and the gfp_mask.
 * This zone list contains a maximum of MAX_NUMNODES*MAX_NR_ZONES zones.
 * There are two zonelists per node, one for all zones with memory and
 * one containing just zones from the node the zonelist belongs to.
 *
 * For the case of non-NUMA systems the NODE_DATA() gets optimized to
 * &contig_page_data at compile-time.
 */
static inline struct zonelist *node_zonelist(int nid, gfp_t flags)
{
	return NODE_DATA(nid)->node_zonelists + gfp_zonelist(flags);
}

```



NUMA:

```c

extern struct pglist_data *node_data[];

#define NODE_DATA(nid)		(node_data[nid])

```



UMA:

```c

extern struct pglist_data contig_page_data;
static inline struct pglist_data *NODE_DATA(int nid)
{
	return &contig_page_data;
}
```



init

```c

/*
 * Set up kernel memory allocators
 */
static void __init mm_init(void)
{
	/*
	 * page_ext requires contiguous pages,
	 * bigger than MAX_ORDER unless SPARSEMEM.
	 */
	page_ext_init_flatmem();
	init_mem_debugging_and_hardening();
	kfence_alloc_pool();
	report_meminit();
	stack_depot_init();
	mem_init();
	mem_init_print_info();
	/* page_owner must be initialized after buddy is ready */
	page_ext_init_flatmem_late();
	kmem_cache_init();
	kmemleak_init();
	pgtable_init();
	debug_objects_mem_init();
	vmalloc_init();
	/* Should be run before the first non-init thread is created */
	init_espfix_bsp();
	/* Should be run after espfix64 is set up. */
	pti_init();
}
```





```c

void __init mem_init(void)
{
	pci_iommu_alloc();

	/* clear_bss() already clear the empty_zero_page */

	/* this will put all memory onto the freelists */
	memblock_free_all();
	after_bootmem = 1;
	x86_init.hyper.init_after_bootmem();

	/*
	 * Must be done after boot memory is put on freelist, because here we
	 * might set fields in deferred struct pages that have not yet been
	 * initialized, and memblock_free_all() initializes all the reserved
	 * deferred pages for us.
	 */
	register_page_bootmem_info();

	/* Register memory areas for /proc/kcore */
	if (get_gate_vma(&init_mm))
		kclist_add(&kcore_vsyscall, (void *)VSYSCALL_ADDR, PAGE_SIZE, KCORE_USER);

	preallocate_vmalloc_pages();
}
```





```c

static void __init register_page_bootmem_info(void)
{
#if defined(CONFIG_NUMA) || defined(CONFIG_HUGETLB_PAGE_FREE_VMEMMAP)
	int i;

	for_each_online_node(i)
		register_page_bootmem_info_node(NODE_DATA(i));
#endif
}
```





```c

void __init register_page_bootmem_info_node(struct pglist_data *pgdat)
{
	unsigned long i, pfn, end_pfn, nr_pages;
	int node = pgdat->node_id;
	struct page *page;

	nr_pages = PAGE_ALIGN(sizeof(struct pglist_data)) >> PAGE_SHIFT;
	page = virt_to_page(pgdat);

	for (i = 0; i < nr_pages; i++, page++)
		get_page_bootmem(node, page, NODE_INFO);

	pfn = pgdat->node_start_pfn;
	end_pfn = pgdat_end_pfn(pgdat);

	/* register section info */
	for (; pfn < end_pfn; pfn += PAGES_PER_SECTION) {
		/*
		 * Some platforms can assign the same pfn to multiple nodes - on
		 * node0 as well as nodeN.  To avoid registering a pfn against
		 * multiple nodes we check that this pfn does not already
		 * reside in some other nodes.
		 */
		if (pfn_valid(pfn) && (early_pfn_to_nid(pfn) == node))
			register_page_bootmem_info_section(pfn);
	}
}
```





