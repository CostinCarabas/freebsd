/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2018, 2019 Andrew Turner
 * All rights reserved.
 *
 * This software was developed by SRI International and the University of
 * Cambridge Computer Laboratory under DARPA/AFRL contract FA8750-10-C-0237
 * ("CTSRD"), as part of the DARPA CRASH research programme.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include "opt_sanitizer.h"

#include <sys/cdefs.h>
#include <sys/types.h>
#include <sys/kasan.h>
#include <sys/systm.h>

#include <vm/vm.h>
#include <vm/pmap.h>
#include <vm/vm_param.h>
#include <vm/vm_page.h>

#include <machine/pte.h>

#define	KASAN_L2_TABLES	64

static pd_entry_t kasan_l1[Ln_ENTRIES] __aligned(PAGE_SIZE);
static pd_entry_t kasan_l2[KASAN_L2_TABLES * Ln_ENTRIES] __aligned(PAGE_SIZE);

/* Sanity check the KASAN region has enough virtual address space */
CTASSERT((KASAN_MAX_ADDRESS - KASAN_MIN_ADDRESS) ==
    (VM_MAX_KERNEL_ADDRESS - VM_MIN_KERNEL_ADDRESS) >> 3);
/* Check the L1 and L2 tables are large enough */
CTASSERT((KASAN_MAX_ADDRESS - KASAN_MIN_ADDRESS) <=
    ((uint64_t)L1_SIZE * nitems(kasan_l1)));
CTASSERT((KASAN_MAX_ADDRESS - KASAN_MIN_ADDRESS) <=
    ((uint64_t)L2_SIZE * nitems(kasan_l2)));


void
kasan_arch_init(void)
{
	vm_paddr_t pa;
	int i, j;

	KASSERT(kernel_pmap->pm_l0[pmap_l0_index(KASAN_MIN_ADDRESS)] == 0, 
	    ("kasan_init: Already mapped KASAN region"));

	memset(kasan_l1, 0, sizeof(kasan_l1));
	memset(kasan_l2, 0, sizeof(kasan_l2));

	for (i = pmap_l1_index(KASAN_MIN_ADDRESS), j = 0;
	    i < pmap_l1_index(KASAN_MAX_ADDRESS); i++, j++) {
		KASSERT(j < KASAN_L2_TABLES,
		    ("kasan_init: Not enough L2 page tables"));
		pa = pmap_kextract((vm_offset_t)&kasan_l2[j * Ln_ENTRIES]);
		KASSERT(pa != 0,
		    ("kasan_init: Unable to find L2 physical address"));
		kasan_l1[i] = pa | L1_TABLE;
	}

	KASSERT(pmap_l0_index(KASAN_MIN_ADDRESS) == pmap_l0_index(KASAN_MAX_ADDRESS - 1), ("kasan_init: KASAN region doesn't fit in one L0 table"));
	pa = pmap_kextract((vm_offset_t)&kasan_l1[0]);
	KASSERT(pa != 0, ("kasan_init: Unable to find L1 physical address"));
	kernel_pmap->pm_l0[pmap_l0_index(KASAN_MIN_ADDRESS)] = pa | L0_TABLE;
}

void
kasan_shadow_map(vm_offset_t addr, vm_size_t size)
{
	vm_offset_t start, end;
	vm_paddr_t paddr;
	vm_page_t nkpg;
	int idx;

	KASSERT(addr >= VM_MIN_KERNEL_ADDRESS,
	    ("kasan_grow_shadow_map: Invalid userspace address %lx", addr));
	KASSERT(addr < VM_MAX_KERNEL_ADDRESS,
	    ("kasan_grow_shadow_map: Invalid address %lx", addr));

	start = kasan_kmem_to_shadow(addr);
	KASSERT(start < KASAN_MAX_ADDRESS,
	    ("kasan_grow_shadow_map: Bad start address found: %lx", start));
	end = kasan_kmem_to_shadow(addr + size);
	if (end > KASAN_MAX_ADDRESS)
		end = KASAN_MAX_ADDRESS;
	while (start < end) {
		if (pmap_kextract(start) != 0)
			goto next;
		idx = (start - KASAN_MIN_ADDRESS) >> L2_SHIFT;
		KASSERT(idx < nitems(kasan_l2),
		    ("kasan_grow_shadow_map: L2 Index out of range (%d >= %zu)",
		    idx, nitems(kasan_l2)));
		if (kasan_l2[idx] == 0) {
			nkpg = vm_page_alloc(NULL, 0,
			    VM_ALLOC_INTERRUPT | VM_ALLOC_NOOBJ |
			    VM_ALLOC_WIRED | VM_ALLOC_ZERO);
			if (nkpg == NULL)
				panic("kasan_grow_shadow_map: "
				    "no memory to grow L2 shadow map");
			if ((nkpg->flags & PG_ZERO) == 0)
				pmap_zero_page(nkpg);
			paddr = VM_PAGE_TO_PHYS(nkpg);
			kasan_l2[idx] = paddr | L2_TABLE;
		}

		nkpg = vm_page_alloc(NULL, 0,
		    VM_ALLOC_INTERRUPT | VM_ALLOC_NOOBJ | VM_ALLOC_WIRED |
		    VM_ALLOC_ZERO);
		if (nkpg == NULL)
			panic("kasan_grow_shadow_map: "
			    "no memory to grow L3 shadow map");
		if ((nkpg->flags & PG_ZERO) == 0)
			pmap_zero_page(nkpg);
		paddr = VM_PAGE_TO_PHYS(nkpg);
		pmap_kenter(start, PAGE_SIZE, paddr, VM_MEMATTR_WRITE_BACK);

		__builtin_memset((void *)start, 0xff, PAGE_SIZE);
next:
		start = (start + L3_SIZE) & ~L3_OFFSET;
	}
}
