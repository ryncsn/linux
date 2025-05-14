/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _MM_SWAP_TABLE_H
#define _MM_SWAP_TABLE_H

#include <linux/rcupdate.h>
#include "swap.h"

/*
 * Swap table entry type and bit layouts:
 *
 * NULL:     | ------------    0   -------------|
 * Shadow:   | SWAP_COUNT |---- SHADOW_VAL ---|1|
 * Folio:    | SWAP_COUNT |------ PFN -------|10|
 * Pointer:  |----------- Pointer ----------|100|
 *
 * Usage:
 * - NULL: Swap Entry is unused.
 *
 * - Shadow: Swap Entry is used and not cached (swapped out).
 *   It's reusing XA_VALUE format to be compatible with workingset
 *   shadows. SHADOW_VAL part could be all 0.
 *
 * - Folio: Swap Entry is in cache.
 *
 * - Pointer: Unused yet. Because only the last three bit of a pointer
 *   is usable so now `100` is reserved for potential pointer use.
 */

#define ENTRY_COUNT_BITS	BITS_PER_BYTE
#define ENTRY_SHADOW_MARK	0b1UL
#define ENTRY_PFN_MARK		0b10UL
#define ENTRY_PFN_LOW_MASK	0b11UL
#define ENTRY_PFN_SHIFT		2
#define ENTRY_PFN_MASK		((~0UL) >> ENTRY_COUNT_BITS)
#define ENTRY_COUNT_MASK	(~((~0UL) >> ENTRY_COUNT_BITS))
#define ENTRY_COUNT_SHIFT	(BITS_PER_LONG - BITS_PER_BYTE)
#define ENTRY_COUNT_MAX		((1 << ENTRY_COUNT_BITS) - 2)
#define ENTRY_COUNT_BAD		((1 << ENTRY_COUNT_BITS) - 1) /* ENTRY_BAD */
#define ENTRY_BAD		(~0UL)

/* For shadow offset calculation */
#define SWAP_COUNT_SHIFT	ENTRY_COUNT_BITS

/*
 * Helpers for casting one type of info into a swap table entry.
 */
static inline swp_te_t null_swp_te(void)
{
	swp_te_t swp_te = ATOMIC_LONG_INIT(0);
	return swp_te;
}

static inline swp_te_t folio_swp_te(struct folio *folio)
{
	BUILD_BUG_ON((MAX_POSSIBLE_PHYSMEM_BITS - PAGE_SHIFT) >
		     (BITS_PER_LONG - ENTRY_PFN_SHIFT - ENTRY_COUNT_BITS));
	swp_te_t swp_te = {
		.counter = (folio_pfn(folio) << ENTRY_PFN_SHIFT) | ENTRY_PFN_MARK
	};
	return swp_te;
}

static inline swp_te_t shadow_swp_te(void *shadow)
{
	swp_te_t swp_te = { .counter = ((unsigned long)shadow) };
	BUILD_BUG_ON((BITS_PER_XA_VALUE + 1) != BITS_PER_BYTE * sizeof(swp_te_t));
	BUILD_BUG_ON((unsigned long)xa_mk_value(0) != ENTRY_SHADOW_MARK);
	VM_WARN_ON_ONCE(shadow && !xa_is_value(shadow));
	VM_WARN_ON((unsigned long)shadow & ENTRY_COUNT_MASK);
	swp_te.counter |= ENTRY_SHADOW_MARK;
	return swp_te;
}

static inline swp_te_t bad_swp_te(void)
{
	swp_te_t swp_te = { .counter = ENTRY_BAD };
	return swp_te;
}

/*
 * Helpers for swap table entry type checking.
 */
static inline bool swp_te_is_null(swp_te_t swp_te)
{
	return !swp_te.counter;
}

static inline bool swp_te_is_folio(swp_te_t swp_te)
{
	return ((swp_te.counter & ENTRY_PFN_LOW_MASK) == ENTRY_PFN_MARK);
}

static inline bool swp_te_is_shadow(swp_te_t swp_te)
{
	return xa_is_value((void *)swp_te.counter);
}

static inline bool swp_te_is_valid_shadow(swp_te_t swp_te)
{
	/* The shadow could be empty, just for holding the swap count */
	return xa_is_value((void *)swp_te.counter) &&
	       xa_to_value((void *)swp_te.counter);
}

static inline bool swp_te_is_bad(swp_te_t swp_te)
{
	return swp_te.counter == ENTRY_BAD;
}

static inline bool __swp_te_is_countable(swp_te_t ent)
{
	return (swp_te_is_shadow(ent) || swp_te_is_folio(ent) ||
		swp_te_is_null(ent));
}

/*
 * Helpers for retrieving info from swap table.
 */
static inline struct folio *swp_te_folio(swp_te_t swp_te)
{
	VM_WARN_ON(!swp_te_is_folio(swp_te));
	return pfn_folio((swp_te.counter & ENTRY_PFN_MASK) >> ENTRY_PFN_SHIFT);
}

static inline void *swp_te_shadow(swp_te_t swp_te)
{
	VM_WARN_ON(!swp_te_is_shadow(swp_te));
	return (void *)(swp_te.counter & ~ENTRY_COUNT_MASK);
}

static inline unsigned char swp_te_get_count(swp_te_t swp_te)
{
	VM_WARN_ON(!__swp_te_is_countable(swp_te));
	return ((swp_te.counter & ENTRY_COUNT_MASK) >> ENTRY_COUNT_SHIFT);
}

static inline unsigned char swp_te_try_get_count(swp_te_t swp_te)
{
	if (__swp_te_is_countable(swp_te))
		return swp_te_get_count(swp_te);
	return 0;
}

static inline swp_te_t swp_te_set_count(swp_te_t swp_te,
					unsigned char count)
{
	VM_BUG_ON(!__swp_te_is_countable(swp_te));
	VM_BUG_ON(count > ENTRY_COUNT_MAX);

	swp_te.counter &= ~ENTRY_COUNT_MASK;
	swp_te.counter |= ((unsigned long)count) << ENTRY_COUNT_SHIFT;
	VM_BUG_ON(swp_te_get_count(swp_te) != count);

	return swp_te;
}

/*
 * Helpers for accessing or modifying the swap table,
 * the swap cluster must be locked.
 */
static inline void __swap_table_set(struct swap_cluster_info *ci, pgoff_t off,
				    swp_te_t swp_te)
{
	atomic_long_set(&ci->table[off % SWAPFILE_CLUSTER], swp_te.counter);
	lockdep_assert_held(&ci->lock);
	swp_te_t *table = rcu_dereference_protected(ci->table, true);
	atomic_long_set(&table[off % SWAPFILE_CLUSTER], swp_te.counter);
}

static inline swp_te_t swap_table_try_get(struct swap_cluster_info *ci, pgoff_t off)
{
	swp_te_t swp_te;
	rcu_read_lock();
	swp_te_t *table = rcu_dereference_check(ci->table,
						lockdep_is_held(&ci->lock));
	if (table)
		swp_te.counter = atomic_long_read(&table[off % SWAPFILE_CLUSTER]);
	else
		swp_te = null_swp_te();
	rcu_read_unlock();
	return swp_te;
}

static inline swp_te_t __swap_table_get(struct swap_cluster_info *ci, pgoff_t off)
{
	swp_te_t swp_te;
	swp_te_t *table = rcu_dereference_check(ci->table,
						lockdep_is_held(&ci->lock));
	swp_te.counter = atomic_long_read(&table[off % SWAPFILE_CLUSTER]);
	return swp_te;
}

static inline void __swap_table_set_folio(struct swap_cluster_info *ci, pgoff_t off,
					  struct folio *folio)
{
	swp_te_t swp_te;
	unsigned char count;

	swp_te = __swap_table_get(ci, off);
	count = swp_te_get_count(swp_te);
	swp_te = swp_te_set_count(folio_swp_te(folio), count);

	__swap_table_set(ci, off, swp_te);
}

static inline void __swap_table_set_shadow(struct swap_cluster_info *ci, pgoff_t off,
					   void *shadow)
{
	swp_te_t swp_te;
	unsigned char count;

	swp_te = __swap_table_get(ci, off);
	count = swp_te_get_count(swp_te);
	swp_te = swp_te_set_count(shadow_swp_te(shadow), count);

	__swap_table_set(ci, off, swp_te);
}

static inline void __swap_table_set_null(struct swap_cluster_info *ci, pgoff_t off)
{
	__swap_table_set(ci, off, null_swp_te());
}

static inline void __swap_table_set_count(struct swap_cluster_info *ci, pgoff_t off,
					  unsigned char count)
{
	swp_te_t swp_te;
	swp_te = swp_te_set_count(__swap_table_get(ci, off), count);
	__swap_table_set(ci, off, swp_te);
}
#endif
