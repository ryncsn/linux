/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _MM_SWAP_TABLE_H
#define _MM_SWAP_TABLE_H

#include <linux/rcupdate.h>
#include "swap.h"

#define SWP_TE_SIZE (BITS_PER_LONG / BITS_PER_BYTE)
#define SWP_TABLE_FLAT_SIZE (SWP_TE_SIZE * SWAPFILE_CLUSTER)
#if SWP_TABLE_FLAT_SIZE == PAGE_SIZE
#define SWP_TABLE_FLAT_USE_PAGE 1
#else
#define SWP_TABLE_FLAT_USE_PAGE 0
#endif

/* A typical flat array as swap table */
struct swap_table_flat {
	swp_te_t entries[SWAPFILE_CLUSTER];
};

/*
 * Swap table entry could be a pointer (folio), a XA_VALUE (shadow), or NULL.
 */

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
	BUILD_BUG_ON(sizeof(swp_te_t) != sizeof(void *));
	swp_te_t swp_te = { .counter = (unsigned long)folio };
	return swp_te;
}

static inline swp_te_t shadow_swp_te(void *shadow)
{
	BUILD_BUG_ON((BITS_PER_XA_VALUE + 1) !=
		     BITS_PER_BYTE * sizeof(swp_te_t));
	VM_WARN_ON_ONCE(shadow && !xa_is_value(shadow));
	swp_te_t swp_te = { .counter = ((unsigned long)shadow) };
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
	return !xa_is_value((void *)swp_te.counter) && !swp_te_is_null(swp_te);
}

static inline bool swp_te_is_shadow(swp_te_t swp_te)
{
	return xa_is_value((void *)swp_te.counter);
}

/*
 * Helpers for retrieving info from swap table.
 */
static inline struct folio *swp_te_folio(swp_te_t swp_te)
{
	VM_WARN_ON(!swp_te_is_folio(swp_te));
	return (void *)swp_te.counter;
}

static inline void *swp_te_shadow(swp_te_t swp_te)
{
	VM_WARN_ON(!swp_te_is_shadow(swp_te));
	return (void *)swp_te.counter;
}

/*
 * Helpers for accessing or modifying the swap table of a cluster,
 * the swap cluster must be locked.
 */
static inline void __swap_cluster_set(struct swap_cluster_info *ci,
				      unsigned int off, swp_te_t swp_te)
{
	swp_te_t *table = rcu_dereference_protected(ci->table, true);

	lockdep_assert_held(&ci->lock);
	VM_WARN_ON_ONCE(off >= SWAPFILE_CLUSTER);
	atomic_long_set(&table[off], swp_te.counter);
}

static inline swp_te_t swap_cluster_get(struct swap_cluster_info *ci,
					unsigned int off)
{
	swp_te_t swp_te;
	rcu_read_lock();
	swp_te_t *table = rcu_dereference_check(ci->table,
						lockdep_is_held(&ci->lock));
	if (table)
		swp_te.counter = atomic_long_read(&table[off]);
	else
		swp_te = null_swp_te();
	rcu_read_unlock();
	return swp_te;
}

static inline swp_te_t __swap_cluster_get(struct swap_cluster_info *ci,
					  unsigned int off)
{
	swp_te_t *table = rcu_dereference_protected(ci->table,
						    lockdep_is_held(&ci->lock));
	swp_te_t swp_te;

	VM_WARN_ON_ONCE(off >= SWAPFILE_CLUSTER);
	swp_te.counter = atomic_long_read(&table[off]);
	return swp_te;
}

static inline void __swap_cluster_set_folio(struct swap_cluster_info *ci,
					    unsigned int off, struct folio *folio)
{
	__swap_cluster_set(ci, off, folio_swp_te(folio));
}

static inline void __swap_cluster_set_shadow(struct swap_cluster_info *ci,
					     unsigned int off, void *shadow)
{
	__swap_cluster_set(ci, off, shadow_swp_te(shadow));
}

static inline void __swap_cluster_init_null(struct swap_cluster_info *ci, unsigned int off)
{
	__swap_cluster_set(ci, off, null_swp_te());
}
#endif
