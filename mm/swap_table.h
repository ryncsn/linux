/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _MM_SWAP_TABLE_H
#define _MM_SWAP_TABLE_H

#include "swap.h"

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
 * Helpers for accessing or modifying the swap table,
 * the swap cluster must be locked.
 */
static inline void __swap_table_set(struct swap_cluster_info *ci, pgoff_t off,
				    swp_te_t swp_te)
{
	atomic_long_set(&ci->table[off % SWAPFILE_CLUSTER], swp_te.counter);
}

static inline swp_te_t __swap_table_get(struct swap_cluster_info *ci, pgoff_t off)
{
	swp_te_t swp_te = {
		.counter = atomic_long_read(&ci->table[off % SWAPFILE_CLUSTER])
	};
	return swp_te;
}

static inline void __swap_table_set_folio(struct swap_cluster_info *ci, pgoff_t off,
					  struct folio *folio)
{
	__swap_table_set(ci, off, folio_swp_te(folio));
}

static inline void __swap_table_set_shadow(struct swap_cluster_info *ci, pgoff_t off,
					   void *shadow)
{
	__swap_table_set(ci, off, shadow_swp_te(shadow));
}

static inline void __swap_table_set_null(struct swap_cluster_info *ci, pgoff_t off)
{
	__swap_table_set(ci, off, null_swp_te());
}
#endif
