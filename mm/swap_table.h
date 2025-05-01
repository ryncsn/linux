#ifndef _MM_SWAP_TABLE_H
#define _MM_SWAP_TABLE_H

#include "swap.h"

/*
 * Swap table entry could be a pointer (folio), 0, or a XA_VALUE (shadow).
 */

/*
 * Helpers for embedding one type of info into a swap table entry.
 */
static inline swp_te_t null_swp_te(void)
{
	swp_te_t entry = ATOMIC_LONG_INIT(0);
	return entry;
}

static inline swp_te_t folio_swp_te(struct folio *folio)
{
	BUILD_BUG_ON(sizeof(swp_te_t) != sizeof(void*));
	swp_te_t entry = { .counter = (unsigned long)folio };
	return entry;
}

static inline swp_te_t shadow_swp_te(void *shadow)
{
	BUILD_BUG_ON((BITS_PER_XA_VALUE + 1) !=
		     BITS_PER_BYTE * sizeof(swp_te_t));
	VM_WARN_ON(!xa_is_value(shadow));
	swp_te_t entry = { .counter = ((unsigned long)shadow) };
	return entry;
}

/*
 * Helpers for swap table entry type checking.
 */
static inline bool swp_te_is_null(swp_te_t entry)
{
	return !entry.counter;
}

static inline bool swp_te_is_folio(swp_te_t entry)
{
	return !xa_is_value((void*)entry.counter) && !swp_te_is_null(entry);
}

static inline bool swp_te_is_shadow(swp_te_t entry)
{
	return xa_is_value((void*)entry.counter);
}

/*
 * Helpers for retrieving info from swap table.
 */
static inline struct folio *swp_te_folio(swp_te_t entry)
{
	VM_WARN_ON(!swp_te_is_folio(entry));
	return (void*)entry.counter;
}

static inline void *swp_te_shadow(swp_te_t entry)
{
	VM_WARN_ON(!swp_te_is_shadow(entry));
	return (void*)entry.counter;
}

/*
 * Helpers for accessing or modifying the swap table.
 */
static inline void __swap_table_set(struct swap_cluster_info *ci, pgoff_t off,
			   swp_te_t entry)
{
	atomic_long_set(&ci->table[off % SWAPFILE_CLUSTER], entry.counter);
}

static inline swp_te_t __swap_table_get(struct swap_cluster_info *ci, pgoff_t off)
{
	swp_te_t entry = {
		.counter = atomic_long_read(&ci->table[off % SWAPFILE_CLUSTER])
	};
	return entry;
}

static inline void __swap_table_set_folio(struct swap_cluster_info *ci, pgoff_t off,
					  struct folio *folio)
{
	swp_te_t entry;
	entry = folio_swp_te(folio);
	__swap_table_set(ci, off, entry);
}

static inline void __swap_table_set_null_shadow(struct swap_cluster_info *ci, pgoff_t off)
{
	__swap_table_set(ci, off, shadow_swp_te(xa_mk_value(0)));
}

static inline void __swap_table_set_shadow(struct swap_cluster_info *ci, pgoff_t off,
					   void *shadow)
{
	swp_te_t entry;
	entry = shadow_swp_te(shadow);
	__swap_table_set(ci, off, entry);
}

static inline void __swap_table_set_null(struct swap_cluster_info *ci, pgoff_t off)
{
	__swap_table_set(ci, off, null_swp_te());
}
#endif
