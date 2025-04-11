#include "swap.h"

/* Swap cache entry could be a pointer (folio), 0, or a XA_VALUE (shadow). */
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
	swp_te_t entry = { .counter = ((unsigned long)shadow) };
	return entry;
}

/* Swap table entry type checking */
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

/* Cast swap table entry to other types */
static inline struct folio *swp_te_folio(swp_te_t entry)
{
	return swp_te_is_folio(entry) ? (void*)entry.counter : NULL;
}

static inline void *swp_te_shadow(swp_te_t entry)
{
	return swp_te_is_shadow(entry) ? (void*)entry.counter : NULL;
}

/* Modifying the swap table */
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
