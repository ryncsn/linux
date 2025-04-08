#include "swap.h"

static inline void __swap_table_set(struct swap_cluster_info *ci, pgoff_t off,
			   swp_table_ent_t entry)
{
	atomic_long_set(&ci->table[off % SWAPFILE_CLUSTER], entry.counter);
}

static inline swp_table_ent_t __swap_table_get(struct swap_cluster_info *ci, pgoff_t off)
{
	swp_table_ent_t entry = {
		.counter = atomic_long_read(&ci->table[off % SWAPFILE_CLUSTER])
	};
	return entry;
}

/*
 * Swap cache entry could be a pointer (folio), 0, or a XA_VALUE (shadow).
 */
static inline swp_table_ent_t null_to_entry(void)
{
	swp_table_ent_t entry = ATOMIC_LONG_INIT(0);
	return entry;
}

static inline bool entry_is_null(swp_table_ent_t entry)
{
	return !entry.counter;
}

static inline swp_table_ent_t folio_to_entry(struct folio *folio)
{
	BUILD_BUG_ON(sizeof(swp_table_ent_t) != sizeof(void*));
	swp_table_ent_t entry = { .counter = (unsigned long)folio };
	return entry;
}

static inline bool entry_is_folio(swp_table_ent_t entry)
{
	return !xa_is_value((void*)entry.counter) && !entry_is_null(entry);
}

static inline struct folio *entry_to_folio(swp_table_ent_t entry)
{
	return entry_is_folio(entry) ? (void*)entry.counter : NULL;
}

static inline swp_table_ent_t shadow_to_entry(void *shadow)
{
	BUILD_BUG_ON((BITS_PER_XA_VALUE + 1) !=
		     BITS_PER_BYTE * sizeof(swp_table_ent_t));
	swp_table_ent_t entry = { .counter = ((unsigned long)shadow) };
	return entry;
}

static inline bool entry_is_shadow(swp_table_ent_t entry)
{
	return xa_is_value((void*)entry.counter);
}

static inline void *entry_to_shadow(swp_table_ent_t entry)
{
	return entry_is_shadow(entry) ? (void*)entry.counter : NULL;
}

