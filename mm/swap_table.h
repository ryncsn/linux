#include "swap.h"

/*
 * Swap table entry type and bit layouts:
 * NULL:     | ------------    0   -------------|
 * XA_VALUE: | SWAP_COUNT |----- Shadow ------|1|
 * PFN:      | SWAP_COUNT |------ PFN -------|10|
 * Pointer:  |----------- Pointer ----------|100|
 *
 * Swap table entry type and info:
 * NULL:     Swap Entry is unused
 * XA_VALUE: Swap Entry is a shadow in XA_VALUE format, with memcg
 *           data embedded in shadow.
 * PFN:      Swap Entry is in cache, memcg data in folio.
 * Pointer:  (Reserved for other components)
 */
#define ENTRY_COUNT_BITS	BITS_PER_BYTE
#define ENTRY_PFN_MARK		0b10UL
#define ENTRY_PFN_LOW_MASK	0b11UL
#define ENTRY_PFN_SHIFT		2
#define ENTRY_PFN_MASK		((~0UL) >> ENTRY_COUNT_BITS)
#define ENTRY_COUNT_MASK	(~((~0UL) >> ENTRY_COUNT_BITS))
#define ENTRY_COUNT_SHIFT	(BITS_PER_LONG - BITS_PER_BYTE)

static void __swap_table_set(struct swap_cluster_info *ci, pgoff_t off,
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
	BUILD_BUG_ON(sizeof(swp_table_ent_t) != sizeof(unsigned long));
	BUILD_BUG_ON((MAX_POSSIBLE_PHYSMEM_BITS - PAGE_SHIFT) >
		     (BITS_PER_LONG - ENTRY_PFN_SHIFT - ENTRY_COUNT_BITS));
	swp_table_ent_t entry = {
		.counter = (folio_pfn(folio) << ENTRY_PFN_SHIFT) | ENTRY_PFN_MARK
	};
	return entry;
}

static inline bool entry_is_folio(swp_table_ent_t entry)
{
	return ((entry.counter & ENTRY_PFN_LOW_MASK) == ENTRY_PFN_MARK);
}

static inline struct folio *entry_to_folio(swp_table_ent_t entry)
{
	if (!entry_is_folio(entry))
		return NULL;
	return pfn_folio((entry.counter & ENTRY_PFN_MASK) >> ENTRY_PFN_SHIFT);
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

static inline unsigned char entry_get_count(swp_table_ent_t entry)
{
	if (!entry_is_shadow(entry) && !entry_is_folio(entry))
		return 0;
	return (entry.counter & ENTRY_COUNT_MASK >> ENTRY_COUNT_SHIFT);
}

static inline swp_table_ent_t entry_set_count(swp_table_ent_t entry,
					       unsigned char count)
{
	entry.counter &= ~ENTRY_COUNT_MASK;
	entry.counter |= ((unsigned long)count) << ENTRY_COUNT_SHIFT;
	return entry;
}
