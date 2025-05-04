/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _MM_SWAP_H
#define _MM_SWAP_H

struct mempolicy;
extern int page_cluster;

#ifdef CONFIG_SWAP
#include <linux/swapops.h> /* for swp_offset */
#include <linux/blk_types.h> /* for bio_end_io_t */

extern struct swap_info_struct *swap_info[];

/*
 * A swap table entry represents the status of a swap slot
 * on a swap (physical or virtual) device. Swap table is a
 * 1:1 map of the swap device, composed of swap table entries.
 *
 * See mm/swap_table.h for details.
 */
typedef atomic_long_t swp_te_t;

/*
 * We use this to track usage of a cluster. A cluster is a block of swap disk
 * space with SWAPFILE_CLUSTER pages long and naturally aligns in disk. All
 * free clusters are organized into a list. We fetch an entry from the list to
 * get a free cluster.
 *
 * The flags field determines if a cluster is free. This is
 * protected by cluster lock.
 */
struct swap_cluster_info {
	spinlock_t lock; /* Protects all fields below except `list`. */
	u16 count;
	u8 flags;
	u8 order;
	swp_te_t *table;
	struct list_head list;
};

/* All on-list cluster must have a non-zero flag. */
enum swap_cluster_flags {
	CLUSTER_FLAG_NONE = 0, /* For temporary off-list cluster */
	CLUSTER_FLAG_FREE,
	CLUSTER_FLAG_NONFULL,
	CLUSTER_FLAG_FRAG,
	/* Clusters with flags above are allocatable */
	CLUSTER_FLAG_USABLE = CLUSTER_FLAG_FRAG,
	CLUSTER_FLAG_FULL,
	CLUSTER_FLAG_DISCARD,
	CLUSTER_FLAG_MAX,
};

/* linux/mm/swapfile.c */
#ifdef CONFIG_THP_SWAP
#define SWAPFILE_CLUSTER	HPAGE_PMD_NR
#define swap_entry_order(order)	(order)
#else
#define SWAPFILE_CLUSTER	256
#define swap_entry_order(order)	0
#endif

/* Swap entry operations should never involve more than one cluster */
#define VM_BUG_ON_BAD_SWAP_CLUSTER(entry, nr_ents) \
	VM_BUG_ON((swp_offset(entry) + (nr_ents) - 1) / SWAPFILE_CLUSTER != \
		  (swp_offset(entry)) / SWAPFILE_CLUSTER)

/*
 * All swp_* function users must hold a swap device reference or
 * ensure the device is pinned in other ways, e.g. locked folio with
 * swap entry allocated.
 */
static inline struct swap_info_struct *swp_type_info(int type)
{
	struct swap_info_struct *si;

	VM_BUG_ON(type >= MAX_SWAPFILES);
	si = READ_ONCE(swap_info[type]); /* rcu_dereference() */
	VM_WARN_ON(percpu_ref_is_zero(&si->users));

	return si;
}

static inline struct swap_info_struct *swp_info(swp_entry_t entry)
{
	struct swap_info_struct *si = swp_type_info(swp_type(entry));
	VM_WARN_ON(percpu_ref_is_zero(&si->users));
	VM_WARN_ON(swp_offset(entry) >= si->max);
	return si;
}

static inline struct swap_cluster_info *swp_offset_cluster(
		struct swap_info_struct *si, pgoff_t offset)
{
	VM_WARN_ON(percpu_ref_is_zero(&si->users));
	return &si->cluster_info[offset / SWAPFILE_CLUSTER];
}

static inline struct swap_cluster_info *swp_cluster(swp_entry_t entry)
{
	return swp_offset_cluster(swp_info(entry), swp_offset(entry));
}

/*
 * Nothing should touch swap clusters in interrupt, as swap cache
 * updates should only come from:
 * - Swap in: page fault, shmem read, or swapoff.
 * - Swap out: user space memory pressure.
 * - Huge page split.
 * - Page migration.
 */
static inline struct swap_cluster_info *swap_lock_cluster(
		struct swap_info_struct *si,
		unsigned long offset)
{
	struct swap_cluster_info *ci = swp_offset_cluster(si, offset);
	VM_WARN_ON(in_interrupt());
	VM_WARN_ON(percpu_ref_is_zero(&si->users));
	spin_lock(&ci->lock);
	return ci;
}

static inline struct swap_cluster_info *swap_lock_cluster_irq(
		struct swap_info_struct *si,
		unsigned long offset)
{
	struct swap_cluster_info *ci = swp_offset_cluster(si, offset);
	VM_WARN_ON(in_interrupt());
	spin_lock_irq(&ci->lock);
	return ci;
}

static inline void swap_unlock_cluster(struct swap_cluster_info *ci)
{
	spin_unlock(&ci->lock);
}

static inline void swap_unlock_cluster_irq(struct swap_cluster_info *ci)
{
	spin_unlock_irq(&ci->lock);
}

extern int __swap_cache_set_map(struct swap_info_struct *si,
				struct swap_cluster_info *ci,
				unsigned long offset);
extern int __swap_cache_put_map(struct swap_info_struct *si,
				struct swap_cluster_info *ci,
				unsigned long offset);

/* linux/mm/page_io.c */
int sio_pool_init(void);
struct swap_iocb;
void swap_read_folio(struct folio *folio, struct swap_iocb **plug);
void __swap_read_unplug(struct swap_iocb *plug);
static inline void swap_read_unplug(struct swap_iocb *plug)
{
	if (unlikely(plug))
		__swap_read_unplug(plug);
}
void swap_write_unplug(struct swap_iocb *sio);
int swap_writepage(struct page *page, struct writeback_control *wbc);
void __swap_writepage(struct folio *folio, struct writeback_control *wbc);

/* linux/mm/swap_state.c */
extern struct address_space swap_space __ro_after_init;
static inline struct address_space *swap_address_space(swp_entry_t entry)
{
	return &swap_space;
}

/* Below helpers requires caller to pin the swap device */
extern struct folio *swap_cache_get_folio(swp_entry_t entry);
extern struct folio *swap_cache_add_folio(swp_entry_t entry, struct folio *folio,
					  void **shadow, bool swapin);
extern void *swap_cache_get_shadow(swp_entry_t entry);
extern void __swap_cache_del_folio(swp_entry_t entry,
				   struct folio *folio, void *shadow);
extern int __swap_cache_replace_folio(struct swap_cluster_info *ci,
				      swp_entry_t entry, struct folio *old,
				      struct folio *new);
extern void __swap_cache_override_folio(struct swap_cluster_info *ci,
					swp_entry_t entry, struct folio *old,
					struct folio *new);
extern void __swap_cache_clear_shadow(swp_entry_t entry, int nr_ents);

/*
 * Return the swap device position of the swap entry.
 */
static inline loff_t swap_dev_pos(swp_entry_t entry)
{
	return ((loff_t)swp_offset(entry)) << PAGE_SHIFT;
}

/*
 * Return the swap cache index of the swap entry.
 */
static inline pgoff_t swap_cache_index(swp_entry_t entry)
{
	return swp_offset(entry);
}

/*
 * Check if a folio still contains a swap entry, must be called after a
 * swap cache lookup as the folio might have been invalidated while
 * it's unlocked.
 */
static inline bool folio_swap_contains(struct folio *folio, swp_entry_t entry)
{
	VM_BUG_ON(!folio_test_locked(folio));
	pgoff_t index = swp_offset(entry);
	if (unlikely(!folio_test_swapcache(folio)))
		return false;
	if (unlikely(swp_type(entry) != swp_type(folio->swap)))
		return false;
	return (index - swp_offset(folio->swap)) < folio_nr_pages(folio);
}

void show_swap_cache_info(void);
void delete_from_swap_cache(struct folio *folio);
void swapcache_clear(struct swap_info_struct *si, swp_entry_t entry, int nr);
struct folio *read_swap_cache_async(swp_entry_t entry, gfp_t gfp_mask,
		struct vm_area_struct *vma, unsigned long addr,
		struct swap_iocb **plug);
struct folio *__swapin_cache_alloc(swp_entry_t entry, gfp_t gfp_flags,
		struct mempolicy *mpol, pgoff_t ilx, bool *new_page_allocated,
		bool skip_if_exists);
struct folio *swap_cluster_readahead(swp_entry_t entry, gfp_t flag,
		struct mempolicy *mpol, pgoff_t ilx);
struct folio *swapin_readahead(swp_entry_t entry, gfp_t flag,
		struct vm_fault *vmf);
struct folio *swapin_entry(swp_entry_t entry, struct folio *folio);
void swap_update_readahead(struct folio *folio, struct vm_area_struct *vma,
			   unsigned long addr);

static inline unsigned int folio_swap_flags(struct folio *folio)
{
	return swp_info(folio->swap)->flags;
}

/*
 * Return the count of contiguous swap entries that share the same
 * zeromap status as the starting entry. If is_zeromap is not NULL,
 * it will return the zeromap status of the starting entry.
 */
static inline int swap_zeromap_batch(swp_entry_t entry, int max_nr,
		bool *is_zeromap)
{
	struct swap_info_struct *sis = swp_info(entry);
	unsigned long start = swp_offset(entry);
	unsigned long end = start + max_nr;
	bool first_bit;

	first_bit = test_bit(start, sis->zeromap);
	if (is_zeromap)
		*is_zeromap = first_bit;

	if (max_nr <= 1)
		return max_nr;
	if (first_bit)
		return find_next_zero_bit(sis->zeromap, end, start) - start;
	else
		return find_next_bit(sis->zeromap, end, start) - start;
}

#else /* CONFIG_SWAP */
struct swap_iocb;
static inline struct swap_info_struct *swp_info(swp_entry_t entry)
{
	return NULL;
}

static inline void swap_read_folio(struct folio *folio, struct swap_iocb **plug)
{
}
static inline void swap_write_unplug(struct swap_iocb *sio)
{
}

static inline struct address_space *swap_address_space(swp_entry_t entry)
{
	return NULL;
}

static inline pgoff_t swap_cache_index(swp_entry_t entry)
{
	return 0;
}

static inline bool folio_swap_contains(struct folio *folio, swp_entry_t entry)
{
	return false;
}

static inline void show_swap_cache_info(void)
{
}

static inline struct folio *swap_cluster_readahead(swp_entry_t entry,
			gfp_t gfp_mask, struct mempolicy *mpol, pgoff_t ilx)
{
	return NULL;
}

static inline struct folio *swapin_readahead(swp_entry_t swp, gfp_t gfp_mask,
			struct vm_fault *vmf)
{
	return NULL;
}

static inline struct folio *swapin_entry(swp_entry_t, struct folio *);
{
	return NULL;
}

static inline void swap_update_readahead(struct folio *folio,
		struct vm_area_struct *vma, unsigned long addr)
{
}

static inline int swap_writepage(struct page *p, struct writeback_control *wbc)
{
	return 0;
}

static inline int swap_cache_swapon(int type, unsigned long max_pages)
{
	return 0;
}

static inline void swap_cache_swapoff(int type)
{
}

static inline struct folio *swap_cache_get_folio(swp_entry_t entry)
{
	return NULL;
}

static inline struct folio *swap_cache_add_folio(swp_entry_t entry,
						 struct folio *folio,
						 void **shadow, bool swapin);

static inline void __swap_cache_del_folio(struct folio *, swp_entry_t, void *)
{
}

static inline int __swap_cache_replace_folio(swp_entry_t, struct folio *, struct folio *)
{
	return -EINVAL;
}

static inline int __swap_cache_override_folio(swp_entry_t, struct folio *, struct folio *)
{
	return -EINVAL;
}

static inline void *swap_cache_get_shadow(swp_entry_t)
{
}

static inline void __swap_cache_clear_shadow(swp_entry_t, int)
{
}

static inline void delete_from_swap_cache(struct folio *folio)
{
}

static inline void clear_shadow_from_swap_cache(int type, unsigned long begin,
				unsigned long end)
{
}

static inline unsigned int folio_swap_flags(struct folio *folio)
{
	return 0;
}

static inline int swap_zeromap_batch(swp_entry_t entry, int max_nr,
		bool *has_zeromap)
{
	return 0;
}

#endif /* CONFIG_SWAP */

/**
 * folio_index - File index of a folio.
 * @folio: The folio.
 *
 * For a folio which is either in the page cache or the swap cache,
 * return its index within the address_space it belongs to.  If you know
 * the folio is definitely in the page cache, you can look at the folio's
 * index directly.
 *
 * Return: The index (offset in units of pages) of a folio in its file.
 */
static inline pgoff_t folio_index(struct folio *folio)
{
	if (unlikely(folio_test_swapcache(folio)))
		return swap_cache_index(folio->swap);
	return folio->index;
}

#endif /* _MM_SWAP_H */
