// SPDX-License-Identifier: GPL-2.0
/*
 *  linux/mm/swap_state.c
 *
 *  Copyright (C) 1991, 1992, 1993, 1994  Linus Torvalds
 *  Swap reorganised 29.12.95, Stephen Tweedie
 *
 *  Rewritten to use page cache, (C) 1998 Stephen Tweedie
 */
#include <linux/mm.h>
#include <linux/gfp.h>
#include <linux/kernel_stat.h>
#include <linux/mempolicy.h>
#include <linux/swap.h>
#include <linux/swapops.h>
#include <linux/init.h>
#include <linux/pagemap.h>
#include <linux/pagevec.h>
#include <linux/backing-dev.h>
#include <linux/blkdev.h>
#include <linux/migrate.h>
#include <linux/vmalloc.h>
#include <linux/huge_mm.h>
#include <linux/shmem_fs.h>
#include "internal.h"
#include "swap_table.h"
#include "swap.h"

/*
 * swapper_space is a fiction, retained to simplify the path through
 * vmscan's shrink_folio_list.
 */
static const struct address_space_operations swap_aops = {
	.dirty_folio	= noop_dirty_folio,
#ifdef CONFIG_MIGRATION
	.migrate_folio	= migrate_folio,
#endif
};

/* swap_space is read only as swap cache is handled by swap table */
struct address_space swap_space __ro_after_init = {
	.a_ops = &swap_aops,
};

static bool enable_vma_readahead __read_mostly = true;

#define SWAP_RA_ORDER_CEILING	5

#define SWAP_RA_WIN_SHIFT	(PAGE_SHIFT / 2)
#define SWAP_RA_HITS_MASK	((1UL << SWAP_RA_WIN_SHIFT) - 1)
#define SWAP_RA_HITS_MAX	SWAP_RA_HITS_MASK
#define SWAP_RA_WIN_MASK	(~PAGE_MASK & ~SWAP_RA_HITS_MASK)

#define SWAP_RA_HITS(v)		((v) & SWAP_RA_HITS_MASK)
#define SWAP_RA_WIN(v)		(((v) & SWAP_RA_WIN_MASK) >> SWAP_RA_WIN_SHIFT)
#define SWAP_RA_ADDR(v)		((v) & PAGE_MASK)

#define SWAP_RA_VAL(addr, win, hits)				\
	(((addr) & PAGE_MASK) |					\
	 (((win) << SWAP_RA_WIN_SHIFT) & SWAP_RA_WIN_MASK) |	\
	 ((hits) & SWAP_RA_HITS_MASK))

/* Initial readahead hits is 4 to start up with a small window */
#define GET_SWAP_RA_VAL(vma)					\
	(atomic_long_read(&(vma)->swap_readahead_info) ? : 4)

static atomic_t swapin_readahead_hits = ATOMIC_INIT(4);

void show_swap_cache_info(void)
{
	printk("%lu pages in swap cache\n", total_swapcache_pages());
	printk("Free swap  = %ldkB\n", K(get_nr_swap_pages()));
	printk("Total swap = %lukB\n", K(total_swap_pages));
}

/*
 * Lookup a swap entry in the swap cache. A found folio will be returned
 * unlocked and with its refcount incremented.
 *
 * Caller must ensure @entry is valid and pin the swap device, also check
 * the returned folio after locking it (e.g. folio_swap_contains).
 */
struct folio *swap_cache_get_folio(swp_entry_t entry)
{
	swp_te_t swp_te;
	struct folio *folio;

	swp_te = swap_table_try_get(swp_cluster(entry), swp_offset(entry));
	if (!swp_te_is_folio(swp_te))
		return NULL;

	folio = swp_te_folio(swp_te);
	if (!folio_try_get(folio))
		return NULL;

	return folio;
}

/*
 * Check if a swap entry has folio cached, may return false positive.
 * Caller must hold a reference of the swap device or pin it in other ways.
 */
bool swap_cache_check_folio(swp_entry_t entry)
{
	swp_te_t swp_te;
	swp_te = swap_table_try_get(swp_cluster(entry), swp_offset(entry));
	return swp_te_is_folio(swp_te);
}

/*
 * Caller must hold a reference on the swap device, and check if the
 * returned folio is still valid after locking it (e.g. folio_swap_contains).
 */
void *swap_cache_get_shadow(swp_entry_t entry)
{
	swp_te_t swp_te;
	pgoff_t offset = swp_offset(entry);

	swp_te = swap_table_try_get(swp_cluster(entry), offset);
	return swp_te_is_shadow(swp_te) ? swp_te_shadow(swp_te) : NULL;
}

/* Preflight check for adding a backing folio for allocated swap entries */
static int __swap_cache_check_exist(swp_entry_t target_entry,
				    struct swap_cluster_info *ci,
				    unsigned long nr_pages, void **shadow)
{
	swp_te_t exist;
	pgoff_t offset, end;
	unsigned short memcg_id;

	offset = swp_offset(target_entry);
	if (unlikely(!ci->table))
		return -ENOENT;
	exist = __swap_table_get(ci, offset);
	if (unlikely(swp_te_is_folio(exist)))
		return -EEXIST;
	if (unlikely(!swp_te_get_count(exist)))
		return -ENOENT;
	*shadow = swp_te_shadow(exist);
	if (nr_pages == 1)
		return 0;

	memcg_id = swp_te_shadow_memcgid(exist);
	offset = round_down(offset, nr_pages);
	end = offset + nr_pages;
	do {
		exist = __swap_table_get(ci, offset);
		if (unlikely(swp_te_is_folio(exist) ||
			     !swp_te_get_count(exist) ||
			     swp_te_shadow_memcgid(exist) != memcg_id))
			return -EAGAIN;
	} while (++offset < end);

	return 0;
}

static void __swap_cache_do_add_folio(swp_entry_t entry, struct swap_cluster_info *ci,
				      struct folio *folio)
{
	pgoff_t offset = swp_offset(entry), end;
	unsigned long nr_pages = folio_nr_pages(folio);

	/*
	 * Allocator should always allocate aligned entries so folio based
	 * operations never crossed more than one cluster.
	 */
	VM_WARN_ON_ONCE_FOLIO(!IS_ALIGNED(offset, nr_pages), folio);
	VM_WARN_ON_ONCE_FOLIO(!folio_test_locked(folio), folio);
	VM_WARN_ON_ONCE_FOLIO(folio_test_swapcache(folio), folio);
	VM_WARN_ON_ONCE_FOLIO(!folio_test_swapbacked(folio), folio);

	end = offset + nr_pages;
	do {
		VM_WARN_ON(swp_te_is_folio(__swap_table_get(ci, offset)));
		__swap_table_set_folio(ci, offset, folio);
	} while (++offset < end);

	folio_ref_add(folio, nr_pages);
	folio_set_swapcache(folio);
	folio->swap = entry;
}

/*
 * Allocate a folio in the swap cache for a set of swap slots before
 * doing IO (swap in or out). All swap slots covered by the allocation
 * must all have a non-zero swap count.
 * @target_entry: swap entry indicating the target slot
 * @orders: allocation orders
 * @vmf: fault information
 * @gfp_mask: memory allocation flags
 * @mpol: NUMA memory allocation policy to be applied
 * @ilx: NUMA interleave index, for use only when MPOL_INTERLEAVE
 *
 * Return error code if failed, possible error codes:
 * -EEXIST: @target_entry is cached already.
 * -ENOENT: @target_entry is freed already.
 * -ENOMEM: failed to allocate due to memory pressure.
 *
 * Caller must holds an reference of the swap device of @target_entry.
 */
struct folio *swap_cache_alloc_folio(swp_entry_t target_entry, gfp_t gfp_mask,
				     unsigned long orders, struct vm_fault *vmf,
				     struct mempolicy *mpol, pgoff_t ilx)
{
	gfp_t gfp;
	int err, order = 0;
	struct folio *folio;
	unsigned long address;
	void *shadow, *shadow_check;
	struct swap_cluster_info *ci;

	/*
	 * If uffd is active for the vma we need per-page fault fidelity to
	 * maintain the uffd semantics. ZSWAP doesn't work with large folio
	 * either.
	 */
	if (orders &&
	    (!vmf || likely(!userfaultfd_armed(vmf->vma))) &&
	    zswap_never_enabled())
		order = highest_order(orders);

	ci = swp_cluster(target_entry);
	for (;;) {
		unsigned long nr_pages = 1 << order;
		swp_entry_t folio_entry = { .val = round_down(target_entry.val, nr_pages) };

		/* First check if the range is available */
		spin_lock(&ci->lock);
		err = __swap_cache_check_exist(target_entry, ci, nr_pages, &shadow);
		spin_unlock(&ci->lock);
		if (unlikely(err))
			goto fallback;

		if (order && vmf)
			gfp = thp_limit_gfp_mask(vma_thp_gfp_mask(vmf->vma), gfp_mask);
		else
			gfp = gfp_mask;

		if (mpol) {
			folio = folio_alloc_mpol(gfp, order, mpol, ilx, numa_node_id());
		} else {
			address = round_down(vmf->address, PAGE_SIZE << order);
			folio = vma_alloc_folio(gfp, order, vmf->vma, address);
		}
		if (unlikely(!folio)) {
			err = -ENOMEM;
			goto fallback;
		}

		if (mem_cgroup_swapin_charge_folio(folio, gfp_mask, target_entry,
						   shadow_memcgid(shadow))) {
			folio_put(folio);
			count_mthp_stat(order, MTHP_STAT_SWPIN_FALLBACK_CHARGE);
			err = -ENOMEM;
			goto fallback;
		}

		/* Double check the range is still not in conflict */
		spin_lock(&ci->lock);
		err = __swap_cache_check_exist(target_entry, ci, nr_pages, &shadow_check);
		if (unlikely(err)) {
			spin_unlock(&ci->lock);
			folio_put(folio);
			goto fallback;
		}

		if (shadow_check != shadow) {
			spin_unlock(&ci->lock);
			folio_put(folio);
			continue;
		}

		__folio_set_locked(folio);
		__folio_set_swapbacked(folio);
		__swap_cache_do_add_folio(folio_entry, ci, folio);
		spin_unlock(&ci->lock);

		VM_WARN_ON_ONCE(!shadow);
		workingset_refault(folio, shadow);

		/* For memsw accouting, swap is uncharged here */
		memcg1_swapin(folio_entry, nr_pages);
		node_stat_mod_folio(folio, NR_FILE_PAGES, nr_pages);
		lruvec_stat_mod_folio(folio, NR_SWAPCACHE, nr_pages);

		/* Caller will initiate read into locked new_folio */
		folio_add_lru(folio);

		return folio;
fallback:
		if ((err != -ENOMEM && err != -EAGAIN) || !order)
			return ERR_PTR(err);

		count_mthp_stat(order, MTHP_STAT_SWPIN_FALLBACK);
		order = next_order(&orders, order);
	}
}

/*
 * For swap allocator's initial allocation of entries to a folio.
 * Caller holds the cluster lock and ensures the range is free.
 */
void __swap_cache_add_folio(swp_entry_t entry, struct swap_cluster_info *ci,
			    struct folio *folio)
{
	unsigned long nr_pages = folio_nr_pages(folio);

	__swap_cache_do_add_folio(entry, ci, folio);
	node_stat_mod_folio(folio, NR_FILE_PAGES, nr_pages);
	lruvec_stat_mod_folio(folio, NR_SWAPCACHE, nr_pages);
}

/*
 * This must be called only on folios that have been verified to
 * be in the swap cache and locked. It will never put the folio
 * into the free list, the caller has a reference on the folio.
 */
void __swap_cache_del_folio(swp_entry_t entry,
			    struct folio *folio, void *shadow)
{
	swp_te_t exist;
	pgoff_t offset, start, end;
	struct swap_info_struct *si;
	struct swap_cluster_info *ci;
	bool folio_swapped = false, need_free = false;
	unsigned long nr_pages = folio_nr_pages(folio);

	VM_WARN_ON_ONCE_FOLIO(!folio_test_locked(folio), folio);
	VM_WARN_ON_ONCE_FOLIO(!folio_test_swapcache(folio), folio);
	VM_WARN_ON_ONCE_FOLIO(folio_test_writeback(folio), folio);

	start = swp_offset(entry);
	end = start + nr_pages;

	si = swp_info(entry);
	ci = swp_offset_cluster(si, start);
	offset = start;
	do {
		exist = __swap_table_get(ci, offset);
		VM_WARN_ON_ONCE(swp_te_folio(exist) != folio);
		/* If shadow is NULL, we sets an empty shadow */
		__swap_table_set_shadow(ci, offset, shadow);
		if (swp_te_get_count(exist))
			folio_swapped = true;
		else
			need_free = true;
	} while (++offset < end);

	folio->swap.val = 0;
	folio_clear_swapcache(folio);
	node_stat_mod_folio(folio, NR_FILE_PAGES, -nr_pages);
	lruvec_stat_mod_folio(folio, NR_SWAPCACHE, -nr_pages);

	if (!folio_swapped) {
		__swap_free_entries(si, ci, start, nr_pages, !do_memsw_account());
	} else if (need_free) {
		offset = start;
		do {
			if (!swp_te_get_count(__swap_table_get(ci, offset)))
				__swap_free_entries(si, ci, offset, 1, !do_memsw_account());
		} while (++offset < end);
	}
}

/* For huge page splitting, override an old folio with a smaller new one. */
void __swap_cache_override_folio(struct swap_cluster_info *ci, swp_entry_t entry,
				 struct folio *old, struct folio *new)
{
	pgoff_t offset = swp_offset(entry);
	pgoff_t end = offset + folio_nr_pages(new);

	VM_WARN_ON_ONCE(entry.val < old->swap.val || entry.val != new->swap.val);
	VM_WARN_ON_ONCE(!folio_test_locked(old) || !folio_test_locked(new));

	do {
		VM_WARN_ON_ONCE(swp_te_folio(__swap_table_get(ci, offset)) != old);
		__swap_table_set_folio(ci, offset, new);
	} while (++offset < end);
}

/* For migration and shmem replacement, replace an old folio with a new one. */
int __swap_cache_replace_folio(struct swap_cluster_info *ci, swp_entry_t entry,
			       struct folio *old, struct folio *new)
{
	unsigned long nr_pages = folio_nr_pages(old);
	pgoff_t offset = swp_offset(entry);
	pgoff_t end = offset + nr_pages;

	VM_WARN_ON_ONCE(entry.val != old->swap.val || entry.val != new->swap.val);
	VM_WARN_ON_ONCE(!folio_test_locked(old) || !folio_test_locked(new));
	do {
		if (swp_te_folio(__swap_table_get(ci, offset)) != old)
			return -ENOENT;
		__swap_table_set_folio(ci, offset, new);
	} while (++offset < end);

	return 0;
}

void swap_cache_del_folio(struct folio *folio)
{
	struct swap_cluster_info *ci;
	swp_entry_t entry = folio->swap;

	ci = swap_lock_cluster(swp_info(entry), swp_offset(entry));
	__swap_cache_del_folio(entry, folio, NULL);
	swap_unlock_cluster(ci);

	folio_ref_sub(folio, folio_nr_pages(folio));
}

/*
 * If we are the only user, then try to free up the swap cache.
 *
 * Its ok to check the swapcache flag without the folio lock
 * here because we are going to recheck again inside
 * folio_free_swap() _with_ the lock.
 * 					- Marcelo
 */
void free_swap_cache(struct folio *folio)
{
	if (folio_test_swapcache(folio) && !folio_mapped(folio) &&
	    folio_trylock(folio)) {
		folio_free_swap(folio);
		folio_unlock(folio);
	}
}

/*
 * Freeing a folio and also freeing any swap cache associated with
 * this folio if it is the last user.
 */
void free_folio_and_swap_cache(struct folio *folio)
{
	free_swap_cache(folio);
	if (!is_huge_zero_folio(folio))
		folio_put(folio);
}

/*
 * Passed an array of pages, drop them all from swapcache and then release
 * them.  They are removed from the LRU and freed if this is their last use.
 */
void free_pages_and_swap_cache(struct encoded_page **pages, int nr)
{
	struct folio_batch folios;
	unsigned int refs[PAGEVEC_SIZE];

	folio_batch_init(&folios);
	for (int i = 0; i < nr; i++) {
		struct folio *folio = page_folio(encoded_page_ptr(pages[i]));

		free_swap_cache(folio);
		refs[folios.nr] = 1;
		if (unlikely(encoded_page_flags(pages[i]) &
			     ENCODED_PAGE_BIT_NR_PAGES_NEXT))
			refs[folios.nr] = encoded_nr_pages(pages[++i]);

		if (folio_batch_add(&folios, folio) == 0)
			folios_put_refs(&folios, refs);
	}
	if (folios.nr)
		folios_put_refs(&folios, refs);
}

static inline bool swap_use_vma_readahead(void)
{
	return READ_ONCE(enable_vma_readahead) && !atomic_read(&nr_rotate_swap);
}

/*
 * Update the readahead statistics of a vma or globally.
 */
void swap_update_readahead(struct folio *folio,
			   struct vm_area_struct *vma,
			   unsigned long addr)
{
	bool readahead, vma_ra = swap_use_vma_readahead();

	/*
	 * At the moment, we don't support PG_readahead for anon THP
	 * so let's bail out rather than confusing the readahead stat.
	 */
	if (unlikely(folio_test_large(folio)))
		return;

	readahead = folio_test_clear_readahead(folio);
	if (vma && vma_ra) {
		unsigned long ra_val;
		int win, hits;

		ra_val = GET_SWAP_RA_VAL(vma);
		win = SWAP_RA_WIN(ra_val);
		hits = SWAP_RA_HITS(ra_val);
		if (readahead)
			hits = min_t(int, hits + 1, SWAP_RA_HITS_MAX);
		atomic_long_set(&vma->swap_readahead_info,
				SWAP_RA_VAL(addr, win, hits));
	}

	if (readahead) {
		count_vm_event(SWAP_RA_HIT);
		if (!vma || !vma_ra)
			atomic_inc(&swapin_readahead_hits);
	}
}

struct folio *swap_cache_read_folio(swp_entry_t entry, gfp_t gfp_mask,
				    unsigned long orders, struct mempolicy *mpol,
				    pgoff_t ilx, struct swap_iocb **plug,
				    bool readahead)
{
	struct folio *folio;

	/*
	 * Just skip read for unused swap slot.
	 */
	if (!swap_entry_swapped(swp_info(entry), entry))
		return NULL;

	do {
		folio = swap_cache_get_folio(entry);
		if (folio)
			return folio;

		folio = swap_cache_alloc_folio(entry, gfp_mask, 0, NULL, mpol, ilx);
	} while (PTR_ERR(folio) == -EEXIST);

	if (IS_ERR(folio))
		return NULL;

	if (readahead) {
		folio_set_readahead(folio);
		count_vm_event(SWAP_RA);
	}
	swap_read_folio(folio, plug);

	return folio;
}

/**
 * swapin_entry - swap-in one or multiple entries skipping readahead.
 *
 * @entry: swap entry to swap in
 * @folio: new allocated folio
 *
 * Reads @entry into @folio. @folio will be added to swap cache first, if
 * this raced with other users, only one user will successfully add its
 * folio into swap cache, and that folio will be returned for all readers.
 *
 * If @folio is a large folio, the entry will be rounded down to match
 * the folio start and the whole range will be read in. May return error
 * code if any sub-entry is cached or freed.
 */
struct folio *swapin_entry(swp_entry_t entry, gfp_t gfp, unsigned long orders,
			   struct vm_fault *vmf, struct mempolicy *mpol, pgoff_t ilx)
{
	struct folio *folio;

	do {
		folio = swap_cache_get_folio(entry);
		if (folio)
			return folio;
		folio = swap_cache_alloc_folio(entry, gfp, 0, vmf, mpol, ilx);
	} while (PTR_ERR(folio) == -EEXIST);

	if (IS_ERR(folio))
		return NULL;

	swap_read_folio(folio, NULL);

	return folio;
}

/*
 * Locate a page of swap in physical memory, reserving swap cache space
 * and reading the disk if it is not already cached.
 * A failure return means that either the page allocation failed or that
 * the swap entry is no longer in use.
 *
 * get/put_swap_device() aren't needed to call this function, because
 * swap_cache_alloc_folio() call them and swap_read_folio() holds the
 * swap cache folio lock.
 */
struct folio *read_swap_cache_async(swp_entry_t entry, gfp_t gfp_mask,
		struct vm_area_struct *vma, unsigned long addr,
		struct swap_iocb **plug)
{
	struct swap_info_struct *si;
	struct mempolicy *mpol;
	pgoff_t ilx;
	struct folio *folio;

	si = get_swap_device(entry);
	if (!si)
		return NULL;

	mpol = get_vma_policy(vma, addr, 0, &ilx);
	folio = swap_cache_read_folio(entry, gfp_mask, 0, mpol,
				      ilx, NULL, false);
	mpol_cond_put(mpol);

	put_swap_device(si);
	return folio;
}

static unsigned int __swapin_nr_pages(unsigned long prev_offset,
				      unsigned long offset,
				      int hits,
				      int max_pages,
				      int prev_win)
{
	unsigned int pages, last_ra;

	/*
	 * This heuristic has been found to work well on both sequential and
	 * random loads, swapping to hard disk or to SSD: please don't ask
	 * what the "+ 2" means, it just happens to work well, that's all.
	 */
	pages = hits + 2;
	if (pages == 2) {
		/*
		 * We can have no readahead hits to judge by: but must not get
		 * stuck here forever, so check for an adjacent offset instead
		 * (and don't even bother to check whether swap type is same).
		 */
		if (offset != prev_offset + 1 && offset != prev_offset - 1)
			pages = 1;
	} else {
		unsigned int roundup = 4;
		while (roundup < pages)
			roundup <<= 1;
		pages = roundup;
	}

	if (pages > max_pages)
		pages = max_pages;

	/* Don't shrink readahead too fast */
	last_ra = prev_win / 2;
	if (pages < last_ra)
		pages = last_ra;

	return pages;
}

static unsigned long swapin_nr_pages(unsigned long offset)
{
	static unsigned long prev_offset;
	unsigned int hits, pages, max_pages;
	static atomic_t last_readahead_pages;

	max_pages = 1 << READ_ONCE(page_cluster);
	if (max_pages <= 1)
		return 1;

	hits = atomic_xchg(&swapin_readahead_hits, 0);
	pages = __swapin_nr_pages(READ_ONCE(prev_offset), offset, hits,
				  max_pages,
				  atomic_read(&last_readahead_pages));
	if (!hits)
		WRITE_ONCE(prev_offset, offset);
	atomic_set(&last_readahead_pages, pages);

	return pages;
}

/**
 * swap_cluster_readahead - swap in pages in hope we need them soon
 * @entry: swap entry of this memory
 * @gfp_mask: memory allocation flags
 * @mpol: NUMA memory allocation policy to be applied
 * @ilx: NUMA interleave index, for use only when MPOL_INTERLEAVE
 *
 * Returns the struct folio for entry and addr, after queueing swapin.
 *
 * Primitive swap readahead code. We simply read an aligned block of
 * (1 << page_cluster) entries in the swap area. This method is chosen
 * because it doesn't cost us any seek time.  We also make sure to queue
 * the 'original' request together with the readahead ones...
 *
 * Note: it is intentional that the same NUMA policy and interleave index
 * are used for every page of the readahead: neighbouring pages on swap
 * are fairly likely to have been swapped out from the same node.
 */
struct folio *swap_cluster_readahead(swp_entry_t entry, gfp_t gfp_mask,
				    struct mempolicy *mpol, pgoff_t ilx)
{
	struct folio *folio;
	unsigned long entry_offset = swp_offset(entry);
	unsigned long offset = entry_offset;
	unsigned long start_offset, end_offset;
	unsigned long mask;
	struct swap_info_struct *si = swp_info(entry);
	struct blk_plug plug;
	struct swap_iocb *splug = NULL;

	mask = swapin_nr_pages(offset) - 1;
	if (!mask)
		goto skip;

	/* Read a page_cluster sized and aligned cluster around offset. */
	start_offset = offset & ~mask;
	end_offset = offset | mask;
	if (!start_offset)	/* First page is swap header. */
		start_offset++;
	if (end_offset >= si->max)
		end_offset = si->max - 1;

	blk_start_plug(&plug);
	for (offset = start_offset; offset <= end_offset ; offset++) {
		/* Ok, do the async read-ahead now */
		folio = swap_cache_read_folio(
				swp_entry(swp_type(entry), offset),
				gfp_mask, 0, mpol, ilx, &splug,
				offset != entry_offset);
		if (folio)
			folio_put(folio);
	}
	blk_finish_plug(&plug);
	swap_read_unplug(splug);
	lru_add_drain();	/* Push any new pages onto the LRU now */
skip:
	/* The page was likely read above, so no need for plugging here */
	return swap_cache_read_folio(entry, gfp_mask, 0, mpol, ilx,
					   NULL, false);
}

static int swap_vma_ra_win(struct vm_fault *vmf, unsigned long *start,
			   unsigned long *end)
{
	struct vm_area_struct *vma = vmf->vma;
	unsigned long ra_val;
	unsigned long faddr, prev_faddr, left, right;
	unsigned int max_win, hits, prev_win, win;

	max_win = 1 << min(READ_ONCE(page_cluster), SWAP_RA_ORDER_CEILING);
	if (max_win == 1)
		return 1;

	faddr = vmf->address;
	ra_val = GET_SWAP_RA_VAL(vma);
	prev_faddr = SWAP_RA_ADDR(ra_val);
	prev_win = SWAP_RA_WIN(ra_val);
	hits = SWAP_RA_HITS(ra_val);
	win = __swapin_nr_pages(PFN_DOWN(prev_faddr), PFN_DOWN(faddr), hits,
				max_win, prev_win);
	atomic_long_set(&vma->swap_readahead_info, SWAP_RA_VAL(faddr, win, 0));
	if (win == 1)
		return 1;

	if (faddr == prev_faddr + PAGE_SIZE)
		left = faddr;
	else if (prev_faddr == faddr + PAGE_SIZE)
		left = faddr - (win << PAGE_SHIFT) + PAGE_SIZE;
	else
		left = faddr - (((win - 1) / 2) << PAGE_SHIFT);
	right = left + (win << PAGE_SHIFT);
	if ((long)left < 0)
		left = 0;
	*start = max3(left, vma->vm_start, faddr & PMD_MASK);
	*end = min3(right, vma->vm_end, (faddr & PMD_MASK) + PMD_SIZE);

	return win;
}

/**
 * swap_vma_readahead - swap in pages in hope we need them soon
 * @targ_entry: swap entry of the targeted memory
 * @gfp_mask: memory allocation flags
 * @mpol: NUMA memory allocation policy to be applied
 * @targ_ilx: NUMA interleave index, for use only when MPOL_INTERLEAVE
 * @vmf: fault information
 *
 * Returns the struct folio for entry and addr, after queueing swapin.
 *
 * Primitive swap readahead code. We simply read in a few pages whose
 * virtual addresses are around the fault address in the same vma.
 *
 * Caller must hold read mmap_lock if vmf->vma is not NULL.
 *
 */
static struct folio *swap_vma_readahead(swp_entry_t targ_entry, gfp_t gfp_mask,
		struct mempolicy *mpol, pgoff_t targ_ilx, struct vm_fault *vmf)
{
	struct blk_plug plug;
	struct swap_iocb *splug = NULL;
	struct folio *folio;
	pte_t *pte = NULL, pentry;
	int win;
	unsigned long start, end, addr;
	swp_entry_t entry;
	pgoff_t ilx;

	win = swap_vma_ra_win(vmf, &start, &end);
	if (win == 1)
		goto skip;

	ilx = targ_ilx - PFN_DOWN(vmf->address - start);

	blk_start_plug(&plug);
	for (addr = start; addr < end; ilx++, addr += PAGE_SIZE) {
		if (!pte++) {
			pte = pte_offset_map(vmf->pmd, addr);
			if (!pte)
				break;
		}
		pentry = ptep_get_lockless(pte);
		if (!is_swap_pte(pentry))
			continue;
		entry = pte_to_swp_entry(pentry);
		if (unlikely(non_swap_entry(entry)))
			continue;
		pte_unmap(pte);
		pte = NULL;
		folio = swap_cache_read_folio(entry, gfp_mask, 0, mpol, ilx,
						    &splug, addr != vmf->address);
		if (folio)
			folio_put(folio);
	}
	if (pte)
		pte_unmap(pte);
	blk_finish_plug(&plug);
	swap_read_unplug(splug);
	lru_add_drain();
skip:
	/* The folio was likely read above, so no need for plugging here */
	folio = swap_cache_read_folio(targ_entry, gfp_mask, 0, mpol, targ_ilx,
					    NULL, false);
	return folio;
}

/**
 * swapin_readahead - swap in pages in hope we need them soon
 * @entry: swap entry of this memory
 * @gfp_mask: memory allocation flags
 * @vmf: fault information
 *
 * Returns the struct folio for entry and addr, after queueing swapin.
 *
 * It's a main entry function for swap readahead. By the configuration,
 * it will read ahead blocks by cluster-based(ie, physical disk based)
 * or vma-based(ie, virtual address based on faulty address) readahead.
 */
struct folio *swapin_readahead(swp_entry_t entry, gfp_t gfp_mask,
				struct vm_fault *vmf)
{
	struct mempolicy *mpol;
	pgoff_t ilx;
	struct folio *folio;

	mpol = get_vma_policy(vmf->vma, vmf->address, 0, &ilx);
	folio = swap_use_vma_readahead() ?
		swap_vma_readahead(entry, gfp_mask, mpol, ilx, vmf) :
		swap_cluster_readahead(entry, gfp_mask, mpol, ilx);
	mpol_cond_put(mpol);

	return folio;
}

#ifdef CONFIG_SYSFS
static ssize_t vma_ra_enabled_show(struct kobject *kobj,
				     struct kobj_attribute *attr, char *buf)
{
	return sysfs_emit(buf, "%s\n", str_true_false(enable_vma_readahead));
}
static ssize_t vma_ra_enabled_store(struct kobject *kobj,
				      struct kobj_attribute *attr,
				      const char *buf, size_t count)
{
	ssize_t ret;

	ret = kstrtobool(buf, &enable_vma_readahead);
	if (ret)
		return ret;

	return count;
}
static struct kobj_attribute vma_ra_enabled_attr = __ATTR_RW(vma_ra_enabled);

static struct attribute *swap_attrs[] = {
	&vma_ra_enabled_attr.attr,
	NULL,
};

static const struct attribute_group swap_attr_group = {
	.attrs = swap_attrs,
};

static int __init swap_init(void)
{
	int err;
	struct kobject *swap_kobj;

	swap_kobj = kobject_create_and_add("swap", mm_kobj);
	if (!swap_kobj) {
		pr_err("failed to create swap kobject\n");
		return -ENOMEM;
	}
	err = sysfs_create_group(swap_kobj, &swap_attr_group);
	if (err) {
		pr_err("failed to register swap group\n");
		goto delete_obj;
	}
	mapping_set_no_writeback_tags(&swap_space);
	return 0;

delete_obj:
	kobject_put(swap_kobj);
	return err;
}
subsys_initcall(swap_init);
#endif
