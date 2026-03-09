/* SPDX-License-Identifier: GPL-2.0 */
#ifndef LINUX_MM_INLINE_H
#define LINUX_MM_INLINE_H

#include <linux/huge_mm.h>
#include <linux/swap.h>
#include <linux/string.h>
#ifndef __GENKSYMS__
#define PROTECT_TRACE_INCLUDE_PATH
#include <trace/hooks/mm.h>
#endif

/* Simple one-to-one mappings for folio compat */
#define folio page
#define folio_zonenum page_zonenum
#define folio_nr_pages thp_nr_pages
#define lru_to_folio lru_to_page
#define folio_evictable page_evictable
#define folio_nid page_to_nid
#define folio_pgdat page_pgdat
#define folio_memcg page_memcg
#define folio_memcg_check page_memcg_check
#define folio_matches_lruvec page_matches_lruvec
#define folio_lruvec_lock_irq lock_page_lruvec_irq
#define folio_lruvec_lock_irqsave lock_page_lruvec_irqsave
#define folio_lruvec_relock_irq relock_page_lruvec_irq
#define folio_lruvec_relock_irqsave relock_page_lruvec_irqrestore
#define lru_gen_folio lru_gen_struct
#define folio_mark_dirty set_page_dirty
#define folio_activate activate_page
#define folio_try_get get_page_unless_zero
#define folio_put put_page
#define folio_putback_lru putback_lru_page
#define folio_mapped page_mapped
#define VM_BUG_ON_FOLIO VM_BUG_ON_PAGE
#define VM_WARN_ON_ONCE_FOLIO VM_WARN_ON_ONCE_PAGE
#define folio_flags(folio, n) (&(folio)->flags)
#define const_folio_flags(folio, n) (&(folio)->flags)

/*
 * Meta macros to generate folio compat wrappers. Using the C preprocessor
 * we can batch create the PageFoo / ClearPageFoo / SetPageFoo mappings.
 */
#define FOLIO_COMPAT_TEST(name, page_op) \
	static inline bool folio_test_##name(struct folio *folio) \
	{ return page_op((struct page *)folio); }
#define FOLIO_COMPAT_SET(name, page_op) \
	static inline void folio_set_##name(struct folio *folio) \
	{ page_op((struct page *)folio); }
#define FOLIO_COMPAT_CLEAR(name, page_op) \
	static inline void folio_clear_##name(struct folio *folio) \
	{ page_op((struct page *)folio); }
#define FOLIO_COMPAT_TEST_CLEAR(name, page_op) \
	static inline bool folio_test_clear_##name(struct folio *folio) \
	{ return page_op((struct page *)folio); }

FOLIO_COMPAT_TEST(lru, PageLRU)
FOLIO_COMPAT_TEST(active, PageActive)
FOLIO_COMPAT_TEST(unevictable, PageUnevictable)
FOLIO_COMPAT_TEST(swapbacked, PageSwapBacked)
FOLIO_COMPAT_TEST(referenced, PageReferenced)
FOLIO_COMPAT_TEST(workingset, PageWorkingset)
FOLIO_COMPAT_TEST(swapcache, PageSwapCache)
FOLIO_COMPAT_TEST(reclaim, PageReclaim)
FOLIO_COMPAT_TEST(dirty, PageDirty)
FOLIO_COMPAT_TEST(writeback, PageWriteback)
FOLIO_COMPAT_TEST(mlocked, PageMlocked)
FOLIO_COMPAT_TEST(locked, PageLocked)
FOLIO_COMPAT_TEST(anon, PageAnon)

FOLIO_COMPAT_SET(active, SetPageActive)
FOLIO_COMPAT_SET(referenced, SetPageReferenced)
FOLIO_COMPAT_SET(swapbacked, SetPageSwapBacked)
FOLIO_COMPAT_SET(workingset, SetPageWorkingset)
FOLIO_COMPAT_SET(unevictable, SetPageUnevictable)
FOLIO_COMPAT_SET(lru, SetPageLRU)

FOLIO_COMPAT_CLEAR(active, ClearPageActive)
FOLIO_COMPAT_CLEAR(referenced, ClearPageReferenced)
FOLIO_COMPAT_CLEAR(workingset, ClearPageWorkingset)
FOLIO_COMPAT_CLEAR(swapbacked, ClearPageSwapBacked)
FOLIO_COMPAT_CLEAR(reclaim, ClearPageReclaim)
FOLIO_COMPAT_CLEAR(lru, ClearPageLRU)

FOLIO_COMPAT_TEST_CLEAR(referenced, TestClearPageReferenced)
FOLIO_COMPAT_TEST_CLEAR(lru, TestClearPageLRU)

#undef FOLIO_COMPAT_TEST
#undef FOLIO_COMPAT_SET
#undef FOLIO_COMPAT_CLEAR
#undef FOLIO_COMPAT_TEST_CLEAR

#define page_folio(page) page
#define folio_page(folio) folio
static inline struct lruvec *folio_lruvec(struct folio *folio)
{
	return mem_cgroup_lruvec(folio_memcg(folio), folio_pgdat(folio));
}

/* Internal helpers still used by __folio_clear_lru_flags() */
#define __folio_clear_lru(folio)	__ClearPageLRU((struct page *)(folio))
#define __folio_clear_active(folio)	__ClearPageActive((struct page *)(folio))
#define __folio_clear_unevictable(folio) __ClearPageUnevictable((struct page *)(folio))

/**
 * folio_is_file_lru - Should the folio be on a file LRU or anon LRU?
 * @folio: The folio to test.
 *
 * We would like to get this info without a page flag, but the state
 * needs to survive until the folio is last deleted from the LRU, which
 * could be as far down as __page_cache_release.
 *
 * Return: An integer (not a boolean!) used to sort a folio onto the
 * right LRU list and to account folios correctly.
 * 1 if @folio is a regular filesystem backed page cache folio
 * or a lazily freed anonymous folio (e.g. via MADV_FREE).
 * 0 if @folio is a normal anonymous folio, a tmpfs folio or otherwise
 * ram or swap backed folio.
 */
static inline int folio_is_file_lru(struct folio *folio)
{
	return !folio_test_swapbacked(folio);
}
#define page_is_file_lru folio_is_file_lru

static __always_inline void __update_lru_size(struct lruvec *lruvec,
				enum lru_list lru, enum zone_type zid,
				long nr_pages)
{
	struct pglist_data *pgdat = lruvec_pgdat(lruvec);

	WARN_ON_ONCE(nr_pages != (int)nr_pages);

	mod_lruvec_state(lruvec, NR_LRU_BASE + lru, nr_pages);
	mod_zone_page_state(&pgdat->node_zones[zid],
			    NR_ZONE_LRU_BASE + lru, nr_pages);
}

static __always_inline void update_lru_size(struct lruvec *lruvec,
				enum lru_list lru, enum zone_type zid,
				long nr_pages)
{
	__update_lru_size(lruvec, lru, zid, nr_pages);
#ifdef CONFIG_MEMCG
	mem_cgroup_update_lru_size(lruvec, lru, zid, nr_pages);
#endif
}

/**
 * __folio_clear_lru_flags - Clear page lru flags before releasing a page.
 * @folio: The folio that was on lru and now has a zero reference.
 */
static __always_inline void __folio_clear_lru_flags(struct folio *folio)
{
	VM_BUG_ON_FOLIO(!folio_test_lru(folio), folio);

	__folio_clear_lru(folio);

	/* this shouldn't happen, so leave the flags to bad_page() */
	if (folio_test_active(folio) && folio_test_unevictable(folio))
		return;

	__folio_clear_active(folio);
	__folio_clear_unevictable(folio);
}
#define __clear_page_lru_flags __folio_clear_lru_flags

/**
 * folio_lru_list - Which LRU list should a folio be on?
 * @folio: The folio to test.
 *
 * Return: The LRU list a folio should be on, as an index
 * into the array of LRU lists.
 */
static __always_inline enum lru_list folio_lru_list(struct folio *folio)
{
	enum lru_list lru;

	VM_BUG_ON_FOLIO(folio_test_active(folio) && folio_test_unevictable(folio), folio);

	if (folio_test_unevictable(folio))
		return LRU_UNEVICTABLE;

	lru = folio_is_file_lru(folio) ? LRU_INACTIVE_FILE : LRU_INACTIVE_ANON;
	if (folio_test_active(folio))
		lru += LRU_ACTIVE;

	return lru;
}
#define page_lru folio_lru_list

#ifdef CONFIG_LRU_GEN

static inline bool lru_gen_switching(void)
{
	return false;
}

static inline bool lru_gen_enabled(void)
{
	return true;
}

static inline bool lru_gen_in_fault(void)
{
	return current->in_lru_fault;
}

static inline int lru_gen_from_seq(unsigned long seq)
{
	return seq % MAX_NR_GENS;
}

static inline int lru_hist_from_seq(unsigned long seq)
{
	return seq % NR_HIST_GENS;
}

static inline int lru_tier_from_refs(int refs, bool workingset)
{
	VM_WARN_ON_ONCE(refs > BIT(LRU_REFS_WIDTH));

	/* see the comment on MAX_NR_TIERS */
	return workingset ? MAX_NR_TIERS - 1 : order_base_2(refs);
}

/**
 * lru_gen_from_flags - Return the LRU generation number from folio flags.
 * @flags: folio flags
 *
 * Returns: A number between 0 and LRU_GEN_MAX, inclusive. Returns -1 if the
 * flags indicate the folio is off the list (e.g., isolated).
 */
static inline int lru_gen_from_flags(unsigned long flags)
{
	int gen = ((flags & LRU_GEN_MASK) >> LRU_GEN_PGOFF);

	gen -= 1;
	VM_WARN_ON_ONCE(gen != -1 && gen > LRU_GEN_MAX);
	return gen;
}

/**
 * lru_gen_set_flags - Set the LRU generation number to specified folio flags.
 * @flags: pointer to the folio flags
 * @gen: generation number, between 0 and LRU_GEN_MAX, inclusive.
 */
static inline void lru_gen_set_flags(unsigned long *flags, int gen)
{
	VM_WARN_ON_ONCE(gen > LRU_GEN_MAX || gen < 0);
	BUILD_BUG_ON((LRU_GEN_MAX + 1) != MAX_NR_GENS);

	*flags &= ~LRU_GEN_MASK;
	*flags |= (gen + 1UL) << LRU_GEN_PGOFF;
}

/**
 * lru_refs_from_flags - Return LRU referenced / access count from folio flags.
 * @flags: folio flags
 */
static inline int lru_refs_from_flags(unsigned long flags)
{
	if (!(flags & BIT(PG_referenced)))
		return 0;
	/*
	 * Return the total number of accesses including PG_referenced. Also see
	 * the comment on LRU_REFS_FLAGS.
	 */
	return ((flags & LRU_REFS_MASK) >> LRU_REFS_PGOFF) + 1;
}

/**
 * lru_refs_set_flags - Set the LRU referenced / access count to specified folio flags.
 * @flags: pointer to the folio flags
 * @refs: referenced / access count number, between 0 and LRU_REFS_MAX, inclusive.
 */
static inline void lru_refs_set_flags(unsigned long *flags, unsigned int refs)
{
	VM_WARN_ON_ONCE(refs > LRU_REFS_MAX);

	*flags &= ~LRU_REFS_FLAGS;
	if (!refs)
		return;
	*flags |= (BIT(PG_referenced) | ((refs - 1UL) << LRU_REFS_PGOFF));
}

static inline int folio_lru_refs(const struct folio *folio)
{
	return lru_refs_from_flags(READ_ONCE(*const_folio_flags(folio, 0)));
}

static inline void folio_set_lru_refs(struct folio *folio, unsigned int refs)
{
	unsigned long new_flags, old_flags = READ_ONCE(*folio_flags(folio, 0));

	do {
		new_flags = old_flags;
		lru_refs_set_flags(&new_flags, refs);
	} while (!try_cmpxchg(folio_flags(folio, 0), &old_flags, new_flags));
}

static inline int folio_lru_gen(const struct folio *folio)
{
	return lru_gen_from_flags(READ_ONCE(*const_folio_flags(folio, 0)));
}

static inline bool lru_gen_is_active(const struct lruvec *lruvec, int gen)
{
	unsigned long max_seq = lruvec->lrugen.max_seq;

	VM_WARN_ON_ONCE(gen > LRU_GEN_MAX);

	/* see the comment on MIN_NR_GENS */
	return gen == lru_gen_from_seq(max_seq) || gen == lru_gen_from_seq(max_seq - 1);
}

static inline void lru_gen_update_size(struct lruvec *lruvec, struct folio *folio,
				       int old_gen, int new_gen)
{
	int type = folio_is_file_lru(folio);
	int zone = folio_zonenum(folio);
	int delta = folio_nr_pages(folio);
	enum lru_list lru = type * LRU_INACTIVE_FILE;
	struct lru_gen_folio *lrugen = &lruvec->lrugen;

	VM_WARN_ON_ONCE(old_gen != -1 && old_gen >= MAX_NR_GENS);
	VM_WARN_ON_ONCE(new_gen != -1 && new_gen >= MAX_NR_GENS);
	VM_WARN_ON_ONCE(old_gen == -1 && new_gen == -1);

	if (old_gen >= 0)
		atomic_long_sub(delta, (atomic_long_t *)&lrugen->nr_pages[old_gen][type][zone]);
	if (new_gen >= 0)
		atomic_long_add(delta, (atomic_long_t *)&lrugen->nr_pages[new_gen][type][zone]);

	/* addition */
	if (old_gen < 0) {
		if (lru_gen_is_active(lruvec, new_gen))
			lru += LRU_ACTIVE;
		__update_lru_size(lruvec, lru, zone, delta);
		return;
	}

	/* deletion */
	if (new_gen < 0) {
		if (lru_gen_is_active(lruvec, old_gen))
			lru += LRU_ACTIVE;
		__update_lru_size(lruvec, lru, zone, -delta);
		return;
	}

	/* promotion */
	if (!lru_gen_is_active(lruvec, old_gen) && lru_gen_is_active(lruvec, new_gen)) {
		__update_lru_size(lruvec, lru, zone, -delta);
		__update_lru_size(lruvec, lru + LRU_ACTIVE, zone, delta);
	}

	/* demotion requires isolation, e.g., llru_gen_folio_seqru_deactivate_fn() */
	VM_WARN_ON_ONCE(lru_gen_is_active(lruvec, old_gen) && !lru_gen_is_active(lruvec, new_gen));
}

static inline unsigned long lru_gen_folio_seq(const struct lruvec *lruvec,
					      struct folio *folio,
					      bool reclaiming)
{
	int gen;
	int type = folio_is_file_lru(folio);
	const struct lru_gen_folio *lrugen = &lruvec->lrugen;

	/*
	 * +-----------------------------------+-----------------------------------+
	 * | Accessed through page tables and  | Accessed through file descriptors |
	 * | promoted by folio_update_gen()    | and protected by folio_inc_gen()  |
	 * +-----------------------------------+-----------------------------------+
	 * | PG_active (set while isolated)    |                                   |
	 * +-----------------+-----------------+-----------------+-----------------+
	 * |  PG_workingset  |  PG_referenced  |  PG_workingset  |  LRU_REFS_FLAGS |
	 * +-----------------------------------+-----------------------------------+
	 * |<---------- MIN_NR_GENS ---------->|                                   |
	 * |<---------------------------- MAX_NR_GENS ---------------------------->|
	 */
	if (folio_test_active(folio))
		gen = MIN_NR_GENS - folio_test_workingset(folio);
	else if (reclaiming)
		gen = MAX_NR_GENS;
	else if ((!folio_is_file_lru(folio) && !folio_test_swapcache(folio)) ||
		 (folio_test_reclaim(folio) &&
		  (folio_test_dirty(folio) || folio_test_writeback(folio))))
		gen = MIN_NR_GENS;
	else
		gen = MAX_NR_GENS - folio_test_workingset(folio);

	return max(READ_ONCE(lrugen->max_seq) - gen + 1, READ_ONCE(lrugen->min_seq[type]));
}

static inline bool lru_gen_add_folio(struct lruvec *lruvec, struct folio *folio, bool reclaiming)
{
	unsigned long seq;
	unsigned long flags;
	int gen = folio_lru_gen(folio);
	int type = folio_is_file_lru(folio);
	int zone = folio_zonenum(folio);
	struct lru_gen_folio *lrugen = &lruvec->lrugen;

	VM_WARN_ON_ONCE_FOLIO(gen != -1, folio);

	if (folio_test_unevictable(folio) || !lrugen->enabled)
		return false;

	seq = lru_gen_folio_seq(lruvec, folio, reclaiming);
	gen = lru_gen_from_seq(seq);
	flags = (gen + 1UL) << LRU_GEN_PGOFF;
	/* see the comment on MIN_NR_GENS about PG_active */
	set_mask_bits(folio_flags(folio, 0), LRU_GEN_MASK | BIT(PG_active), flags);

	lru_gen_update_size(lruvec, folio, -1, gen);
	/* for rotate_reclaimable_page() / folio_rotate_reclaimable() */
	if (reclaiming)
		list_add_tail(&folio->lru, &lrugen->lists[gen][type][zone]);
	else
		list_add(&folio->lru, &lrugen->lists[gen][type][zone]);

	return true;
}

static inline bool lru_gen_del_folio(struct lruvec *lruvec, struct folio *folio, bool reclaiming)
{
	unsigned long flags;
	int gen = folio_lru_gen(folio);

	if (gen < 0)
		return false;

	VM_WARN_ON_ONCE_FOLIO(folio_test_active(folio), folio);
	VM_WARN_ON_ONCE_FOLIO(folio_test_unevictable(folio), folio);

	/* for folio_migrate_flags() */
	flags = !reclaiming && lru_gen_is_active(lruvec, gen) ? BIT(PG_active) : 0;
	flags = set_mask_bits(folio_flags(folio, 0), LRU_GEN_MASK, flags);
	gen = ((flags & LRU_GEN_MASK) >> LRU_GEN_PGOFF) - 1;

	lru_gen_update_size(lruvec, folio, gen, -1);
	list_del(&folio->lru);

	return true;
}

static inline void folio_migrate_refs(struct folio *new, const struct folio *old)
{
	folio_set_lru_refs(new, folio_lru_refs(old));
}
#else /* !CONFIG_LRU_GEN */

static inline bool lru_gen_enabled(void)
{
	return false;
}

static inline bool lru_gen_switching(void)
{
	return false;
}

static inline bool lru_gen_in_fault(void)
{
	return false;
}

static inline bool lru_gen_add_folio(struct lruvec *lruvec, struct folio *folio, bool reclaiming)
{
	return false;
}

static inline bool lru_gen_del_folio(struct lruvec *lruvec, struct folio *folio, bool reclaiming)
{
	return false;
}

static inline void folio_migrate_refs(struct folio *new, const struct folio *old)
{
	if (folio_test_referenced(old))
		folio_set_referenced(new);
}
#endif /* CONFIG_LRU_GEN */

static __always_inline void add_page_to_lru_list(struct page *page,
				struct lruvec *lruvec)
{
	enum lru_list lru = page_lru(page);

	if (lru_gen_add_folio(lruvec, page, false))
		return;

	trace_android_vh_add_page_to_lrulist(page, false, lru);
	update_lru_size(lruvec, lru, page_zonenum(page), thp_nr_pages(page));
	list_add(&page->lru, &lruvec->lists[lru]);
}

static __always_inline void add_page_to_lru_list_tail(struct page *page,
				struct lruvec *lruvec)
{
	enum lru_list lru = page_lru(page);

	if (lru_gen_add_folio(lruvec, page, true))
		return;

	trace_android_vh_add_page_to_lrulist(page, false, page_lru(page));
	update_lru_size(lruvec, lru, page_zonenum(page), thp_nr_pages(page));
	list_add_tail(&page->lru, &lruvec->lists[lru]);
}

static __always_inline void del_page_from_lru_list(struct page *page,
				struct lruvec *lruvec)
{
	if (lru_gen_del_folio(lruvec, page, false))
		return;

	trace_android_vh_del_page_from_lrulist(page, false, page_lru(page));
	list_del(&page->lru);
	update_lru_size(lruvec, page_lru(page), page_zonenum(page),
			-thp_nr_pages(page));
}

#ifdef CONFIG_ANON_VMA_NAME
/*
 * mmap_lock should be read-locked when calling anon_vma_name(). Caller should
 * either keep holding the lock while using the returned pointer or it should
 * raise anon_vma_name refcount before releasing the lock.
 */
extern struct anon_vma_name *anon_vma_name(struct vm_area_struct *vma);
extern struct anon_vma_name *anon_vma_name_alloc(const char *name);
extern void anon_vma_name_free(struct kref *kref);

/* mmap_lock should be read-locked */
static inline void anon_vma_name_get(struct anon_vma_name *anon_name)
{
	if (anon_name)
		kref_get(&anon_name->kref);
}

static inline void anon_vma_name_put(struct anon_vma_name *anon_name)
{
	if (anon_name)
		kref_put(&anon_name->kref, anon_vma_name_free);
}

static inline
struct anon_vma_name *anon_vma_name_reuse(struct anon_vma_name *anon_name)
{
	/* Prevent anon_name refcount saturation early on */
	if (kref_read(&anon_name->kref) < REFCOUNT_MAX) {
		anon_vma_name_get(anon_name);
		return anon_name;

	}
	return anon_vma_name_alloc(anon_name->name);
}

static inline void dup_anon_vma_name(struct vm_area_struct *orig_vma,
				     struct vm_area_struct *new_vma)
{
	struct anon_vma_name *anon_name = anon_vma_name(orig_vma);

	if (anon_name)
		new_vma->anon_name = anon_vma_name_reuse(anon_name);
}

static inline void free_anon_vma_name(struct vm_area_struct *vma)
{
	/*
	 * Not using anon_vma_name because it generates a warning if mmap_lock
	 * is not held, which might be the case here.
	 */
	if (!vma->vm_file)
		anon_vma_name_put(vma->anon_name);
}

static inline bool anon_vma_name_eq(struct anon_vma_name *anon_name1,
				    struct anon_vma_name *anon_name2)
{
	if (anon_name1 == anon_name2)
		return true;

	return anon_name1 && anon_name2 &&
		!strcmp(anon_name1->name, anon_name2->name);
}
#else /* CONFIG_ANON_VMA_NAME */
static inline struct anon_vma_name *anon_vma_name(struct vm_area_struct *vma)
{
	return NULL;
}

static inline struct anon_vma_name *anon_vma_name_alloc(const char *name)
{
	return NULL;
}

static inline void anon_vma_name_get(struct anon_vma_name *anon_name) {}
static inline void anon_vma_name_put(struct anon_vma_name *anon_name) {}
static inline void dup_anon_vma_name(struct vm_area_struct *orig_vma,
				     struct vm_area_struct *new_vma) {}
static inline void free_anon_vma_name(struct vm_area_struct *vma) {}

static inline bool anon_vma_name_eq(struct anon_vma_name *anon_name1,
				    struct anon_vma_name *anon_name2)
{
	return true;
}

#endif  /* CONFIG_ANON_VMA_NAME */

#endif
