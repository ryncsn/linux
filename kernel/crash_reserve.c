// SPDX-License-Identifier: GPL-2.0-only

#include <linux/crash_core.h>
#include <linux/crash_dump.h>
#include <linux/utsname.h>
#include <linux/vmalloc.h>
#include <linux/device.h>
#include <linux/memory_hotplug.h>
#include <linux/memory.h>
#include <linux/page-isolation.h>

#include <asm/page.h>
#include <asm/sections.h>
#include "kexec_internal.h"

/* Location of the reserved area for the crash kernel */
struct resource crashk_res = {
	.name  = "Crash kernel",
	.start = 0,
	.end   = 0,
	.flags = IORESOURCE_BUSY | IORESOURCE_SYSTEM_RAM,
	.desc  = IORES_DESC_CRASH_KERNEL
};

struct resource crashk_low_res = {
	.name  = "Crash kernel",
	.start = 0,
	.end   = 0,
	.flags = IORESOURCE_BUSY | IORESOURCE_SYSTEM_RAM,
	.desc  = IORES_DESC_CRASH_KERNEL
};

unsigned long long crashk_fragments_kdump;

/*
 * The crashkernel memory is reserved at boot, we want a way to dynamicaly
 * alloc more usable page for second kernel so userspace will not hit OOM
 */
struct crash_fragments_hdr {
	int entry_num;
	int container_size;
};

struct crash_fragments_entry {
	unsigned long long paddr;	/* PFN of starting for free page fragment */
	int size;			/* How many continues pages available */
};

struct crash_fragments {
	struct crash_fragments_hdr hdr;
	struct crash_fragments_entry entries[];
} __packed *crashk_fragments;

/*
 * parsing the "crashkernel" commandline
 *
 * codes below is intended to be called from architecture specific code
 */

/*
 * This function parses command lines in the format
 *
 *   crashkernel=ramsize-range:size[,...][@offset]
 *
 * The function returns 0 on success and -EINVAL on failure.
 */
static int __init parse_crashkernel_mem(char *cmdline,
					unsigned long long system_ram,
					unsigned long long *crash_size,
					unsigned long long *crash_base)
{
	char *cur = cmdline, *tmp;

	/* for each entry of the comma-separated list */
	do {
		unsigned long long start, end = ULLONG_MAX, size;

		/* get the start of the range */
		start = memparse(cur, &tmp);
		if (cur == tmp) {
			pr_warn("crashkernel: Memory value expected\n");
			return -EINVAL;
		}
		cur = tmp;
		if (*cur != '-') {
			pr_warn("crashkernel: '-' expected\n");
			return -EINVAL;
		}
		cur++;

		/* if no ':' is here, than we read the end */
		if (*cur != ':') {
			end = memparse(cur, &tmp);
			if (cur == tmp) {
				pr_warn("crashkernel: Memory value expected\n");
				return -EINVAL;
			}
			cur = tmp;
			if (end <= start) {
				pr_warn("crashkernel: end <= start\n");
				return -EINVAL;
			}
		}

		if (*cur != ':') {
			pr_warn("crashkernel: ':' expected\n");
			return -EINVAL;
		}
		cur++;

		size = memparse(cur, &tmp);
		if (cur == tmp) {
			pr_warn("Memory value expected\n");
			return -EINVAL;
		}
		cur = tmp;
		if (size >= system_ram) {
			pr_warn("crashkernel: invalid size\n");
			return -EINVAL;
		}

		/* match ? */
		if (system_ram >= start && system_ram < end) {
			*crash_size = size;
			break;
		}
	} while (*cur++ == ',');

	if (*crash_size > 0) {
		while (*cur && *cur != ' ' && *cur != '@')
			cur++;
		if (*cur == '@') {
			cur++;
			*crash_base = memparse(cur, &tmp);
			if (cur == tmp) {
				pr_warn("Memory value expected after '@'\n");
				return -EINVAL;
			}
		}
	} else
		pr_info("crashkernel size resulted in zero bytes\n");

	return 0;
}

/*
 * That function parses "simple" (old) crashkernel command lines like
 *
 *	crashkernel=size[@offset]
 *
 * It returns 0 on success and -EINVAL on failure.
 */
static int __init parse_crashkernel_simple(char *cmdline,
					   unsigned long long *crash_size,
					   unsigned long long *crash_base)
{
	char *cur = cmdline;

	*crash_size = memparse(cmdline, &cur);
	if (cmdline == cur) {
		pr_warn("crashkernel: memory value expected\n");
		return -EINVAL;
	}

	if (*cur == '@')
		*crash_base = memparse(cur+1, &cur);
	else if (*cur != ' ' && *cur != '\0') {
		pr_warn("crashkernel: unrecognized char: %c\n", *cur);
		return -EINVAL;
	}

	return 0;
}

#define SUFFIX_HIGH 0
#define SUFFIX_LOW  1
#define SUFFIX_NULL 2
static __initdata char *suffix_tbl[] = {
	[SUFFIX_HIGH] = ",high",
	[SUFFIX_LOW]  = ",low",
	[SUFFIX_NULL] = NULL,
};

/*
 * That function parses "suffix"  crashkernel command lines like
 *
 *	crashkernel=size,[high|low]
 *
 * It returns 0 on success and -EINVAL on failure.
 */
static int __init parse_crashkernel_suffix(char *cmdline,
					   unsigned long long	*crash_size,
					   const char *suffix)
{
	char *cur = cmdline;

	*crash_size = memparse(cmdline, &cur);
	if (cmdline == cur) {
		pr_warn("crashkernel: memory value expected\n");
		return -EINVAL;
	}

	/* check with suffix */
	if (strncmp(cur, suffix, strlen(suffix))) {
		pr_warn("crashkernel: unrecognized char: %c\n", *cur);
		return -EINVAL;
	}
	cur += strlen(suffix);
	if (*cur != ' ' && *cur != '\0') {
		pr_warn("crashkernel: unrecognized char: %c\n", *cur);
		return -EINVAL;
	}

	return 0;
}

static __init char *get_last_crashkernel(char *cmdline,
					 const char *suffix)
{
	char *p = cmdline, *ck_cmdline = NULL;

	/* find crashkernel and use the last one if there are more */
	p = strstr(p, "crashkernel=");
	while (p) {
		char *end_p = strchr(p, ' ');
		char *q;

		if (!end_p)
			end_p = p + strlen(p);

		if (!suffix) {
			int i;

			/* skip the one with any known suffix */
			for (i = 0; suffix_tbl[i]; i++) {
				q = end_p - strlen(suffix_tbl[i]);
				if (!strncmp(q, suffix_tbl[i],
					     strlen(suffix_tbl[i])))
					goto next;
			}
			ck_cmdline = p;
		} else {
			q = end_p - strlen(suffix);
			if (!strncmp(q, suffix, strlen(suffix)))
				ck_cmdline = p;
		}
next:
		p = strstr(p + 1, "crashkernel=");
	}

	if (!ck_cmdline)
		return NULL;

	return ck_cmdline + sizeof("crashkernel=") - 1;
}

static int __init __parse_crashkernel(char *cmdline,
			     unsigned long long system_ram,
			     unsigned long long *crash_size,
			     unsigned long long *crash_base,
			     const char *suffix)
{
	char	*first_colon, *first_space;
	char	*ck_cmdline;

	BUG_ON(!crash_size || !crash_base);
	*crash_size = 0;
	*crash_base = 0;

	ck_cmdline = get_last_crashkernel(cmdline, suffix);

	if (!ck_cmdline)
		return -EINVAL;

	if (suffix)
		return parse_crashkernel_suffix(ck_cmdline, crash_size,
				suffix);
	/*
	 * if the commandline contains a ':', then that's the extended
	 * syntax -- if not, it must be the classic syntax
	 */
	first_colon = strchr(ck_cmdline, ':');
	first_space = strchr(ck_cmdline, ' ');
	if (first_colon && (!first_space || first_colon < first_space))
		return parse_crashkernel_mem(ck_cmdline, system_ram,
				crash_size, crash_base);

	return parse_crashkernel_simple(ck_cmdline, crash_size, crash_base);
}

/*
 * That function is the entry point for command line parsing and should be
 * called from the arch-specific code.
 */
int __init parse_crashkernel(char *cmdline,
			     unsigned long long system_ram,
			     unsigned long long *crash_size,
			     unsigned long long *crash_base)
{
	return __parse_crashkernel(cmdline, system_ram, crash_size, crash_base,
				   NULL);
}

int __init parse_crashkernel_high(char *cmdline,
			     unsigned long long system_ram,
			     unsigned long long *crash_size,
			     unsigned long long *crash_base)
{
	return __parse_crashkernel(cmdline, system_ram, crash_size, crash_base,
				   suffix_tbl[SUFFIX_HIGH]);
}

int __init parse_crashkernel_low(char *cmdline,
			     unsigned long long system_ram,
			     unsigned long long *crash_size,
			     unsigned long long *crash_base)
{
	return __parse_crashkernel(cmdline, system_ram, crash_size, crash_base,
				   suffix_tbl[SUFFIX_LOW]);
}

size_t crash_get_memory_size(void)
{
	size_t size = 0;

	mutex_lock(&kexec_mutex);
	if (crashk_res.end != crashk_res.start)
		size = resource_size(&crashk_res);
	mutex_unlock(&kexec_mutex);
	return size;
}

void __weak crash_free_reserved_phys_range(unsigned long begin,
					   unsigned long end)
{
	unsigned long addr;

	for (addr = begin; addr < end; addr += PAGE_SIZE)
		free_reserved_page(boot_pfn_to_page(addr >> PAGE_SHIFT));
}

int crash_shrink_memory(unsigned long new_size)
{
	int ret = 0;
	unsigned long start, end;
	unsigned long old_size;
	struct resource *ram_res;

	mutex_lock(&kexec_mutex);

	if (kexec_crash_image) {
		ret = -ENOENT;
		goto unlock;
	}
	start = crashk_res.start;
	end = crashk_res.end;
	old_size = (end == 0) ? 0 : end - start + 1;
	if (new_size >= old_size) {
		ret = (new_size == old_size) ? 0 : -EINVAL;
		goto unlock;
	}

	ram_res = kzalloc(sizeof(*ram_res), GFP_KERNEL);
	if (!ram_res) {
		ret = -ENOMEM;
		goto unlock;
	}

	start = roundup(start, KEXEC_CRASH_MEM_ALIGN);
	end = roundup(start + new_size, KEXEC_CRASH_MEM_ALIGN);

	crash_free_reserved_phys_range(end, crashk_res.end);

	if ((start == end) && (crashk_res.parent != NULL))
		release_resource(&crashk_res);

	ram_res->start = end;
	ram_res->end = crashk_res.end;
	ram_res->flags = IORESOURCE_BUSY | IORESOURCE_SYSTEM_RAM;
	ram_res->name = "System RAM";

	crashk_res.end = end - 1;

	insert_resource(&iomem_resource, ram_res);

unlock:
	mutex_unlock(&kexec_mutex);
	return ret;
}

size_t crash_get_dynamic_memory_size(void)
{
	int i;
	size_t size = 0;

	if (!crashk_fragments) {
		return 0;
	}

	pr_err("Dynmem adddress at %llx with size %d/%d\n", __pa(crashk_fragments),
			crashk_fragments->hdr.entry_num,
			crashk_fragments->hdr.container_size);
	mutex_lock(&kexec_mutex);
	for (i = 0; i < crashk_fragments->hdr.entry_num; i++)
		size += crashk_fragments->entries[i].size;
	mutex_unlock(&kexec_mutex);

	return size;
}

int crash_shrink_dynamic_memory(unsigned long new_size)
{
	// TODO
	return 0;
}

phys_addr_t paddr_crashk_fragments(void)
{
	return __pa((void*)crashk_fragments);
}

static int add_crash_fragment(unsigned long long paddr, size_t size)
{
	struct crash_fragments *old;
	struct crash_fragments_hdr *hdr;

	int entry_num = 0, container_size = 64;

	pr_err("Adding adddress at %llx with size %ld\n", paddr, size);

	if (!crashk_fragments) {
		crashk_fragments = kzalloc(GFP_KERNEL,
					   sizeof(struct crash_fragments_hdr) + sizeof(struct crash_fragments_entry) * container_size);
		if (!crashk_fragments)
			return -ENOMEM;

		crashk_fragments->hdr.entry_num = entry_num;
		crashk_fragments->hdr.container_size = container_size;

		pr_err("Initial alloc %d@%llx\n", container_size, crashk_fragments);
	}

	hdr = &crashk_fragments->hdr;
	if (hdr->container_size == hdr->entry_num) {
		entry_num = hdr->entry_num;
		container_size = hdr->container_size * 2;

		old = crashk_fragments;
		crashk_fragments = kzalloc(GFP_KERNEL,
					   sizeof(struct crash_fragments_hdr) + sizeof(struct crash_fragments_entry) * container_size);
		if (!crashk_fragments)
			return -ENOMEM;
		pr_err("Extend alloc %d@%llx\n", container_size, crashk_fragments);

		memcpy(&crashk_fragments->entries, &old->entries, sizeof(struct crash_fragments_entry) * entry_num);
		crashk_fragments->hdr.entry_num = entry_num;
		crashk_fragments->hdr.container_size = container_size;
		hdr = &crashk_fragments->hdr;
	}

	crashk_fragments->entries[hdr->entry_num].size = size;
	crashk_fragments->entries[hdr->entry_num].paddr = paddr;
	hdr->entry_num ++;

	return 0;
}

int crash_increase_dynamic_memory(unsigned long new_size)
{
	int ret = 0, order;
	unsigned long old_size = 0, alloc, vstart;
	unsigned long long paddr;
	int size;

	old_size = crash_get_dynamic_memory_size();

	if (new_size < old_size) {
		return -EINVAL;
	}

	if (kexec_crash_image) {
		return -ENOENT;
	}

	mutex_lock(&kexec_mutex);
	alloc = roundup(new_size - old_size, PAGE_SIZE);
	while (alloc) {
		pr_err("Pending alloc %ld\n", alloc);
		/* Alloc the largest possible order smaller than allocation size */
		order = get_order(alloc);
		while ((PAGE_SIZE << order) > alloc)
			order--;

		vstart = 0;
		while (order >= 0) {
			vstart = __get_free_pages(GFP_KERNEL, order);
			if (vstart)
				break;
			order --;
		}

		if (!vstart) {
			ret = -ENOMEM;
			goto unlock;
		}
		pr_err("Found page at %lx with order %d\n", __pa(vstart), order);

		paddr = __pa(vstart);
		size = PAGE_SIZE << order;
		alloc -= size;

		if (add_crash_fragment(paddr, size))
			return -ENOMEM;
	}

unlock:
	mutex_unlock(&kexec_mutex);
	return ret;
}

static int __init kdump_crashk_fragments(char *arg)
{
	char *end;

	if (!arg)
		return -EINVAL;

	crashk_fragments_kdump = memparse(arg, &end);
	if (!crashk_fragments_kdump)
		return -EINVAL;

	return 0;
}
early_param("crash_fragment", kdump_crashk_fragments);

static unsigned long long frag_paddr, frag_size;

static void __frag_online_page(void)
{
	unsigned long long pfn;
	struct page *pg;

	pr_err("CB: actuall online page addr %llx - %llx\n", frag_paddr, frag_paddr + frag_size);
	pr_err("CB: actuall online page vaddr %llx - %llx\n", __va(frag_paddr), __va(frag_paddr + frag_size));
	pr_err("CB: actuall online pfn %ld - %ld\n", __phys_to_pfn(frag_paddr), __phys_to_pfn(frag_paddr + frag_size));

	for (pfn = __phys_to_pfn(frag_paddr);
			pfn < __phys_to_pfn(frag_paddr + frag_size);
			pfn ++)
	{
		pg = pfn_to_page(pfn);

		// kernel_map_pages(pg, 1, 1);

		if (!kern_addr_valid(__va(__pfn_to_phys(pfn)))) {
			pr_err("CB: Ignore overlapeed pfn %ld\n", pfn);
			continue;
		}

		if (PageReserved(pg))
			__ClearPageReserved(pg);

		__online_page_set_limits(pg);
		__online_page_increment_counters(pg);
		__online_page_free(pg);

		set_pageblock_migratetype(pg, MIGRATE_UNMOVABLE);
	}
}

static void frag_online_page(struct page *pg, unsigned int order)
{
	unsigned long start_pfn = page_to_pfn(pg);
	unsigned long nr_page = 1UL << order;
	unsigned long i;

	pr_err("CB: online region range addr %llx - %llx\n", __pfn_to_phys(start_pfn), __pfn_to_phys(start_pfn) + nr_page * PAGE_SIZE);

	for (i = 0; i < nr_page; i++) {
		pg = pfn_to_page(start_pfn + i);
		__SetPageReserved(pg);
	}
}

int __init parse_crashk_fragments(void) {
	struct crash_fragments_entry *frag, *old;
	struct crash_fragments_hdr hdr;
	struct page *pg;
	u64 addr;
	int i;
	unsigned long long vstart;

	if (!crashk_fragments_kdump)
		return 0;

	addr = crashk_fragments_kdump;

	pr_err("DEBUG !!!!!!!!!!!!!!!!!!!!!!!!\n");
	pr_err("Fragment head %llx\n", addr);

	read_from_oldmem((char*)&hdr,
			 sizeof(struct crash_fragments_hdr),
			 &addr, 0, false);
	pr_err("Found fragment %d, %d\n", hdr.entry_num, hdr.container_size);

	pr_err("Loading %d fragment records at %llx\n", hdr.entry_num, addr);
	frag = kzalloc(GFP_KERNEL, sizeof(struct crash_fragments_entry) * hdr.container_size);
	if (!frag) {
		pr_err("!!!!!!!!!!!!! OOM !!!!!!!!!!!!!!!!\n");
		return -ENOMEM;
	}

	addr = crashk_fragments_kdump + sizeof(struct crash_fragments_hdr);
	read_from_oldmem((char*)frag, sizeof(struct crash_fragments_entry) * hdr.container_size,
			 &addr, 0, false);

	old = frag;
	set_online_page_callback(&frag_online_page);

	for (i = 0; i < hdr.entry_num; i++) {
		unsigned long long pfn, align_start, align_end, align_size;
		unsigned long long paddr, size, nr_pages, count, nid;
		unsigned long flags;

		local_irq_save(flags);

		frag_paddr = paddr = frag->paddr;
		frag_size = size = frag->size;

		pfn = __phys_to_pfn(frag->paddr);
		nr_pages = frag->size / PAGE_SIZE;
		frag ++;

		align_size = memory_block_size_bytes();
		align_start = rounddown(paddr, align_size);
		align_end = roundup(paddr + size, align_size);

		if (!online_section_nr(pfn_to_section_nr(pfn))) {
			pr_err("new region %llx - %llx\n", paddr, paddr + size);
			nid = memory_add_physaddr_to_nid(PFN_PHYS(paddr));
			add_memory(nid, align_start, align_size);
		} else {
			pr_err("online page %llx - %llx\n", paddr, paddr + size);
		}
		__frag_online_page();
		local_irq_restore(flags);
	}

	vstart = __get_free_pages(GFP_KERNEL, 0);
	free_page(vstart);

	pg = virt_to_page(vstart);
	pr_err("Alloc %llx\n", __pa(vstart));
	pr_err("Type %x\n", pg->page_type);
	pr_err("Active %x\n", pg->active);
	pr_err("Units %x\n", pg->units);
	dump_page(virt_to_page(vstart), "ALLOC KERNEL PAGE");

	pr_err("Last %llx\n", (frag - 1)->paddr + PAGE_SIZE);
	pg = pfn_to_page(__phys_to_pfn((frag - 1)->paddr + PAGE_SIZE));
	pr_err("Type %x\n", pg->page_type);
	pr_err("Active %x\n", pg->active);
	pr_err("Units %x\n", pg->units);

	dump_page(virt_to_page(vstart), "ALLOC KERNEL PAGE");
	dump_page(pfn_to_page(__phys_to_pfn((frag - 1)->paddr)), "NEW ADDED PAGE");

	dump_page(pfn_to_page(__phys_to_pfn((frag - 1)->paddr + PAGE_SIZE)), "NEW ADDED PAGE");

	kfree(old);
	restore_online_page_callback(&frag_online_page);

	return 0;
}
subsys_initcall(parse_crashk_fragments)

// struct resource res = {};
// int i;

// res = kzalloc(sizeof(*res), GFP_KERNEL);
// if (!res)
// 	return NULL;

// res->name = "System RAM";
// res->flags = IORESOURCE_SYSTEM_RAM | IORESOURCE_BUSY;
// res->start =
