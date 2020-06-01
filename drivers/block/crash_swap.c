// SPDX-License-Identifier: GPL-2.0-only
/*
 * Ram backed block device driver for crash kernel
 *
 */

#define KMSG_COMPONENT "crash-swap"
#define pr_fmt(fmt) KMSG_COMPONENT ": " fmt

#include <linux/sizes.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/major.h>
#include <linux/blkdev.h>
#include <linux/bio.h>
#include <linux/highmem.h>
#include <linux/mutex.h>
#include <linux/xarray.h>
#include <linux/fs.h>
#include <linux/backing-dev.h>
#include <linux/crash_dump.h>

#define PAGE_SECTORS_SHIFT	(PAGE_SHIFT - SECTOR_SHIFT)
#define PAGE_SECTORS		(1 << PAGE_SECTORS_SHIFT)

/*
 * Similiar to block ramdisk device, but the backend memory could be continues
 * or fragmental (from PAGE_SIZE to 2M), so split into 2M blocks and manage the segments in units of blocks
 */

struct crash_swap_seg {
	u64 start;
	u64 paddr;
	u64 size;
};

static DEFINE_MUTEX(crash_swap_block_lock);
static DEFINE_XARRAY(page_xarray);

static int crash_swap_major;
static unsigned long swap_size;
static int in_use;

struct gendisk *crash_swap_disk;

static int crash_swap_append(phys_addr_t paddr, unsigned long size) {
	struct crash_swap_seg *seg;
	struct page *page;
	phys_addr_t offset_paddr;
	unsigned long i;
	char *mem;
	int ret;

	if (!IS_ALIGNED(paddr, PAGE_SIZE) || !IS_ALIGNED(size, PAGE_SIZE))
		return -EINVAL;

	mutex_lock(&crash_swap_block_lock);

	/* Try clean the reuse memory region first, make sure it's writable */
	page = alloc_page(GFP_KERNEL | __GFP_ZERO);
	if (!page)
		return -ENOMEM;

	mem = kmap_atomic(page);
	offset_paddr = paddr;
	while (offset_paddr < paddr + size) {
		ret = write_to_oldmem(mem, PAGE_SIZE, &offset_paddr, 0, 0);
		if (ret < 0 || ret != PAGE_SIZE) {
			pr_err("%llx - %llx contains non-writable memory.\n", paddr, paddr + size);
			kunmap_atomic(mem);
			__free_page(page);
			return -EINVAL;
		}
	}
	kunmap_atomic(mem);
	__free_page(page);

	/* Ensure no overlap with current index */
	xa_for_each(&page_xarray, i, seg) {
		if (seg->paddr <= paddr + size && seg->paddr + seg->size >= paddr) {
			pr_err("%llx - %llx overlaps with currently mapped regions.\n", paddr, paddr + size);
			mutex_unlock(&crash_swap_block_lock);
			return -EINVAL;
		}
	}

	/* Add to index */
	seg = kzalloc(sizeof(struct crash_swap_seg), GFP_KERNEL);
	seg->paddr = paddr;
	seg->start = swap_size;

	xa_store_range(&page_xarray, swap_size << PAGE_SHIFT, (swap_size + size) << PAGE_SHIFT,
			seg, GFP_KERNEL);

	swap_size += size;
	set_capacity(crash_swap_disk, swap_size >> SECTOR_SHIFT);
	revalidate_disk(crash_swap_disk);

	mutex_unlock(&crash_swap_block_lock);
	return 0;
}

/*
 * Process a single bvec of a bio.
 */
static int crash_swap_do_bvec(struct page *page,
			unsigned int len, unsigned int off, unsigned int op,
			sector_t sector)
{
	void *mem;
	struct crash_swap_seg *seg;
	unsigned long pfn, offset;
	u64 paddr;
	unsigned int copy;
	int err = 0;

	mem = kmap_atomic(page);
	do {
		copy = min(len, PAGE_SIZE);
		pfn = sector >> PAGE_SECTORS_SHIFT;
		offset = (sector & (PAGE_SECTORS - 1)) << SECTOR_SHIFT;

		seg = xa_load(&page_xarray, pfn);
		paddr = seg->paddr + ((pfn  << PAGE_SHIFT) - seg->start) + offset;

		if (!op_is_write(op)) {
			read_from_oldmem(mem + off, copy, &paddr, 0, 0);
			flush_dcache_page(page);
		} else {
			flush_dcache_page(page);
			write_to_oldmem(mem + off, copy, &paddr, 0, 0);
		}

		off += copy;
		len -= copy;
	} while (len);

	kunmap_atomic(mem);

	return err;
}

static blk_qc_t crash_swap_submit_bio(struct bio *bio)
{
	struct bio_vec bvec;
	sector_t sector;
	struct bvec_iter iter;

	sector = bio->bi_iter.bi_sector;
	if (bio_end_sector(bio) > get_capacity(bio->bi_disk))
		goto io_error;

	bio_for_each_segment(bvec, bio, iter) {
		unsigned int len = bvec.bv_len;
		int err;

		/* Don't support un-aligned buffer */
		WARN_ON_ONCE((bvec.bv_offset & (SECTOR_SIZE - 1)) ||
				(len & (SECTOR_SIZE - 1)));

		err = crash_swap_do_bvec(bvec.bv_page, len, bvec.bv_offset,
				  bio_op(bio), sector);

		if (err)
			goto io_error;
		sector += len >> SECTOR_SHIFT;
	}

	bio_endio(bio);
	return BLK_QC_T_NONE;

io_error:
	bio_io_error(bio);
	return BLK_QC_T_NONE;
}

static int crash_swap_rw_page(struct block_device *bdev, sector_t sector,
		       struct page *page, unsigned int op)
{
	int err;

	if (PageTransHuge(page))
		return -ENOTSUPP;
	err = crash_swap_do_bvec(page, PAGE_SIZE, 0, op, sector);
	page_endio(page, op_is_write(op), err);
	return err;
}

static int crash_swap_open(struct block_device *bdev, fmode_t mode)
{
	int ret = 0;

	if (in_use)
		ret = -EBUSY;

	return ret;
}

static const struct block_device_operations crash_swap_devops = {
	.open = crash_swap_open,
	.owner = THIS_MODULE,
	.submit_bio = crash_swap_submit_bio,
	.rw_page = crash_swap_rw_page,
};

static ssize_t segments_show(struct class *class,
			     struct class_attribute *attr,
			     char *buf)
{
	return scnprintf(buf, PAGE_SIZE, "%d\n", 0);
}
static CLASS_ATTR_RO(segments);

static ssize_t append_store(struct class *class, struct class_attribute *attr, const char *buf, size_t count)
{
	unsigned long long paddr;
	unsigned long size;
	char *addr_arg;
	int ret;

	size = memparse(buf, &addr_arg);
	if (addr_arg == buf)
		return -EINVAL;

	if (*addr_arg == '@') {
		ret = kstrtoull(++addr_arg, 0, &paddr);
		if (ret)
			return ret;
	} else {
		return -EINVAL;
	}

	ret = crash_swap_append(paddr, size);
	if (ret < 0)
		return ret;

	return count;
}
static CLASS_ATTR_WO(append);

static struct attribute *crash_swap_control_class_attrs[] = {
	&class_attr_segments.attr,
	&class_attr_append.attr,
	NULL,
};
ATTRIBUTE_GROUPS(crash_swap_control_class);

static struct class crash_swap_control_class = {
	.name		= "crash-swap-control",
	.owner		= THIS_MODULE,
	.class_groups	= crash_swap_control_class_groups,
};

static int __init crash_swap_init(void)
{
	int ret;
	struct request_queue *queue;

	if (!is_kdump_kernel())
		return -ENODEV;

	ret = class_register(&crash_swap_control_class);
	crash_swap_major = register_blkdev(0, "crash-swap");
	if (crash_swap_major <= 0) {
		pr_err("Unable to get major number\n");
		class_unregister(&crash_swap_control_class);
		return -EBUSY;
	}

	/* Only one disk supported */
	queue = blk_alloc_queue(NUMA_NO_NODE);
	if (!queue) {
		pr_err("Error allocating disk queue for crash swap\n");
		ret = -ENOMEM;
		goto out_free_queue;
	}

	/* gendisk structure */
	crash_swap_disk = alloc_disk(1);
	if (!crash_swap_disk) {
		pr_err("Error allocating disk structure for crash swap\n");
		ret = -ENOMEM;
		goto out_free_queue;
	}

	crash_swap_disk->major = crash_swap_major;
	crash_swap_disk->first_minor = 0;
	crash_swap_disk->fops = &crash_swap_devops;
	crash_swap_disk->queue = queue;
	snprintf(crash_swap_disk->disk_name, 16, "crash-swap");

	/* Actual capacity is updated dynamically */
	set_capacity(crash_swap_disk, 0);

	/* It's non-rotational disks */
	blk_queue_flag_set(QUEUE_FLAG_NONROT, crash_swap_disk->queue);
	blk_queue_flag_clear(QUEUE_FLAG_ADD_RANDOM, crash_swap_disk->queue);

	/*
	 * To ensure that we always get PAGE_SIZE aligned
	 * and n*PAGE_SIZED sized I/O requests.
	 */
	blk_queue_physical_block_size(crash_swap_disk->queue, PAGE_SIZE);
	blk_queue_logical_block_size(crash_swap_disk->queue, PAGE_SIZE);
	blk_queue_io_min(crash_swap_disk->queue, PAGE_SIZE);
	blk_queue_io_opt(crash_swap_disk->queue, PAGE_SIZE);
	queue->backing_dev_info->capabilities |= BDI_CAP_SYNCHRONOUS_IO;

	add_disk(crash_swap_disk);

	pr_info("Crash swap started\n");
	return 0;

out_free_queue:
	blk_cleanup_queue(queue);
	unregister_blkdev(crash_swap_major, "crash-swap");
	pr_err("crash_swap failed to load\n");
	return -ENOMEM;
}

static void __exit crash_swap_exit(void)
{
	pr_info("crash_swap: module unloaded\n");
}

MODULE_LICENSE("GPL");
MODULE_ALIAS("crash_swap");

module_init(crash_swap_init);
module_exit(crash_swap_exit);
