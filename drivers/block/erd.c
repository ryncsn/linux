// SPDX-License-Identifier: GPL-2.0-only
/*
 * Ram backed block device driver for crash kernel
 *
 */

#define KMSG_COMPONENT "erd"
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
#include <linux/initrd.h>

#define PAGE_SECTORS_SHIFT	(PAGE_SHIFT - SECTOR_SHIFT)
#define PAGE_SECTORS		(1 << PAGE_SECTORS_SHIFT)

static DEFINE_MUTEX(erd_block_lock);
static int erd_major;

static char* initrd_mem;
static unsigned long erd_size;

struct gendisk *erd_disk;

/*
 * Process a single bvec of a bio.
 */
static int erd_do_bvec(struct page *page,
			unsigned int len, unsigned int off, unsigned int op,
			sector_t sector)
{
	void *mem;
	unsigned long offset;
	offset = sector << SECTOR_SHIFT;

	BUG_ON(offset > erd_size);

	mem = kmap_atomic(page);
	if (!op_is_write(op)) {
		memcpy(mem + off, initrd_mem + offset, len);
	} else {
		memcpy(initrd_mem + offset, mem + off, len);
	}
	kunmap_atomic(mem);

	return 0;
}

static blk_qc_t erd_submit_bio(struct bio *bio)
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

		err = erd_do_bvec(bvec.bv_page, len, bvec.bv_offset,
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

static int erd_rw_page(struct block_device *bdev, sector_t sector,
		       struct page *page, unsigned int op)
{
	int err;

	if (PageTransHuge(page))
		return -ENOTSUPP;
	err = erd_do_bvec(page, PAGE_SIZE, 0, op, sector);
	page_endio(page, op_is_write(op), err);
	return err;
}

static const struct block_device_operations erd_devops = {
	.owner = THIS_MODULE,
	.submit_bio = erd_submit_bio,
	.rw_page = erd_rw_page,
};

static int __init erd_init(void)
{
	int ret;
	struct request_queue *queue;

	erd_major = register_blkdev(0, "crash-swap");
	if (erd_major <= 0) {
		pr_err("Unable to get major number\n");
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
	erd_disk = alloc_disk(1);
	if (!erd_disk) {
		pr_err("Error allocating disk structure for crash swap\n");
		ret = -ENOMEM;
		goto out_free_queue;
	}

	erd_disk->major = erd_major;
	erd_disk->first_minor = 0;
	erd_disk->fops = &erd_devops;
	erd_disk->queue = queue;
	snprintf(erd_disk->disk_name, 16, "erd");

	/* It's non-rotational disks */
	blk_queue_flag_set(QUEUE_FLAG_NONROT, erd_disk->queue);
	blk_queue_flag_clear(QUEUE_FLAG_ADD_RANDOM, erd_disk->queue);

	/*
	 * To ensure that we always get PAGE_SIZE aligned
	 * and n*PAGE_SIZED sized I/O requests.
	 */
	blk_queue_physical_block_size(erd_disk->queue, PAGE_SIZE);
	blk_queue_logical_block_size(erd_disk->queue, PAGE_SIZE);
	blk_queue_io_min(erd_disk->queue, PAGE_SIZE);
	blk_queue_io_opt(erd_disk->queue, PAGE_SIZE);
	queue->backing_dev_info->capabilities |= BDI_CAP_SYNCHRONOUS_IO;

	add_disk(erd_disk);

	initrd_mem = initrd_start;
	erd_size = initrd_end - initrd_start;

	set_capacity(erd_disk, erd_size >> SECTOR_SHIFT);
	revalidate_disk(erd_disk);

	pr_info("Crash swap started\n");
	return 0;

out_free_queue:
	blk_cleanup_queue(queue);
	unregister_blkdev(erd_major, "erd");
	pr_err("erd failed to load\n");
	return -ENOMEM;
}

static void __exit erd_exit(void)
{
	pr_info("erd: module unloaded\n");
}

MODULE_LICENSE("GPL");
MODULE_ALIAS("erd");

module_init(erd_init);
module_exit(erd_exit);
