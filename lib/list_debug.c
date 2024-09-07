/*
 * Copyright 2006, Red Hat, Inc., Dave Jones
 * Released under the General Public License (GPL).
 *
 * This file contains the linked list validation for DEBUG_LIST.
 */

#include <linux/export.h>
#include <linux/list.h>
#include <linux/bug.h>
#include <linux/kernel.h>
#include <linux/rculist.h>

/*
 * Check that the data structures for the list manipulations are reasonably
 * valid. Failures here indicate memory corruption (and possibly an exploit
 * attempt).
 */

bool __list_add_valid(struct list_head *new, struct list_head *prev,
		      struct list_head *next)
{
	CHECK_DATA_CORRUPTION(prev == NULL || next == NULL || \
			      next->prev != prev || prev->next != next || \
			      new == prev || new == next,
			      "list_corruption\n");

	return true;
}
EXPORT_SYMBOL(__list_add_valid);

bool __list_del_entry_valid(struct list_head *entry)
{
	struct list_head *prev, *next;

	prev = entry->prev;
	next = entry->next;

	CHECK_DATA_CORRUPTION(next == NULL || prev == NULL || \
			      next == LIST_POISON1 || prev == LIST_POISON2 || \
			      prev->next != entry || next->prev != entry,
			      "list_corruption\n");

	return true;
}
EXPORT_SYMBOL(__list_del_entry_valid);
