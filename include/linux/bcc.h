#ifndef _BLOCK_CACHE_H
#define _BLOCK_CACHE_H

#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kdev_t.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/sysfs.h>
#include <linux/kobject.h>
#include <linux/blkdev.h>
#include <linux/blk_types.h>
#include <linux/bio.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/workqueue.h>
#include <linux/iocontext.h>
#include <linux/uaccess.h>


#ifdef CONFIG_BLOCK_CACHE_MEMORY

#define MAX_NUM_SECS    512

struct block_cache_entry {
	unsigned long sector;
	int size;
//    void* data;
	int start;
	int end;
};

struct block_cache_data {
	char data[4096];
};

#endif


#endif /* BLOCK_CACHE */
