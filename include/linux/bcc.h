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


#define MAX_NUM_SECS    512
struct bc{
    unsigned long sector;
    int size;
//    void* data;
    int start;
    int end;
};

struct block_data{
    char data[4096];
};

struct bc_bitmap{

};
#endif /* BLOCK_CACHE */
