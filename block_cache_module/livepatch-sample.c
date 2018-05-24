/*
 * livepatch-sample.c - Kernel Live Patching Sample Module
 *
 * Copyright (C) 2014 Seth Jennings <sjenning@redhat.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/livepatch.h>
#include "blk.h"

/*
 * This (dumb) live patch overrides the function that prints the
 * kernel boot cmdline when /proc/cmdline is read.
 *
 * Example:
 *
 * $ cat /proc/cmdline
 * <your cmdline>
 *
 * $ insmod livepatch-sample.ko
 * $ cat /proc/cmdline
 * this has been live patched
 *
 * $ echo 0 > /sys/kernel/livepatch/livepatch_sample/enabled
 * $ cat /proc/cmdline
 * <your cmdline>
 */

#include <linux/seq_file.h>
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
#include <linux/bitmap.h>
#include <linux/backing-dev.h>
#include <linux/blk-mq.h>
#include <linux/highmem.h>
#include <linux/mm.h>
#include <linux/kernel_stat.h>
#include <linux/string.h>
#include <linux/init.h>
#include <linux/completion.h>
#include <linux/slab.h>
#include <linux/swap.h>
#include <linux/writeback.h>
#include <linux/task_io_accounting_ops.h>
#include <linux/fault-inject.h>
#include <linux/list_sort.h>
#include <linux/delay.h>
#include <linux/ratelimit.h>
#include <linux/pm_runtime.h>
#include <linux/blk-cgroup.h>

#define CREATE_TRACE_POINTS
#include <trace/events/block.h>

#include "blk-mq.h"

#define MAX_NUM_SECS    2048
struct bc{
    unsigned long sector;
    int size;
    int start;
    int end;
};

struct block_data{
    char data[4096];
};

struct block_bitmap{
    DECLARE_BITMAP(bc_bitmap,6553600);
    unsigned int nbits;
};

struct bc           bc_set[MAX_NUM_SECS];
struct block_data   bd_set[MAX_NUM_SECS];
struct block_bitmap bb;
struct block_bitmap bb_status;

volatile int num_of_sector=0;
volatile int load_bio_flag=-1;
volatile int cur_bd_set_idx=0;


// for block record insert
static ssize_t insert_show(struct kobject *kobj, struct kobj_attribute *attr, const char *buf);
static ssize_t insert_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf,size_t count);
void store_sector_and_size(unsigned long target_sector,int size);

static ssize_t load_show(struct kobject *kobj, struct kobj_attribute *attr, const char *buf);
static ssize_t load_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf,size_t count);
int load_bio(unsigned long target_sector,int target_size,void* data);
int check_target(struct bio *bio,unsigned long sector,int size);
void hit_stored_data(struct bio *dst, int ret);

struct kobj_attribute insert_attr = __ATTR(insert,0644,insert_show,insert_store);
struct kobj_attribute load_attr   = __ATTR(load_bio,0644,load_show,load_store);

int check_target(struct bio *bio,unsigned long sector,int size)
{
    int i = 0;
    //for test
    if(!(bio->bi_bdev->bd_disk->disk_name[2] == 'c'))
        return -1;

    for(i=0;i<num_of_sector;i++)
    {
        if(bc_set[i].sector-(bio->bi_bdev->bd_part->start_sect) == sector && \
           (bc_set[i].size << 9) == size && \
           load_bio_flag != 1)
        {
            return i;
        }
    }
    return -1;
}
void hit_stored_data(struct bio *dst, int ret)
{
    int i = 0;
    if(bc_set[ret].size == 8) // 바꿔야함
        set_page_address(dst->bi_io_vec->bv_page,bd_set[bc_set[ret].start].data);
    else
    {
        int tmp = 0;
        for(i=bc_set[ret].start;i<=bc_set[ret].end;i++)
        {
            printk(KERN_ALERT"data : %s\n",bd_set[i].data);
            memcpy(page_address(dst->bi_io_vec[tmp++].bv_page),bd_set[i].data,4096);
        }

    }
}

int load_bio(unsigned long target_sector,int target_size,void* data)
{
    struct bio bio;
    struct bio_vec bio_vec;
    struct page *page; // bio page 갯수?어떻게 할건지

    // page allocation
    page = alloc_page(GFP_TEMPORARY);
    kmap(page);
    if(!page)
    {
        printk(KERN_ALERT"failed : alloc page\n");
        goto error_page;
    }
    else
        printk(KERN_ALERT"success: alloc page\n");

    // make custom bio
    bio_init(&bio);
    bio.bi_bdev = blkdev_get_by_path("/dev/sdc1", FMODE_READ | FMODE_WRITE, NULL);
    if(IS_ERR(bio.bi_bdev))
        printk(KERN_ALERT"error: %l\n", PTR_ERR(bio.bi_bdev));
    else
        printk(KERN_ALERT"success: finding bi_bdev\n");

    bio.bi_max_vecs = 1;

    // do things done in bio_add_page()
    bio.bi_io_vec = &bio_vec;
    bio_vec.bv_page = page;
    bio_vec.bv_len = 4096;
    bio_vec.bv_offset = 0;
    bio.bi_vcnt = 1;

    // manual setting
    bio.bi_iter.bi_sector = target_sector - bio.bi_bdev->bd_part->start_sect;
    bio.bi_iter.bi_size = target_size << 9;

    submit_bio_wait(READ, &bio);

    if(!data)
        printk("error\n");
    else
        memcpy(data,page_address(page),4096);

    printk(KERN_ALERT"original : %s\n",page_address(page));
    printk(KERN_ALERT"copied : %s\n",data);
    __free_page(page);

    return 0;
error_page:
    __free_page(page);
    return -1;
}
static ssize_t load_show(struct kobject *kobj, struct kobj_attribute *attr, const char *buf)
{
    int i = 0;
    for(i=0;i<num_of_sector;i++)
        printk(KERN_ALERT"sectors = %lu size = %d data = %s\n",bc_set[i].sector,bc_set[i].size,bd_set[i].data);
    return sprintf(buf, "end\n");
}

static ssize_t load_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf,size_t count)
{
    int i,j;
    load_bio_flag=1;
    for(i=0;i<num_of_sector;i++)
    {
        if(bc_set[i].size == 8)
        {
            bitmap_set(bb_status.bc_bitmap,bc_set[i].sector-2048,1);
            load_bio(bc_set[i].sector,bc_set[i].size,bd_set[bc_set[i].start].data);
            bitmap_set(bb.bc_bitmap,bc_set[i].sector-2048,1);
            bitmap_clear(bb_status.bc_bitmap,bc_set[i].sector-2048,1);
        }
        else
        {
            bitmap_set(bb_status.bc_bitmap,bc_set[i].sector-2048,bc_set[i].size >> 3);
            for(j=bc_set[i].start;j<=bc_set[i].end;j++){
                load_bio(bc_set[i].sector+(j<<3),8,bd_set[j].data);
            }
            bitmap_set(bb.bc_bitmap,bc_set[i].sector-2048,bc_set[i].size >> 3);
            bitmap_clear(bb_status.bc_bitmap,bc_set[i].sector-2048,bc_set[i].size >> 3);
        }
    }
    load_bio_flag=0;
    return count;
}
void store_sector_and_size(unsigned long target_sector,int size)
{
    bc_set[num_of_sector].sector = target_sector;
    bc_set[num_of_sector].size   = size;
    if(size == 8)
    {
        bc_set[num_of_sector].start = cur_bd_set_idx;
        bc_set[num_of_sector].end   = cur_bd_set_idx;
    }
    else
    {
        bc_set[num_of_sector].start = cur_bd_set_idx;
        cur_bd_set_idx += (size >> 3) - 1;
        bc_set[num_of_sector].end   = cur_bd_set_idx;
    }
    num_of_sector++;
    cur_bd_set_idx++;
}
static ssize_t insert_show(struct kobject *kobj, struct kobj_attribute *attr, const char *buf)
{
    int i = 0;
    for(i=0;i<num_of_sector;i++)
        printk(KERN_ALERT"sectors = %lu size = %d\n",bc_set[i].sector,bc_set[i].size);
    return sprintf(buf,"check dmesg\n");
}

static ssize_t insert_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf,size_t count)
{
    unsigned long target_sector;
    int size;
    sscanf(buf,"%lu %d",&target_sector,&size);
    store_sector_and_size(target_sector,size);
    return count;

}
static int livepatch_cmdline_proc_show(struct seq_file *m, void *v)
{
	seq_printf(m, "%s\n", "this has been live patched");
	return 0;
}
blk_qc_t generic_make_request_new(struct bio *bio)
{
    struct bio_list bio_list_on_stack[2];
    blk_qc_t ret = BLK_QC_T_NONE;
    int ret_bc;

    ret_bc = check_target(bio,bio->bi_iter.bi_sector,bio->bi_iter.bi_size);

    if (ret_bc != -1)
    {
        printk(KERN_ALERT"hit\n");
        hit_stored_data(bio,ret_bc);
        bio_set_flag(bio,3);
        bio_endio(bio);
        goto out;
    }
    if (!generic_make_request_checks(bio))
        goto out;
    if (current->bio_list) {
        bio_list_add(&current->bio_list[0], bio);
        goto out;
    }
    BUG_ON(bio->bi_next);
    bio_list_init(&bio_list_on_stack[0]);
    current->bio_list = bio_list_on_stack;
    do {
        struct request_queue *q = bdev_get_queue(bio->bi_bdev);

        if (likely(blk_queue_enter(q, __GFP_DIRECT_RECLAIM) == 0)) {
            struct bio_list lower, same;

            /* Create a fresh bio_list for all subordinate requests */
            bio_list_on_stack[1] = bio_list_on_stack[0];
            bio_list_init(&bio_list_on_stack[0]);

            ret = q->make_request_fn(q, bio);

            blk_queue_exit(q);
            /* sort new bios into those for a lower level
             * and those for the same level
             */
            bio_list_init(&lower);
            bio_list_init(&same);
            while ((bio = bio_list_pop(&bio_list_on_stack[0])) != NULL)
                if (q == bdev_get_queue(bio->bi_bdev))
                    bio_list_add(&same, bio);
                else
                    bio_list_add(&lower, bio);
            /* now assemble so we handle the lowest level first */
            bio_list_merge(&bio_list_on_stack[0], &lower);
            bio_list_merge(&bio_list_on_stack[0], &same);
            bio_list_merge(&bio_list_on_stack[0], &bio_list_on_stack[1]);
        } else {
            bio_io_error(bio);
        }
        bio = bio_list_pop(&bio_list_on_stack[0]);
    } while (bio);
    current->bio_list = NULL; /* deactivate */

out:
    return ret;
}

static struct klp_func funcs[] = {
	{
		.old_name = "generic_make_request",
		.new_func = generic_make_request_new,
	}, { }
};

static struct klp_object objs[] = {
	{
		/* name being NULL means vmlinux */
		.funcs = funcs,
	}, { }
};

static struct klp_patch patch = {
	.mod = THIS_MODULE,
	.objs = objs,
};

static int livepatch_init(void)
{
	int ret;

	ret = klp_register_patch(&patch);
	if (ret)
		return ret;
	ret = klp_enable_patch(&patch);
	if (ret) {
		WARN_ON(klp_unregister_patch(&patch));
		return ret;
	}
    if(sysfs_create_file(&(patch.kobj), &insert_attr.attr)){
        printk(KERN_ALERT"Cannot create sysfs file!\n");
        goto r_sysfs;
    }
    if(sysfs_create_file(&(patch.kobj), &load_attr.attr)){
        printk(KERN_ALERT"Cannot create sysfs file!\n");
        goto r_sysfs;
    }
	return 0;
r_sysfs:
    kobject_put(&(patch.kobj));
    sysfs_remove_file(&(patch.kobj), &insert_attr.attr);
    sysfs_remove_file(&(patch.kobj), &load_attr.attr);
    return -1;
}

static void livepatch_exit(void)
{
	WARN_ON(klp_disable_patch(&patch));
	WARN_ON(klp_unregister_patch(&patch));
}

module_init(livepatch_init);
module_exit(livepatch_exit);
MODULE_LICENSE("GPL");
