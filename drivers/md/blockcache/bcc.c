#include <linux/init.h>
#include <linux/module.h>
#include <linux/sysfs.h>
#include <linux/kobject.h>
#include <linux/bcc.h>
#include <linux/bitmap.h>
#include <linux/device.h>
#include <linux/bootmem.h> // bitmap


/* 
 * init & exit function for the device driver
 */

static int __init bcc_driver_init(void);
static void __exit bcc_driver_exit(void);

#ifdef CONFIG_BLOCK_CACHE_MEMORY

struct submit_bio_ret {
    struct completion event;
    int error;
};

struct block_cache_entry bc_set[MAX_NUM_SECS];
struct block_cache_data bd_set[MAX_NUM_SECS];

#endif /* CONFIG_BLOCK_CACHE_MEMORY */


#ifdef CONFIG_BLOCK_CACHE_BITMAP

#define BITMAP_SHOW_REF_LEVEL 1

#if BITMAP_SHOW_REF_LEVEL == 1
struct bcc_bitmap bcc_bitmap;
#else
static DECLARE_BITMAP(bcc_bitmap, 300);
#endif

#endif /* CONFIG_BLOCK_CACHE_BITMAP */



#ifdef CONFIG_BLOCK_CACHE_MEMORY
/*
 * base setup for block cache
 */

int num_of_sector;

void store_sector_and_size(unsigned long target_sector, int size)
{
    //TODO : 맥스 값에 대한 예외처리 해줘야함
    bc_set[num_of_sector].sector = target_sector;
    bc_set[num_of_sector].size   = size;
    num_of_sector++;
}

void free_buffer(void)
{
    int i = 0;
    for(i=0;i<MAX_NUM_SECS;i++)
    {
        bc_set[i].sector=-1;
        bc_set[i].size=-1;
    }
    num_of_sector=0;
}

int load_bio(unsigned long target_sector, int target_size, void* data)
{
    struct bio bio;
    struct bio_vec bio_vec;
    struct page *page;

    printk("%s\n", __FUNCTION__);

    page = alloc_page(GFP_TEMPORARY);
    kmap(page);
    if (!page) {
        printk("failed: alloc page\n");
        goto error_page;
    }
    else
        printk("success: alloc page\n");

    bio_init(&bio);
    bio.bi_bdev = blkdev_get_by_path("/dev/sdc5", FMODE_READ | FMODE_WRITE, NULL);
    if(IS_ERR(bio.bi_bdev))
        printk("error: %lu\n", (unsigned long)PTR_ERR(bio.bi_bdev));
    else
        printk("success: finding bi_bdev\n");

    bio.bi_max_vecs = 1;

    // do things done in bio_add_page()
    bio.bi_io_vec = &bio_vec;
    bio_vec.bv_page = page;
    bio_vec.bv_len = target_size << 9;
    bio_vec.bv_offset = 0;
    bio.bi_vcnt = 1;

    // manual setting
    bio.bi_iter.bi_sector = target_sector - bio.bi_bdev->bd_part->start_sect;
    bio.bi_iter.bi_size = target_size << 9;

    submit_bio_wait(READ, &bio);

    printk("data in bio: %s\n", (char*)page_address(page) );

    if(!data)
        printk("error\n");
    else
        memcpy(data,page_address(page),4096);
    printk("data: %s\n", (char*)data );
    printk("pointer page : %lu data %lu\n", (unsigned long)page_address(page), (unsigned long) data);
    return 0;

error_page:
    __free_page(page);
    return -1;
}

#endif /* CONFIG_BLOCK_CACHE_MEMORY */



#ifdef CONFIG_BLOCK_CACHE_CONTROL /* CONFIG_BLOCK_CACHE_CONTROL */

struct kobject *kobj_ref;

/* 
 * Sysfs functions
 */

/**********/
/* insert */
/**********/
static ssize_t insert_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
    int i = 0;
    for (i = 0; i < num_of_sector; i++)
        printk("sectors = %lu size = %d\n", bc_set[i].sector, bc_set[i].size);
    return sprintf(buf, "end\n");
}


static ssize_t insert_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count)
{
    unsigned long target_sector;
    int size;
    sscanf(buf, "%lu %d", &target_sector, &size);
    store_sector_and_size(target_sector, size);
    return count;
}
static struct kobj_attribute bcc_insert_attr = __ATTR(insert, 0660, insert_show, insert_store);


/**********/
/* free */
/**********/
static ssize_t free_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
    return sprintf(buf, "Can't read this file\n");
}


static ssize_t free_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count)
{
    free_buffer();
    return count;
}
struct kobj_attribute bcc_free_attr = __ATTR(free, 0660,free_show, free_store);


/**********/
/* load */
/**********/
volatile int load_bio_flag;
static ssize_t load_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
    int i = 0;
    for (i = 0; i < num_of_sector; i++)
        printk("sectors = %lu size = %d data = %s\n", bc_set[i].sector, bc_set[i].size, bd_set[i].data);
    return sprintf(buf, "end\n");
}


static ssize_t load_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count)
{
    int i;
    load_bio_flag = 1;
    for (i = 0; i < num_of_sector; i++)
        load_bio(bc_set[i].sector, bc_set[i].size, bd_set[i].data);
    load_bio_flag = 0;
    return count;
}
struct kobj_attribute bcc_load_attr = __ATTR(load_buffer, 0660,load_show,load_store);


extern void submit_bio_wait_endio(struct bio *bio);
struct device *find_dev(const char *name);


#endif /* CONFIG_BLOCK_CACHE_CONTROL  */


#ifdef CONFIG_BLOCK_CACHE_BITMAP
/* bitmap */

static ssize_t bitmap_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
    
#if BITMAP_SHOW_REF_LEVEL == 1
    printk("lev1. bcc_bitmap: 0x%lu\n", *(bcc_bitmap.bitmap));

#elif BITMAP_SHOW_REF_LEVEL == 2
    int nr_bitmap = sizeof(bcc_bitmap) / sizeof(bcc_bitmap[0]);

    printk("lev2. bcc_bitmap.bitmap[%d]: 0x", nr_bitmap);

    int i = 0;
    for (i = nr_bitmap - 1; nr_bitmap >= 0; nr_bitmap--)
        printk("%x", bcc_bitmap.bitmap[i]);
    printk("\n");
#endif
    
    return 0;
}

static ssize_t bitmap_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count)
{
    /* extern void bitmap_set(unsigned long *map, unsigned int start, int len); */
    int i = 0, pos = 0, size = 0;
    sscanf(buf, "%d %d %d", &i,  &pos, &size);

#if BITMAP_SHOW_REF_LEVEL == 1
    bitmap_set(bcc_bitmap.bitmap, pos, size);
#else
    bitmap_set(&(bcc_bitmap.bitmap[i]), pos, size);
#endif

    return 0;
}

#define BITMAP_GRANUL_SECT_NR 8
static int bitmap_init(void)
{
    struct block_device* device = blkdev_get_by_path("/dev/sdc5", FMODE_READ | FMODE_WRITE, NULL);
    // unsigned long start = device->bd_part->start_sect;
    unsigned long nr_sects = device->bd_part->nr_sects;
    // unsigned long size = nr_sects / BITMAP_GRANUL_SECT_NR;
    unsigned long size = 120;

    unsigned long bitmap_size = BITS_TO_LONGS(size);
    printk("bcc_bitmap: allocator bitmap size is 0x%x bytes\n", bitmap_size);

    bcc_bitmap.bitmap_from_slab = slab_is_available();
    if (bcc_bitmap.bitmap_from_slab)
        // bcc_bitmap.bitmap = kzalloc(bitmap_size, GFP_KERNEL);
        bcc_bitmap.bitmap = kzalloc(BITS_TO_LONGS(size), GFP_KERNEL);
    else {
        bcc_bitmap.bitmap = memblock_virt_alloc(bitmap_size, 0);
        /* the bitmap won't be freed from memblock allocator */
        kmemleak_not_leak(bcc_bitmap.bitmap);
    }

    if (!bcc_bitmap.bitmap) {
        printk("bcc_bitmap: ENOMEM allocating allocator bitmap!\n");
        return -ENOMEM;
    }

    /* We zalloc'ed the bitmap, so all irqs are free by default */
    spin_lock_init(&bcc_bitmap.lock);
    // bcc_bitmap.of_node = of_node_get(of_node);
    // bcc_bitmap.irq_count = irq_count;

    return 0;
}

#if 0
static unsigned long bitmap_cal_pos(unsigned long sector_addr, unsigned long base_unit_size)
{
    return sector_addr / base_unit_size;
}
#endif

struct kobj_attribute bcc_bitmap_attr = __ATTR(bitmap, 0660,bitmap_show,bitmap_store); 


#endif /* CONFIG_BLOCK_CACHE_BITMAP */



static int __init bcc_driver_init(void)
{
    int ret = 0;

#ifdef CONFIG_BLOCK_CACHE_CONTROL
    /*Creating a directory in /sys/kernel/ */
    kobj_ref = kobject_create_and_add("bcc",kernel_kobj);

    if(sysfs_create_file(kobj_ref,&bcc_insert_attr.attr)){
        printk("Cannot create sysfs file......\n");
        goto r_sysfs;
    }
    if(sysfs_create_file(kobj_ref,&bcc_free_attr.attr)){
        printk("Cannot create sysfs file......\n");
        goto r_sysfs;
    }
    if(sysfs_create_file(kobj_ref,&bcc_load_attr.attr)){
        printk("Cannot create sysfs file......\n");
        goto r_sysfs;
    }
#endif

#ifdef CONFIG_BLOCK_CACHE_BITMAP
    if(sysfs_create_file(kobj_ref,&bcc_bitmap_attr.attr)){
        printk("Cannot create sysfs file.....\n");
        goto r_sysfs;
    }
    ret = bitmap_init();
    if(ret)
        printk("Bit Map Error\n");
#endif
    printk( "Device Driver Insert...Done!!!\n");
    printk( "BITMAP_SHOW_REF_LEVEL == %d\n", BITMAP_SHOW_REF_LEVEL);
    return 0;

r_sysfs:
#ifdef CONFIG_BLOCK_CACHE_CONTROL
    kobject_put(kobj_ref);
    sysfs_remove_file(kernel_kobj, &bcc_insert_attr.attr);
    sysfs_remove_file(kernel_kobj, &bcc_free_attr.attr);
    sysfs_remove_file(kernel_kobj, &bcc_load_attr.attr);
#endif

#ifdef CONFIG_BLOCK_CACHE_BITMAP
    sysfs_remove_file(kernel_kobj, &bcc_bitmap_attr.attr);
#endif /* CONFIG_BLOCK_CACHE_BITMAP */

    return -1;
}

void __exit bcc_driver_exit(void)
{
#ifdef CONFIG_BLOCK_CACHE_CONTROL
    kobject_put(kobj_ref);
    sysfs_remove_file(kernel_kobj, &bcc_insert_attr.attr);
    sysfs_remove_file(kernel_kobj, &bcc_free_attr.attr);
    sysfs_remove_file(kernel_kobj, &bcc_load_attr.attr);
#endif

#ifdef CONFIG_BLOCK_CACHE_BITMAP    
    sysfs_remove_file(kernel_kobj, &bcc_bitmap_attr.attr);
#endif /* CONFIG_BLOCK_CACHE_BITMAP */

    printk( "Device Driver Remove...Done!!!\n");
}

module_init(bcc_driver_init);
module_exit(bcc_driver_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("DongDongJu <commisori28@gmail.com>");
MODULE_AUTHOR("Dongyun Shin <naxelsdy@gmail.com>");
MODULE_DESCRIPTION("Block Cache Controller");
MODULE_VERSION("0.2");
