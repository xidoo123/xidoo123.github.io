# SLUB & Buddy System in Linux Kernel


CTF games have flourished in recent years. However, more GLIBC heap allocator exploit techiniques are becoming boring and meaningless, especially for games in China. Challenges are well-designed, deliberately constructed, leading to specific ways to solve them, which is actually further and further away from real world exploits. I started to aim more at Linux kernel memory allocator these days and gathered some imformation about Buddy System & SLUB hitherto.

<!--more-->

## Buddy System

Buddy allocation system is an algorithm in which a larger memory block is divided into small parts to satisfy the request. This algorithm is used to give best fit[1]. 

There are couple of types of Buddy allocation system

* Binary buddy system
* Fibonacci buddy system
* Weighted buddy system
* Tertiary buddy system

In Binary buddy system, memory is allocated and freed in PAGE_SIZE (e.g. 4K) using `order` to indicate size of chunks. Typically we have

> SIZE [of chunks of `order=n`] = 2^n * PAGE_SIZE

We note an example from wiki[2]. Suppose minimum size of chunk is 64K and maximum order of chunk is 4, and user tries to allocate memory of 34K.

![](https://i.loli.net/2021/08/24/snKzB3tw16vGMql.png)

This allocation could have occurred in the following manner

1. The initial situation.
2. Program A requests memory 34 K, order 0.
    1. No order 0 blocks are available, so an order 4 block is split, creating two order 3 blocks.
    2. Still no order 0 blocks available, so the first order 3 block is split, creating two order 2 blocks.
    3. Still no order 0 blocks available, so the first order 2 block is split, creating two order 1 blocks.
    4. Still no order 0 blocks available, so the first order 1 block is split, creating two order 0 blocks.
    5. Now an order 0 block is available, so it is allocated to A.
3. Program B requests memory 66 K, order 1. An order 1 block is available, so it is allocated to B.
4. Program C requests memory 35 K, order 0. An order 0 block is available, so it is allocated to C.
5. Program D requests memory 67 K, order 1.
    1. No order 1 blocks are available, so an order 2 block is split, creating two order 1 blocks.
    2. Now an order 1 block is available, so it is allocated to D.
6. Program B releases its memory, freeing one order 1 block.
7. Program D releases its memory.
    1. One order 1 block is freed.
    2. Since the buddy block of the newly freed block is also free, the two are merged into one order 2 block.
8. Program A releases its memory, freeing one order 0 block.
9. Program C releases its memory.
    1. One order 0 block is freed.
    2. Since the buddy block of the newly freed block is also free, the two are merged into one order 1 block.
    3. Since the buddy block of the newly formed order 1 block is also free, the two are merged into one order 2 block.
    4. Since the buddy block of the newly formed order 2 block is also free, the two are merged into one order 3 block.
    5. Since the buddy block of the newly formed order 3 block is also free, the two are merged into one order 4 block.

As you can see, what happens when a memory request is made is as follows:

* If memory is to be allocated
    1. Look for a memory slot of a suitable size (the minimal 2k block that is larger or equal to that of the requested memory)
        1. If it is found, it is allocated to the program
        2. If not, it tries to make a suitable memory slot. The system does so by trying the following:
            1. Split a free memory slot larger than the requested memory size into half
            2. If the lower limit is reached, then allocate that amount of memory
            3. Go back to step 1 (look for a memory slot of a suitable size)
            4. Repeat this process until a suitable memory slot is found
* If memory is to be freed
    1. Free the block of memory
    2. Look at the neighboring block – is it free too?
    3. If it is, combine the two, and go back to step 2 and repeat this process until either the upper limit is reached (all memory is freed), or until a non-free neighbour block is encountered

Linux complements buddy system mainly by `get_free_pages()` and `alloc_pages()`. Memory allocated is continuous and return address of memory can be converted to physical address using const `virts_to_phys()`

use `/proc/buddyinfo` and `/proc/pagetypeinfo` on your computer.

```
x1do0@x1do0:~/kernel_learning/khop$ sudo cat /proc/pagetypeinfo
Page block order: 9
Pages per block:  512

Free pages count per migrate type at order       0      1      2      3      4      5      6      7      8      9     1
Node    0, zone      DMA, type    Unmovable      0      0      0      1      1      1      1      0      1      0
Node    0, zone      DMA, type      Movable      0      0      0      0      0      0      0      0      0      1
Node    0, zone      DMA, type  Reclaimable      1      1      0      2      2      1      0      1      1      1
Node    0, zone      DMA, type   HighAtomic      0      0      0      0      0      0      0      0      0      0
Node    0, zone      DMA, type          CMA      0      0      0      0      0      0      0      0      0      0
Node    0, zone      DMA, type      Isolate      0      0      0      0      0      0      0      0      0      0
Node    0, zone    DMA32, type    Unmovable    433    336    227    257     77     26     15      1      3      0
Node    0, zone    DMA32, type      Movable  13282   9929   4863    441   6437   4340   1477    232     14     53
Node    0, zone    DMA32, type  Reclaimable    223    139     66    110     25      4      1      2      1      0
Node    0, zone    DMA32, type   HighAtomic      0      0      0      0      0      0      0      0      0      0
Node    0, zone    DMA32, type          CMA      0      0      0      0      0      0      0      0      0      0
Node    0, zone    DMA32, type      Isolate      0      0      0      0      0      0      0      0      0      0
Node    0, zone   Normal, type    Unmovable     83    151     92    121     41     13      4      3      3      0
Node    0, zone   Normal, type      Movable   2029   4852   3866   5212   5979   3642   1616    508    173     41     1
Node    0, zone   Normal, type  Reclaimable      2      9     27     20      4      0      0      1      1      1
Node    0, zone   Normal, type   HighAtomic      0      0      0      0      0      0      0      0      0      0
Node    0, zone   Normal, type          CMA      0      0      0      0      0      0      0      0      0      0
Node    0, zone   Normal, type      Isolate      0      0      0      0      0      0      0      0      0      0

Number of blocks type     Unmovable      Movable  Reclaimable   HighAtomic          CMA      Isolate
Node 0, zone      DMA            1            5            2            0            0            0
Node 0, zone    DMA32           91         1398           39            0            0            0
Node 0, zone   Normal          127         2088           89            0            0            0
```

## SLUB

### Bird's eye view

Most of the time, memory allocated by buddy system is too large for users. To go to a step further, slub allocator will continue to divide and allocate memory into pieces, just like heap chunks in GLIBC.  

Linux modified SLAB codes and come up with a more efficient mechanism, SLUB[3], intended for memory allocation of kernel objects. There are many structures in slub and I paste an execellent picture of framework here.

![](https://i.loli.net/2021/08/27/JKRCEhmqfXeTYZP.png)

A more brief version.

<img src="https://i.loli.net/2021/08/27/H34QF7hZCNfRSYi.png" style="zoom:150%;" />

`kmem_cache` is like `main_arena` in GLIBC, and every `kmem_cache` contains many `slab`, each of which is made up of one or more consecutive pages and there are many `object` of identical size in every pages, which are exposed to users.

Type `cat /proc/slabinfo` to see more info on your computer.

```
/ # cat /proc/slabinfo
slabinfo - version: 2.1
# name            <active_objs> <num_objs> <objsize> <objperslab> <pagesperslab> : tunables <limit> <batchcount> <sharedfactor> : slabdata <activ>
fsverity_info          0      0    248   16    1 : tunables    0    0    0 : slabdata      0      0      0
ip6-frags              0      0    184   22    1 : tunables    0    0    0 : slabdata      0      0      0
PINGv6                 0      0   1280   12    4 : tunables    0    0    0 : slabdata      0      0      0
RAWv6                 12     12   1280   12    4 : tunables    0    0    0 : slabdata      1      1      0
UDPv6                  0      0   1408   11    4 : tunables    0    0    0 : slabdata      0      0      0
tw_sock_TCPv6          0      0    248   16    1 : tunables    0    0    0 : slabdata      0      0      0
request_sock_TCPv6      0      0    304   13    1 : tunables    0    0    0 : slabdata      0      0      0
TCPv6                  0      0   2432   13    8 : tunables    0    0    0 : slabdata      0      0      0
kcopyd_job             0      0   3312    9    8 : tunables    0    0    0 : slabdata      0      0      0
dm_uevent              0      0   2632   12    8 : tunables    0    0    0 : slabdata      0      0      0
scsi_sense_cache      32     32    128   32    1 : tunables    0    0    0 : slabdata      1      1      0
mqueue_inode_cache      8      8   1024    8    2 : tunables    0    0    0 : slabdata      1      1      0
fuse_request           0      0    144   28    1 : tunables    0    0    0 : slabdata      0      0      0
fuse_inode             0      0    896    9    2 : tunables    0    0    0 : slabdata      0      0      0
ecryptfs_inode_cache      0      0   1024    8    2 : tunables    0    0    0 : slabdata      0      0      0
ecryptfs_file_cache      0      0     16  256    1 : tunables    0    0    0 : slabdata      0      0      0
ecryptfs_auth_tok_list_item      0      0    896    9    2 : tunables    0    0    0 : slabdata      0      0      0
fat_inode_cache        0      0    744   11    2 : tunables    0    0    0 : slabdata      0      0      0
fat_cache              0      0     40  102    1 : tunables    0    0    0 : slabdata      0      0      0
squashfs_inode_cache      0      0    768   10    2 : tunables    0    0    0 : slabdata      0      0      0
jbd2_journal_handle      0      0     48   85    1 : tunables    0    0    0 : slabdata      0      0      0
jbd2_journal_head      0      0    120   34    1 : tunables    0    0    0 : slabdata      0      0      0
jbd2_revoke_table_s      0      0     16  256    1 : tunables    0    0    0 : slabdata      0      0      0
ext4_inode_cache       0      0   1096   29    8 : tunables    0    0    0 : slabdata      0      0      0
ext4_allocation_context      0      0    128   32    1 : tunables    0    0    0 : slabdata      0      0      0
ext4_system_zone       0      0     40  102    1 : tunables    0    0    0 : slabdata      0      0      0
ext4_io_end            0      0     64   64    1 : tunables    0    0    0 : slabdata      0      0      0
ext4_pending_reservation      0      0     32  128    1 : tunables    0    0    0 : slabdata      0      0      0
ext4_extent_status      0      0     40  102    1 : tunables    0    0    0 : slabdata      0      0      0
mbcache                0      0     56   73    1 : tunables    0    0    0 : slabdata      0      0      0
userfaultfd_ctx_cache      0      0    256   16    1 : tunables    0    0    0 : slabdata      0      0      0
dnotify_struct         0      0     32  128    1 : tunables    0    0    0 : slabdata      0      0      0
pid_namespace          0      0    208   19    1 : tunables    0    0    0 : slabdata      0      0      0
ip4-frags              0      0    200   20    1 : tunables    0    0    0 : slabdata      0      0      0
xfrm_dst_cache         0      0    384   10    1 : tunables    0    0    0 : slabdata      0      0      0
xfrm_state             0      0    768   10    2 : tunables    0    0    0 : slabdata      0      0      0
PING                   8      8   1024    8    2 : tunables    0    0    0 : slabdata      1      1      0
RAW                    8      8   1024    8    2 : tunables    0    0    0 : slabdata      1      1      0
tw_sock_TCP            0      0    248   16    1 : tunables    0    0    0 : slabdata      0      0      0
request_sock_TCP       0      0    304   13    1 : tunables    0    0    0 : slabdata      0      0      0
TCP                    0      0   2304   14    8 : tunables    0    0    0 : slabdata      0      0      0
hugetlbfs_inode_cache     25     25    632   25    4 : tunables    0    0    0 : slabdata      1      1      0
dquot                  0      0    256   16    1 : tunables    0    0    0 : slabdata      0      0      0
eventpoll_pwq          0      0     72   56    1 : tunables    0    0    0 : slabdata      0      0      0
dax_cache             10     10    768   10    2 : tunables    0    0    0 : slabdata      1      1      0
request_queue         15     15   2104   15    8 : tunables    0    0    0 : slabdata      1      1      0
biovec-max            32     32   4096    8    8 : tunables    0    0    0 : slabdata      4      4      0
biovec-128             8      8   2048    8    4 : tunables    0    0    0 : slabdata      1      1      0
biovec-64              8      8   1024    8    2 : tunables    0    0    0 : slabdata      1      1      0
khugepaged_mm_slot      0      0    112   36    1 : tunables    0    0    0 : slabdata      0      0      0
user_namespace         0      0    536   15    2 : tunables    0    0    0 : slabdata      0      0      0
uid_cache             32     32    128   32    1 : tunables    0    0    0 : slabdata      1      1      0
dmaengine-unmap-256     15     15   2176   15    8 : tunables    0    0    0 : slabdata      1      1      0
dmaengine-unmap-128     14     14   1152   14    4 : tunables    0    0    0 : slabdata      1      1      0
sock_inode_cache      27     27    896    9    2 : tunables    0    0    0 : slabdata      3      3      0
skbuff_fclone_cache      8      8    512    8    1 : tunables    0    0    0 : slabdata      1      1      0
skbuff_head_cache     16     16    256   16    1 : tunables    0    0    0 : slabdata      1      1      0
file_lock_cache        0      0    216   18    1 : tunables    0    0    0 : slabdata      0      0      0
fsnotify_mark_connector    128    128     32  128    1 : tunables    0    0    0 : slabdata      1      1      0
net_namespace          0      0   4928    6    8 : tunables    0    0    0 : slabdata      0      0      0
task_delay_info      102    102     80   51    1 : tunables    0    0    0 : slabdata      2      2      0
taskstats              0      0    344   23    2 : tunables    0    0    0 : slabdata      0      0      0
proc_dir_entry       294    294    192   21    1 : tunables    0    0    0 : slabdata     14     14      0
pde_opener           102    102     40  102    1 : tunables    0    0    0 : slabdata      1      1      0
proc_inode_cache      72     72    680   12    2 : tunables    0    0    0 : slabdata      6      6      0
bdev_cache            19     19    832   19    4 : tunables    0    0    0 : slabdata      1      1      0
shmem_inode_cache    583    583    720   11    2 : tunables    0    0    0 : slabdata     53     53      0
kernfs_node_cache  14130  14130    136   30    1 : tunables    0    0    0 : slabdata    471    471      0
mnt_cache             36     36    320   12    1 : tunables    0    0    0 : slabdata      3      3      0
filp                  16     16    256   16    1 : tunables    0    0    0 : slabdata      1      1      0
inode_cache        11024  11024    608   13    2 : tunables    0    0    0 : slabdata    848    848      0
dentry             11676  11676    192   21    1 : tunables    0    0    0 : slabdata    556    556      0
names_cache            8      8   4096    8    8 : tunables    0    0    0 : slabdata      1      1      0
iint_cache             0      0    120   34    1 : tunables    0    0    0 : slabdata      0      0      0
lsm_file_cache       170    170     24  170    1 : tunables    0    0    0 : slabdata      1      1      0
buffer_head            0      0    104   39    1 : tunables    0    0    0 : slabdata      0      0      0
uts_namespace          0      0    440    9    1 : tunables    0    0    0 : slabdata      0      0      0
nsproxy               73     73     56   73    1 : tunables    0    0    0 : slabdata      1      1      0
vm_area_struct        57     57    208   19    1 : tunables    0    0    0 : slabdata      3      3      0
mm_struct             15     15   1088   15    4 : tunables    0    0    0 : slabdata      1      1      0
files_cache           11     11    704   11    2 : tunables    0    0    0 : slabdata      1      1      0
signal_cache          84     84   1152   14    4 : tunables    0    0    0 : slabdata      6      6      0
sighand_cache         60     60   2112   15    8 : tunables    0    0    0 : slabdata      4      4      0
task_struct           60     60   5632    5    8 : tunables    0    0    0 : slabdata     12     12      0
cred_jar              84     84    192   21    1 : tunables    0    0    0 : slabdata      4      4      0
anon_vma_chain        64     64     64   64    1 : tunables    0    0    0 : slabdata      1      1      0
anon_vma              46     46     88   46    1 : tunables    0    0    0 : slabdata      1      1      0
pid                   96     96    128   32    1 : tunables    0    0    0 : slabdata      3      3      0
Acpi-Operand         392    392     72   56    1 : tunables    0    0    0 : slabdata      7      7      0
Acpi-ParseExt         39     39    104   39    1 : tunables    0    0    0 : slabdata      1      1      0
Acpi-State            51     51     80   51    1 : tunables    0    0    0 : slabdata      1      1      0
numa_policy           15     15    264   15    1 : tunables    0    0    0 : slabdata      1      1      0
trace_event_file    1472   1472     88   46    1 : tunables    0    0    0 : slabdata     32     32      0
ftrace_event_field   3995   3995     48   85    1 : tunables    0    0    0 : slabdata     47     47      0
pool_workqueue        64     64    256   16    1 : tunables    0    0    0 : slabdata      4      4      0
radix_tree_node      336    336    584   14    2 : tunables    0    0    0 : slabdata     24     24      0
task_group            12     12    640   12    2 : tunables    0    0    0 : slabdata      1      1      0
vmap_area            192    192     64   64    1 : tunables    0    0    0 : slabdata      3      3      0
dma-kmalloc-8k         0      0   8192    4    8 : tunables    0    0    0 : slabdata      0      0      0
dma-kmalloc-4k         0      0   4096    8    8 : tunables    0    0    0 : slabdata      0      0      0
dma-kmalloc-2k         0      0   2048    8    4 : tunables    0    0    0 : slabdata      0      0      0
dma-kmalloc-1k         0      0   1024    8    2 : tunables    0    0    0 : slabdata      0      0      0
dma-kmalloc-512        8      8    512    8    1 : tunables    0    0    0 : slabdata      1      1      0
dma-kmalloc-256        0      0    256   16    1 : tunables    0    0    0 : slabdata      0      0      0
dma-kmalloc-128        0      0    128   32    1 : tunables    0    0    0 : slabdata      0      0      0
dma-kmalloc-64         0      0     64   64    1 : tunables    0    0    0 : slabdata      0      0      0
dma-kmalloc-32         0      0     32  128    1 : tunables    0    0    0 : slabdata      0      0      0
dma-kmalloc-16         0      0     16  256    1 : tunables    0    0    0 : slabdata      0      0      0
dma-kmalloc-8          0      0      8  512    1 : tunables    0    0    0 : slabdata      0      0      0
dma-kmalloc-192        0      0    192   21    1 : tunables    0    0    0 : slabdata      0      0      0
dma-kmalloc-96         0      0     96   42    1 : tunables    0    0    0 : slabdata      0      0      0
kmalloc-rcl-8k         0      0   8192    4    8 : tunables    0    0    0 : slabdata      0      0      0
kmalloc-rcl-4k         0      0   4096    8    8 : tunables    0    0    0 : slabdata      0      0      0
kmalloc-rcl-2k         0      0   2048    8    4 : tunables    0    0    0 : slabdata      0      0      0
kmalloc-rcl-1k         0      0   1024    8    2 : tunables    0    0    0 : slabdata      0      0      0
kmalloc-rcl-512        0      0    512    8    1 : tunables    0    0    0 : slabdata      0      0      0
kmalloc-rcl-256        0      0    256   16    1 : tunables    0    0    0 : slabdata      0      0      0
kmalloc-rcl-192        0      0    192   21    1 : tunables    0    0    0 : slabdata      0      0      0
kmalloc-rcl-128        0      0    128   32    1 : tunables    0    0    0 : slabdata      0      0      0
kmalloc-rcl-96         0      0     96   42    1 : tunables    0    0    0 : slabdata      0      0      0
kmalloc-rcl-64        64     64     64   64    1 : tunables    0    0    0 : slabdata      1      1      0
kmalloc-rcl-32         0      0     32  128    1 : tunables    0    0    0 : slabdata      0      0      0
kmalloc-rcl-16         0      0     16  256    1 : tunables    0    0    0 : slabdata      0      0      0
kmalloc-rcl-8          0      0      8  512    1 : tunables    0    0    0 : slabdata      0      0      0
kmalloc-8k            12     12   8192    4    8 : tunables    0    0    0 : slabdata      3      3      0
kmalloc-4k            32     32   4096    8    8 : tunables    0    0    0 : slabdata      4      4      0
kmalloc-2k           176    176   2048    8    4 : tunables    0    0    0 : slabdata     22     22      0
kmalloc-1k           416    416   1024    8    2 : tunables    0    0    0 : slabdata     52     52      0
kmalloc-512          320    320    512    8    1 : tunables    0    0    0 : slabdata     40     40      0
kmalloc-256          512    512    256   16    1 : tunables    0    0    0 : slabdata     32     32      0
kmalloc-192          420    420    192   21    1 : tunables    0    0    0 : slabdata     20     20      0
kmalloc-128          384    384    128   32    1 : tunables    0    0    0 : slabdata     12     12      0
kmalloc-96           714    714     96   42    1 : tunables    0    0    0 : slabdata     17     17      0
kmalloc-64          2624   2624     64   64    1 : tunables    0    0    0 : slabdata     41     41      0
kmalloc-32          3328   3328     32  128    1 : tunables    0    0    0 : slabdata     26     26      0
kmalloc-16          1536   1536     16  256    1 : tunables    0    0    0 : slabdata      6      6      0
kmalloc-8           2048   2048      8  512    1 : tunables    0    0    0 : slabdata      4      4      0
kmem_cache_node      192    192     64   64    1 : tunables    0    0    0 : slabdata      3      3      0
kmem_cache           144    144    448    9    1 : tunables    0    0    0 : slabdata     16     16      0
```

The instruction lists all of the current `kmem_cache`, taking `kmalloc-64` for example

* name: name of this `kmem_cache`
* active_objs: amount of objects being allocated, which is 2624
* num_objs: max number of objects users can allocate, which is 2624
* objsize: size of each object, which is 64 bytes.
* objperslab: max amount of objects per slab, which is 64
* pagesperslab: numbers of pages per slab, which is 1 here

So we can see that, in `kmalloc-64` if we allocate `n` objects.

1. if n>64, more than one slabs are needed.
2. if n>2624, buddy system will allocate a new slab in this `kmeme_cache`.

### APIs

There are some important APIs for users.

1. create a `kmem_cache` with specific size and name.

```c
struct kmem_cache * kmem_cache_create (	const char *name,
 	size_t  	size,
 	size_t  	align,
 	unsigned long  	flags,
 	void (*ctor(void*, struct kmem_cache *, unsigned long),
 	void (*dtor(void*, struct kmem_cache *, unsigned long));
```

2. create a `object` in specific `kmem_cache`

```c
void * kmem_cache_alloc (struct kmem_cache * cachep, gfp_t flags);
```

3. free a specific `object` in specific `kmem_cache`

```c
void kmem_cache_free (struct kmem_cache * cachep, void * objp);
```

4. allocate a `object` in `kmalloc-***`. Kernel will find a best matched `kmem_cache`, and if sizes required are more than the biggest size of them (8K), buddy system will help to allocator the memory directly. 

```c
void * kmalloc (size_t size, gfp_t flags);
```

5. free a `object`. Kernel will find the page of the object, read out pointer of the object and copy to a `freelist`, with `fd` pointer points to next freed `object`, same as `tcache` in GLIBC.

```c
void kfree (const void * objp);
```

### Details

Let's go deep into `kmalloc-***`. As you can see, the smallest is  `kmalloc-8` and the largest is `kmalloc-8k` with size of 2^3 to 2^13 bytes. In older kernel version, max size is 2^11 bytes. Details are in the following picture. 

![](https://i.loli.net/2021/08/27/wHduGFAIfjpoJLP.jpg)

`kmem_cache_cpu` is like a supermarket

* `freelist` is the header of freed object lists
* `page` is the header of allocated object lists 

And `kmem_cache_node` is the depository.

* `partial` points to partially allocated slub lists.
* `full` points to fully allocated slub lists.

We will go through it step by step together. 

#### Allocating process

1. `kmem_cache_node` and `kmem_cache_cpu` contain no slub.

2. After an allocation request, buddy system allocates a large chunk of memory, divides it into pieces, returns one piece to users. Now `kmem_cache_cpu` has a slub ready to use with `freelist` and `page` point to correct places.

![](https://i.loli.net/2021/08/27/qEvnH7gifNFXhRb.jpg)

3. Users continue to require allocation

![](https://i.loli.net/2021/08/27/sI51QKd9zObtyWG.jpg)

4. After slab of `kmem_cache_cpu` is filled with objects, the next allocation will trigger a swtich, putting the previous full slab into the `full` lists of `kmem_cache_node` and one not full slab from `partial` lists to `kmem_cache_cpu`, and then return a object to users.

![](https://i.loli.net/2021/08/27/amTwIj4x13oyKpl.jpg)

![](https://i.loli.net/2021/08/27/5zOdDJv1cSmGgRL.jpg)

![](https://i.loli.net/2021/08/27/q4KRAT7oiwdIjae.jpg)


5. And finally, all slabs are full. Buddy system stands out again and gives us a brand new empty slab. 

![](https://i.loli.net/2021/08/27/ybaSTqXkJNPn9Cl.jpg)

![](https://i.loli.net/2021/08/27/mH65vSYrbDlXZng.jpg)

![](https://i.loli.net/2021/08/27/RXAV9HQdKhsvOZr.jpg)

Now you may want to ask, how can a slab be added into `partial` lists? Well, follow me with the process of freeing these objects.

#### Freeing process

Depending on where the object to be free is, there are some kinds of situation.

1. In `kmem_cache_cpu`, Kernel will put it from `page` list to `freelist` list.

2. In not full slab of `partial` list in `kmem_cache_node`, mark the object freed.

![](https://i.loli.net/2021/08/27/gRC1iN5Pn4QVU8O.jpg)

![](https://i.loli.net/2021/08/27/Gp6qtU5Slry1bQ7.jpg)

3. In full slab of `full` list, free it and put the slab into `partial` list. 

![](https://i.loli.net/2021/08/27/csqlf4NFOwezLHb.jpg)

![](https://i.loli.net/2021/08/27/LjKs5At3PYqiyDl.jpg)

What's more, if a slub is entirely empty, the whole slab will be freed.

![](https://i.loli.net/2021/08/27/v4MjQCFHBoqfNl8.jpg)

![](https://i.loli.net/2021/08/27/RhxaOC25TAos1Jy.jpg)

![](https://i.loli.net/2021/08/27/nhIMfAgFZbDaH39.png)


### exploits

If there is a use-after-free slab vulnerability in kernel mode, modifying `fd` to attack `mprobe_path` may be an easy way to exploit.

If there is an overflow vulnerability in slab structure, the first thing is to allocate lots of objects to make later objects we allocate continuous. By overwriting the content of next ojbect, we can achieve our goal. For example, use  `fork` to arrange `cred` structure of child process to the nexe object and zero it out by overflowing the previous object. In [5], author uses `shmid_kernel` structure to get root privilege.

# Ref

[1] https://www.geeksforgeeks.org/operating-system-allocating-kernel-memory-buddy-system-slab-system/

[2] https://en.wikipedia.org/wiki/Buddy_memory_allocation

[3] https://en.wikipedia.org/wiki/SLUB_(software)

[4] https://blog.csdn.net/lukuen/article/details/6935068

[5] https://www.cnblogs.com/bittorrent/p/3266308.html


