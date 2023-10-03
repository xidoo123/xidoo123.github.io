# Linux Kernel Mitigation & Bypass


Like user mode, there are also couples of ways of mitigation against exploits in Linux kernel. Here is a list of mitigation in kernel mode and methods to bypass some of them. 

<!--more-->

## 0x00 CANARY

Same as user mode, lying at rbp-8 (or ebp-4 in 32 bits machine)

## 0x01 KASLR

Same as ASLR in user mode, adding random and varied PAGE SIZE to kernel and module loading address when booted.

## 0x02 FG_KASLR

Quite new techniques patched to strengthen KASLR, provides an address randomization at Function Granular rather than module granular at KASLR, which means even offset of the function would vary from time to time.

Two way to bypass it

1. Kernel symbols are not affected by FG_KASLR, so we can compute the actual address of functions.

e.g. Address of `commit_creds` = Address of `ksymtab_commit_creds` + `value_offset` of it

```c
struct kernel_symbol {
	  int value_offset;
	  int name_offset;
	  int namespace_offset;
};
```

2. `modprobe_path` and `swapgs_restore_regs_and_return_to_usermode` are unaffected by FG_KASLR

More details about exploits using modprobe_path were mentioned in the previous article [1] and [2]

## 0x03 SMEP

User mode codes are not permmited to execute in kernel mode (ring 0). Typically Return-to-user will no longer work out because of it. But we can still find gadgets to do Return-Oriented-Programming in kernel mode.

## 0x04 SMAP

User mode data should be unaccessible in kernel mode. 

```bash
x1do0@x1do0:~$ cat /proc/cpuinfo | grep smep | grep smap
flags           : fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush mmx fxsr sse sse2 syscall nx mmxext fxsr_opt pdpe1gb rdtscp lm constant_tsc rep_good nopl tsc_reliable nonstop_tsc cpuid extd_apicid pni pclmulqdq ssse3 fma cx16 sse4_1 sse4_2 x2apic movbe popcnt aes xsave avx f16c rdrand hypervisor lahf_lm extapic cr8_legacy abm sse4a misalignsse 3dnowprefetch osvw topoext ssbd ibpb vmmcall fsgsbase bmi1 avx2 smep bmi2 erms invpcid rdseed adx smap clflushopt clwb sha_ni xsaveopt xsavec xgetbv1 xsaves clzero wbnoinvd arat umip pku ospke vaes vpclmulqdq rdpid overflow_recov succor
```

Along with SMEP, there are several ways to bypass them

1. Use kernel gadgets to do ROP

2. tamper CR4 register. By zero out high bits of CR4, we can disable kernel SMEP and SMAP mitigation.

![](https://i.loli.net/2021/08/24/LFq6NIV2ntmrYiU.png)

3. ret-to-direct-mapped memory (short as ret2dir). Ideas come from [3]. Memory users maped will be identically copied into `physmap`, see [4] for more about ram layout. So when SMAP and SMEP are enabled, we can actually jump to our codes in `physmap` to execute user mode codes. More details are in the original thesis and [5].

![](https://i.loli.net/2021/08/24/G751WSjRoB68AdN.png)

4. overwrite vdso (Virtual Dynamic Shared Object). vDSO is a chunk of memory used for making glibc and kernel compatible[6]. Typically, vDSO is r/w in kernel mode and r/x in user mode. So if we can modify vDSO to our shellcode in kernel mode and trigger codes in vDSO in user mode (basically `gettimeofday()` will automatically do this), we can execute codes in root privilege. If vDSO is not permitted to write, we can use `set_memory_rw()` to set area authority flag. More details in [7] and [8].

## 0x05 mmap_min_addr 

`mmap_min_addr` is a system value set to constrain the minimum address users can mmap to. This restriction prevents kernel from null pointer dereferences.

```bash
x1do0@x1do0:~$ cat /proc/sys/vm/mmap_min_addr
65536
```

## 0x06 KPTI

Used to separate user page table and kernel page table, which means not only cs, ss regiseters should be set properly when return to user mode from ring 0, but also gs register. `swapgs` should be executed before `iret`.

```
*RAX  0x1001
*RBX  0x1614000 ◂— 0
*RCX  0x1614000 ◂— 0
*RDX  0x1615000
*RDI  0x705820 ◂— 0
*RSI  0x1615000
*R8   0x0
*R9   0x0
*R10  0x0
*R11  0x297
*R12  0x1613ff0 ◂— 0x540
*R13  0x1
 R14  0x0
*R15  0x1
*RBP  0x1614000 ◂— 0
*RSP  0xfffffe0000002fd8 —▸ 0x400eea ◂— mov    qword ptr [rdx - 0x10], rax
*RIP  0xffffffff81c00aaf ◂— swapgs
────────────────────────────────────────────────────────────────────[ DISASM ]────────────────────────────────────────────────────────────────────
 ► 0xffffffff81c00aaf    swapgs
   0xffffffff81c00ab2    nop    dword ptr [rax]
   0xffffffff81c00ab5    jmp    0xffffffff81c00ae0 <0xffffffff81c00ae0>
    ↓
   0xffffffff81c00ae0    test   byte ptr [rsp + 0x20], 4
   0xffffffff81c00ae5    jne    0xffffffff81c00ae9 <0xffffffff81c00ae9>

   0xffffffff81c00ae7    iretq
   0xffffffff81c00ae9    push   rdi
   0xffffffff81c00aea    swapgs
   0xffffffff81c00aed    nop    dword ptr [rax]
   0xffffffff81c00af0    nop
   0xffffffff81c00af2    mov    rdi, cr3
────────────────────────────────────────────────────────────────────[ STACK ]─────────────────────────────────────────────────────────────────────
00:0000│ rsp 0xfffffe0000002fd8 —▸ 0x400eea ◂— mov    qword ptr [rdx - 0x10], rax
01:0008│     0xfffffe0000002fe0 ◂— 0x33 /* '3' */
02:0010│     0xfffffe0000002fe8 ◂— 0x202
03:0018│     0xfffffe0000002ff0 —▸ 0x7fffd2abf100 ◂— 0x20 /* ' ' */
04:0020│     0xfffffe0000002ff8 ◂— 0x2b /* '+' */
05:0028│     0xfffffe0000003000 ◂— add    byte ptr [rax], al
06:0030│     0xfffffe0000003008 ◂— add    dh, bh
07:0038│     0xfffffe0000003010 ◂— add    cl, cl
──────────────────────────────────────────────────────────────────[ BACKTRACE ]───────────────────────────────────────────────────────────────────
 ► f 0 0xffffffff81c00aaf
   f 1         0x400eea
   f 2             0x33
   f 3            0x202
   f 4   0x7fffd2abf100
   f 5             0x2b
   f 6   0x300000000000
   f 7 0x1ac000fffffe00
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
pwndbg> info registers
rax            0x1001              4097
rbx            0x1614000           23150592
rcx            0x1614000           23150592
rdx            0x1615000           23154688
rsi            0x1615000           23154688
rdi            0x705820            7362592
rbp            0x1614000           0x1614000
rsp            0xfffffe0000002fd8  0xfffffe0000002fd8
r8             0x0                 0
r9             0x0                 0
r10            0x0                 0
r11            0x297               663
r12            0x1613ff0           23150576
r13            0x1                 1
r14            0x0                 0
r15            0x1                 1
rip            0xffffffff81c00aaf  0xffffffff81c00aaf
eflags         0x6                 [ IOPL=0 PF ]
cs             0x10                16
ss             0x0                 0
ds             0x0                 0
es             0x0                 0
fs             0x0                 0
gs             0x0                 0
fs_base        0x705418            7361560
gs_base        0xffff88801f000000  -131391119425536
k_gs_base      0x0                 0
```

you can see that this instruction simply does `xchg gs_base, k_gs_base`. After `swapgs`, page locations are switched between user mode and kernel mode.

```
 RAX  0x1001
 RBX  0x1614000 ◂— 0
 RCX  0x1614000 ◂— 0
 RDX  0x1615000
 RDI  0x705820 ◂— 0
 RSI  0x1615000
 R8   0x0
 R9   0x0
 R10  0x0
 R11  0x297
 R12  0x1613ff0 ◂— 0x540
 R13  0x1
 R14  0x0
 R15  0x1
 RBP  0x1614000 ◂— 0
 RSP  0xfffffe0000002fd8 —▸ 0x400eea ◂— mov    qword ptr [rdx - 0x10], rax
*RIP  0xffffffff81c00ab2 ◂— nop    dword ptr [rax]
────────────────────────────────────────────────────────────────────[ DISASM ]────────────────────────────────────────────────────────────────────
   0xffffffff81c00aaf    swapgs
 ► 0xffffffff81c00ab2    nop    dword ptr [rax]
   0xffffffff81c00ab5    jmp    0xffffffff81c00ae0 <0xffffffff81c00ae0>
    ↓
   0xffffffff81c00ae0    test   byte ptr [rsp + 0x20], 4
   0xffffffff81c00ae5    jne    0xffffffff81c00ae9 <0xffffffff81c00ae9>

   0xffffffff81c00ae7    iretq
   0xffffffff81c00ae9    push   rdi
   0xffffffff81c00aea    swapgs
   0xffffffff81c00aed    nop    dword ptr [rax]
   0xffffffff81c00af0    nop
   0xffffffff81c00af2    mov    rdi, cr3
────────────────────────────────────────────────────────────────────[ STACK ]─────────────────────────────────────────────────────────────────────
00:0000│ rsp 0xfffffe0000002fd8 —▸ 0x400eea ◂— mov    qword ptr [rdx - 0x10], rax
01:0008│     0xfffffe0000002fe0 ◂— 0x33 /* '3' */
02:0010│     0xfffffe0000002fe8 ◂— 0x202
03:0018│     0xfffffe0000002ff0 —▸ 0x7fffd2abf100 ◂— 0x20 /* ' ' */
04:0020│     0xfffffe0000002ff8 ◂— 0x2b /* '+' */
05:0028│     0xfffffe0000003000 ◂— add    byte ptr [rax], al
06:0030│     0xfffffe0000003008 ◂— add    dh, bh
07:0038│     0xfffffe0000003010 ◂— add    cl, cl
──────────────────────────────────────────────────────────────────[ BACKTRACE ]───────────────────────────────────────────────────────────────────
 ► f 0 0xffffffff81c00ab2
   f 1         0x400eea
   f 2             0x33
   f 3            0x202
   f 4   0x7fffd2abf100
   f 5             0x2b
   f 6   0x300000000000
   f 7 0x1ac000fffffe00
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
pwndbg> info registers
rax            0x1001              4097
rbx            0x1614000           23150592
rcx            0x1614000           23150592
rdx            0x1615000           23154688
rsi            0x1615000           23154688
rdi            0x705820            7362592
rbp            0x1614000           0x1614000
rsp            0xfffffe0000002fd8  0xfffffe0000002fd8
r8             0x0                 0
r9             0x0                 0
r10            0x0                 0
r11            0x297               663
r12            0x1613ff0           23150576
r13            0x1                 1
r14            0x0                 0
r15            0x1                 1
rip            0xffffffff81c00ab2  0xffffffff81c00ab2
eflags         0x6                 [ IOPL=0 PF ]
cs             0x10                16
ss             0x0                 0
ds             0x0                 0
es             0x0                 0
fs             0x0                 0
gs             0x0                 0
fs_base        0x705418            7361560
gs_base        0x0                 0
k_gs_base      0xffff88801f000000  -131391119425536
cr0            0x80050033          [ PG AM WP NE ET MP PE ]
cr2            0x1614ff0           23154672
cr3            0x1d947000          [ PDBR=14 PCID=0 ]
cr4            0x1006f0            [ SMEP OSXMMEXCPT OSFXSR PGE MCE PAE PSE ]
cr8            0x1                 1
efer           0xd01               [ NXE LMA LME SCE ]
```

BYPASS

1. There is no way to find a single `swapgs` instruction, so we may use the kernel function itself to switch from user mode and kernel mode cleanly.

Here comes the function swapgs_restore_regs_and_return_to_usermode()

```
/ # cat /proc/kallsyms | grep swapgs_restore_regs_and_return_to_usermode
ffffffff81c00a34 T swapgs_restore_regs_and_return_to_usermode
```

This function literally push and pop all info into and from stack and do `swapgs` and `iret`. We can jump to `0xFFFFFFFF81600A4A` and let the rest of the code itself help us switch gracefully.

```asm
.text:FFFFFFFF81600A34 41 5F                          pop     r15
.text:FFFFFFFF81600A36 41 5E                          pop     r14
.text:FFFFFFFF81600A38 41 5D                          pop     r13
.text:FFFFFFFF81600A3A 41 5C                          pop     r12
.text:FFFFFFFF81600A3C 5D                             pop     rbp
.text:FFFFFFFF81600A3D 5B                             pop     rbx
.text:FFFFFFFF81600A3E 41 5B                          pop     r11
.text:FFFFFFFF81600A40 41 5A                          pop     r10
.text:FFFFFFFF81600A42 41 59                          pop     r9
.text:FFFFFFFF81600A44 41 58                          pop     r8
.text:FFFFFFFF81600A46 58                             pop     rax
.text:FFFFFFFF81600A47 59                             pop     rcx
.text:FFFFFFFF81600A48 5A                             pop     rdx
.text:FFFFFFFF81600A49 5E                             pop     rsi
.text:FFFFFFFF81600A4A 48 89 E7                       mov     rdi, rsp # from here!
.text:FFFFFFFF81600A4D 65 48 8B 24 25+                mov     rsp, gs: 0x5004
.text:FFFFFFFF81600A56 FF 77 30                       push    qword ptr [rdi+30h]
.text:FFFFFFFF81600A59 FF 77 28                       push    qword ptr [rdi+28h]
.text:FFFFFFFF81600A5C FF 77 20                       push    qword ptr [rdi+20h]
.text:FFFFFFFF81600A5F FF 77 18                       push    qword ptr [rdi+18h]
.text:FFFFFFFF81600A62 FF 77 10                       push    qword ptr [rdi+10h]
.text:FFFFFFFF81600A65 FF 37                          push    qword ptr [rdi]
.text:FFFFFFFF81600A67 50                             push    rax
.text:FFFFFFFF81600A68 EB 43                          nop
.text:FFFFFFFF81600A6A 0F 20 DF                       mov     rdi, cr3
.text:FFFFFFFF81600A6D EB 34                          jmp     0xFFFFFFFF81600AA3
 
.text:FFFFFFFF81600AA3 48 81 CF 00 10+                or      rdi, 1000h
.text:FFFFFFFF81600AAA 0F 22 DF                       mov     cr3, rdi
.text:FFFFFFFF81600AAD 58                             pop     rax
.text:FFFFFFFF81600AAE 5F                             pop     rdi
.text:FFFFFFFF81600AAF FF 15 23 65 62+                call    cs: SWAPGS
.text:FFFFFFFF81600AB5 FF 25 15 65 62+                jmp     cs: INTERRUPT_RETURN
 
_SWAPGS
.text:FFFFFFFF8103EFC0 55                             push    rbp
.text:FFFFFFFF8103EFC1 48 89 E5                       mov     rbp, rsp
.text:FFFFFFFF8103EFC4 0F 01 F8                       swapgs
.text:FFFFFFFF8103EFC7 5D                             pop     rbp
.text:FFFFFFFF8103EFC8 C3                             retn
 
 
_INTERRUPT_RETURN
.text:FFFFFFFF81600AE0 F6 44 24 20 04                 test    byte ptr [rsp+0x20], 4
.text:FFFFFFFF81600AE5 75 02                          jnz     native_irq_return_ldt
.text:FFFFFFFF81600AE7 48 CF                          iretq
```

2. As a matter of fact, CR3 register contains page address in these two modes.

![](https://i.loli.net/2021/08/24/b4YaGA5LcNhExes.png)

So if you are lucky enough to find such gadget, you will make it.

```
mov     rdi, cr3
or      rdi, 1000h
mov     cr3, rdi
```

# Ref

[1] https://www.xidoo.top/2021/08/23/hxp-ctf2020

[2] https://www.anquanke.com/post/id/232545

[3] https://cs.brown.edu/~vpk/papers/ret2dir.sec14.pdf

[4] https://elixir.bootlin.com/linux/v5.0/source/Documentation/x86/x86_64/mm.txt

[5] https://www.anquanke.com/post/id/185408

[6] https://blog.csdn.net/juana1/article/details/6904932

[7] https://hardenedlinux.github.io/translation/2015/11/25/Translation-Bypassing-SMEP-Using-vDSO-Overwrites.html

[8] https://www.jianshu.com/p/3d707fac499a
