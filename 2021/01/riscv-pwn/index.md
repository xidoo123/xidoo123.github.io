# RISC-V PWN 调试环境搭建


2019年美国国家安全局(NSA)免费向公众开放其逆向工程框架，集成出工具ghidra并在当年3月登陆github。最近碰到一题risc-v架构（*ctf2021 favourite architecture），需要用ghidra反编译辅助分析，以其为例记录动态与静态调试环境搭建。

<!--more-->

```bash
$ checksec ./main
[*] '/mnt/hgfs/linux_share/starctf/favourite_architecture/share/main'
    Arch:     em_riscv-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x10000)
    RWX:      Has RWX segments

```

## 静态调试

### 下载与使用ghidra

下载略

快捷键见[3]

* L 重命名函数
* G 跳转到
* ctrl+shift+E 查找
* ......

### 踩坑记录

反编译(decompiling)窗口显示unknown error，无法反编译除entry以外的函数

见参考资料[1]，需要设置手动gp（全局寄存器）

在entrypoint最后(0x00101ec)能计算出或者直接在entry的反编译窗口看到gp的正确值为0x6f178

```assembly
                             *************************************************************
                             *                           FUNCTION                          
                             *************************************************************
                             undefined  entry ()
                               assume gp = 0x6f178
             undefined         a0:1           <RETURN>
                             entry                                           XREF[3]:     Entry Point (*) , 00010018 (*) , 
                                                                                          00067e94 (*)   
        000101c0 ef  00  c0  02    jal        ra,FUN_000101ec                                  undefined FUN_000101ec()
        000101c4 aa  87           c.mv       a5,a0
        000101c6 17  05  00  00    auipc      a0,0x0
        000101ca 13  05  a5  23    addi       a0=>LAB_00010400 ,a0,0x23a
        000101ce 82  65           c.ldsp     a1,0x0 =>Stack [0x0 ](sp)
        000101d0 30  00           c.addi4s   a2,sp,0x8
        000101d2 13  71  01  ff    andi       sp,sp,-0x10
        000101d6 97  16  00  00    auipc      a3,0x1
        000101da 93  86  a6  54    addi       a3=>LAB_00011720 ,a3,0x54a
        000101de 17  17  00  00    auipc      a4,0x1
        000101e2 13  07  27  5d    addi       a4=>LAB_000117b0 ,a4,0x5d2
        000101e6 0a  88           c.mv       a6,sp
        000101e8 6f  10  40  0a    j          FUN_0001128c                                     undefined FUN_0001128c()
                             -- Flow Override: CALL_RETURN (CALL_TERMINATOR)
                             *************************************************************
                             *                           FUNCTION                          
                             *************************************************************
                             undefined  FUN_000101ec ()
                               assume gp = 0x6f178
             undefined         a0:1           <RETURN>
                             FUN_000101ec                                    XREF[3]:     entry:000101c0 (c) , 00011762 (c) , 
                                                                                          0006cb80 (*)   
        000101ec 97  f1  05  00    auipc      gp,0x5f
        000101f0 93  81  c1  f8    addi       gp,gp,-0x74
        000101f4 82  80           ret

```

全选以后`ctrl-R`，将gp改对即可。 

![](https://i.loli.net/2021/01/26/9SsF4bUXJuLOBf1.png)

## 动态调试

### qemu+gdb调试

先去掉~/.gdbinit的pwndbg等启动命令，使用原生gdb（如果pwn环境安装在py3中，可以使用gef）

```bash
source ~/pwndbg/gdbinit.py
source ~/GdbPlugins/gef/gef.py
```

调试脚本，gdb连本地23333端口来连

```bash
#!/bin/sh

gdb-multiarch -q \
  -ex 'set architecture riscv:rv64' \
  -ex 'file main' \
  -ex 'target remote localhost:23333' \
  -ex 'break *0x0010582'\
  -ex continue \
;
```

攻击脚本，用qemu在23333端口开一个程序并进行攻击（这里题目给了qemu，也可以用自己的）

```python
io = process(["./qemu-riscv64" , "-g", "23333" ,"./main"], aslr=False)
```

原生gdb比较简陋，并且功能不够强大，暂时只能凑合着用了

![](https://i.loli.net/2021/01/26/F9y2i1suMzC37DO.png)

重新学一下gdb指令...

```bash
Breakpoint 1, 0x0000000000010452 in ?? ()
(gdb) x/10xi 0x10452
=> 0x10452:     jal     ra,0x204e4
   0x10456:     mv      a3,a0
   0x10458:     lw      a4,-1952(gp)
   0x1045c:     lw      a5,-1948(gp)
   0x10460:     addw    a5,a5,a4
   0x10462:     sext.w  a5,a5
   0x10464:     slli    a5,a5,0x20
   0x10466:     srli    a5,a5,0x20
   0x10468:     bne     a3,a5,0x10570
   0x1046c:     lw      a5,-1952(gp)
(gdb) info registers
ra             0x1044c  0x1044c
sp             0x40007ffff0     0x40007ffff0
gp             0x6f178  0x6f178
tp             0x71700  0x71700
t0             0x0      0
t1             0x1a3f2  107506
t2             0x71f93  466835
fp             0x40008001f0     0x40008001f0
s1             0x117b0  71600
a0             0x40008000c8     274886295752
a1             0x6d523  447779
a2             0x1      1
a3             0x0      0
a4             0x1      1
a5             0x40008000c8     274886295752
a6             0xfffffffffbad208b       -72540021
a7             0x3f     63
s2             0x0      0
s3             0x0      0
s4             0x0      0
s5             0x0      0
s6             0x0      0
s7             0x0      0
s8             0x0      0
s9             0x0      0
s10            0x0      0
s11            0x0      0
t3             0x8101010101010100       -9151031864016699136
t4             0x2f     47
t5             0x1      1
t6             0x0      0
pc             0x10452  0x10452
(gdb)
```

gef可以通过gdb-multiarch -p pid号来使用，但是寄存器等却无法正确识别，原因不明

![](https://i.loli.net/2021/02/01/l4wgecMJVAYBS8o.png)

可以看到能正确解析risc-v的指令与寄存器。如果不行也许得先安装一下gcc-riscv64-linux-gnu

```bash
sudo apt-get install git build-essential gdb-multiarch qemu-system-misc gcc-riscv64-linux-gnu binutils-riscv64-linux-gnu
```

具体见参考资料[2]

经过测试，以下常用工具都不支持risc-v...

* ROP_gadget

```bash
(pwn) pwn@ubuntu:~/share/starctf/favourite_architecture/share$ ROPgadget --binary ./main --only "ldsp"
[Error] ELF.getArch() - Architecture not supported
[Error] ELF.getArch() - Architecture not supported
```

* ~~gef/pwndbg/peda/gdbinit均出现以下类似的exception~~ （个人问题，貌似是py3的锅）

```bash
(pwn) pwn@ubuntu:~/share/starctf/favourite_architecture/share$ gdb-multiarch -q ./main
GEF for linux ready, type `gef' to start, `gef config' to configure
50 commands loaded for GDB 9.2 using Python engine 3.8
[*] 4 commands could not be loaded, run `gef missing` to know why.
Reading symbols from ./main...
(No debugging symbols found in ./main)
Python Exception <class '__main__.GefUnsupportedOS'> 'CPU type is currently not supported: riscv:rv64': 
gef➤  set architecture riscv:rv64
The target architecture is assumed to be riscv:rv64
gef➤  r
Starting program: /mnt/hgfs/linux_share/starctf/favourite_architecture/share/main 
/build/gdb-OxeNvS/gdb-9.2/gdb/i387-tdep.c:592: internal-error: void i387_supply_fxsave(regcache*, int, const void*): Assertion `tdep->st0_regnum >= I386_ST0_REGNUM' failed.
A problem internal to GDB has been detected,
further debugging may prove unreliable.

This is a bug, please report it.  For instructions, see:
<http://www.gnu.org/software/gdb/bugs/>.

Aborted (core dumped)
(pwn) pwn@ubuntu:~/share/starctf/favourite_architecture/share$ Input the flag: You are wrong ._.

(pwn) pwn@ubuntu:~/share/starctf/favourite_architecture/share$ 
```

* seccomp-tools乱码且报错

```bash
$ seccomp-tools dump ./main 
./main: 12: ./main: �����>�"tEa��"���#0��#&��������7�#������ׇ��7��w�#���������7��w�#������ׇ��7��w�#��bda��9q�"��#<��#8��#4���7������5�>��1I�7�����1F�5��>���G�����#4��5����?몇��7��#��7���>����骇��7��#��7���>����窇��7��#��7���>���_檇��7��#�5����䪇��7��#��7��>���_㪇��7��#��7��>����᪇��7��#��7��>���ઇ��7��#��7��>���ު���7��#��
�7��>����ܪ���7��#��
�7��>���?۪���7��#��
�7��>����٪���7��#��
�7��#�
5�����ת���7��#��
�7���>���֪���7��#��
�7���>���Ԫ���7��#��
�7�����1F�5��>���-�pBt!a���"�#4��#0���7���7��#��
�7�����>����Ϊ���7��������7��#��: File name too long
./main: 1: ./main: Syntax error: Unterminated quoted string
./main: 3: ./main: ���7������������ُ#: not found./main: 3: ./main: ���7�������������ُ#: not found

./main: 3: ./main: ���7�������������ُ#: not found
./main: 3: ./main: �����7�����k�������`f�G)�!��������``d�G>��p^t ��"���.�#&����#$��������������@���W�Տ�>�bda��yq"�#<��#&��7��������ُ#: not found
./main: 3: ./main: cannot create ��7�: Directory nonexistent
./main: 3: ./main: ��������7�: not found
./main: 3: ./main: cannot create ����p��#0����������������:���N������������6���: Directory nonexistent
./main: 3: ./main: �������G���������D����6����������W������6��������#$�����#: not found
./main: 3: ./main: ���7���C#$��#���7�����#.���7��C#,���7��C#*���7��G#(���7��G#&��# �}�'D��'����#�������G����������D����6����������W�D����6��������#: not found
./main: 1: ./main: �: not found
./main: 1: ./main: ���5XXXDD: not found
./main: 1: ./main: �: not found
./main: 1: ./main:R�td: not found
./main: 1: ./main: �: not found
./main: 1: ./main: dA������Gz��7�A�������cP�: not found
./main: 1: ./main: cannot open ��#8���7���C#: No such file
./main: 1: ./main: ELF��@��@8@t�t����: not found

$  
```

以下常用工具可用

* 原生gdb
* checksec





### 参考资料

[1] https://github.com/NationalSecurityAgency/ghidra/issues/2466

[2] https://pdos.csail.mit.edu/6.828/2019/tools.html

[3] https://www.cnblogs.com/iBinary/p/13852204.html

