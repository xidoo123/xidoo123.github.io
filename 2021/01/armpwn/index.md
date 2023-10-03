# ARM PWN 调试环境搭建


qemu是GNU/linux上十分常用的模拟处理器，可以在ubuntu下跑arm\mips甚至riscv等几乎所有架构的可执行文件，一台机器上可以虚拟化为多种架构的机器。

<!--more-->

* system mode：系统模式，模拟整个电脑系统，包括中央处理器及其他周边设备。它使得跨平台编写程序得测试与debug工作变得更容易，但是配置比较麻烦，需要在里面起一个linux虚拟机
* user mode：用户模式，模拟解析可执行文件的指令，比较方便且功能够用，暂时只记录user模式

### 安装qemu-user

ubuntu下

```bash
sudo apt-get install qemu
```

user模式支持的架构下载，暂时完全够用了

```bash
sudo apt install qemu-user
```

下载static版本（可选）

```bash
sudo apt-get install -y qemu-user-static
```

下载完成后，qemu-自动补全可以看到其支持的架构十分全面

```bash
(base) pwn@ubuntu:~$ qemu-
qemu-aarch64              qemu-mips                 qemu-riscv32
qemu-aarch64_be           qemu-mips64               qemu-riscv32-static
qemu-aarch64_be-static    qemu-mips64el             qemu-riscv64
qemu-aarch64-static       qemu-mips64el-static      qemu-riscv64-static
qemu-alpha                qemu-mips64-static        qemu-s390x
qemu-alpha-static         qemu-mipsel               qemu-s390x-static
qemu-arm                  qemu-mipsel-static        qemu-sh4
qemu-armeb                qemu-mipsn32              qemu-sh4eb
qemu-armeb-static         qemu-mipsn32el            qemu-sh4eb-static
qemu-arm-static           qemu-mipsn32el-static     qemu-sh4-static
qemu-cris                 qemu-mipsn32-static       qemu-sparc
qemu-cris-static          qemu-mips-static          qemu-sparc32plus
qemu-debootstrap          qemu-nbd                  qemu-sparc32plus-static
qemu-hppa                 qemu-nios2                qemu-sparc64
qemu-hppa-static          qemu-nios2-static         qemu-sparc64-static
qemu-i386                 qemu-or1k                 qemu-sparc-static
qemu-i386-static          qemu-or1k-static          qemu-system-aarch64
qemu-img                  qemu-ppc                  qemu-system-arm
qemu-io                   qemu-ppc64                qemu-tilegx
qemu-m68k                 qemu-ppc64abi32           qemu-tilegx-static
qemu-m68k-static          qemu-ppc64abi32-static    qemu-x86_64
qemu-make-debian-root     qemu-ppc64le              qemu-x86_64-static
qemu-microblaze           qemu-ppc64le-static       qemu-xtensa
(base) pwn@ubuntu:~$ 

```

### 运行qemu-user

最近*ctf2021中遇到一题名为babypac，是arm64架构

```bash
(pwn) pwn@ubuntu:~/share/starctf/babypac$ ls
chall  chall.i64  chall_patched  cmd  ld-linux-aarch64.so.1  lib  libc.so.6
(pwn) pwn@ubuntu:~/share/starctf/babypac$ checksec ./chall
[*] '/mnt/hgfs/linux_share/starctf/babypac/chall'
    Arch:     aarch64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)

```

可以自己配环境，把库全部加到`/lib`以后用如下命令启动

```bash
qemu-aarch64 ./chall
```

更方便的是指定路径参数等，具体见`-h`

```bash
$ qemu-aarch64 -h
usage: qemu-aarch64 [options] program [arguments...]
Linux CPU emulator (compiled for aarch64 emulation)

Options and associated environment variables:

Argument             Env-variable      Description
-h                                     print this help
-help                                  
-g port              QEMU_GDB          wait gdb connection to 'port'
-L path              QEMU_LD_PREFIX    set the elf interpreter prefix to 'path'
-s size              QEMU_STACK_SIZE   set the stack size to 'size' bytes
-cpu model           QEMU_CPU          select CPU (-cpu help for list)
-E var=value         QEMU_SET_ENV      sets targets environment variable (see below)
-U var               QEMU_UNSET_ENV    unsets targets environment variable (see below)
-0 argv0             QEMU_ARGV0        forces target process argv[0] to be 'argv0'
-r uname             QEMU_UNAME        set qemu uname release string to 'uname'
-B address           QEMU_GUEST_BASE   set guest_base address to 'address'
-R size              QEMU_RESERVED_VA  reserve 'size' bytes for guest virtual address space
-d item[,...]        QEMU_LOG          enable logging of specified items (use '-d help' for a list of items)
-dfilter range[,...] QEMU_DFILTER      filter logging based on address range
-D logfile           QEMU_LOG_FILENAME write logs to 'logfile' (default stderr)
-p pagesize          QEMU_PAGESIZE     set the host page size to 'pagesize'
-singlestep          QEMU_SINGLESTEP   run in singlestep mode
-strace              QEMU_STRACE       log system calls
-seed                QEMU_RAND_SEED    Seed for pseudo-random number generator
-trace               QEMU_TRACE        [[enable=]<pattern>][,events=<file>][,file=<file>]
-version             QEMU_VERSION      display version information and exit

Defaults:
QEMU_LD_PREFIX  = /etc/qemu-binfmt/aarch64
QEMU_STACK_SIZE = 8388608 byte

You can use -E and -U options or the QEMU_SET_ENV and
QEMU_UNSET_ENV environment variables to set and unset
environment variables for the target process.
It is possible to provide several variables by separating them
by commas in getsubopt(3) style. Additionally it is possible to
provide the -E and -U options multiple times.
The following lines are equivalent:
    -E var1=val2 -E var2=val2 -U LD_PRELOAD -U LD_DEBUG
    -E var1=val2,var2=val2 -U LD_PRELOAD,LD_DEBUG
    QEMU_SET_ENV=var1=val2,var2=val2 QEMU_UNSET_ENV=LD_PRELOAD,LD_DEBUG
Note that if you provide several changes to a single variable
the last change will stay in effect.

See <https://qemu.org/contribute/report-a-bug> for how to report bugs.
More information on the QEMU project at <https://qemu.org>.
```

用`-L`指定来lib位置即可，我们直接运行如下命令就可以跑起来

```bash
qemu-aarch64 -cpu max -L . ./chall
```

当然，出题人帮我们写了个启动脚本，只要正确安装qemu并且有aarch64架构便能直接运行。

```bash
(pwn) pwn@ubuntu:~/share/starctf/babypac$ ./cmd

 #   #    ####    #####  ######
  # #    #    #     #    #
### ###  #          #    #####
  # #    #          #    #
 #   #   #    #     #    #
          ####      #    #

```

### 调试ARM

先安装gdb-multiarch

```bash
sudo apt-get gdb-multiarch 
```

以*CTF2021 babypac为例，调试bash如下，选择端口为23333

```bash
#!/bin/sh

gdb-multiarch -q \
  -ex 'set architecture aarch64' \ # 指定架构
  -ex 'file chall' \ # 指定文件
  -ex 'target remote localhost:23333' \  # 指定端口
  -ex 'break *0x400C00' \
  -ex 'break *0x400FF0' \  # 下断点
  -ex continue \
;
```

exp中`-g`指定端口，`-L`指定lib位置

```python
io = process(["qemu-aarch64", "-cpu", "max", "-g", "23333", "-L", ".", "./chall"])
```

然后先跑exp，再跑bash就能进行调试

![](https://i.loli.net/2021/01/24/RdO5slQmKYnPHiT.png)


