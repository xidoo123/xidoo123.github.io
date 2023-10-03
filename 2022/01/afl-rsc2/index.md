# AFL 源码分析（二）路径覆盖信息 & 队列优胜者


紧接上一部分，本文将更进一步探讨 AFL 如何在运行时保存和分析路径覆盖信息，以及队列优胜者的选取思路。前者为启发式变异提供导向，后者为 [culling the corpus](https://xidoo.top/2022/01/afl-white-book/#4-%E8%AF%AD%E6%96%99%E5%BA%93%E7%B2%BE%E7%AE%80-culling-the-corpus) 的基础。

<!--more-->

## 路径覆盖信息的保存与分析

这部分主要涉及到 has_new_bits

### 初始化

[前文](https://xidoo.top/2022/01/afl-rsc/#check-configuration) 提到 AFL 会调用 `setup_shm`  初始化内存。在这个函数中，`virgin_bits` 被初始化为一段二进制一的内存并全程维护作为总表，对于其中的每个字节，全一则代表对应元组未被访问。`shmget` 初始化一段同样大小的共享内存，通过 IPC 进行进程间的通信与同步。如果不是 dumb 模式就会将此共享内存的标识符设置在环境变量中，方便子进程（见 forkserver 部分）锁定。AFL 本身通过 `trace_bits` 变量指向这段共享内存，用来记录每次运行得到的路径执行情况。

```c
EXP_ST void setup_shm(void) {

  u8* shm_str;

  if (!in_bitmap) memset(virgin_bits, 255, MAP_SIZE);

  memset(virgin_tmout, 255, MAP_SIZE);
  memset(virgin_crash, 255, MAP_SIZE);

  shm_id = shmget(IPC_PRIVATE, MAP_SIZE, IPC_CREAT | IPC_EXCL | 0600);

  if (shm_id < 0) PFATAL("shmget() failed");

  atexit(remove_shm);

  shm_str = alloc_printf("%d", shm_id);

  /* If somebody is asking us to fuzz instrumented binaries in dumb mode,
     we don't want them to detect instrumentation, since we won't be sending
     fork server commands. This should be replaced with better auto-detection
     later on, perhaps? */

  if (!dumb_mode) setenv(SHM_ENV_VAR, shm_str, 1);

  ck_free(shm_str);

  trace_bits = shmat(shm_id, NULL, 0);
  
  if (trace_bits == (void *)-1) PFATAL("shmat() failed");

}
```

### 运行时获取

每次 `run_target()` 的最开始会清零 `trace_bits` ，在执行时用如下插桩代码改变 `trace_bits` （ 见 afl-as.h/__afl_maybe_log ）回忆 [白皮书 ](https://xidoo.top/2022/01/afl-white-book/#1-%E8%A6%86%E7%9B%96%E5%BA%A6%E6%B5%8B%E9%87%8F-coverage-measurements)中对于插桩代码的伪代码描述。

在 afl-as.h/trampoline_fmt_64 中，插桩代码用 rcx 存储一个 `(random() % (MAP_SIZE))` 范围的随机值，因此在处理到某个分支并且需要插入插桩代码时，afl-as 会产生一个此范围的随机数作为此边的 ID. 对应于伪代码第一行 `cur_location = <COMPILE_TIME_RANDOM>;` 

```c
static const u8* trampoline_fmt_64 =
 
  "/* --- AFL TRAMPOLINE (64-BIT) --- */\n"
  //...
  "movq %%rcx,  8(%%rsp)\n"
  "movq $0x%08x, %%rcx\n"
  "call __afl_maybe_log\n"
  //...
  "\n"
  "/* --- END --- */\n"
  "\n";
```

进入到 __afl_maybe_log，首先会检查共享内存是否设置好

```c
  "  /* Check if SHM region is already mapped. */\n"
  "\n"
  "  movl  __afl_area_ptr, %edx\n"
  "  testl %edx, %edx\n"
  "  je    __afl_setup\n"
  "\n"
  "__afl_store:\n"
```

然后开始如下计算，可见 `__afl_pre_loc`  便是伪代码中 `prev_location` ，保存上一个元组位置。在对 `cur_location` 进行异或后将 `cur_location` 右移一位作为新的 `prev_location` .

```c
#ifndef COVERAGE_ONLY
  "  movl __afl_prev_loc, %edi\n"
  "  xorl %ecx, %edi\n"
  "  shrl $1, %ecx\n"
  "  movl %ecx, __afl_prev_loc\n"
#else
  "  movl %ecx, %edi\n"
#endif /* ^!COVERAGE_ONLY */
  "\n"
```

然后用 rcx 与 rdx 来改变 `trace_bits` 内存区域。

```c
#ifdef SKIP_COUNTS
  "  orb  $1, (%rdx, %rcx, 1)\n"
#else
  "  incb (%rdx, %rcx, 1)\n"
```

这便是在一次执行中插桩代码对路径覆盖表做的改变。

### 以路径覆盖为指导

在上一步得到改变 `trace_bits` 后调用 `classify_counts(trace_bits)`  对其做预处理，此函数将传入的内存按每两个字节做 `count_class_lookup16` 变换。

```c
static inline void classify_counts(u64* mem) {
      //...
      mem16[0] = count_class_lookup16[mem16[0]];
      mem16[1] = count_class_lookup16[mem16[1]];
      mem16[2] = count_class_lookup16[mem16[2]];
      mem16[3] = count_class_lookup16[mem16[3]];
	  //...
}
```


其中 `count_class_lookup8` 便是白皮书提到的桶操作，将一字节宽的变量按如下映射。


```c
static const u8 count_class_lookup8[256] = {
    
      [0]           = 0, // 00000000
      [1]           = 1, // 00000001
      [2]           = 2, // 00000010
      [3]           = 4, // 00000100
      [4 ... 7]     = 8, // 00001000
      [8 ... 15]    = 16,// 00010000
      [16 ... 31]   = 32,// 00100000
      [32 ... 127]  = 64,// 01000000
      [128 ... 255] = 128// 10000000
      
};
```


二字节宽的 `count_class_lookup16` 就是将前后两个字节分开计算 `count_class_lookup8`，可能是为了提高效率。


```c
static u16 count_class_lookup16[65536];

EXP_ST void init_count_class16(void) {

  u32 b1, b2;

  for (b1 = 0; b1 < 256; b1++) 
    for (b2 = 0; b2 < 256; b2++)
      count_class_lookup16[(b1 << 8) + b2] = 
        (count_class_lookup8[b1] << 8) |
        count_class_lookup8[b2];

}
```

 `run_target()` 结束后会调用 `has_new_bits(virgin_bits) ` 去判断是否产生了新的元组，该函数将 `trace_bits` 与 `virgin_bits` 做一系列对比，得到返回值：1 代表元组命中数改变，2 代表新元组产生。这个函数会将上述两个待比较的内存以 8 个 字节为一组（64位下），对每组进行如下对比判断，最后清零 `virgin_bits` 相应位，代表此位置对应元组已被命中。

```c
    if (unlikely(*current) && unlikely(*current & *virgin)) {
      if (likely(ret < 2)) {

        u8* cur = (u8*)current;
        u8* vir = (u8*)virgin;

        if ((cur[0] && vir[0] == 0xff) || (cur[1] && vir[1] == 0xff) ||
            (cur[2] && vir[2] == 0xff) || (cur[3] && vir[3] == 0xff) ||
            (cur[4] && vir[4] == 0xff) || (cur[5] && vir[5] == 0xff) ||
            (cur[6] && vir[6] == 0xff) || (cur[7] && vir[7] == 0xff)) ret = 2;
        else ret = 1;
      }
      *virgin &= ~*current;
    }
```

> 应该不会有人像我一样因为不注意 && 与 == 运算符的优先级而看不懂逻辑吧？

同样，save_if_interesting 中也会调用 has_new_bits 获取返回值，如果为 0 则代表本次执行没有新的路径产生，该测试用例不会被放入测试队列，也不会写入磁盘。只有返回 1 或 2 时才会保留测试用例。

总的来说，AFL 的启发式变异就体现在此，只有当 has_new_bits 返回非 0 时（即测试用例带来了元组命中次数的改变或新命中元组的产生）该测试用例才会被放入测试队列被进一步变异。如白皮书说所，这样的启发式思想给 AFL 带来了超过 Blind fuzzing, 以 Block coverage, Edge coverage 为导向的 fuzzing 性能。

## 优胜者策略

此部分主要涉及到 update_bitmap_score, cull_queue .

### 指导因子标记

队列用链表实现，每个元素代表一个测试用例，结构体为 `queue_entry`，着重注意它的成员变量 `trace_mini`  与 `tc_ref` ，在这一部分起到重要效果。

```c
struct queue_entry {

  u8* fname;                          /* File name for the test case      */
  u32 len;                            /* Input length                     */

  u8  cal_failed,                     /* Calibration failed?              */
      trim_done,                      /* Trimmed?                         */
      was_fuzzed,                     /* Had any fuzzing done yet?        */
      passed_det,                     /* Deterministic stages passed?     */
      has_new_cov,                    /* Triggers new coverage?           */
      var_behavior,                   /* Variable behavior?               */
      favored,                        /* Currently favored?               */
      fs_redundant;                   /* Marked as redundant in the fs?   */

  u32 bitmap_size,                    /* Number of bits set in bitmap     */
      exec_cksum;                     /* Checksum of the execution trace  */

  u64 exec_us,                        /* Execution time (us)              */
      handicap,                       /* Number of queue cycles behind    */
      depth;                          /* Path depth                       */

  u8* trace_mini;                     /* Trace bytes, if kept             */
  u32 tc_ref;                         /* Trace bytes ref count            */

  struct queue_entry *next,           /* Next element, if any             */
                     *next_100;       /* 100 elements ahead               */

};
```

AFL 维护一个数组 `top_rated` ，它的每个条目对应 bitmap 中一个字节（即一个元组的命中情况）。 `static struct queue_entry* top_rated[MAP_SIZE];  ` 对表中每一个字节，即每一个元组，都用 `top_rated` 一一对应到一个队列元素，代表这个元组的“最佳测试用例”。

对每个队列元素定义参考值 `u64 fav_factor = q->exec_us * q->len;` AFL 用测试用例执行时间与长度的乘积作为“最佳测试用例”的度量标准，如白皮书所说，简单却有效。

在 `run_target()` 中得到 bitmap 后会调用 update_bitmap_score 函数。它遍历 `trace_bits` 的每个字节，如果当前字节为 1（即此元组在此次执行时命中）则初始化 `top_rated` 条目为此队列元素。当以后执行又命中此元组时（即当 `top_rated` 对应条目不为空时），该元组会选取更小参考值的队列元素作为其 `top_rated` 条目，并将 `score_changed` 置 1 。在这个过程中，队列元素的成员变量 `tc_ref` 记录了此队列元素被元组认为是优胜者的次数，如果减为 0，则会将 `trace_mini` 空间释放；如果从 0 到 1，则为 成员变量 `trace_mini ` 分配内存，并调用 minimize_bits 来缩减 `trace_bits` 得到 `trace_mini` 。

```c
    if (top_rated[i]) {
        if (fav_factor > top_rated[i]->exec_us * top_rated[i]->len) continue;
        if (!--top_rated[i]->tc_ref) {  // 减到 0 则释放内存
            ck_free(top_rated[i]->trace_mini);
            top_rated[i]->trace_mini = 0;
        }
    }
    top_rated[i] = q;
    q->tc_ref++;
    if (!q->trace_mini) {	
        q->trace_mini = ck_alloc(MAP_SIZE >> 3); // 分配内存
        minimize_bits(q->trace_mini, trace_bits);
    }
    score_changed = 1;
```

update_bitmap_score 的优化方向为：`trace_bits` 不变但队列元素的 `fav_factor` 趋于最小。

而 minimize_bits 函数就是简单地将 `trace_bits `  缩减到原来的 1/8 存储到 `trace_mini` ,  `trace_mini` 的一个 bit 对应了 `trace_bits` 的一个字节。也就是说，这样的压缩方式去掉了 `trace_bits` 中元组命中次数的信息，而只保留了该元组是否命中的信息。

```c
/* Compact trace bytes into a smaller bitmap. We effectively just drop the
   count information here. This is called only sporadically, for some
   new paths. */
 
static void minimize_bits(u8 *dst, u8 *src) {
 
    u32 i = 0;
 
    while (i < MAP_SIZE) {
 
        if (*(src++)) dst[i >> 3] |= 1 << (i & 7);
        i++;
 
    } 
}
```

上述过程得到的 `trace_mini`, `top_rated`, `score_changed` 将作为指导因子，指导后续过程。

### 剪枝因子标记

`run_target()` 后会调用 cull_queue 对队列进行剪枝。该函数如下：

初始化 `temp_v`  为全二进制一的内存，大小与 `trace_mini` 相同，它的一个 bit 同样对应了 `trace_bits` 的一个字节，用于在这一函数中标识没有被访问的元组。

这里本质上还是使用了贪心算法。前面提到，队列元素的 `trace_mini` 保存了该测试用例命中的元组信息。而 `top_rated` 指示的队列元素的 `trace_mini` 便是在优胜者圈子内的测试用例命中的元组信息。但不是所有优胜者的 `favored` 都被置 1，AFL 贪心地认为对于每个被命中的元组，遍历时第一次遇到的优胜者就是“更受喜爱的”，并置成员变量 `favored` 为 1.

```c
	  if (top_rated[i] && (temp_v[i >> 3] & (1 << (i & 7)))) {

      u32 j = MAP_SIZE >> 3;

      /* Remove all bits belonging to the current entry from temp_v. */

      while (j--) 
        if (top_rated[i]->trace_mini[j])
          temp_v[j] &= ~top_rated[i]->trace_mini[j];

      top_rated[i]->favored = 1;
      queued_favored++;

      if (!top_rated[i]->was_fuzzed) pending_favored++;
```

标记好“更受喜爱”的测试用例之后，遍历每个测试用例调用 mark_as_redundant 做处理。

```c
  q = queue;

  while (q) {
    mark_as_redundant(q, !q->favored);
    q = q->next;
  }
```

在 mark_as_redundant 中，未被 `favored ` 标记的测试用例，其成员变量 `fs_redundant` 会被置 1，并放入 out_dir/queue/.state/redundant_edges/ 文件夹中。如果它在后续又被 `favored` 标记，则从文件夹中删去；反之同理。

所以总的来说 cull_queue 干了两件事情，选择优胜者并标记为 `favored` ，并将剩余测试用例标记为 `fs_redundant` 并在磁盘中留下名字。正如白皮书所说，AFL 并未将非优胜者直接剔除。

### 指导测试过程

在 fuzz_one 函数中

* pending_favored 时，was_fuzzed 或是 非优胜者 会以 `SKIP_TO_NEW_PROB` 概率跳过测试。

  

* 没有 pending_favored 时

  * 非优胜者
    * 没被 fuzz 过会以 `SKIP_NFAV_NEW_PROB` 概率跳过。
    * 被 fuzz 过以 `SKIP_NFAV_OLD_PROB` 概率跳过。
  * 优胜者不跳过

```c
  if (pending_favored) {

    /* If we have any favored, non-fuzzed new arrivals in the queue,
       possibly skip to them at the expense of already-fuzzed or non-favored
       cases. */

    if ((queue_cur->was_fuzzed || !queue_cur->favored) &&
        UR(100) < SKIP_TO_NEW_PROB) return 1;

  } else if (!dumb_mode && !queue_cur->favored && queued_paths > 10) {

    /* Otherwise, still possibly skip non-favored cases, albeit less often.
       The odds of skipping stuff are higher for already-fuzzed inputs and
       lower for never-fuzzed entries. */

    if (queue_cycle > 1 && !queue_cur->was_fuzzed) {

      if (UR(100) < SKIP_NFAV_NEW_PROB) return 1;

    } else {

      if (UR(100) < SKIP_NFAV_OLD_PROB) return 1;

    }

  }
```

这便是剪枝因子指导测试队列减小的全过程。

