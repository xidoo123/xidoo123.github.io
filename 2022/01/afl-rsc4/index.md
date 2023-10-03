# AFL 源码分析（完）变异详解


本文将细致阐述 AFL 变异方式，包括各阶段的变异算子与次数等细节。变异模式是固定的，所以变异细节看上去繁琐又无趣。但正如白皮书中提到，“它被认为是一个被实践证实有效的 hack 行为集合，把这些行为以最简单、最健壮的形式实现便得到了 AFL”，经验主义的产物是不可小觑的。

<!--more-->

[前文](https://xidoo.top/2022/01/afl-rsc/#%E7%AC%AC-n-%E6%AC%A1%E6%89%A7%E8%A1%8C)提到在 fuzz_one 中会对测试用例进行如下阶段的变异：

1. simple bitflip（+ dictionary construction）
2. arithmetic inc/dec
3. interesting values
4. dictionary stuff
5. random havoc
6. splicing

接下来我们来详细描述一下各个过程。

## simple bitflip

每个翻转的原子操作都是 `FLIP_BIT(out_buf, stage_cur);` ，其中 `out_buf` 为输出缓冲区，存放结果；`stage_cur` 是循环变量，从 0 自增到特定长度。

```c
#define FLIP_BIT(_ar, _b) do { \
    u8* _arf = (u8*)(_ar); \
    u32 _bf = (_b); \
    _arf[(_bf) >> 3] ^= (128 >> ((_bf) & 7)); \
  } while (0)
```

此部分有以下几个阶段

### bitflip 1/1

从头到尾，步长为 1 bit，每次翻转 1 bit

```c
  for (stage_cur = 0; stage_cur < stage_max; stage_cur++) {

    stage_cur_byte = stage_cur >> 3;

    FLIP_BIT(out_buf, stage_cur); // 翻一位

    if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry; // 执行看看效果

    FLIP_BIT(out_buf, stage_cur); // 复原
      // ...
      // token 处理
  }
```

这个阶段比较特殊的是 token 处理。每第八次翻转并执行之后（即翻转每个 byte 的最低有效位之后），都会检查 `trace_bits` 的改变情况。如果 checksum 和最初没翻转之前的不一样，但是连续几个 byte 翻转以后得到的 checksum 却相同，则将这个字节加入字典。

>  如白皮书所说，以此来改善 magic number 等固定结构的 fuzz 表现。如果遇到 magic number，对它的每个字节改变都会使程序走向崩溃路径，表现相同且与原路径不同。

> “对于一些文件来说，我们已知其格式中出现的 token 长度不会超过 4，那么我们就可以修改`MAX_AUTO_EXTRA` 为 4 并重新编译 AFL，以排除一些明显不会是 token 的情况。遗憾的是，这些设置是通过宏定义来实现，所以不能做到运行时指定，每次修改后必须重新编译 AFL。”
>
> http://rk700.github.io/2018/01/04/afl-mutations/

### bitflip 2/1

从头到尾，步长为 1 bit，每次翻转相邻的 2 bit

```c
  for (stage_cur = 0; stage_cur < stage_max; stage_cur++) {

    stage_cur_byte = stage_cur >> 3;

    FLIP_BIT(out_buf, stage_cur);
    FLIP_BIT(out_buf, stage_cur + 1);

    if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;

    FLIP_BIT(out_buf, stage_cur);  // 复原
    FLIP_BIT(out_buf, stage_cur + 1);

  }
```

### bitflip 4/1

从头到尾，步长为 1 bit，每次翻转相邻的 4 bit

```c
  for (stage_cur = 0; stage_cur < stage_max; stage_cur++) {

    stage_cur_byte = stage_cur >> 3;

    FLIP_BIT(out_buf, stage_cur);
    FLIP_BIT(out_buf, stage_cur + 1);
    FLIP_BIT(out_buf, stage_cur + 2);
    FLIP_BIT(out_buf, stage_cur + 3);

    if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;

    FLIP_BIT(out_buf, stage_cur);
    FLIP_BIT(out_buf, stage_cur + 1);
    FLIP_BIT(out_buf, stage_cur + 2);
    FLIP_BIT(out_buf, stage_cur + 3);

  }
```

### bitflip 8/8

这一阶段首先会创建 `eff_map` 空间，长度为测试用例字节数，并将头尾置 1，其余为 0.

```c
#define EFF_APOS(_p)          ((_p) >> EFF_MAP_SCALE2)
#define EFF_REM(_x)           ((_x) & ((1 << EFF_MAP_SCALE2) - 1))
#define EFF_ALEN(_l)          (EFF_APOS(_l) + !!EFF_REM(_l))
#define EFF_SPAN_ALEN(_p, _l) (EFF_APOS((_p) + (_l) - 1) - EFF_APOS(_p) + 1)

  /* Initialize effector map for the next step (see comments below). Always
     flag first and last byte as doing something. */

  eff_map    = ck_alloc(EFF_ALEN(len));
  eff_map[0] = 1;

  if (EFF_APOS(len - 1) != 0) { 	
    eff_map[EFF_APOS(len - 1)] = 1;
    eff_cnt++;
  }
```

从头到尾，步长为 1 byte，每次翻转 1 byte

```c
	for (stage_cur = 0; stage_cur < stage_max; stage_cur++) {

    stage_cur_byte = stage_cur;

    out_buf[stage_cur] ^= 0xFF; // 翻转整个 byte

    if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;
    // ...
    // effector map 处理
        
    out_buf[stage_cur] ^= 0xFF; // 复原
	}
```

翻转后检查 `eff_map` ，如果此字节对应项为 0 ，则检查翻转以后是否带来了路径变化，是则置 1.

> 当整个 byte 的改变都没有带来任何路径变化时， AFL 认为这个 byte 是没有价值的，后续会根据 `eff_map` 来选择性跳过。白皮书指出，这样的字节可能只是单纯的非元数据。

当然，AFL 做了一点例外处理。

```c
/* Minimum input file length at which the effector logic kicks in: */

#define EFF_MIN_LEN 128 
/* Maximum effector density past which everything is just fuzzed unconditionally (%): */

#define EFF_MAX_PERC 90
```

> “ 默认情况下，如果文件小于 128 bytes，那么所有字符都是“有效”的；同样地，如果 AFL 发现一个文件有超过 90% 的 bytes 都是“有效”的，那么也不差那 10% 了，大笔一挥，干脆把所有字符都划归为“有效”。”

至此以后的翻转操作，均会参考 `eff_map` ，没有意义的 byte 会直接跳过操作。

### bitflip 16/8

从头到尾，步长为 1 byte，每次翻转相邻的 2 byte

```c
  for (i = 0; i < len - 1; i++) {

    /* Let's consult the effector map... */
	// 两个字节都没意义，不用翻了
    if (!eff_map[EFF_APOS(i)] && !eff_map[EFF_APOS(i + 1)]) {
      stage_max--;
      continue;
    }

    stage_cur_byte = i;

    *(u16*)(out_buf + i) ^= 0xFFFF;

    if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;
    stage_cur++;

    *(u16*)(out_buf + i) ^= 0xFFFF;


  }
```

### bitflip 32/8

从头到尾，步长为 1 byte，每次翻转相邻的 4 byte

```c
	for (i = 0; i < len - 3; i++) {

    /* Let's consult the effector map... */
    if (!eff_map[EFF_APOS(i)] && !eff_map[EFF_APOS(i + 1)] &&
        !eff_map[EFF_APOS(i + 2)] && !eff_map[EFF_APOS(i + 3)]) {
      stage_max--;
      continue;
    }

    stage_cur_byte = i;

    *(u32*)(out_buf + i) ^= 0xFFFFFFFF;

    if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;
    stage_cur++;

    *(u32*)(out_buf + i) ^= 0xFFFFFFFF;

  }
```

## arithmetic inc/dec

这一阶段对测试用例做加减法变异。config.h 中将宏 `ARITH_MAX` 定义为 35，代表了算术运算范围为 -35 到 +35. 其中用 could_be_bitflip 来检查是否此步骤会产生和 bitflip 一样的结果（这是可以用位比较做到的），以减少重复执行。同时， `eff_map` 也指导了此步骤。

### arith 8/8

从头到尾，步长为 1 byte，对每个字节都从 -35 一直试到 +35.

```c
for (i = 0; i < len; i++) {

    u8 orig = out_buf[i];

    /* Let's consult the effector map... */

    if (!eff_map[EFF_APOS(i)]) {
      stage_max -= 2 * ARITH_MAX;
      continue;
    }

    stage_cur_byte = i;

    for (j = 1; j <= ARITH_MAX; j++) {

      u8 r = orig ^ (orig + j);

      /* Do arithmetic operations only if the result couldn't be a product
         of a bitflip. */

      if (!could_be_bitflip(r)) {

        stage_cur_val = j;
        out_buf[i] = orig + j;

        if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;
        stage_cur++;

      } else stage_max--;

      r =  orig ^ (orig - j);

      if (!could_be_bitflip(r)) {

        stage_cur_val = -j;
        out_buf[i] = orig - j;

        if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;
        stage_cur++;

      } else stage_max--;

      out_buf[i] = orig;

    }
```

### arith 16/8

从头到尾，步长为 1 byte，对每个 word 都从 -35 一直试到 +35.

这里 AFL 考虑了大小端两种情况。

### arith 32/8

从头到尾，步长为 1 byte，对每个 dword 都从 -35 一直试到 +35.

同样考虑了大小端。

## interesting values

这一阶段用一些特殊的常数对测试用例做替换操作。config.h 中定义了这些 interesting values.

```c
static s8  interesting_8[]  = { INTERESTING_8 };
static s16 interesting_16[] = { INTERESTING_8, INTERESTING_16 };
static s32 interesting_32[] = { INTERESTING_8, INTERESTING_16, INTERESTING_32 };

/* List of interesting values to use in fuzzing. */

#define INTERESTING_8 \ -128, /* Overflow signed 8-bit when decremented */ \ -1, /* */ \ 0, /* */ \ 1, /* */ \ 16, /* One-off with common buffer size */ \ 32, /* One-off with common buffer size */ \ 64, /* One-off with common buffer size */ \ 100, /* One-off with common buffer size */ \ 127 /* Overflow signed 8-bit when incremented */ 
#define INTERESTING_16 \ -32768, /* Overflow signed 16-bit when decremented */ \ -129, /* Overflow signed 8-bit */ \ 128, /* Overflow signed 8-bit */ \ 255, /* Overflow unsig 8-bit when incremented */ \ 256, /* Overflow unsig 8-bit */ \ 512, /* One-off with common buffer size */ \ 1000, /* One-off with common buffer size */ \ 1024, /* One-off with common buffer size */ \ 4096, /* One-off with common buffer size */ \ 32767 /* Overflow signed 16-bit when incremented */ 
#define INTERESTING_32 \ -2147483648LL, /* Overflow signed 32-bit when decremented */ \ -100663046, /* Large negative number (endian-agnostic) */ \ -32769, /* Overflow signed 16-bit */ \ 32768, /* Overflow signed 16-bit */ \ 65535, /* Overflow unsig 16-bit when incremented */ \ 65536, /* Overflow unsig 16 bit */ \ 100663045, /* Large positive number (endian-agnostic) */ \ 2147483647 /* Overflow signed 32-bit when incremented */
```

could_be_arith 与上一阶段去重。并且，这一阶段同样受 `eff_map` 影响。

### interest 8/8

从头到尾，步长为 1 byte，用 `INTERESTING_8` 中的每个数替换测试用例 1 byte

```c
  for (i = 0; i < len; i++) {

    u8 orig = out_buf[i];

    /* Let's consult the effector map... */

    if (!eff_map[EFF_APOS(i)]) {
      stage_max -= sizeof(interesting_8);
      continue;
    }

    stage_cur_byte = i;

    for (j = 0; j < sizeof(interesting_8); j++) {

      /* Skip if the value could be a product of bitflips or arithmetics. */

      if (could_be_bitflip(orig ^ (u8)interesting_8[j]) ||
          could_be_arith(orig, (u8)interesting_8[j], 1)) {
        stage_max--;
        continue;
      }

      stage_cur_val = interesting_8[j];
      out_buf[i] = interesting_8[j];

      if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;

      out_buf[i] = orig;
      stage_cur++;

    }

  }
```

### interest 16/8

从头到尾，步长为 1 byte，用 `INTERESTING_16` 中的每个数替换测试用例 1 word

### interest 32/8

从头到尾，步长为 1 byte，用 `INTERESTING_32` 中的每个数替换测试用例 1 dword

## dictionary stuff

这一阶段用字典内容对测试用例进行替换。

### user extras (over)

先将 extras 按长度从小到大排，以便复原。

从头到尾，步长为 1 byte，用 extras 中的每个字符串替换测试用例相同长度。受 `eff_map` 影响。

```c
    for (j = 0; j < extras_cnt; j++) {

      /* Skip extras probabilistically if extras_cnt > MAX_DET_EXTRAS. Also skip them if there's no room to insert the payload, if the token is redundant, or if its entire span has no bytes set in the effector map. */

      if ((extras_cnt > MAX_DET_EXTRAS && UR(extras_cnt) >= MAX_DET_EXTRAS) ||
          extras[j].len > len - i ||
          !memcmp(extras[j].data, out_buf + i, extras[j].len) ||
          !memchr(eff_map + EFF_APOS(i), 1, EFF_SPAN_ALEN(i, extras[j].len))) {

        stage_max--;
        continue;

      }
```

> “AFL 会检查 tokens 的数量，如果数量大于预设的 `MAX_DET_EXTRAS`（默认值为 200），那么对每个 token 会根据概率来决定是否进行替换：这里的 `UR(extras_cnt)` 是运行时生成的一个 `0` 到 `extras_cnt ` 之间的随机数。所以，如果用户词典中一共有 400 个 tokens，那么每个 token 就有 `200/400=50%` 的概率执行替换变异。我们可以修改 `MAX_DET_EXTRAS` 的大小来调整这一概率。”

### user extras (insert)

从头到尾，步长为 1 byte，将 extras 中的每个字符串尝试插入测试用例。不受 `eff_map` 影响。

这一阶段复原相比于上述阶段更耗时，涉及到空间分配、拷贝、复原等操作。

> “所以，如果用户提供了大量 tokens，或者原文件很大，那么这一阶段的运算量就会非常的多。直观表现上，就是AFL的执行状态栏中，”user extras (insert)” 的总执行量很大，执行时间很长。如果出现了这种情况，那么就可以考虑适当删减一些 tokens。”

### auto extras (over)

上文提到 bitflip 时会产生字典。在这一步将使用这个字典。

从头到尾，步长为 1 byte，用其中的每个字符串替换测试用例相同长度。受 `eff_map` 影响。

## random havoc

dumb mode 会直接从这一阶段开始，跳过上述确定性过程。后续所有的变异都是随机的。

在这一阶段，AFL 会计算得到一个操作轮数，每一轮再产生一个随机数作为每轮的操作次数，每次在以下操作中选择一个：

- 随机选取某个 bit 进行翻转

- 随机选取某个 byte，将其设置为随机的 interesting value

- 随机选取某个 word，并随机选取大、小端序，将其设置为随机的 interesting value

- 随机选取某个 dword，并随机选取大、小端序，将其设置为随机的 interesting value

- 随机选取某个 byte，对其减去一个随机数

- 随机选取某个 byte，对其加上一个随机数

- 随机选取某个 word，并随机选取大、小端序，对其减去一个随机数

- 随机选取某个 word，并随机选取大、小端序，对其加上一个随机数

- 随机选取某个 dword，并随机选取大、小端序，对其减去一个随机数

- 随机选取某个 dword，并随机选取大、小端序，对其加上一个随机数

- 随机选取某个 byte，将其设置为随机数

- 随机删除一段 bytes

- 随机选取一个位置，插入一段随机长度的内容，其中 75% 的概率是插入原文中随机位置的内容，25% 的概率是插入一段随机选取的数

- 随机选取一个位置，替换为一段随机长度的内容，其中 75% 的概率是替换成原文中随机位置的内容，25% 的概率是替换成一段随机选取的数

- 随机选取一个位置，用随机选取的 token（用户提供的或自动生成的）替换

- 随机选取一个位置，用随机选取的 token（用户提供的或自动生成的）插入

  （摘自 https://bbs.pediy.com/thread-254705.htm）

在充满随机的 havoc 大杂烩中，AFL 对测试用例做了一系列天马行空的变异尝试。

## splicing

在这一阶段，AFL 尝试对各个测试用例之间做切分、拼接操作。

在队列中随机选取另一个测试用例，用 locate_diffs 在这两个测试用例的 first differing byte 与 last differing byte 中选取一个切分位置（如果两个测试用例太接近则重新选），将它们各自分割为 2 部分。最后，将随机选取的测试用例的尾与该测试用例的头拼接起来，作为变异结果。

至此，一个测试用例的所有变异尝试便结束了。

