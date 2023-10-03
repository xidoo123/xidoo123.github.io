# AFL 白皮书翻译与读书笔记


原文地址 https://lcamtuf.coredump.cx/afl/technical_details.txt

<!--more-->

=================================本文格式如下====================================

>笔记

{{< admonition question >}}
**问题** 
{{< /admonition >}}

 原文 <font color='grey'> 水平有限，难以翻译 </font> <font color='green'> 专有名词 or 有必要保留原词 </font>

==================================这是分割线=====================================

## 0 设计陈述 Design statement

AFL 既不关注于单一方面的操作规则，也不是某一特定理论的 PoC 。此工具可以被认为是一个被实践证实有效的 hack 行为集合，把这些行为以最简单、最健壮的形式实现便得到了 AFL.

轻量级的插桩技术<font color='green'> instrumentation</font> 使 AFL 的许多特性成为可能，并作为其基础，但是这个技术只应该被认为是一种达到目的的手段，这里最核心的原则应该是速度 <font color='green'> speed</font>，可靠性 <font color='green'>reliability </font>与易用性 <font color='green'> ease of use</font>.

##  1 覆盖度测量 Coverage measurements

注入编译后程序的插桩代码会捕捉分支（边）覆盖率 <font color='green'> branch (edge) civerage </font>与粗略的分支命中次数<font color='green'> branch-taken hit counts </font>. 本质上来说，插桩代码如下

	  cur_location = <COMPILE_TIME_RANDOM>;
	  shared_mem[cur_location ^ prev_location]++; 
	  prev_location = cur_location >> 1;
cur_location 取随机值以简化连接复杂项目的过程，并且保持异或输出均匀分布

shared_mem[] 是一个 64 kB 大小的共享内存区域<font color='green'> SHM </font>，被调用者 <font color='green'> caller </font>传给被插桩的程序。其每个字节可以认为是对于元组 (branch_src, branch_dst) 的一次命中  <font color='green'> hit </font>.  此数组大小选择为 64 kB 是为了减少碰撞的发生。通常的目标大概有在 2k 到 10k 的可发现分支点，碰撞概率如下

| Branch cnt | Colliding tuples | Example targets |
| :--------: | :--------------: | :-------------: |
|   1,000    |      0.75%       |   giflib, lzo   |
|   2,000    |       1.5%       |  zlib, tar, xz  |
|   5,000    |       3.5%       | libpng, libwebp |
|   10,000   |        7%        |     libxml      |
|   20,000   |       14%        |     sqlite      |
|   50,000   |       30%        |        -        |

同时，这个大小也足够小，以微秒级分析的同时也能轻易地塞进 L2 缓存。

这种覆盖率的计算型是可以比简单的块覆盖 <font color='green'> block coverage </font>提供更多程序执行路径的信息。并且，它能轻易区分如下执行路径：

		#1: A -> B -> C -> D -> E (tuples: AB, BC, CD, DE)
		#2: A -> B -> D -> C -> E (tuples: AB, BD, DC, CE)

> 由上下文可以认为大写字母代表程序基本块之间的边，每一条边都有一个随机化的ID（即cur_location），值分别为A-E，所以
>
> B->C->D 路径表现为 `shared_mem[(B>>1)^C]++`  `shared_mem[(C>>1)^D]++`
>
> B->D->C 路径表现为 `shared_mem[(B>>1)^D]++`  `shared_mem[(D>>1)^C]++`
>
> 显然是可以区分的。但是块覆盖只会记录 B,C,D 块均命中，却无法区分。
>
> [Difference between block coverage and branch coverage](https://stackoverflow.com/questions/35844439/what-is-the-difference-between-block-coverage-and-branch-coverage)

这有助于发现代码潜在的微小缺陷，因为安全漏洞更多地出现在非预期或者错误的状态转变，仅仅追求达到更多新的基本块是不够的。

代码最后一行的移位操作是为了保证元组的方向性（否则，A^B 与 B^A 是无法区分的），并且可以区分不同的紧环 <font color='green'>tight loops </font>（否则, A ^ A 与 B ^ B 也无法区分）.

> 如果不移位，对于路径 A->B 与 B->A 表现均为 `shared_mem[A^B]++`  ，无法区分
>
> 如果不移位，对于环形路径 A->A 与 B->B 表现均为 `shared_mem[0]++`  ，无法区分

Intel CPU 上没有饱和算数指令 <font color='green'> saturating arithmetic opcodes </font>导致命中计数器有时可能会归零 <font color='green'> wrap around to zero </font>. 但这是一个相当稀有且局部的事件，可以看作是一个 trade-off.

> 通俗来讲，[饱和算数指令](https://en.wikipedia.org/wiki/Saturation_arithmetic)就是具有上下界的算数指令，比如一个规定算数范围为-100~100的饱和算数指令中，(40+80)-(50+60)=100-100=0（而不是10）
>
> Intel 没有使用饱和算数指令，而使用[modular arithmetic](https://en.wikipedia.org/wiki/Modular_arithmetic). 导致最大值的溢出会向最小值保留，比如最常见的正溢出与负溢出
>
> Wikipedia 认为饱和算数指令更接近真实值，并如下举例：
>
> for 8-bit binary signed arithmetic, when the correct answer is 130, it is considerably less surprising to get an answer of 127 from saturating arithmetic than to get an answer of −126 from modular arithmetic. Likewise, for 8-bit binary unsigned arithmetic, when the correct answer is 258, it is less surprising to get an answer of 255 from saturating arithmetic than to get an answer of 2 from modular arithmetic.

## 2 新路径检测 Detecting new behaviors

AFL 全程维护这个全局的元组 map `shared_mem[]`. 这些数据能在各自的路径中被快速对比，并可以在一个简单的循环里用几个 dword- 或者 qword- 宽度的指令进行更新。

当变异后 <font color='green'> mutated </font> 的输入产生了包含新元组的执行路径时，对应的输入就会被保存，并指导接下来的过程（见 Section #3）. 没有触发新的局部状态转变的输入（换句话说，没有产生新的元组）将被丢弃，即使它们产生了新的全局控制流。

这样的解决方案允许非常细粒度<font color='green'> fine-grained </font>的对程序状态长期探索，并且可以不被复杂计算与不可靠的全局比较所困扰，同时也能防止搜寻过程中的路径爆炸 <font color='green'> path explosion </font>.

为了进一步陈述这个性质，考虑下面的路径。这两个路径是不同的，因为新元组 CA, AE 的出现

	    #1: A -> B -> C -> D -> E
	    #2: A -> B -> C -> A -> E

同时 #2 产生后，#3 就不再认为是有意义的了，尽管它产生的全局路径几乎完全不同

	    #3: A -> B -> C -> A -> B -> C -> A -> B -> C -> D -> E

AFL 在检测新元组出现的同时，也粗略地考虑了元组命中次数，它们被分为了如下几个桶 <font color='green'> bucket </font>：

	    1, 2, 3, 4-7, 8-15, 16-31, 32-127, 128+

<font color='grey'> To some extent, the number of buckets is an implementation artifact. </font> 它是一个从 8-bit 计数器到 8-position 位图的映射，前者由插桩产生，后者由 AFL 运行时跟踪已出现的元组数来计数。

元组数在每个桶内的变化是可以忽略的；从一个桶到另一个桶的改变将会被认为是程序控制流中的一次有趣的改变，也会指导下一阶段的进化过程 <font color='green'> evolutionary process </font>.

之所以以这种方式去关心各个元组命中数，是因为它能发现一些潜在的有趣的控制流改变，比如某块代码以往通常只命中一次，但这次却被执行了两次。同时，它显著地降低了对一些经验上不会被注意的改变的敏感度，比如循环的第48次。并且，它在某种程度上也增强了高密度路径图中元组碰撞的抵抗力 <font color='green'>tuple collisions in dense trace maps</font>.

> 循环执行某条边 47 次以后，再循环一次也不应该被认为是有趣的。桶式分类可以让绝大部分循环次数能落在同一个桶，减少对循环的敏感度。同时，偶然的元组碰撞产生的影响也会被忽略。

执行过程由时间与空间限制来严格管制；默认情况下，超时 <font color='green'>timeout</font> 被设置为初始化标准执行速度对应时间的 5 倍，大概 20 ms. 这样看似激进的超时设置可以阻止 fuzzer 表现产生巨大衰减至 <font color='grey'> tarpit </font>，也就是说，增加 1% 的覆盖率然而 fuzzer 却慢了 100 倍；我们十分务实地拒绝了这种情况的发生，并希望 fuzzer 可以找到一个更轻松的方式来遍历相同数量的代码。经验性的测试明确告诉我们，宽松的时间限制并不值得！

## 3 输入队列变异 Evolving the input queue

正如 Section #2 中提到的，变异后产生新的状态转移的测试用例将被添加到输入队列 <font color='green'> input queue </font>，并作为新一轮 fuzzing 的起点。它们会增补而并非替代已有的发现。

和其他更贪心的遗传算法 <font color='green'>genetic algorithms </font>相比，这样做可以让 AFL 循序渐进地探索各种各样的程序断联处与自身潜在的数据格式不匹配之处，正如[此图](https://lcamtuf.coredump.cx/afl/afl_gzip.png)所见

{{< admonition question >}}
对 gzip 6轮 fuzzing 产生的测试用例图，意义不明
{{< /admonition >}}

还有一些对于此算法实践的结果讨论：[讨论1](http://lcamtuf.blogspot.com/2014/11/pulling-jpegs-out-of-thin-air.html)，[讨论2](http://lcamtuf.blogspot.com/2014/11/afl-fuzz-nobody-expects-cdata-sections.html)

> 讨论1中，作者记录了只喂给 AFL 一个 ‘hello’，AFL 如何在 fuzzing djpeg 的过程中慢慢变异出了合法的 JPEG 格式的测试用例的过程。正如文中形容的，传统 fuzzer 不停地随机扭曲、拼接数十个 bit 而恰好拼对的概率是 astronomically 低的，肯定了 AFL 的先进性。同时也能看到 AFL 的局限，但认为在很远的将来才会产生完全另一层次的更高级 fuzzer.
>
> 并发现大对于搜索空间的判断， AFL 绕过的效率很低：
>
> `if (strcmp(header.magic_password, "h4ck3d by p1gZ")) goto terminate_now;`

{{< admonition question >}}

/out_dir/queue/... 中存放所有的测试用例，命名方式暂时不清楚

{{< /admonition >}}

> 讨论2中，作者低调地将 AFL fuzzing 过程归纳为「随机地变异输入文件，缓慢地向新发现推进」，并对 AFL 的表现表示惊讶，他本人也不想从静态分析和符号执行的角度去理解喂给程序的数据到底做了什么。
>
> 接讨论1，由于字符串匹配搜索空间大，所以对于人类易阅读的语言 HTML 与 JavaScript, AFL 效率反而很低。而在这篇讨论中，作者发现 AFL fuzzing XML 语法的过程中，从最初的 &lt;a b="c"&gt;d&lt;/a&gt; 变异到了合法的 [CDATA](https://en.wikipedia.org/wiki/CDATA) 结构，他认为原因有二：-O3 编译选项将字符串常量比较直接优化为内联，以及 *libxml2* 使用宏来进行字符串比较会产生大量相同结构的代码易于插桩。并认为这个结果是非预期并且不稳定的（spooky），得出的结论是：让 AFL 去 fuzz 这些  highly verbose text-based syntax 的程序是在浪费时间

在这个过程中合成出来的语料库就是一个个“哇噢，它出乎了我的意料”的输入集合，它们也会顺其自然地作为任何其他测试过程的种子（比如，手动对资源密集型 <font color='green'>resource-intensive </font>的桌面应用做压力测试 <font color='green'>stress-test </font>）

这样做的话，对于大多数目标的队列会扩充到大概 1k 到 10k 个条目；其中大概 10-30% 是因为发现了新的元组，剩下的与命中次数桶的改变相关。

下面这张表对比了在不同指导 fuzzing 的方法下发现文件语义、探索程序状态的能力。这里的目标程序是 GNU patch 2.7.2 ，编译选项 -O3， 种子是一个空的文本文件；<font color='grey'> the session consisted of a single pass over the
input queue with afl-fuzz: </font>

| Fuzzer guidance strategy used | Blocks reached | Edges reached | Edge hit cnt var | Highest-coverage test case generated |
| :---------------------------: | :------------: | :-----------: | :--------------: | :----------------------------------: |
|        (Initial file)         |      156       |      163      |       1.00       |                (none)                |
|        Blind fuzzing S        |      182       |      205      |       2.23       |        First 2 B of RCS diff         |
|        Blind fuzzing L        |      228       |      265      |       2.23       |      First 4 B of -c mode diff       |
|        Block coverage         |      855       |     1,130     |       1.57       |        Almost-valid RCS diff         |
|         Edge coverage         |     1,452      |     2,070     |       2.18       |        One-chunk -c mode diff        |
|           AFL model           |     1,765      |     2,597     |       4,99       |       Four-chunk -c mode diff        |

> 该表测试程序为 [patch](https://savannah.gnu.org/projects/patch/)，使用不同模式 (RCS, -c) 的 [diff](https://www.runoob.com/linux/linux-comm-diff.html) 可以产生最高覆盖度的测试用例，比对了这几种指导 fuzzing 变异的方式的最佳表现

第一个条目是 blind fuzzing ("S")，代表只盲变异 <font color='green'>blind fuzzing </font>一轮；第二行 ("L") 代表 fuzzer 会在循环中盲变异多轮，直到运行了和插桩运行 <font color='green'>instrumented runs </font>差不多的执行周期 <font color='green'>execution cycles </font> 的整个过程的表现. 当然，插桩运行时队列生长的速度会慢很多。

>Blind fuzzing 为盲变异，有 S 与 Ｌ 两种方式，均相当于对照组
>
>execution cycles 就是字面意思，即计算机体系结构中[取指、译码、执行](https://www.quora.com/What-is-fetch-cycle-instruction-cycle-and-execution-cycle)中的执行周期。
>
>instrumented runs 可以翻译成插桩运行，也可以认为是有指导、有反馈地运行，指代的就是后续 Block, Edge coverage, AFL model 这些有指导的、不盲的 fuzzing. 
>
>保持 Blind fuzzing 与后续 instrumented runs 的循环执行周期数大致相近，才有比较的意义。
>
>插桩运行时队列生长的速度慢，因为需要反复分析；盲 fuzzing 弄出一个测试用例队列是最快的，但能不能有效就不一定了。

另一个独立的实验获得了大致相同的效果，在这里让 fuzzer 在编译时去掉所有的随机 fuzzing 阶段，只保留一系列基础的序列操作，比如游走位翻转 <font color='green'>walking bit flips </font>.

> 原文为 the fuzzer was modified to **compile out all** the random fuzzing stages, 有[文章](https://blog.csdn.net/baizhi2361/article/details/101084436)将其翻译为「修改成所有都是 random fuzzing」，我认为「compile out」应该是指「编译去除掉」而不是「编译出」，并在[这里](https://stackoverflow.com/questions/28596298/is-it-possible-to-compile-out-stream-expressions-in-c)找到了类似的语境。
>
> 作者在[这里](https://lcamtuf.blogspot.com/2014/08/binary-fuzzing-strategies-what-works.html)解释了 walking bit flips, 它是一种从头到尾按位依次翻转的一种变异方法。

因为这样做会让 fuzzer 没办法去改变输入文件的大小，所以这里我们给了它一个合法的、统一的 diff 输出作为种子。结果如下：

| Queue extension strategy used | Blocks reached | Edges reached | Edge hit cnt var | Number of unique crashes found |
| :---------------------------: | :------------: | :-----------: | :--------------: | :----------------------------: |
|        (initial file)         |      624       |      717      |       1.00       |               -                |
|         Blind fuzzing         |     1,101      |     1,409     |       1.60       |               0                |
|        Block coverage         |     1,255      |     1,649     |       1.48       |               0                |
|         Edge coverage         |     1,259      |     1,734     |       1.72       |               0                |
|           AFL model           |     1,452      |     2,040     |       3.16       |               1                |

上文提到过，有一些基于遗传算法的 fuzzing，它们维护单个测试用例并试图将其进化到其能达到的最大覆盖率。但至少从上面的测试结果来看，这些”贪婪“的解决方法并没有比盲 fuzzing 策略有明显的好处。

## 4 语料库精简 culling the corpus

上述提到的渐进式状态探索方式也会不可避免地导致：一些后续合成的测试用例产生的边覆盖情况反而是它们祖先的边覆盖情况的真子集 <font color='green'>strict superset </font>.

为了优化 fuzzing 结果，AFL 会定期用一个快速算法重新评价队列元素，让剩下的测试用例变得特别有效。这个算法做了这样一件事：去选择一个更小的测试用例子集，并保证仍然覆盖同样的元组数。

它是这样做的：给队列中每个元素按照执行延迟 <font color='green'>execution latency </font>与文件大小按比例打分；以此来选择每个元组的低分参与元素。

然后这些元组便可以用如下一套简单的工作流来完成处理：

1. 寻找下一个没有出现在当前工作集中的元组
2. 定位对于这个元组的最高分的队列元素
3. 将此元素产生的路径上出现的所有元组加入当前工作集
4. 回到第 1 步，直到所有元组都出现在当前工作集中

> 队列元素即为一个个测试用例，测试用例产生元组，要在达到相同数量的元组下精简测试用例
>
> 两个条件相互制约的优化算法，很容易联想到机器学习中的[EM算法](https://zhuanlan.zhihu.com/p/40991784)，可谓异曲同工。

由上述”更受欢迎的“的元素组成的语料库通常比一开始的集合小 5-10 倍。"不受欢迎的"元素也没有被丢弃，但它们在队列中将以特定概率被跳过：

* 如果队列里还有新的、尚未喂给程序的”受欢迎的“元素，那么”不受欢迎的“元素会以 99% 的概率跳过。
* 如果没有新的”受欢迎的“元素：
  * 如果当前”不受欢迎的“元素以前已经被喂给程序过，它将以 95% 的概率跳过。
  * 如果它没有经历过任何一轮 fuzzing，跳过的概率将下调到 75%.

基于实际测试，我们认为上述策略很好地平衡了队列循环速度 <font color='green'>queue cycling speed </font>与测试用例密度 <font color='green'>test case diversity </font>.

对于更加成熟但慢得多的精简算法，我们可以使用 afl-cmin 来在输入或者输出语料库上应用。这个工具永久地丢弃了多余的元素，产生了更小的适合于 afl-fuzz 以及其他外部工具的语料库。

## 5 输入文件减枝 Trimming input files

输入文件大小对于 fuzzing 表现有很大的影响，不仅因为大文件会导致目标程序执行缓慢，大文件也会减少变异重要部分的可能，比如控制格式与结构，而增加变异无用数据块的可能。在 perf_tips.txt 中详细讨论了这一点。

先不说用户可能提供一个低质量语料集作为开始，一些变异方式本身也有在迭代过程中增加文件大小的趋势，所以减少文件大小是很重要的。

幸运的是，插桩反馈提供了一种自动对输入文件减枝的同时保证执行路径不受影响的简单方法。

afl-fuzz 内置的减枝器使用变化的长度和单步步长 <font color='green'>variable length and stepover </font>来顺序地尝试删去数据块；任何不会影响路径图校验和 <font color='green'>checksum of the trace map </font>的删除就会被 commit 回硬盘。这个减枝器并没有设计地非常准确详尽；相反，它试图找到一个「准确性」与「在选择合适块大小与单步步长时进程花费的 execve 调用数」的折中点。最后的结果是，平均每个文件需要多花费 5-20% 的 execve 调用数。

{{< admonition question >}}
看上去减枝过程中的两个参数是 length 与 stepover. 

stepover 代表 扫描的步长？length 代表数据块大小？两者在顺序扫描的时候有什么区别？
{{< /admonition >}}

> 这里 commit 借用了 git 相关概念，是歪果仁比较常说的话，代表这个变化是被承认的，是应该生效的。易领会意思，但因为文化差异很难确切翻译。

而另一独立工具 afl-tmin 使用一个更详尽的迭代算法，也尝试在减枝后的文件上使用字符标准化 <font color='green'>alphabet normalization </font>. 具体来说，afl-tmin 操作如下：

首先，此工具会自动选择操作模式。如果初始输入就会引起目标程序崩溃，afl-tmin 会运行非插桩模式<font color='green'> non-instrumented mode </font>, 不断尝试去调整输入让它变得更简单的同时仍然可以导致目标程序崩溃。第二种情况，如果目标程序没有崩溃，afl-tmin 会运行插桩模式<font color='green'> instrumented mode </font>, 调整减小输入的同时不改变执行路径。

这个最小化的算法实际上是这样的：

1. 尝试用大步长去清零大的数据块。从经验上看，这将会为后续更细粒度的工作铺路，从而降低 execve 调用。
2. 尝试进行一轮块删减，在这个过程中减少块大小，单步长度以及二分查找样式<font color='green'> binary-search-style </font>.
3. 数出不同的字母数并尝试批量替换成零，以实现字符标准化
4. 最后，对剩下的非零字节进行逐字节的标准化

{{< admonition question >}}
binary-search-style ?? alphabet normalization 是指 unicode-normalization ？

{{< /admonition >}}

afl-tmin 使用 ASCII 码数字 0 来清零，而不是 \x00 . 这样做的原因是我们认为这样修改会更不易干扰到程序解析输入的过程，以更快达到成功的最小化结果。

这个算法比学术界上提出的一些测试用例精简方法的设想所涉及到的东西要少，但它需要的 execve 调用同样要少很多，并且在真实世界应用时能产生与其相媲美的结果。

> Section #4 强调的是如何最小化输入队列，Section #5 则是如何最小化输入队列中的每个元素

## 6 模糊测试策略 Fuzzing strategies

插桩带来的反馈也使我们评估不同 fuzzing 策略以及优化它们的参数变得容易，最终使其在各种不同的输入文件类型上都能奏效。afl-fuzz 使用的策略是格式不可知论<font color='green'> format-agnostic </font>, 并在[此文](http://lcamtuf.blogspot.com/2014/08/binary-fuzzing-strategies-what-works.html)中详细描述。

> “设计 fuzzer 的变异引擎其实更像一门艺术而非科学。AFL 变异新输入是渐进的，即先应用一些简单的变异比如顺序位翻转和简单的算术变换等，再进行更复杂的变换。这样做是想让变异结果尽量的先变得简单与优雅。
>
> AFL fuzzing 策略有效性的衡量对于各种各样真实世界的程序是基本一致的，从 JPEG, PNG, GIF, WebP 到 gzip, xz, tar 等格式都是如此。这样使得不同 fuzzing 策略更好比较效果：
>
> 1. **Walking bit flips***  顺序翻转位，步长恒定为 1 bit，每行翻转的位数范围为 1 到 4. 执行开销太大（一字节八次 execve），所以 AFL 在 3 轮之后就会进行策略2
>
> 2. **Walking byte flips*** 顺序翻转字节，步长恒定为 1 byte，执行开销较小（一字节一次 execve），虽然有局限性但是效果不差
>
> 3. **Simple arithmetics***  步长恒定为 1 byte，做 -35 到 +35 的算术加法。实现细节分为三个阶段，不再展开。执行开销相当大（大约一字节 20 次执行）但如果将算术限制在 -16 到 +16 之间，开销会急剧下降，路径覆盖率也只会产生微小影响。
>
> 4. **Known integers*** 步长恒定为 1 byte，硬编码一个整数集合，顺序地用它去覆盖输入。大约一字节 30 次执行.
>
> 5. **Stacked tweaks** 在死循环中随机执行一系列操作。这一阶段效果通常比上述都好。
>
> 6. **Test case splicing** 最后，随机交换两个不同的测试用例的一部分。
>
>    （注：* - deterministic strategy，并且从上到下即为 AFL 策略的应用顺序）”

值得注意的是，afl-fuzz 大部分工作实际上具有高度的确定性，<font color='green'> stacked tweaks </font>与 <font color='green'> test case splicing </font>在很后面的阶段才被应用。确定性的策略包括：

* 顺序位翻转，步长与翻转长度可变
* 顺序小整数加减
* 顺序特殊整数（如 0, 1, INT_MAX 等） 插入

一开始使用这些确定性策略是为了产生紧凑的测试用例，并且使得到的引起崩溃的测试用例和不崩溃的测试用例区别尽量小。

在确定性策略应用结束后，会应用堆叠的位翻转、插入、删除、算术运算与拼接等非确定性操作。

所有策略的效果与 execve 开销都在上述博客中阐明。

在 historical_notes.txt 中描述了关于首要性<font color='green'> chiefly </font>，表现<font color='green'> performance </font>，复杂度<font color='green'> simplicity </font>，可靠性<font color='green'> reliability </font>的原因，AFL 也通常不会去考虑特定变异对程序状态改变的具体影响；这些 fuzzing 步骤只是名义上的盲（随机），它们会也只会受输入队列指导。

即便如此，这套规则也有一个（不太重要的）例外：当一个新进入输入队列的元素经过部分确定性的步骤后发现对执行路径的校验和没有产生任何影响，它们可能会被跳过剩下的确定性步骤而直接进入到后续的随机性步骤。特别是对于冗长的、人类易读的数据结构，这样做可以在基本不影响覆盖率的情况下减少 10-40% 的 execve 开销。对于极端的例子，比如通常是块对齐的 tar 文件，这样做可以减少高达 90% 开销.

<font color='grey'> Because the underlying "effector maps" are local every queue entry and remain
in force only during deterministic stages that do not alter the size or the
general layout of the underlying file, this mechanism appears to work very
reliably and proved to be simple to implement. </font>

> Section #3 将 AFL model 与其他变异策略进行大致对比，Section #6 探讨了 AFL model 的细节，并对 model 内各个变异策略进行阐述与对比。

## 7 字典构建 Dictionaries

插桩反馈同样使得自动检测输入文件的语法 token 变得容易，进而更易检测某些被测试的 parser 并得出合法组合，通过一些提前定义的或是自动检测出的字典项。

[这里](http://lcamtuf.blogspot.com/2015/01/afl-fuzz-making-up-grammar-with.html
)讨论了 afl-fuzz 是如何实现语法检测的

> “AFL 变异引擎一个最大的局限性就是 syntax-blind，对于这种目标广泛的 fuzzer ，处理类似于 SQL 与 HTTP 等冗长文法目标都很困难。但也有解决方法，并且效果惊奇。
>
> 其实这也是一种折中，毕竟每次构建一个一次性的、针对特定协议的变异引擎并不简单。我们认为，提前在 spec 中保留一系列的基础文法 token 看上去毫无意义，实际上插桩指导的 fuzzing 会区分出有意义与没意义的测试用例，进而去生成合文法的输入。这个想法很简单，但在实现之后我们发现赌对了：对 sqlite 的 fuzzing 过程中，提前为 fuzzer 准备一些从官方文档中提取出的关键词之后，它就能快速产生不寻常并且符合文法的测试用例。
>
> 提取关键词比定义文法规约要简单得多，但工作量也不小。为了帮助那些没时间，也不情愿去构造合适字典的人，我们应用了一个算法原则去发现关键词：识别那些改变后比改变周围位置造成完全不同执行路径的位置。当发现这种情况时，很大程度上说明改变这些位置的改变导致了文法原子判断语句的错误，这时我们将整块代码加入字典，以待后续进一步变异。
>
> 但这样也有局限性，比如它只能知道初始输入内的或是一些很容易变异得到的  token . 并且对于一些树形解析器等不包含文法原子判断的应用，这个算法并没有做到任何事情（虽然 fuzzer 最终会解决这个问题，但是会比较慢）。”	

本质上说，当一些经典的、基础的、易获得的语法 token 完全随机结合时，插桩代码与队列的变异设计在插桩模式下会一起提供反馈去区分没意义的与能导致新表现的变异——并且在这基础上去构建更复杂的语义。

这些字典已经被证实可以让 fuzzer 迅速重构高度冗长、复杂的语言文法，比如 JavaScript, SQL, XML；前面这篇文章中列举出了一些产生出的 SQL 表达式的例子。

有趣的是，AFL 同样会自动隔离已经出现在输入文件中的 token . 它在通过在翻转比特时定位对程序执行路径产生一致性改变的位置来实现；这是一个出现潜在的原子比较语句的暗示。fuzzer 依靠这个暗示去压缩这部分产生的“自动构建的字典"，后续再与其他 fuzzing 策略结合。

> 原子比较语句指的就是一些在程序中写死的字符串等数值的比较语句，比如前文提到的：
>
> `if (strcmp(header.magic_password, "h4ck3d by p1gZ")) goto terminate_now;`

## 8 崩溃去重 De-duping crashes

崩溃去重也是一个有竞争力的 fuzzer 该处理的问题。许多直白的解决方法都会陷入问题；特别是仅仅查看出错地址，在常用的库函数上（比如 strcmp, strcpy）很可能会导致完全不相关的错误被归为一类；而如果崩溃可以在几步不同的、可能导致递归的代码路径上达到，回溯调用栈去计算校验和这种不直白的方法也将导致严重的崩溃数量膨胀。

afl-fuzz 实现的方法是，只有在以下两种情况之一发生时才认为产生了一个不同的崩溃：

* 此次崩溃路径上包括了从未出现在之前崩溃路径上的元组
* 此次崩溃路径上缺少了在之前崩溃路径上的元组

这种方法在 fuzzing 过程的早期会易受路径数量膨胀的影响，但它会慢慢展示出非常强的自我限制<font color='green'> self-limiting </font>能力。这种去重方式与执行路径分析的逻辑一起构成了 afl-fuzz 的基石。

> 将元组作为记录单元能有效避免组合爆炸，尽管初始路径探索时会有大量新的元组产生，但是后续产生的路径再多，却很有可能都是相同元组的不同组合，这就是 self-limiting 的含义.

## 9 崩溃调查 Investigating crashes

很多类型的崩溃的可利用性<font color='green'> exploitability </font>是难以界定的；afl-fuzz 会尝试使用崩溃调查模式<font color='green'> crash exploration mode </font>来解决这一问题：规则与正常操作模式类似，但变异过后不崩溃的测试用例会被直接丢弃。

这种解决方法的价值在[这篇文章](http://lcamtuf.blogspot.com/2014/11/afl-fuzz-crash-exploration-mode.html)中详细探讨。

> “对于任何一个 fuzzing 的项目来说，确定崩溃存在怎样的风险都需要大量的努力。一小部分情况下十分清晰，比如程序尝试去写或者跳到一些在输入文件中出现的地址。但大部分崩溃的原因十分模糊，比如 NULL pointer dereferences 或者 从奇奇怪怪的地方错误读，它们也许包含了潜在的漏洞，也许只是一些无害的 bug .
>
> 我们做出了一个名为 crash exploration mode 的模式，用 -C 开启。用户只需要拿着一个崩溃的测试用例丢给 AFL ，并 -C 开启即可。使崩溃不再发生或者执行路径没有显著改变的变异结果会被直接丢弃，而一些产生微妙变化的结果会被留下来指导下一轮变异。
>
> 这样做可以非常快的产生相关却不同的语料集，来探索这个崩溃对于出错地址的控制能力，来将越界读慢慢推至边界。”
>
> 最后作者举了一个 fuzzing unrtf 的实际例子。

这个方法运用插桩反馈来探索崩溃程序的状态，尝试弄清楚原因模糊的崩溃情况，然后将新发现的输入丢给人类进一步审查。

对于崩溃来说，与通常的队列元素相反，将崩溃的输入进行减枝是毫无意义的。它们被发现之后就会原封不动的保存，以便将它们与父（未崩溃）元素进行对比分析。也就是说，是否用 afl-tmin 去剪枝都行。

## 10 复制服务器 The fork server

为了提高效率，afl-fuzz 使用“复制服务器”，使得在 fuzzing 过程中，execve 调用、链接、libc 库初始化等工作都只会做一次，后续只要通过写时复制<font color='green'> copy-on-write </font>机制从停止的进程镜像中复制、clone 即可。实现细节在[这里](http://lcamtuf.blogspot.com/2014/10/fuzzing-binaries-without-execve.html)。

> “一般的 fuzzing 反复测试的过程中，就是简单地 waitpid() 去等待子进程执行结束，然后看看它是否抛出了 **SIGSEGV**, **SIGABRT** 等崩溃信号。这种方法被安全研究员所喜爱，因为它能更直接地测试程序，并且每次重新运行程序看上去十分健壮与安全，不会因为随机的内存错误与 fuzzer 本身的存在产生奇怪的副作用。
>
> 然而，他们会发现大多数时间都被花费在等待 execve 执行、链接器和库函数初始化的过程上。我以前也想过自己写一个 EFL loader，并在实时执行程序时使用 mprotect 去暂时锁住 fuzzer 自身的内存区域；第二种方法是执行单个子进程，给内存拍个快照，然后通过 **/proc/pid/mem** 塞给后续的镜像。但这两种方法信号处理都过于麻烦。
>
> 幸运的是，我们最后提出了一个简单得多的方法：向被测试库插入一小段代码，让 execve 执行并跳过链接器，然后停在 main 函数，等待 fuzzer 信号。fuzzer 发出“开始”信号后，它就 fork 出一个和已加载内存完全相同的克隆镜像。多亏了 copy-on-write 技术，上述过程可以快速且健壮地进行。而子进程运行结束后，又会重新返回到原 binary，以此往复。 ”
>
> 后续作者提到了具体实现时遇到的困难与解决方法，比如文件描述符的定位与复制等。最后给出了这段代码的缩减版本，并认为努力是值得的。

> [copy-on-write](https://zh.wikipedia.org/wiki/%E5%AF%AB%E5%85%A5%E6%99%82%E8%A4%87%E8%A3%BD) 是体系结构中很常见的一个概念。现代计算机为了提高效率，多个进程同时请求相同的资源，系统并不会在内存中给它们每人起一份镜像，而让它们共用一份。只有当其中某个进程尝试去修改资源时，才会给它单独复制一份。

fork server 被集成在了插桩过程中，它做的仅仅是在插桩代码执行的第一个函数前停住，并等待 afl-fuzz 发号施令。

它可以带来显著的表现提升，通常会快 1.5 到 2 倍。它还可能做到更多：

* 在手动模式<font color='green'> manual ("deferred") mode  </font>下使用，跳过用户选择的更大块的初始化代码。它只需要改变一点点目标程序，就能在一些目标程序上取得 10+ 倍的增益。
* 启动顽固模式<font color='green'> persistent mode  </font>后，一个进程会被喂多个输入，大量减少了重复的 fork 调用。这通常需要对目标程序做改变，但可以提高 5+ 倍的表现。
* 估算实时<font color='green'> in-process </font>任务的收益，同时也能保持 fuzzer 进程与目标进程的良好隔离。

## 11 并行处理  Parallelization

并行技术中，需要周期性检查 CPU 其他核心内（或远程机器上）独立运行的实例产生的队列，然后选择性地将这些测试用例拿到这个核心（或本地）上来产生从未见过的路径。

这给 fuzzer 设置带来显著的灵活性，包括以同一数据格式的不同解析器为目标，同步运行实例，这通常会带来协同作用<font color='green'> synergistic effects </font>.

对于这部分的更多信息，见 parallel_fuzzing.txt .

## 12 二进制插桩 Binary-only instrumentation

二进制目标的黑盒插桩借助一个分支版本的 QEMU 的用户态实现。这也允许 AFL 执行跨架构的代码——比如，在 x86 架构上执行 ARM 程序。

QEMU 使用基础块<font color='green'> basic blocks </font>作为翻译单元；插桩也在这基础上实现，用基本和 compile-time hooks 类似的模型：

	  if (block_address > elf_text_start && block_address < elf_text_end) {
	
	    cur_location = (block_address >> 4) ^ (block_address << 8);
	    shared_mem[cur_location ^ prev_location]++; 
	    prev_location = cur_location >> 1;
	
	  }

第二行的移位-异或运算用来做指令对齐的掩码。

二进制翻译器比如 QEMU, DynamoRIO, PIN 等启动都相当慢；为了弥补这一点，QEMU 模式下的 AFL 也应用了一个 fork server，与编译时插桩的代码作用相同，在程序 _start 处停下并复制来有效减少已经初始化的镜像复制。

首次翻译新基本块也会导致后续的时延。为了缓解这一问题，AFL fork server 添加了一个连接运行中的模拟器与父进程的管道。这个管道用来将模拟器新遇到的块地址告诉父进程，后者将其添加到翻译 cache 中，后续子进程复制时直接从 cache 里拿地址即可。

这两方面优化后 QEMU 模式的 AFL 需要大概花费 2-5 倍的白盒模式开销，而 PIN 需要 100+ 倍。

## 13 AFL 分析工具 The afl-analyze tool

文件格式分析器<font color='green'> file format analyzer </font>是以前讨论的最小化算法的简单扩展；这个工具不再是尝试去删去无意义的数据块，而会进行一系列的 walking byte flips 操作，然后给输入文件执行的各个字节做注解与分类。

它的分类策略如下：

* 无意义数据块<font color='green'> No-op blocks </font>
  * 位翻转对控制流没有明显改变。
  * 常见的例子比如注释区域、位图中的像素数据等。
* 多余内容<font color='green'> Superficial content </font>
  * 该内容部分（不是全部）位翻转会带来控制流改变。
  * 例子包括富文本（ XML, RTF） 中的字符串。
* 重要流<font color='green'> Critical stream </font>
  * 一个比特序列中所有比特进行位翻转都会改变以不同但相关的方式控制流。
  * 这可能是一些压缩后的数据、非原子比较语句、魔数等。
* 疑似长度域<font color='green'> Suspected length field </font>
  * 小的、原子整数，不管怎么改变都会对程序流产生一致的变化。
  * 这往往预示着长度检测的错误。
* 疑似校验和或魔整数域<font color='green'> Suspected cksum or magic int </font>
  * 与疑似长度域表现相似的整数，但其数值不太可能是代表长度
  * 预示这是一个校验和或者其他含义的魔数。
* 疑似校验块<font color='green'> Suspected checksummed block </font>
  * 一大块数据，改变其中任何地方都要导致执行路径产生相同的新改变。
  * 很像是在进行解析之前的校验和或是相似的复合检查失效。
* 魔数域<font color='green'> Magic value section </font>
  * 与上述表现相同的 token ，但是并没有发现其他准则
  * 可能就是一个原子比较语句。

完。

==================================这是分割线=====================================

上述提出的很多问题相信在分析 AFL 源码之后便能迎刃而解。

但翻译时能感受到的最大的问题是：

​	小到每一句，都有被繁乱的定语、从句遮盖重点的风险。

​	大到整个白皮书，可以看出作者大量描述一些思想与实现过程，而某种程度上遮蔽了对结果的阐述。

是重点去详尽叙述 AFL 已应用的算法细节与思想（换句话说，是对源码的一篇技术总结）更有用，还是去回忆并记录 AFL 设计过程中的取舍与估量更有用，不同的人有不同的看法，但作者无疑是选择了后者。所以其实进一步的阅读材料已经很明确了：AFL 源码分析！

{{< admonition warning >}}
在翻译过程中的意译是不可忽略也无法避免的，如陷入误区请指正。
{{< /admonition >}}

