# AFL 源码分析（一）从 0 到 1 再到 n


[afl-fuzz.c](https://github.com/google/AFL/blob/master/afl-fuzz.c) 概览，后续重点将放在 forkserver 和启发式变异细节上。

<!--more-->

## Main 函数鸟瞰

![](https://s2.loli.net/2022/01/13/JZqVIGjstCUumYp.png)

### Get Option

**在这一部分，AFL 会读取用户指定的参数**

	   "Required parameters:\n\n"
	
	   "  -i dir        - input directory with test cases\n"
	   "  -o dir        - output directory for fuzzer findings\n\n"
	
	   "Execution control settings:\n\n"
	
	   "  -f file       - location read by the fuzzed program (stdin)\n"
	   "  -t msec       - timeout for each run (auto-scaled, 50-%u ms)\n"
	   "  -m megs       - memory limit for child process (%u MB)\n"
	   "  -Q            - use binary-only instrumentation (QEMU mode)\n\n"     
	 
	   "Fuzzing behavior settings:\n\n"
	
	   "  -d            - quick & dirty mode (skips deterministic steps)\n"
	   "  -n            - fuzz without instrumentation (dumb mode)\n"
	   "  -x dir        - optional fuzzer dictionary (see README)\n\n"
	
	   "Other stuff:\n\n"
	
	   "  -T text       - text banner to show on the screen\n"
	   "  -M / -S id    - distributed mode (see parallel_fuzzing.txt)\n"
	   "  -C            - crash exploration mode (the peruvian rabbit thing)\n"
	   "  -V            - show version number and exit\n\n"
	   "  -b cpu_id     - bind the fuzzing process to the specified CPU core\n\n"

文档中给出的输入参数如上，查阅源码会得到如下更详细的信息

1. -i, -o 指定输入、输出文件夹，改变 `in_dir`,  `out_dir`

   

2. -M, -S 并行设置，改变 `sync_id`

   

3. -f 指定临时输出文件（并行时不同 fuzzer 不能指定为同一个）改变 `out_file`

   

4. -x 用户指定额外的字典，读给 `extras_dir`

   

5. -t 指定超时时间， `%u%c` 读给 `exec_tmout` 与 `suffix`，改变 `timeout_given`

    ```c
    u8 suffix = 0;
    
    if (timeout_given) FATAL("Multiple -t options not supported");
    
    if (sscanf(optarg, "%u%c", &exec_tmout, &suffix) < 1 ||
    optarg[0] == '-') FATAL("Bad syntax used for -t");
    
    if (exec_tmout < 5) FATAL("Dangerously low value of -t");
    
    if (suffix == '+') timeout_given = 2; else timeout_given = 1;
    ```

6. -m 指定内存限制，`%llu%c` 读给 `mem_limit` 与 `suffix`，改变 `mem_limit_given` 

     以 MB 为单位，不得低于 5 MB，不得大于 2000 MB（sizeof(rlim_t) == 4时）

     ```c
        switch (suffix) {
        	case 'T': mem_limit *= 1024 * 1024; break;
        	case 'G': mem_limit *= 1024; break;
        	case 'k': mem_limit /= 1024; break;
        	case 'M': break;
       }
     ```

7. -b 指定特定 CPU 核心，读给 `cpu_to_bind`，改变 `cpu_to_bind_given`

   

8. -B 指定 bitmap，读给 `in_bitmap`

	> “这是一个没有在文档中记录的选项，如果你在 fuzzing 过程中找到了一个有趣的测试用例，想将它变异又不想从头开始，可以用 -B 指示 fuzz_bitmap 为你这一轮得到的 bitmap，AFL 会在这个基础上去做 fuzz”

    ```c
    if (in_bitmap) FATAL("Multiple -B options not supported");

    in_bitmap = optarg;
    read_bitmap(in_bitmap);
    ```

9. -C 开关选项，打开 crash mode（见白皮书 #9）

		crash_mode = FAULT_CRASH;

10. -n 开关选项，打开 dumb mode（不插桩）

		if (getenv("AFL_DUMB_FORKSRV")) dumb_mode = 2; else dumb_mode = 1;

11. -Q 开关选项，打开 qemu mode（黑盒插桩）

    

12. -d 开关选项，可跳过确定性变异过程

	    skip_deterministic = 1;
	    use_splicing = 1;

13. -T 指定横幅（貌似没什么用...），读给 `use_banner`



### Check Configuration

**在这一部分，AFL 会如下依次检查当前配置是否存在冲突，并准备运行**

1. 输入、输出文件夹必须指定

2. setup_signal_handlers 设置信号处理函数

3. check_asan_opts 检查 ASAN 设置是否正确

4. 如果开启并行，fix_up_sync 检查并行ID等

5. 输入、输出文件夹不能是相同

6. dumb mode 与 crash mode 互斥

7. dumb mode 与 qemu mode 互斥

8. getenv 获取如下配置

    * AFL_NO_FORKSRV：与 AFL_DUMB_FORKSRV 冲突

    * AFL_NO_CPU_RED

    * AFL_NO_ARITH

    * AFL_SHUFFLE_QUEUE

    * AFL_FAST_CAL

    * AFL_HANG_TMOUT

    * 用 AFL_PRELOAD 设置系统变量 LD_PRELOAD

    * AFL_LD_PRELOAD 参数已被 AFL_PRELOAD 取代

9. save_cmdline 将命令行保存在`orig_cmdline`

10. fix_up_banner 修复`use_banner`

11. check_if_tty 查看是否在 tty 终端上运行的 AFL，改变`not_no_tty`

12. get_core_count, bind_to_free_cpu 查看、绑定空闲 CPU 核心

13. check_crash_handling 查看崩溃处理的句柄，转存崩溃

14. check_cpu_governor

15. setup_post 加载 postprocessor（if available）

16. setup_shm 设置共享内存，初始化`virgin_bits`, `virgin_tmout`, `virgin_crash`, `trace_bits`

17. init_count_class16

18. setup_dirs_fds 初始化输出文件夹与描述符

19. read_testcases 从输入文件夹读取种子，入队（后续包含较多 Linux 系统编程）

    * 用 scandir 与 [alphasort](https://baike.baidu.com/item/alphasort/3873759?fr=aladdin) 扫描文件夹
    * `shuffle_queue` 决定是否调用 shuffle_ptrs 去随机打乱输入顺序
    * 将未经过确定性变异的测试用例入队
      * [access](https://blog.csdn.net/fengbingchun/article/details/100342049) 判断该队列元素（测试用例）名字是否于 <font color='grey'>"in_dir/.state/deterministic_done/" </font>文件夹中存在
      * 存在则认为该测试用例已经完成了确定性变异，不再送入队列重新处理
      * 不存在则调用 add_to_queue 送入队列

20. load_auto 自动加载字典 token，从 <font color='grey'>"in_dir/auto_extras/auto_%06u" % cnt </font>位置处依次读取，调用 maybe_add_auto 按规则加入字典

21. pivot_inputs 在输出文件夹中为测试用例创建硬链接，有如下命名规则

    * `SIMPLE_FILES` 有定义时， <font color='grey'>"in_dir/queue/id:%06u" % id</font>
    * `SIMPLE_FILES` 无定义时， <font color='grey'>"in_dir/queue/id:%06u,orig:%s" % id, use_name</font>
    * 调用 mark_as_det_done 在 <font color='grey'> "out_dir/queue/.state/deterministic_done/" </font>文件夹中产生已经完成确定性变异的测试用例文件
    * 调用 nuke_resume_dir 删除掉   <font color='grey'>"out_dir/_resume/.state/" </font>文件夹中所有临时文件

22. load_extras 调用 load_extras_file 加载 token

23. 如果没有设置 `timeout_given`，调用 find_timeout

24. detect_file_args 处理 @@ 的输入命令（用于 AFL 的文件输入，harness 见[前文](https://xidoo.top/2021/11/fuzzing1/#harness)）

25. 如果没有 -f 设置临时输出，调用 setup_stdio_file 按 <font color='grey'>"out_dir/.cur_input"</font> 设置并创建

26. check_binary 检查待测试文件的信息

27. get_cur_time 获取当前时间作为启动时间

28. 如果开启 qemu mode 则 get_qemu_argv

### Dry Run

**在这一部分，AFL 会执行首轮 fuzz，预热。**

1. perform_dry_run<font color='red'>*</font> 
   1. 依次读取 queue 中内容
   2. 调用 calibrate_case 校准测试用例，得到返回值 `res`
   3. 根据 `res` 判断错误类型

   

2. cull_queue<font color='red'>*</font> 精简队列

   

3. show_init_stats 显示这一轮 dry run 的统计信息

   

4. find_start_position 从 fuzzer_stats 中找到当前测试用例，以便从这个位置继续

   

5. write_stats_file 在 fuzzer_stats 中创建新的统计数据

   

6. save_auto 将这一轮过程中产生的 token 保存在 <font color='grey'>"out_dir/queue/.state/auto_extras/auto_%06u" % cnt </font> 目录下

### Main Loop

**模糊测试终于开始了，在这一部分 AFL 会反复如下执行，直至停止条件满足。**

1. cull_queue

   

2. 如果当前 `queue_cur` 为空，代表已经遍历完一遍队列，初始化到队首重新遍历

   * show_stats 显示信息

   * 如果这一轮队列与上一轮完全相同，说明此轮 fuzz 没有效果，则重组变异策略

     

3. fuzz_one<font color='red'>*</font> 对 `queue_cur` 指示的测试用例进行测试

   

4. 移动 `queue_cur`

关闭方式有两种，programmatically （设置 `stop_soon`）以及 by user（ctrl-c）

### Exit

**在这一部分 AFL 会保存测试结果，并圆润地关闭自己**

1. 向还没关掉的子进程以及 forkserver 进程发送 kill 信号，并等待它们圆润地关闭

   

2. write_bitmap 保存 bitmap 到硬盘，通常是为了 -B 选项进一步 fuzz

   

3. write_stats_file

   

4. save_auto

   

5. destroy_queue, destroy_extras 销毁内存

   

6. exit(0)

## 第 1 次执行

**紧接上文，AFL 调用 perform_dry_run 开启对队列的第一轮遍历，如果有错误或者不合适的测试用例及时报错。结束后使用 cull_queue 修剪测试队列。**

###  perform_dry_run()

![](https://s2.loli.net/2022/01/18/daJQr3UFs8k5SN9.png)

遍历队列，对其中每个元素进行如下操作

1. 打开文件，读出内容

    

2. 将其传入 calibrate_case，得到返回值 `res` 

    

3. 根据返回值判断错误

* FAULT_NONE 队列没有元素错误。check_map_coverage 后结束。
* FAULT_TMOUT 当前元素超时错误。判断 `timeout_given` 设置，为 2 则跳过该元素。
* FAULT_CRASH 初始元素就引发了崩溃。需要排除 Out Of Memory（`mem_limit` 太小） 与 MacOS （非标准平台下的 fork 系统调用）问题。如果确实需要从崩溃元素开始变异，应该开启 crash mode.
* FAULT_ERROR 目标程序无法执行
* FAULT_NOINST 没检测到插桩代码
* FAULT_NOBITS 无用测试用例。如果 `in_bitmap` 没有初始化，且不让打乱顺序（ `shuffle_queue` 指示），则报警。

### calibrate_case()

> 该函数在 perform_dry_run, save_if_interesting, fuzz_one 中均会调用。每个测试轮都会对测试用例遍历，而对每个测试用例都会进行多轮校验。

init_forkserver 确保开启 forkserver ，获取当前时间。

将初始 `trace_bits` 保存到 `first_trace` ，has_new_bits<font color='red'>*</font> 检查  `trace_bits`  是否改变（相比于 `virgin_bits` ），`new_bits` 存放返回值。设定校准轮数 `stage_max` . 每一轮校准如下：

1. write_to_testcase 将新的内容写入测试用例

   

2. run_target 做一次 fuzz，这次执行中的路径记录会保存在 `trace_bits` 。

   

3. 如果 `count_bytes(trace_bits)` 返回 0，则返回 FAULT_NONE 错误

   

4. 用 `trace_bits` 计算 `cksum` ，如果改变则调用 has_new_bits 更新 `new_bits` . 并且在非 dry run 时，如果 `trace_bits` 发生了改变则调大校准轮数。

这个测试用例的校准结束，收集信息。调用 update_bitmap_score<font color='red'>*</font> 更新此队列优胜者。

如果这是第一轮，该测试用例经过校验以后 `new_bits` 还是 0，则返回 FAULT_NOBITS 错误。

如果 `new_bits` 为 2，代表有新的路径产生.	

## 第 n 次执行

**AFL 区分第 1 轮与第 n 轮是为了 Fall-Fast, 但不管是哪一轮，其总体逻辑均相同。Dry run 结束后，每一轮对每一个测试用例均调用 fuzz_one 进行测试，然后 cull_queue 修剪队列。**

###  fuzz_one()

![](https://s2.loli.net/2022/01/18/t6m1zHYdLOKQwIp.png)

以队列中的元素为参数，获取该测试用例内容，喂给目标程序。

1. 根据队列优胜者机制，按特定概率跳过此元素。跳过则直接返回。

   

2. 如果上一轮 calibrate_case 产生校对错误，获取得到的 `cal_failed` 计数，小于 `CAL_CHANCES` 时重新调用 calibrate_case，防止产生非法 `trace_bits`.

   

3. 调用 trim_case 对当前元素进行剪枝，即使失败也只剪一次。

   

4. 调用 calculate_score 对当前元素打分，用于 havoc_stage

   

5. 开始变异（每经过一个阶段都会调用 common_fuzz_stuff ） 

   1. simple bitflip（+ dictionary construction）
   2. arithmetic inc/dec
   3. interesting values
   4. dictionary stuff
   5. random havoc
   6. splicing

### common_fuzz_stuff()

将变异得到的测试用例写进硬盘，执行目标程序并将其喂给它，收集结果并处理错误。

1. write_to_testcase 
2. run_target 执行
3. save_if_interesting

### trim_case()

减少测试用例大小，细节略。

### calculate_score()


> Calculate case desirability score to adjust the length of havoc fuzzing. A helper function for fuzz_one(). Maybe some of these constants should go into config.h.

该函数打分是为了变异的 havoc 过程。给执行时间短，代码覆盖高，新发现的，路径深度深的测试用例拥有更多 havoc 变异的机会。细节略。

### save_if_interesting()

> Check if the result of an execve() during routine fuzzing is interesting, save or queue the input test case for further analysis if so. Returns 1 if entry is saved, 0 otherwise.

`has_new_bits(virgin_bits)` 返回值为 0 时直接返回，否则将测试用例放入测试队列文件夹并如下命名（describe_op 会分析该测试用例是如何变异得到的）：

`fn = alloc_printf("%s/queue/id:%06u,%s", out_dir, queued_paths,describe_op(hnb))` 

然后 add_to_queue 为此测试用例开辟空间并放入队列中。重新计算队列 checksum 后将测试用例内容写入并调用 calibrate_case 校验错误码。在校验的过程中记录 crashes 与 hangs 文件夹。

 

