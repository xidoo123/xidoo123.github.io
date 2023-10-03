# AFL 源码分析（三）forkserver 详解


AFL 源源不断地将变异得到的测试用例喂给待测试程序，这个过程中少不了 fork 与 execve. 为提高效率、减少开销，它实现了一套 forkserver 机制来反复运行并测试程序。

<!--more-->

> “为了更高效地进行上述过程，AFL实现了一套 fork server 机制。其基本思路是：启动 target 进程后，target 会运行一个 fork server；fuzzer 并不负责 fork 子进程，而是与这个 fork server 通信，并由 fork server 来完成 fork 及继续执行目标的操作。这样设计的最大好处，就是不需要调用 `execve()`，从而节省了载入目标文件和库、解析符号地址等重复性工作。如果熟悉 Android 的话，可以将 fork server 类比为 zygote. ”

init_fork_server 函数启动 forkserver.

> Spin up fork server (instrumented mode only). The idea is explained [here](http://lcamtuf.blogspot.com/2014/10/fuzzing-binaries-without-execve.html
> ).
>
> In essence, the instrumentation allows us to skip execve(), and just keep cloning a stopped child. So, we just execute once, and then send commands through a pipe. The other part of this logic is in afl-as.h.	

run_target 函数向 forkserver 发送信号，执行待测试程序并分析执行结果。

> Execute target application, monitoring for timeouts. Return status information. The called program will update trace_bits[].

能搜集到的资料中有不少 forkserver 的分析，其本身也十分容易理解。总的来说，fuzzer 进程是 target 进程的祖先，forkserver 进程本身也是 fuzzer 进程 fork and execve 目标程序得来的。

![](https://s2.loli.net/2022/01/27/PTiSa72LD56ZOGx.png)

fuzzer 在 init_forkserver 中布置好管道，fork 出子进程。父进程（fuzzer）持续存在并收集信息、发送信号，子进程调用 `execv(target_path, argv);`  执行 target. 注意此时没有开始喂入测试用例！这个 target 会执行插桩代码，在程序入口点停下等待 fuzzer 发号施令，并从此充当 forkserver 的角色。之后，当收到 fuzzer 进程执行 run_target 函数发来的信号时，forkserver 进程再 fork 出 target 进程，运行并投喂测试用例，并将结果返回给 fuzzer 进程。

一篇非常清晰的 forkserver 插桩代码分析，见[此文](http://rk700.github.io/2017/12/28/afl-internals/)。

正如白皮书所说，这样可以免去 libc 库链接等重复操作。毕竟每个 target 被 fork 出来便已经到了程序入口点，直接执行即可。可以认为，forkserver 机制免去了每次执行 target 都要运行 execve 的烦扰。

