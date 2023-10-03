# American Fuzzy Lop tutorial-basic


After all these frustrations due to the virus, I finally get back on the right track. American fuzzy lop (AFL) is a security-oriented fuzzer that employs a novel type of compile-time instrumentation and genetic algorithms to automatically discover clean, interesting test cases that trigger new internal states in the targeted binary.

<!--more-->

### Overall

This training comes from Github [1] for AFL[2]. According to [3], considering AFL

**Its Benefits:**

- Supports blackbox and whitebox testing. (with or without source code)
- Supports expanding to your own implementation needs
- Uses genetic fuzzing techniques

**Its Cons**:

- Not multi-threaded
- Does not offer any ability to fuzz network protocols natively

I decide to learn fuzzing, starting from AFL.

### QuickStart

Install all the dependencies and AFL++ in this section according to the documents. When I was doing this, I got some errors and managed to fix them as follows.

Remember to find your own path to the following to walk around some Ubuntu annoyances, otherwise you will get the error indicating you are using the outdated clang and llvm. It worked for me on Ubuntu 20.04

```
$ sudo update-alternatives --install /usr/bin/clang clang /usr/bin/clang-11 1
$ sudo update-alternatives --install /usr/bin/clang++ clang++ /usr/bin/clang++-11 1
$ sudo update-alternatives --install /usr/bin/llvm-config llvm-config /usr/bin/llvm-config-11 1
$ sudo update-alternatives --install /usr/bin/llvm-symbolizer llvm-symbolizer /usr/bin/llvm-symbolizer-11 1
```

While trying to start the AFL, I got this which meant that the crashes were not reported to AFL but to the system which is quite normal, so just get the root privilege and do what it said. 

![](https://i.loli.net/2021/11/08/To4el5NcFxwiz9V.png)

`echo core > /proc/sys/kernel/core_pattern`

Finally, I got to start. 

![](https://i.loli.net/2021/11/08/QYpVxEiFmkN8Ld6.png)

Checking for the crashes results, we did find 5 bugs.

```
x1do0@x1do0:~/fuzzing/afl-training/quickstart/out/default/crashes$ ls -la
total 32
drwx------ 2 x1do0 x1do0 4096 Nov  8 04:52 .
drwx------ 6 x1do0 x1do0 4096 Nov  8 05:04 ..
-rw------- 1 x1do0 x1do0   29 Nov  8 04:06 id:000000,sig:11,src:000001,time:865,op:havoc,rep:2
-rw------- 1 x1do0 x1do0   36 Nov  8 04:06 id:000001,sig:06,src:000009,time:3487,op:havoc,rep:2
-rw------- 1 x1do0 x1do0   36 Nov  8 04:06 id:000002,sig:11,src:000006+000003,time:5027,op:splice,rep:8
-rw------- 1 x1do0 x1do0   39 Nov  8 04:06 id:000003,sig:06,src:000005,time:5202,op:havoc,rep:16
-rw------- 1 x1do0 x1do0  210 Nov  8 04:25 id:000004,sig:06,src:000006,time:1182862,op:havoc,rep:4
-rw------- 1 x1do0 x1do0  556 Nov  8 04:06 README.txt
x1do0@x1do0:~/fuzzing/afl-training/quickstart$ cat ./out/default/crashes/id:000000,sig:11,src:000001,time:865,op:havoc,rep:2
head 21111�1111111111111110
x1do0@x1do0:~/fuzzing/afl-training/quickstart$ ./vulnerable < ./out/default/crashes/id:000000,sig:11,src:000001,time:865,op:havoc,rep:2865,op:havoc,rep:2
Segmentation fault
```

I could only find 3 bugs in short time after changing the input example provided. 

```
x1do0@x1do0:~/fuzzing/afl-training/quickstart/out2/default/crashes$ ls -la
total 24
drwx------ 2 x1do0 x1do0 4096 Nov  8 09:36 .
drwx------ 6 x1do0 x1do0 4096 Nov  8 09:39 ..
-rw------- 1 x1do0 x1do0   45 Nov  8 09:36 id:000000,sig:06,src:000003,time:3711,op:havoc,rep:32
-rw------- 1 x1do0 x1do0   27 Nov  8 09:36 id:000001,sig:11,src:000003,time:5635,op:havoc,rep:2
-rw------- 1 x1do0 x1do0   42 Nov  8 09:36 id:000002,sig:06,src:000012+000005,time:6503,op:splice,rep:16
-rw------- 1 x1do0 x1do0  557 Nov  8 09:36 README.txt
```

Up to now you can read the resource code to check the bugs. But here what I want to say is, at this time we don't need to write a harness(see the following section), because the program itself uses `stdin` to receive inputs.

```c
// vulnerable.c
int main(int argc, char *argv[])
{
	char *usage = "Usage: %s\n"
				  "Text utility - accepts commands and data on stdin and prints results to stdout.\n"
				  "\tInput             | Output\n"
				  "\t------------------+-----------------------\n"
				  "\tu <N> <string>    | Uppercased version of the first <N> bytes of <string>.\n"
				  "\thead <N> <string> | The first <N> bytes of <string>.\n";
	char input[INPUTSIZE] = {0};

	// Slurp input
	if (read(STDIN_FILENO, input, INPUTSIZE) < 0)
	{
		fprintf(stderr, "Couldn't read stdin.\n");
	}

	int ret = process(input);
	if (ret)
	{
		fprintf(stderr, usage, argv[0]);
	};
	return ret;
}
```

Let's consider the startup command for AFL, we can see that AFL regard `inputs` as seeds and send to `stdin` of the tested program `vulnerable`. 

`alf-fuzz -i inputs -o out ./vulnerable`



### Harness

In this section, we will encounter some kinds of situation where there is nowhere to send input using AFL, which makes writing a harness program is a must.

The example program about to test contains just two functions implemented, we should at least write a `main` to call these functions instead of throwing it directly to AFL.

```c
// library.c
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>

#include "library.h"

void lib_echo(char *data, ssize_t len){
	if(strlen(data) == 0) {
		return;
	}
	char *buf = calloc(1, len);
	strncpy(buf, data, len);
	printf("%s",buf);
	free(buf);

	// A crash so we can tell the harness is working for lib_echo
	if(data[0] == 'p') {
		if(data[1] == 'o') {
			if(data[2] =='p') {
				if(data[3] == '!') {
					assert(0);
				}
			}
		}
	}
}

int  lib_mul(int x, int y){
	if(x%2 == 0) {
		return y << x;
	} else if (y%2 == 0) {
		return x << y;
	} else if (x == 0) {
		return 0;
	} else if (y == 0) {
		return 0;
	} else {
		return x * y;
	}
}

```

#### Use `stdin` to input

```c
// harness1.c
#include <unistd.h>
#include <string.h>
#include <stdio.h>

#include "library.h"

// fixed size buffer based on assumptions about the maximum size that is likely necessary to exercise all aspects of the target function
#define SIZE 100

int main(int argc, char* argv[]) {
	if((argc == 2) && strcmp(argv[1], "echo") == 0) {
		// make sure buffer is initialized to eliminate variable behaviour that isn't dependent on the input.
		char input[SIZE] = {0};

		ssize_t length;
		length = read(STDIN_FILENO, input, SIZE);

		lib_echo(input, length);
	} else if ((argc == 2) && strcmp(argv[1], "mul") == 0) {
		int a,b = 0;
		read(STDIN_FILENO, &a, 4);
		read(STDIN_FILENO, &b, 4);
		printf("%d\n", lib_mul(a,b));
	} else {
		printf("Usage: %s mul|echo\n", argv[0]);
	}
}
```

Compile it with library.c

```
x1do0@x1do0:~/fuzzing/afl-training/harness$ AFL_HARDEN=1 afl-clang-fast harness1.c library.c -o harness1
afl-cc ++3.15a by Michal Zalewski, Laszlo Szekeres, Marc Heuse - mode: GCC_PLUGIN-DEFAULT
afl-gcc-pass ++3.15a by <oliva@adacore.com>
[*] Inline instrumentation at ratio of 100% in hardened mode.
harness1.c: In function ‘main’:
harness1.c:21:3: warning: ignoring return value of ‘read’, declared with attribute warn_unused_result [-Wunused-result]
   21 |   read(STDIN_FILENO, &a, 4);
      |   ^~~~~~~~~~~~~~~~~~~~~~~~~
harness1.c:22:3: warning: ignoring return value of ‘read’, declared with attribute warn_unused_result [-Wunused-result]
   22 |   read(STDIN_FILENO, &b, 4);
      |   ^~~~~~~~~~~~~~~~~~~~~~~~~
harness1.c: At top level:
cc1: warning: unrecognized command line option ‘-Wno-unused-command-line-argument’
[+] Instrumented 11 locations (hardened mode, inline, ratio 100%).
afl-gcc-pass ++3.15a by <oliva@adacore.com>
[*] Inline instrumentation at ratio of 100% in hardened mode.
[+] Instrumented 15 locations (hardened mode, inline, ratio 100%).
```

Fuzzing like this after creating  `in` directory

```
# first job
afl-fuzz -i in -o out ./harness1 mul
# second job
afl-fuzz -i in -o out ./harness echo
```

And if we want to fuzz in one job testing both of them, we can fix size buffer based on assumptions about the size, for example using the first 8 bytes as input to `lib_mul`, and any remaining bytes as input to `lib_echo`.

#### Use file to input

At that time, honestly I didn't understand the requests here.

> Left as an exercise, as reading from stdin is usually sufficient. The steps are:
>
> 1.  Read a filename from argv
> 2.  Open the specified file and read its contents into a buffer.
> 3.  Pass that buffer to the target function.

If the harness opens the file according to the filename from `argv` and gets the content and sends to the testes program, what does AFL do in this procedure?

Command here is `afl-fuzz -i in -o out ./harness filename`, so the input totally depends on `filename`, so what does `in` use for?

I wrote a harness to test `lib_echo`and type `afl-fuzz -i in -o out ./harness2 testInput`

```c
// harness2.c

#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <fcntl.h>
#include "library.h"

// fixed size buffer
int SIZE = 255;

int main(int argc, char* argv[]) {
        if(argc == 2){
                int fd;
                char buf[SIZE];
                ssize_t length;
                if((fd=open(argv[1], O_RDONLY)) == 0){
                        printf("File open failed!\n");
                        return -1;
                }
                else{
                        length = read(fd, buf, SIZE);
                        lib_echo(buf, length);
                }
        }
        else
                printf("Usage: %s filename\n", argv[0]);
        return 1;
}
```

This was what I got: **odd, check syntax!**, indicating that, as I though before, AFL didn't work.

![](https://i.loli.net/2021/11/13/nhs4eyGBrNO7l8z.png)

Thanks to @QuiHao(see /friends), according to AFL manuals.

> For programs that take input from a file, use ‘@@’ to mark the location in the target’s command line where the input file name should be placed. The fuzzer will substitute this for you:

So actually my harness was right, but the startup command line should be:

`afl-fuzz -i in -o out ./harness2 @@`

And I found a crash `pop!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!kt` in the results, which was exactly what we want!

```c
// A crash so we can tell the harness is working for lib_echo
        if(data[0] == 'p') {
                if(data[1] == 'o') {
                        if(data[2] =='p') {
                                if(data[3] == '!') {
                                        assert(0);
                                }
                        }
                }
        }
```

### Reference

[1] https://github.com/mykter/afl-training

[2] https://github.com/google/AFL

[3] https://bishopfox.com/blog/fuzzing-aka-fuzz-testing






