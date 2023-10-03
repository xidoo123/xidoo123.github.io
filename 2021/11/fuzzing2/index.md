# American Fuzzy Lop tutorial-Challenge #libxml2


This is a white-box fuzzing libxml2 v2.9.2 challenge[1] to reproduce CVE-2015-8317[2] 

Congrats to QuiHao by the way, a brand new qemu 0day Orzzzz!!!

<!--more-->

> The xmlParseXMLDecl function in parser.c in libxml2 before 2.9.3 allows context-dependent attackers to obtain sensitive information via an (1) unterminated encoding value or (2) incomplete XML declaration in XML data, which triggers an out-of-bounds heap read.

### Environment Setup

Download `libxml2 @ 726f67e` and check the version, build and instrument by running:

```shell
	cd libxml2
    CC=afl-clang-fast ./autogen.sh
    AFL_USE_ASAN=1 make -j 4
```

Here we go

```shell
x1do0@x1do0:~/fuzzing/afl-training/challenges/libxml2/libxml2.9.2$ ./testModule
Success!
```

### Find target

According to NVD, function `/parse.c/xmlParseXMLDecl` is to blame. But we cannot simply test this function because this is not the entrance for users. Hint:

> This functionality is exposed in the [parser](http://xmlsoft.org/html/libxml-parser.html) API, and whilst you could dig
>
> through this documentation, the easiest approach is to look at an example.
>
> [`parse1.c`](http://xmlsoft.org/examples/parse1.c) (also in the repo under doc/examples/parse1.c) shows two core
>
> functions: `xmlReadFile` followed by `xmlFreeDoc`.

### Write harness

To avoid forking process every time, AFL has a keyword `__AFL_LOOP()` to largely speed things up. 

> `__AFL_LOOP(1000)` is a macro that detects if the program is running under AFL. If it is, the loop will run 1000 times and 1000 different inputs will be fed to the library. After that, the process is torn down then restarted by AFL. This ensures we regularly replace the process to avoid memory leaks.
>
> But if the program runs on his own (i.e. launched with `./harness_persistent` and not AFL) the loop runs only once. This way we can process testcases from the command line without looping a thousand time. This mean we can use gdb or automated tools to inspect the crashes found by the fuzzer using the same binary.

#### Use file-input to fuzz

In libxml2, `parse1` allow us to parse from a file.

> [parse1.c](http://xmlsoft.org/examples/parse1.c): Parse an XML file to a tree and free it
>
> Demonstrate the use of xmlReadFile() to read an XML file into a tree and xmlFreeDoc() to free the resulting tree
>
> Includes:
>
> - (http://xmlsoft.org/html/libxml-tree.html)
> - (http://xmlsoft.org/html/libxml-parser.html)
>
> Uses:
>
> - line 24: Type [xmlDocPtr](http://xmlsoft.org/html/libxml-tree.html#xmlDocPtr) from tree.h
> - line 26: Function [xmlReadFile](http://xmlsoft.org/html/libxml-parser.html#xmlReadFile) from parser.h
> - line 31: Function [xmlFreeDoc](http://xmlsoft.org/html/libxml-tree.html#xmlFreeDoc) from tree.h
> - line 45: Macro [LIBXML_TEST_VERSION](http://xmlsoft.org/html/libxml-xmlversion.html#LIBXML_TEST_VERSION) from xmlversion.h
> - line 50: Function [xmlCleanupParser](http://xmlsoft.org/html/libxml-parser.html#xmlCleanupParser) from parser.h
> - line 54: Function [xmlMemoryDump](http://xmlsoft.org/html/libxml-xmlmemory.html#xmlMemoryDump) from xmlmemory.h
>
> Usage:
>
>       parse1 test1.xml
>
> Author: Daniel Veillard

I wrote a simple harness and start to fuzz.

```c
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <libxml/tree.h>
#include <libxml/parser.h>

int main(int argc, char* argv[])
{
        if(argc==2){
                while (__AFL_LOOP(1000)) {
                        xmlDocPtr doc = xmlReadFile(argv[1], NULL, 0);
                        if (doc != NULL)
                                xmlFreeDoc(doc);
                }
                xmlCleanupParser();
        }
        else
                printf("Usage: %s filename\n", argv[0]);
        return 1;
}
```

compile command line:

` AFL_USE_ASAN=1 afl-clang-fast ./harness.c -I libxml2.9.2/include libxml2.9.2/.libs/libxml2.a -lz -lm -o fuzzer`

Startup command line:

`afl-fuzz -i ./in -o ./out ./fuzzer @@`

#### Use `stdin` to fuzz

Another way, according to the HINTS, is to use  parse3

> [parse3.c](http://xmlsoft.org/examples/parse3.c): Parse an XML document in memory to a tree and free it
>
> Demonstrate the use of xmlReadMemory() to read an XML file into a tree and xmlFreeDoc() to free the resulting tree
>
> Includes:
>
> - (http://xmlsoft.org/html/libxml-tree.html)
> - (http://xmlsoft.org/html/libxml-parser.html)
>
> Uses:
>
> - line 27: Type [xmlDocPtr](http://xmlsoft.org/html/libxml-tree.html#xmlDocPtr) from tree.h
> - line 33: Function [xmlReadMemory](http://xmlsoft.org/html/libxml-parser.html#xmlReadMemory) from parser.h
> - line 38: Function [xmlFreeDoc](http://xmlsoft.org/html/libxml-tree.html#xmlFreeDoc) from tree.h
> - line 49: Macro [LIBXML_TEST_VERSION](http://xmlsoft.org/html/libxml-xmlversion.html#LIBXML_TEST_VERSION) from xmlversion.h
> - line 54: Function [xmlCleanupParser](http://xmlsoft.org/html/libxml-parser.html#xmlCleanupParser) from parser.h
> - line 58: Function [xmlMemoryDump](http://xmlsoft.org/html/libxml-xmlmemory.html#xmlMemoryDump) from xmlmemory.h
>
> Usage:
>
>       parse3
>
> Author: Daniel Veillard

Check [4] for more information about how to use these functions

```c
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <libxml/tree.h>
#include <libxml/parser.h>

int SIZE = 1000; // fix buf size based on assumptions

int main()
{
        char buf[SIZE];
        ssize_t length;
        while (__AFL_LOOP(1000)) {
                length = read(STDIN_FILENO, buf, SIZE);
                xmlDocPtr doc = xmlReadMemory(buf, SIZE, NULL, NULL, 0);
                if( doc!= NULL)
                        xmlFreeDoc(doc);
        }
        xmlCleanupParser();
        return 1;
}
```

Compile command line:

` AFL_USE_ASAN=1 afl-clang-fast ./harness2.c -I libxml2.9.2/include libxml2.9.2/.libs/libxml2.a -lz -lm -o fuzzer2`

Startup command line:

`afl-fuzz -i ./in -o ./out2 ./fuzzer2`

### Results

In merely one hour, our first harness produces 5 unique crashes, which is actually the same one. ASAN reports a heap-buffer-overflow in `xmlDictComputeFastQKey /home/x1do0/fuzzing/afl-training/challenges/libxml2/libxml2.9.2/dict.c:489`

![](https://i.loli.net/2021/11/14/17PXBpM5JsQZOFi.png)

Check for the source code, we found a reference of array `name` with unchecked index, causing this OOB.

![](https://i.loli.net/2021/11/14/ZqdbiDmR4Jht8sC.png)

So actually, we found CVE-2015-7497[5] accidentally XD, see patchwork[6] 

![](https://i.loli.net/2021/11/14/laF1SPQmu8VXY4o.png)

After 2 hours, another unique crash pops out!

![](https://i.loli.net/2021/11/14/dDfBVAk3Ilot8m7.png)

umm, sounds like this shallow bug hides CVE-2015-8317, according to [7]. Maybe AFL need more time.

![](https://i.loli.net/2021/11/14/zBvqnK9ER1Muaps.png)

### Final Statistic

These are the screen shot for two harnesses right before I stopped.

Harness 1 has a stability of 91.39% and find more crashes in less time.

![](https://i.loli.net/2021/11/14/IPNGy6hJXkzS9El.png)

Harness 2 run for about 1.5 hour but find less crashes with pretty low stability.

![](https://i.loli.net/2021/11/14/8iMbOftA5LGnZNm.png)

Also, I found 6 crashes which did not crash at all.

```shell
x1do0@x1do0:~/fuzzing/afl-training/challenges/libxml2$ cat ./out2/default/crashes/id\:000000\,sig\:06\,src\:000803\,time\:1266536\,op\:havoc\,rep\:4 |
> ./fuzzer2
Entity: line 1: parser error : Char 0x0 out of allowed range
SSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSh:
                                                                               ^
namespace error : Failed to parse QName 'SSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSjSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSCSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSh:'
SSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSh:
                                                                               ^
Entity: line 1: parser error : Char 0x0 out of allowed range
SSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSh:
                                                                               ^
Entity: line 1: parser error : Couldn't find end of Start Tag SSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSjSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSCSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSh: line 1
SSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSh:
```

And a bug where I did not figure out what happened.

```
AddressSanitizer:DEADLYSIGNAL
=================================================================
==1053695==ERROR: AddressSanitizer: SEGV on unknown address 0x618ffffffef6 (pc 0x5592fbf3a477 bp 0x000000000006 sp 0x7ffd30ec62e0 T0)
==1053695==The signal is caused by a READ memory access.
    #0 0x5592fbf3a476 in xmlDictComputeFastQKey /home/x1do0/fuzzing/afl-training/challenges/libxml2/libxml2.9.2/dict.c:489
    #1 0x5592fbf42942 in xmlDictQLookup /home/x1do0/fuzzing/afl-training/challenges/libxml2/libxml2.9.2/dict.c:1093
    #2 0x5592fbf5813f in xmlSAX2StartElementNs /home/x1do0/fuzzing/afl-training/challenges/libxml2/libxml2.9.2/SAX2.c:2238
    #3 0x5592fbb9495f in xmlParseStartTag2 /home/x1do0/fuzzing/afl-training/challenges/libxml2/libxml2.9.2/parser.c:9707
    #4 0x5592fbbbae5e in xmlParseElement /home/x1do0/fuzzing/afl-training/challenges/libxml2/libxml2.9.2/parser.c:10069
    #5 0x5592fbbb763d in xmlParseContent /home/x1do0/fuzzing/afl-training/challenges/libxml2/libxml2.9.2/parser.c:9982
    #6 0x5592fbbbb5d9 in xmlParseElement /home/x1do0/fuzzing/afl-training/challenges/libxml2/libxml2.9.2/parser.c:10155
    #7 0x5592fbbb763d in xmlParseContent /home/x1do0/fuzzing/afl-training/challenges/libxml2/libxml2.9.2/parser.c:9982
    #8 0x5592fbbbb5d9 in xmlParseElement /home/x1do0/fuzzing/afl-training/challenges/libxml2/libxml2.9.2/parser.c:10155
    #9 0x5592fbbb763d in xmlParseContent /home/x1do0/fuzzing/afl-training/challenges/libxml2/libxml2.9.2/parser.c:9982
    #10 0x5592fbbbb5d9 in xmlParseElement /home/x1do0/fuzzing/afl-training/challenges/libxml2/libxml2.9.2/parser.c:10155
    #11 0x5592fbbb763d in xmlParseContent /home/x1do0/fuzzing/afl-training/challenges/libxml2/libxml2.9.2/parser.c:9982
    #12 0x5592fbbbb5d9 in xmlParseElement /home/x1do0/fuzzing/afl-training/challenges/libxml2/libxml2.9.2/parser.c:10155
    #13 0x5592fbbb763d in xmlParseContent /home/x1do0/fuzzing/afl-training/challenges/libxml2/libxml2.9.2/parser.c:9982
    #14 0x5592fbbbb5d9 in xmlParseElement /home/x1do0/fuzzing/afl-training/challenges/libxml2/libxml2.9.2/parser.c:10155
    #15 0x5592fbbb763d in xmlParseContent /home/x1do0/fuzzing/afl-training/challenges/libxml2/libxml2.9.2/parser.c:9982
    #16 0x5592fbbbb5d9 in xmlParseElement /home/x1do0/fuzzing/afl-training/challenges/libxml2/libxml2.9.2/parser.c:10155
    #17 0x5592fbbb763d in xmlParseContent /home/x1do0/fuzzing/afl-training/challenges/libxml2/libxml2.9.2/parser.c:9982
    #18 0x5592fbbbb5d9 in xmlParseElement /home/x1do0/fuzzing/afl-training/challenges/libxml2/libxml2.9.2/parser.c:10155
    #19 0x5592fbbb763d in xmlParseContent /home/x1do0/fuzzing/afl-training/challenges/libxml2/libxml2.9.2/parser.c:9982
    #20 0x5592fbbbb5d9 in xmlParseElement /home/x1do0/fuzzing/afl-training/challenges/libxml2/libxml2.9.2/parser.c:10155
    #21 0x5592fbbb763d in xmlParseContent /home/x1do0/fuzzing/afl-training/challenges/libxml2/libxml2.9.2/parser.c:9982
    #22 0x5592fbbbb5d9 in xmlParseElement /home/x1do0/fuzzing/afl-training/challenges/libxml2/libxml2.9.2/parser.c:10155
    #23 0x5592fbbdb56b in xmlParseDocument /home/x1do0/fuzzing/afl-training/challenges/libxml2/libxml2.9.2/parser.c:10841
    #24 0x5592fbbde0ba in xmlDoRead /home/x1do0/fuzzing/afl-training/challenges/libxml2/libxml2.9.2/parser.c:15298
    #25 0x5592fbb0e99b in main harness.c:12
    #26 0x7f460f7960b2 in __libc_start_main (/lib/x86_64-linux-gnu/libc.so.6+0x270b2)
    #27 0x5592fbb0f45d in _start (/home/x1do0/fuzzing/afl-training/challenges/libxml2/fuzzer+0x6e45d)

AddressSanitizer can not provide additional info.
SUMMARY: AddressSanitizer: SEGV /home/x1do0/fuzzing/afl-training/challenges/libxml2/libxml2.9.2/dict.c:489 in xmlDictComputeFastQKey
==1053695==ABORTING
```

So please let me know if my **harness2** is wrong. What's more, someone found two more bugs. Check [7] for more details.

```
Indirect leak of 48 byte(s) in 1 object(s) allocated from:
    #0 0x4c250c in __interceptor_malloc
    #1 0x5ef0fd in xmlNewDocElementContent valid.c:952:34
    #2 0x532c2b in xmlParseElementMixedContentDecl parser.c:6200:16
    #3 0x5367cd in xmlParseElementContentDecl parser.c:6624:16
    #4 0x537843 in xmlParseElementDecl parser.c:6691:12
    #5 0x538b84 in xmlParseMarkupDecl parser.c:6934:4
    #6 0x562fd7 in xmlParseInternalSubset parser.c:8401:6
    #7 0x56166e in xmlParseDocument parser.c:10809:6
    #8 0x57fe49 in xmlDoRead parser.c:15298:5
    #9 0x4f0f87 in LLVMFuzzerTestOneInput

==235609==ERROR: AddressSanitizer: heap-use-after-free ...
READ of size 1 at 0x625000002908 thread T0
    #0 0x77503e in xmlDictComputeFastKey dict.c:448:13
    #1 0x77503e in xmlDictLookup dict.c:848
    #2 0x573b6f in xmlParseNCNameComplex parser.c:3506:12
    #3 0x573b6f in xmlParseNCName parser.c:3565
    #4 0x57283c in xmlParseQName parser.c:8815:9
    #5 0x548877 in xmlParseStartTag2 parser.c:9336:17
    #6 0x544bd0 in xmlParseElement parser.c:10069:16
    #7 0x543a85 in xmlParseContent parser.c:9982:6
    #8 0x5457bb in xmlParseElement parser.c:10155:5
    #9 0x55540b in xmlParseDocument parser.c:10841:2
    #10 0x5706c1 in xmlDoRead parser.c:15298:5
    #11 0x4f7997 in LLVMFuzzerTestOneInput

```

### References

[1] https://github.com/mykter/afl-training/tree/main/challenges/libxml2

[2] https://nvd.nist.gov/vuln/detail/CVE-2015-8317

[3] https://toastedcornflakes.github.io/articles/fuzzing_capstone_with_afl.html 

[4] http://xmlsoft.org/examples/index.html

[5] https://www.cvedetails.com/cve/CVE-2015-7497/

[6] https://github.com/GNOME/libxml2/compare/v2.9.2...CVE-2015-7497

[7] https://github.com/google/fuzzer-test-suite/tree/master/libxml2-v2.9.2




