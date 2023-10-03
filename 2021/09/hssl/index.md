# 2021 华为夏季实习回顾


&nbsp; &nbsp; &nbsp; 今年上半年很荣幸能通过华为奇点二进制安全实验室的面试，并在暑假进行为期两月的实习。

<!--more-->

&nbsp; &nbsp; &nbsp; 奇点实验室作为华为北研所的核心安全部门，由十几位安全技术狂热爱好者组成，组内人员包括科恩实验室创始人之一、前`DEFCON CTF`腾讯联队队长、前腾讯湛泸实验室技术高管等业内顶尖技术人员。组内任务对标长亭与科恩实验室，负责鸿蒙内核安全防护、车联网安全等华为技术核心，代表了国内最高的安全研究实验室水平。笔者抱着对安全技术的敬畏、渴求之心，与大佬们和谐相处了两个月，在此简略回顾一下（其实是因为教学秘书非要我提交实习回顾报告...）。


&nbsp; &nbsp; &nbsp; 令人印象最深刻的是，实验室是高度自由的。职员只需要早上9:30到晚上6:00在公司即可，组内技术面也很广，给了我极大的选择自由。气氛也十分活跃轻松，大家经常一起吃饭、讨论技术问题，在这里并没有太多职位的高低之分，只有一个对技术执着追求的团体。


&nbsp; &nbsp; &nbsp; 最初我参与到华为车联网安全的研究当中，主要涉及到车载蓝牙`BLE`协议的安全问题。自从科恩实验室几年前攻击特斯拉车载系统成功开始，车联网安全逐渐成为各大厂的安全重头。这是华为安全的一个长期技术目标，主要分为三个阶段，预计在下半年甚至近几年完成。第一阶段为信息收集。组内详细收集了国内外攻击案例、查阅近几年相关CVE，并尝试总结出常见攻击面。同时收集总结了国内外常见汽车品牌，包括大众、奥迪、奔驰等，并具体到车型，收集不同车型的具体架构信息、车载系统信息、蓝牙等短距协议的功能信息、ivi总线信息等。这是一个非常繁琐、枯燥的枯燥，并且这个阶段的完成质量会极大程度地影响后续的安全研究与技术突破，毕竟知己知彼百战不殆。笔者参与到收集宝马x7车型信息的工作中，在这个过程中了解到车载系统比想象中的复杂许多，并且从零开始了解了一些蓝牙`BLE`协议的知识，包括其协议栈、编程细节、时序等。第二阶段为逆向车联网APP及其协议，尝试寻找漏洞并完善攻击链。目前大部分车型都会联动手机APP，提供遥控开锁、控制等功能。我们会在测试机中下载各个车型的APP进行一定程度的逆向，通过对其协议与交互过程的逆向，尝试找到漏洞。实际上组内已经找到了一些针对BLE协议的漏洞，并进行中继攻击等，笔者也在这个过程中参与到安卓逆向工作。但这只是攻击链的第一环，后续还需要有针对车载系统的进一步提权攻击、对ivi网关的限制逃逸甚至是浏览器的`0day`漏洞等。整个过程涉及到对很多技术的深入理解，也正印证了那句老话“团结力量大”，整条攻击链在实验室中都能找到对其有钻研的技术大佬，整个过程也在如火如荼地同步进行。最后一个阶段将进行实车实验，尝试通过租车、公司购车等方式拿到具体车型，进行进一步地详细尝试，完善细节。


&nbsp; &nbsp; &nbsp; 在这个过程中组内某内核安全大佬利用`Mali GPU`的`0day`漏洞完成了对安卓内核的越权，笔者深感佩服，遂即开启自己的Linux内核学习。内核态的学习异常艰难，笔者从CTF题入手慢慢复现常见漏洞利用技术，并尝试理解一些早年内核CVE，产出了一些技术概述文档。虽然只有一些微不足道的进步，但笔者内心十分感谢实验室给予我的自由、尊重与帮助。


&nbsp; &nbsp; &nbsp; 值得一提的是，实验室会组织参与周会、每周一次的CTF训练、每周一到两次的技术分享与不定期的CTF比赛。可以看到组内成员技术交流是十分频繁的，毕竟大家的技术专长不尽相同，组内成员仿佛总有讨论不完的问题。我还记得参与到2021强网杯决赛的场景，实验室与浙大`AAA`战队合作，拿到了全国第三名的成绩。决赛赛制为`cold down`（CTF解题）与`real world`（现场演示）混合，题目质量很高，也很刺激。比赛刚开始没多久，实验室两位巨佬利用老练的技术积累迅速做出了`real world`中MacOS、Windows的系统提权，并打穿了浏览器，甚至拿到了系统的最高权限，因为主办方的要求被迫再降级到`medium`权限，笔者直呼太离谱了。笔者跟着`AAA`的小伙伴看了几道`cold down`，做完以后到了第一天傍晚，开始和实验室另一小伙伴一起all in一道`real world`: ESXI虚拟机逃逸。一开始我们找到了一些资料，发现了一些堆溢出漏洞。大家欣喜若狂，动手调试时才发现堆内存过于难以捉摸，虽然确实是有堆溢出，但是排堆过程令人头疼欲裂，实际应用中的内存结构并不是那么地清晰。不知不觉已经到了半夜，实验室开始投入更多人手，大家都从堆溢出入手慢慢地努力着。半夜两三点我太困就睡下了，第二天起来发现大家还是没有做出来这题，我们再次不断尝试直到比赛快要结束，这时有人发现了另外一个内核漏洞，可以导致加载任意驱动。大家渐渐投入到这个漏洞的利用编写中，但很遗憾在比赛过后的几天才得以利用成功。整个过程对我来说是弥足珍贵的，有幸能参与浙大与科恩长亭的混战，`AAA`从赛前训练动员、到中场会议调整人员、到半夜醒神动员都做的很好，也在陈少和耕铭等巨佬身上看到了去年`DEFCON CTF`夺冠的原因，`A*O*E`确实值得一个世界冠军。


&nbsp; &nbsp; &nbsp; 现在回顾起来，庆幸自己有这个机会去了解实际安全背景下的安全挑战与机遇。但也很遗憾，由于个人的升学大计，笔者很难将精力与时间百分之百投入到实习工作中。尽管每天压力不小，但内心对于技术的追求与对大佬的向往之情从未减少。现在坐在工大的校园里，想起这段回忆有种返璞归真的奇妙感觉，也明白自己可能在很长一段时间内都不会再进入企业。最后，还是想对实验室给我提供无私、耐心帮助的大佬们说一声衷心地感谢，分别匆忙，见谅。

![](https://i.loli.net/2021/09/15/fqxWNCboKTu915d.png)

![](https://i.loli.net/2021/09/15/Mt4CGP2AkvjlQ18.png)

![](https://i.loli.net/2021/09/15/ndw6MLxyWjERuYC.png)

![](https://i.loli.net/2021/09/15/N3yn5mJKY4valzA.png)

{{< admonition question >}}
如果本文有任何私人、公司信息泄露，请立即与我告知，抱歉
{{< /admonition >}}		



