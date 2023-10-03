# 如何为 Minecraft 服务器添加一个播报员（一）


[Mirai](https://github.com/mamoe/mirai) 是一个在全平台下运行，提供 QQ 协议支持的高效率机器人库。这个项目的名字来源于京都动画作品《境界的彼方》的栗山未来(Kuriyama Mirai)，本文将基于 Mirai 构建 Minecraft 与 QQ 协同的聊天机器人，需求有三

<!--more-->

* 让服务器qq群与mc聊天互通
* 让机器人自动通报事件（比如成就、死亡等）
* 与机器人交互了解服务器情况（比如list显示当前服务器人数等）

### 环境搭建

[此博客](https://blog.csdn.net/TL18382950497/article/details/112321956)提供了以python为开发语言的完整的搭建流程，由于其中某些环节的项目已经停止维护，建议配合这个[清单](https://www.cnblogs.com/lxy764139720/p/15246972.html)来食用！以下是我遇到的其他问题

#### 环境异常，以及如何绕过QQ滑块验证检测

强烈建议先在本地成功得到通过检测的`/bots/qq号码/device.json`后再将其拷贝到服务器上!

如果你和我一样不幸全家都是iphone用户，你可能得准备以下工具

* iTunes

* inspect (https://inspect.dev/why)

我们的目的是拿到登录qq时验证滑块成功通过的流量，其中有个ticket就是我们想要的。iTunes帮助Windows电脑能成功连接iPhone，而Inspect可以拿到手机上的流量

![](https://i.loli.net/2021/11/09/B3ZfXyb1iKCojSD.png)

剩下的就好办了，跟着做就行，把Mirai弹出来的url在手机上打开，滑动滑块的同时在Inspect上拿到result，并填入ticket后回车。这时候会再要求扫码或者弹出一个安全检测，在手机上照着做就成功了。如此，我们让一个不常用设备登录上了qq，这也是在服务器上挂qq机器人必须完成的一步。

![](https://i.loli.net/2021/11/09/2CBfKWe7DRvuAIx.png)

登录一次以后每次都不用验证了，并且找到`/bots/qq号码/device.json`文件将其拷贝到任何设备都可以绕过验证！

#### 版本不匹配造成的更多错误

添加`mirai-api-http`并下载后发现这个错误

![](https://i.loli.net/2021/11/09/1HNu8AEJFlfyKMO.png)

这是我此时的版本清单

```
12:02:02 [INFO] Verifying "org.bouncycastle:bcprov-jdk15on" v1.64
12:02:02 [INFO] Verifying "net.mamoe:mirai-console" v2.8.0-RC
12:02:02 [INFO] Verifying "net.mamoe:mirai-console-terminal" v2.8.0-RC
12:02:02 [INFO] Verifying "net.mamoe:mirai-core-all" v2.8.0-RC
12:02:03 [INFO] Verifying "org.itxtech:mcl-addon" v1.2.2
```

你最好立马从头开始，并使用这个[清单](https://www.cnblogs.com/lxy764139720/p/15246972.html)！通过关掉updator并指定配置文件`/config.json`中的版本来自动下载所需版本

这是我最终的`/config.json`

```json
{
  "js_optimization_level": -1,
  "mirai_repo": "https://gitee.com/peratx/mirai-repo/raw/master",
  "maven_repo": [
    "https://maven.aliyun.com/repository/public"
  ],
  "packages": [
    {
      "id": "org.bouncycastle:bcprov-jdk15on",
      "channel": "stable",
      "version": "1.64",
      "type": "libs",
      "versionLocked": false
    },
    {
      "id": "net.mamoe:mirai-console",
      "channel": "beta",
      "version": "2.7.0",
      "type": "libs",
      "versionLocked": false
    },
    {
      "id": "net.mamoe:mirai-console-terminal",
      "channel": "beta",
      "version": "2.7.0",
      "type": "libs",
      "versionLocked": false
    },
    {
      "id": "net.mamoe:mirai-core-all",
      "channel": "beta",
      "version": "2.7.0",
      "type": "libs",
      "versionLocked": false
    },
    {
      "id": "org.itxtech:mcl-addon",
      "channel": "c122",
      "version": "1.2.2",
      "type": "plugins",
      "versionLocked": false
    },
    {
      "id": "net.mamoe:mirai-api-http",
      "channel": "stable",
      "version": "1.12.0",
      "type": "plugins",
      "versionLocked": false
    }
  ],
  "disabled_scripts": [],
  "proxy": "",
  "log_level": 1,
  "script_props": {}
}
```

以及`/config/net.mamoe.mirai-api-http/setting.yml`

```json
# 可选，默认值为0.0.0.0
host: '0.0.0.0'
#
# # 可选，默认值为8080
port: 8080
#
# # 可选，默认由插件第一次启动时随机生成，建议手动指定
authKey: xdchaseforever
#
# # 可选，缓存大小，默认4096.缓存过小会导致引用回复与撤回消息失败
cacheSize: 4096
#
# # 可选，是否开启websocket，默认关闭，建议通过Session范围的配置设置
enableWebsocket: true

cors:
  - '*'

## 消息上报
report:
## 功能总开关
  enable: false

  # 群消息上报
  groupMessage:
    report: false
  # 好友消息上报
  friendMessage:
    report: false
  # 临时消息上报
  tempMessage:
    report: false
  # 事件上报
  eventMessage:
    report: false
  # 上报URL
  destinations: []
  # 上报时的额外Header
  extraHeaders: {}


## 心跳
heartbeat:
   # 功能总开关
    enable: false
    # 启动延迟
    delay: 1000
    # 心跳间隔
    period: 15000
    # 心跳上报URL
    destinations: []
    # 上报时的额外信息
    extraBody: {}
    # 上报时的额外头
    extraHeaders: {}

```

以下报错单纯是因为Mirai没有打开滑块验证，重新登录即可

![](https://i.loli.net/2021/11/09/ui7kHGXNFh9BRpg.png)

#### 如何用python开发

至此，其实你已经可以用java来写了，但我想用python，[graia](https://graia-document.vercel.app/docs/intro)可以解决这个问题，虽然已停止维护但我在使用过程中并没有遇到问题（python3.9.7）同时graia作者指出未来的趋势为此[项目](https://github.com/GraiaProject/Avilla)，也许值得一试但我并没有尝试。

```
pip install graia-application-mirai
```

创建`bot.py` 并修改authenKey与QQ号

```
from graia.broadcast import Broadcast
from graia.application import GraiaMiraiApplication, Session
from graia.application.message.chain import MessageChain
import asyncio

from graia.application.message.elements.internal import Plain
from graia.application.friend import Friend

loop = asyncio.get_event_loop()

bcc = Broadcast(loop=loop)
app = GraiaMiraiApplication(
    broadcast=bcc,
    connect_info=Session(
        host="http://localhost:8080", # 填入 httpapi 服务运行的地址
        authKey="xdchaseforever", # 填入 authKey
        account=dontwannatellyou, # 你的机器人的 qq 号
        websocket=True # Graia 已经可以根据所配置的消息接收的方式来保证消息接收部分的正常运作.
    )
)

@bcc.receiver("FriendMessage")
async def friend_message_listener(app: GraiaMiraiApplication, friend: Friend):
    await app.sendFriendMessage(friend, MessageChain.create([
        Plain("Hello, World!")
    ]))

app.launch_blocking()
```

以上代码就能实现私聊自动回复。

![](https://i.loli.net/2021/11/09/sq6abBDAux8YVmK.png)

#### 如何上云

其实你大可以将本地搭建好的`mcl`文件夹整个送上服务器，只要保证python与java环境不变，然后用 screen 将 Mirai 与 bot.py 全部挂在后台即可。

我的服务器是阿里云Debian9.9镜像，最后是这样

```
(base) root@iZ2zefiis08efdfsj0cydeZ:~# screen -ls
There are screens on:
        29765.bot       (11/09/2021 05:51:43 PM)        (Detached)
        28393.mirai     (11/09/2021 03:48:23 PM)        (Detached)
        2358.minecraft  (11/01/2021 07:24:13 PM)        (Detached)
3 Sockets in /run/screen/S-root.
(base) root@iZ2zefiis08efdfsj0cydeZ:~# uname -a
Linux iZ2zefiis08efdfsj0cydeZ 4.9.0-9-amd64 #1 SMP Debian 4.9.168-1+deb9u3 (2019-06-16) x86_64 GNU/Linux
```

同时 Mirai 支持 `autologin` 自动登录，建议加密方式不要选择`MD5`，我遇到了暂时没有解决的问题。

### 今日开发进度

快速学习了一些API，参见官方文档 [https://graia-document.vercel.app/docs/guides/installation]

私聊回复

```python
@bcc.receiver("FriendMessage")
async def friend_message_listener(app: GraiaMiraiApplication, friend: Friend):
    await app.sendFriendMessage(friend, MessageChain.create([
        Plain(buf)
    ]))
```

群聊回复

```python
@bcc.receiver("GroupMessage")
async def test(
    message: MessageChain,
    app: GraiaMiraiApplication,
    group: Group, member: Member,
):
    if message.asDisplay().startswith("!ping"):
        await app.sendGroupMessage(group, MessageChain.create([
            At(member.id), Plain("pong")
        ]))
```

由于Minecraft会自动记录日志，所以可以读取日志来响应用户

```python
buf = ""

def read_latest_mclog():
    global buf
    buf = ""
    with open(PATH, "r") as logfile:
        for i in logfile:
            buf += i.replace("[Server thread/INFO]", "")
```

然后分别解析即可。但需要改进的地方也很多，而要实现需求最重要的是如何进行实时交互。从搭建环境到这里已经花了一天时间，得赶紧爬回去准备考试和毕设了，只得草草收场。

```python
from graia.broadcast import Broadcast
from graia.application import GraiaMiraiApplication, Session
from graia.application.message.chain import MessageChain
from graia.application.group import Group, Member
import asyncio

from graia.application.message.elements.internal import Plain, At

from graia.application.friend import Friend

import time, os

PATH = "/root/logs/latest.log"

loop = asyncio.get_event_loop()

bcc = Broadcast(loop=loop)
app = GraiaMiraiApplication(
    broadcast=bcc,
    connect_info=Session(
        host="http://localhost:8080", # 填入 httpapi 服务运行的地址
        authKey="xdchaseforever", # 填入 authKey
        account=dontwannatellyou, # 你的机器人的 qq 号
        websocket=True # Graia 已经可以根据所配置的消息接收的方式来保证消息接收部分的正常运作.
    )
)


buf = ""

def read_latest_mclog():
    global buf
    buf = ""
    with open(PATH, "r") as logfile:
        for i in logfile:
            buf += i.replace("[Server thread/INFO]", "")

def get_list():
    global buf
    read_latest_mclog()
    b = buf.split("\n")
    print(b)
    buf = ""
    for i in b:
        if "joined the game" in i or "left the game" in i:
            buf += i + '\n'

def get_event():
    global buf
    read_latest_mclog()
    b = buf.split("\n")
    print(b)
    buf = ""
    for i in b:
        if "advancement" in i:
            buf += " 【喜报】 " + i + '\n'
        elif "swim in lava" in i:
            buf += " 【悲报】 " + i + '\n'

def get_chat():
    global buf
    read_latest_mclog()
    b = buf.split("\n")
    print(b)
    buf = ""
    for i in b:
        if "<" in i and ">" in i:
            buf += i + '\n'

@bcc.receiver("FriendMessage")
async def friend_message_listener(app: GraiaMiraiApplication, friend: Friend):
    read_latest_mclog()
    await app.sendFriendMessage(friend, MessageChain.create([
        Plain(buf)
    ]))

@bcc.receiver("GroupMessage")
async def test(
    message: MessageChain,
    app: GraiaMiraiApplication,
    group: Group, member: Member,
):
    if message.asDisplay().startswith("!ping"):
        await app.sendGroupMessage(group, MessageChain.create([
            At(member.id), Plain("pong")
        ]))
    elif message.asDisplay().startswith("!help"):
        await app.sendGroupMessage(group, MessageChain.create([
            Plain("施工中...\n help 查看帮助\n log 查看日志详情 \n list 查看近期登录情况 \n event 查看近期事件 \n chat  查看近期聊天内容")
        ]))
    elif message.asDisplay().startswith("!log"):
        read_latest_mclog()
        await app.sendGroupMessage(group, MessageChain.create([
            At(member.id), Plain('\n'+buf)
        ]))
    elif message.asDisplay().startswith("!list"):
        get_list()
        await app.sendGroupMessage(group, MessageChain.create([
            At(member.id), Plain('\n'+buf)
        ]))
    elif message.asDisplay().startswith("!event"):
        get_event()
        await app.sendGroupMessage(group, MessageChain.create([
            At(member.id), Plain('\n'+buf)
        ]))
    elif message.asDisplay().startswith("!chat"):
        get_chat()
        await app.sendGroupMessage(group, MessageChain.create([
            At(member.id), Plain("\n"+buf)
        ]))

app.launch_blocking()
```

最终是达到了这样的效果

![](https://i.loli.net/2021/11/09/OdjrLhby7TgiBNu.png)

有空继续完善，后续细分来看需要解决如下问题

1. 每当QQ群有消息，机器人从Mirai手中拿到消息，发给Minecraft后台，后者进一步在Minecraft中广播
   * 若是聊天信息，直接广播即可
   * 若是查询信息，需要从Minecraft后台拿到查询结果并返回给Mirai
2. 每当Minecraft中有消息，机器人需要问询Minecraft后台并拿到这个消息，发送给Mirai

所以至少需要知道

1. Mirai如何向QQ发送消息
2. Minecraft后台如何向游戏内发送消息

3. Mirai与Minecraft后台如何交互（可能考虑重定向IO）




