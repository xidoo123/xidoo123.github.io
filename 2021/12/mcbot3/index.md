# 如何为 Minecraft 服务器添加一名播报员（完）


QQ Minecraft 协同机器人，完

{{< admonition danger >}}
log4j2 的洞可以在启动服务器时添加 -Dlog4j2.formatMsgNoLookups=true 选项来缓解。
{{< /admonition >}}



<!--more-->

==================================这是分割线=====================================

与同学交流时发现 MCDReforged 项目会对 Minecraft 服务器进行封装，并把 IO 的脏活累活封装好。但我在尝试时发现体量较大，耦合性较强，适合长期迭代优化，要满足我的需求是杀鸡用牛刀，遂弃用。

接上文，需求已经很清楚了，这里有两个死循环，一个死循环监听 Mirai ，一个死循环监听 MCServer ，跑两个线程即可。

基础代码如下，其中 `MCLoop` 和 `BotLoop` 分别代表这两个死循环，前置知识包括

1. python 多线程编程（threading）
2. Linux 管道（subprocess）
3. python 异步函数（async，await）

```python
from graia.broadcast import Broadcast
from graia.application import GraiaMiraiApplication, Session
from graia.application.message.chain import MessageChain
from graia.application.group import Group, Member
from subprocess import Popen, PIPE
import select
import fcntl, os, time
import asyncio
import threading
import nest_asyncio

from graia.application.message.elements.internal import Plain, At

from graia.application.friend import Friend

class MCBackServer(object):

    def __init__(self, args, server_env = None):
        self.process = Popen(args, stdin=PIPE, stdout=PIPE)
        flags = fcntl.fcntl(self.process.stdout, fcntl.F_GETFL)
        fcntl.fcntl(self.process.stdout, fcntl.F_SETFL, flags | os.O_NONBLOCK)
        print("[+] MC server start!")

    def send(self, data, tail = '\n'):
        msg = bytes(data+tail, encoding='utf-8')
        self.process.stdin.write(msg)
        self.process.stdin.flush()

    def recv(self, t=.1, stderr=0):
        r = ''
        pr = self.process.stdout
        if stderr:
            pr = self.process.stdout
        while True:
            if not select.select([pr], [], [], 0)[0]:
                time.sleep(t)
                continue
            r = pr.read()
            return r.rstrip().replace(b"[Server thread/INFO]", b'')
        return r.rstrip().replace(b"[Server thread/INFO]", b'')

    def recv_once(self):
        pr = self.process.stdout
        r = pr.read()
        if r == None:
          return b''
        else:
          return r.rstrip().replace(b"[Server thread/INFO]", b'')

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
targetGroup = None
targetMember = None
permittedCmd = ['list', 'seed', 'whitelist']
happyEvent = ['achievement']
badEvent = ['swim in lava']
otherEvent = []
ServerArgs = ['bash', '/root/start_mc_server.sh']
mcserver = MCBackServer(ServerArgs)



@bcc.receiver("FriendMessage")
async def friend_message_listener(app: GraiaMiraiApplication, friend: Friend):
    await app.sendFriendMessage(friend, MessageChain.create([
        Plain("施工中...")
    ]))


@bcc.receiver("GroupMessage")
async def test(
    message: MessageChain,
    app: GraiaMiraiApplication,
    group: Group, member: Member,
):
    global targetGroup, targetMember
    targetGroup = group
    if message.asDisplay().startswith("!"):
        ifPermitted = False
        msg = message.asDisplay()[1:]
       # print("msg: " + msg)
        if msg.startswith('ping'):
            await app.sendGroupMessage(group, MessageChain.create([
                At(member.id), Plain(" pong! I'm working well~~")
            ]))
            return

        for i in permittedCmd:
            if msg.startswith(i):
                ifPermitted = True
                break
        if ifPermitted:
            mcserver.send(msg)
            res = mcserver.recv().decode()
            await app.sendGroupMessage(group, MessageChain.create([
                At(member.id), Plain('\n'+res)
            ]))
        else:
            await app.sendGroupMessage(group, MessageChain.create([
                At(member.id), Plain("\nSorry, Command Error! These are all we permitted : " + ','.join(permittedCmd))
            ]))
    else:
        mcserver.send("say " + member.name + "@QQ : " + message.asDisplay())
       # print(b'[+]' + mcserver.recv())


def BotLoop():
    app.launch_blocking()


def MCLoop():
    global loop
    print("[+] We ask every 2 seconds")
    while(1):
        res = mcserver.recv_once().decode()
        if res != '' and targetGroup != None:
            res = res.split('\n')
            ret2qq = ''
            for mcmsg in res:
                if "Can't keep up" not in mcmsg:
                  print("mcmsg ："+mcmsg)
                  for i in happyEvent:
                      if i in mcmsg:
                          ret2qq += " 【喜报】 " + mcmsg + '\n'
                  for i in badEvent:
                      if i in mcmsg:
                          ret2qq += " 【悲报】 " + mcmsg + '\n'
                  for i in otherEvent:
                      if i in mcmsg:
                          ret2qq += mcmsg + '\n'
                  if 'joined the game' in mcmsg:
                      ret2qq += " Welcome ~~~ \n"
                  else:
                      if "<" in mcmsg and '>' in mcmsg:
                          ret2qq += mcmsg + '\n'
            if ret2qq != '':
              print("now ret2qq is : " + ret2qq)
              asyncio.run_coroutine_threadsafe( app.sendGroupMessage(targetGroup, MessageChain.create([
                    Plain(ret2qq)
                ])), loop).result()

        time.sleep(1)
        print("[+] ", end='')
        print(targetGroup, res)



if __name__ == "__main__":


    print(mcserver.recv())
    bot = threading.Thread(target=BotLoop)
    bot.setDaemon(True)
    bot.start()

    # wait for the coroutine to finish

    MCLoop()
```

基础功能框架已经实现，后续细节完善就在游戏中慢慢体验吧~

![](https://s2.loli.net/2021/12/14/DTpXIZQgGlWY9hN.png)

感谢 Keuin@HIT, Merrg1n@HIT 用丰富的开发经验在架构与插件上给予的帮助，感谢 wxk@HIT, YanqiSong@Earth 陪我 debug 了一晚上异步逻辑 Orz

虽然目前只是一个框架和基础功能，但后续完善工作就比较轻松、自然（且无趣）了

同时，[HIT 校服务器](https://github.com/hit-mc)全部代码已开源，服务器稳定运行超过 500 天，聊天机器人用 MCDR 与 Mirai 编写，包含更多插件以提升游戏体验、降低服务器负载等，均由群友手写开源。笔者在造机器人时尝试借鉴未果，想来原因有三：

1. 我不太会 java ，即我太菜了
2. 我的需求没这么多，即我太菜了
3. 其代码体量较大、架构较复杂，我看不太懂，即我太菜了

但不管怎么说我也是从零开始摸出了这个机器人，给了私服群友一个交代（咕太久了，，，）

完。

