# 如何为 Minecraft 服务器添加一名播报员（二）


这几天思索了一下需求，在脑中构思出了重定向IO的具体解决办法。这里采用python的subprocess模块起两个个进程跑这两个后端，通过Linux管道机制来实现两个后端的交互。（每次在外面恰饭都是大鱼大肉，，我想吃青菜啊😭😭）

<!--more-->

继[前文](https://xidoo.top/2021/11/mcbot/)基础需求
1. x1do0在QQ中说「balabala」，在MC聊天框中出现 `[Server] <x1do0@QQ> : balabala`
2. xdchase在MC中说「balabala」，在QQ群中出现   `xdchase@MC : balabala`

消息流一：从QQ到Minecraft，比较容易

1. graia 收到QQ信息，送进管道stdin
2. 拿到stdout，graia 发送QQ消息

消息流二：从Minecraft到QQ

0. py保持监听stdout，或者 py 以 2s 频率不断问询stdout，是否有需要播报的消息
1. 有需要播报的消息，py里写处理逻辑，得到指定格式info
2. 用 graia 直接发送 info 到QQ

系统架构图

![](https://i.loli.net/2021/11/22/5PUGqgpOle7zQw3.png)

### 第二（半）天开发进度

#### 管道

用子进程跑minecraft服务器，并将其输出输入全部用管道实现，成了！

```python
class MCBackServer(object):

    def __init__(self, args, server_env = None):
        self.process = Popen(args, stdin=PIPE, stdout=PIPE, stderr=PIPE)
        flags = fcntl.fcntl(self.process.stdout, fcntl.F_GETFL)
        fcntl.fcntl(self.process.stdout, fcntl.F_SETFL, flags | os.O_NONBLOCK)

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
            return r.rstrip()
        return r.rstrip()
```

MineCraft 后台 <-> Bot.py(graia) <-> Mirai 后台 <-> QQ

#### 消息流一

Minecraft Console命令

```
help
[13:57:52] [Server thread/INFO]: /advancement (grant|revoke)
[13:57:52] [Server thread/INFO]: /attribute <target> <attribute> (get|base|modifier)
[13:57:52] [Server thread/INFO]: /execute (run|if|unless|as|at|store|positioned|rotated|facing|align|anchored|in)
[13:57:52] [Server thread/INFO]: /bossbar (add|remove|list|set|get)
[13:57:52] [Server thread/INFO]: /clear [<targets>]
[13:57:52] [Server thread/INFO]: /clone <begin> <end> <destination> [replace|masked|filtered]
[13:57:52] [Server thread/INFO]: /data (merge|get|remove|modify)
[13:57:52] [Server thread/INFO]: /datapack (enable|disable|list)
[13:57:52] [Server thread/INFO]: /debug (start|stop|function)
[13:57:52] [Server thread/INFO]: /defaultgamemode (survival|creative|adventure|spectator)
[13:57:52] [Server thread/INFO]: /difficulty [peaceful|easy|normal|hard]
[13:57:52] [Server thread/INFO]: /effect (clear|give)
[13:57:52] [Server thread/INFO]: /me <action>
[13:57:52] [Server thread/INFO]: /enchant <targets> <enchantment> [<level>]
[13:57:52] [Server thread/INFO]: /experience (add|set|query)
[13:57:52] [Server thread/INFO]: /xp -> experience
[13:57:52] [Server thread/INFO]: /fill <from> <to> <block> [replace|keep|outline|hollow|destroy]
[13:57:52] [Server thread/INFO]: /forceload (add|remove|query)
[13:57:52] [Server thread/INFO]: /function <name>
[13:57:52] [Server thread/INFO]: /gamemode (survival|creative|adventure|spectator)
[13:57:52] [Server thread/INFO]: /gamerule (announceAdvancements|commandBlockOutput|disableElytraMovementCheck|disableRaids|doDaylightCycle|doEntityDrops|doFireTick|doImmediateRespawn|doInsomnia|doLimitedCrafting|doMobLoot|doMobSpawning|doPatrolSpawning|doTileDrops|doTraderSpawning|doWeatherCycle|drowningDamage|fallDamage|fireDamage|forgiveDeadPlayers|freezeDamage|keepInventory|logAdminCommands|maxCommandChainLength|maxEntityCramming|mobGriefing|naturalRegeneration|playersSleepingPercentage|randomTickSpeed|reducedDebugInfo|sendCommandFeedback|showDeathMessages|spawnRadius|spectatorsGenerateChunks|universalAnger)
[13:57:52] [Server thread/INFO]: /give <targets> <item> [<count>]
[13:57:52] [Server thread/INFO]: /help [<command>]
[13:57:52] [Server thread/INFO]: /item (replace|modify)
[13:57:52] [Server thread/INFO]: /kick <targets> [<reason>]
[13:57:52] [Server thread/INFO]: /kill [<targets>]
[13:57:52] [Server thread/INFO]: /list [uuids]
[13:57:52] [Server thread/INFO]: /locate (pillager_outpost|mineshaft|mansion|jungle_pyramid|desert_pyramid|igloo|ruined_portal|shipwreck|swamp_hut|stronghold|monument|ocean_ruin|fortress|endcity|buried_treasure|village|nether_fossil|bastion_remnant)
[13:57:52] [Server thread/INFO]: /locatebiome <biome>
[13:57:52] [Server thread/INFO]: /loot (replace|insert|give|spawn)
[13:57:52] [Server thread/INFO]: /msg <targets> <message>
[13:57:52] [Server thread/INFO]: /tell -> msg
[13:57:52] [Server thread/INFO]: /w -> msg
[13:57:52] [Server thread/INFO]: /particle <name> [<pos>]
[13:57:52] [Server thread/INFO]: /playsound <sound> (master|music|record|weather|block|hostile|neutral|player|ambient|voice)
[13:57:52] [Server thread/INFO]: /reload
[13:57:52] [Server thread/INFO]: /recipe (give|take)
[13:57:52] [Server thread/INFO]: /say <message>
[13:57:52] [Server thread/INFO]: /schedule (function|clear)
[13:57:52] [Server thread/INFO]: /scoreboard (objectives|players)
[13:57:52] [Server thread/INFO]: /seed
[13:57:52] [Server thread/INFO]: /setblock <pos> <block> [destroy|keep|replace]
[13:57:52] [Server thread/INFO]: /spawnpoint [<targets>]
[13:57:52] [Server thread/INFO]: /setworldspawn [<pos>]
[13:57:52] [Server thread/INFO]: /spectate [<target>]
[13:57:52] [Server thread/INFO]: /spreadplayers <center> <spreadDistance> <maxRange> (<respectTeams>|under)
[13:57:52] [Server thread/INFO]: /stopsound <targets> [*|master|music|record|weather|block|hostile|neutral|player|ambient|voice]
[13:57:52] [Server thread/INFO]: /summon <entity> [<pos>]
[13:57:52] [Server thread/INFO]: /tag <targets> (add|remove|list)
[13:57:52] [Server thread/INFO]: /team (list|add|remove|empty|join|leave|modify)
[13:57:52] [Server thread/INFO]: /teammsg <message>
[13:57:52] [Server thread/INFO]: /tm -> teammsg
[13:57:52] [Server thread/INFO]: /teleport (<location>|<destination>|<targets>)
[13:57:52] [Server thread/INFO]: /tp -> teleport
[13:57:52] [Server thread/INFO]: /tellraw <targets> <message>
[13:57:52] [Server thread/INFO]: /time (set|add|query)
[13:57:52] [Server thread/INFO]: /title <targets> (clear|reset|title|subtitle|actionbar|times)
[13:57:52] [Server thread/INFO]: /trigger <objective> [add|set]
[13:57:52] [Server thread/INFO]: /weather (clear|rain|thunder)
[13:57:52] [Server thread/INFO]: /worldborder (add|set|center|damage|get|warning)
[13:57:52] [Server thread/INFO]: /ban-ip <target> [<reason>]
[13:57:52] [Server thread/INFO]: /banlist [ips|players]
[13:57:52] [Server thread/INFO]: /ban <targets> [<reason>]
[13:57:52] [Server thread/INFO]: /deop <targets>
[13:57:52] [Server thread/INFO]: /op <targets>
[13:57:52] [Server thread/INFO]: /pardon <targets>
[13:57:52] [Server thread/INFO]: /pardon-ip <target>
[13:57:52] [Server thread/INFO]: /perf (start|stop)
[13:57:52] [Server thread/INFO]: /save-all [flush]
[13:57:52] [Server thread/INFO]: /save-off
[13:57:52] [Server thread/INFO]: /save-on
[13:57:52] [Server thread/INFO]: /setidletimeout <minutes>
[13:57:52] [Server thread/INFO]: /stop
[13:57:52] [Server thread/INFO]: /whitelist (on|off|list|add|remove|reload)


发现后台只有服务器广播播报，不能以玩家身份广播。用` say <x1do0@qq>: balabala`命令即可实现需求一

```python
permittedCmd = ['list', 'seed']
happyEvent = ['achievement']
badEvent = ['swim in lava']
otherEvent = ['joined the game', 'left the game']
ServerArgs = ['bash', '/root/start_mc_server.sh']
mcserver = MCBackServer(ServerArgs)

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
            return r.rstrip()
        return r.rstrip()
```

已经可以从py这里与minecraft服务器交互了

![](https://i.loli.net/2021/11/21/3qNyl9OzHZLhBE4.png)

#### 消息流二

Mirai Console命令

```
> help
◆ /autoLogin add <account> <password> [passwordKind]    # 添加自动登录
  /autoLogin clear    # 清除所有配置
  /autoLogin list    # 查看自动登录账号列表
  /autoLogin remove <account>    # 删除一个账号
  /autoLogin removeConfig <account> <configKey>    # 删除一个账号的一个配置项
  /autoLogin setConfig <account> <configKey> <value>    # 设置一个账号的一个配置项
◆ /help     # 查看指令帮助
◆ /login <qq> <password> [protocol]    # 登录一个账号
◆ /permission cancel <被许可人 ID> <权限 ID>    # 撤销一个权限
  /permission deny <被许可人 ID> <权限 ID>    # 撤销一个权限
  /permission remove <被许可人 ID> <权限 ID>    # 撤销一个权限
  /permission cancelAll <被许可人 ID> <权限 ID>    # 撤销一个权限及其所有子权限
  /permission denyAll <被许可人 ID> <权限 ID>    # 撤销一个权限及其所有子权限
  /permission removeAll <被许可人 ID> <权限 ID>    # 撤销一个权限及其所有子权限
  /permission listPermissions    # 查看所有权限列表
  /permission lp    # 查看所有权限列表
  /permission permit <被许可人 ID> <权限 ID>    # 授权一个权限
  /permission grant <被许可人 ID> <权限 ID>    # 授权一个权限
  /permission add <被许可人 ID> <权限 ID>    # 授权一个权限
  /permission permittedPermissions <被许可人 ID> [包括重复]    # 查看被授权权限列表
  /permission pp <被许可人 ID> [包括重复]    # 查看被授权权限列表
  /permission grantedPermissions <被许可人 ID> [包括重复]    # 查看被授权权限列表
  /permission gp <被许可人 ID> [包括重复]    # 查看被授权权限列表
◆ /status     # 获取 Mirai Console 运行状态
◆ /stop     # 关闭 Mirai Console
◆ /mclc <MCL命令行参数>
◆ /mcl info <package>    # 获取包信息
  /mcl install <package> [channel] [type] [version] [lock or unlock]    # 安装包
  /mcl list    # 列出已安装的包
  /mcl remove <package> [delete]    # 移除包
  /mcl run <script>    # 执行脚本load阶段
  /mcl update    # 执行updater脚本
```

下面我们做另一半：py 与 Mirai 交互

实际上这一部分已经做好了，就是利用graia的http函数封装。我们需要翻阅 graia 手册，考察快速学习能力（指每次考试之前都弄些花里胡哨的东西...

```python
loop = asyncio.get_event_loop()
bcc = Broadcast(loop=loop)
app = GraiaMiraiApplication(
                        broadcast=bcc,
                        connect_info=Session(
                            host="http://localhost:8080", # 填入 httpapi 服务运行的地址
                            authKey="xdchaseforever", # 填入 authKey
                            account=768842556, # 你的机器人的 qq 号
                            websocket=True # Graia 已经可以根据所配置的消息接收的方式来保证消息接收部分的正常运作.
                        )
                    )

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
    targetGroup = Group
    if message.asDisplay().startswith("!"):
        ifPermitted = False
        msg = message.asDisplay()[1:]
        if msg.startswith('ping'):
            await app.sendGroupMessage(group, MessageChain.create([
                At(member.id), Plain("pong")
            ]))
            return 

        for i in permittedCmd:
            if msg.startswith(i):
                ifPermitted = True
                break
        if ifPermitted:
            mcserver.send(msg)
            res = mcserver.recv()
            await app.sendGroupMessage(group, MessageChain.create([
                At(member.id), Plain(res)
            ]))
        else:
            await app.sendGroupMessage(group, MessageChain.create([
                At(member.id), Plain("Sorry, Command Error! These are all we permitted : " + self.permittedCmd)
            ]))
    else:
        mcserver.send("say " + member.name + "@QQ : " + message.asDisplay())
        print(b'[+]' + mcserver.recv())
```

#### 如何结合呢？

心路历程

1. 本来用类封装得很好看，但是发现Mirai监听事件貌似得放全局变量。。于是又全部木大

2. 建议下载Graia时指定版本为0.19.0，版本信息如下。你不能苛求一个停止更新的项目能解决什么兼容问题。

        (base) root@iZ2zefiis08efdfsj0cydeZ:~# pip3.9 show graia-application-mirai
        Name: graia-application-mirai
        Version: 0.19.0
        Summary:
        Home-page:
        Author: GreyElaina
        Author-email: GreyElaina@outlook.com
        License: AGPL-3.0
        Location: /usr/local/lib/python3.9/site-packages
        Requires: aiohttp, regex, yarl, graia-broadcast, pydantic
        Required-by:

更多问题：

1. 在执行完`app.launch_blocking()`后Mirai机器人开始工作，程序开始循环监听QQ后台，并且永远不会跳出。消息流一打开以后如何再打开消息流二？

2. 服务器后端有消息剩余，我想拿到的东西往往不在消息队首

问题一我考虑使用两个py文件来分别运行，但问题二的出现让我考虑到解决问题一带来的更大问题

> 如何实现两个消息流的隔离？

我暂时想到的是创建两个消息队列，分别处理。这个时候管道该如何写，暂时还没查到相关资料。但想想这应该是网络应用的基础需求，奈何我对web知识体系一窍不通...


消息流一圆满完成之时已是深夜，草草截张图赶紧爬去睡觉了

![](https://i.loli.net/2021/11/22/qSPWKMIba5ZOUTH.png)

明天开始复习逆向考试...又不是不能用！





