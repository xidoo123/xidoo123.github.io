# Ubuntu16.04 docker环境搭建


为获取2.27libc下pwn环境，虚拟机过于麻烦，遂启用docker。

<!--more-->

## 安装docker

执行这个命令后，脚本就会自动的将一切准备工作做好，并且把Docker CE 的Edge版本安装在系统中

~~~bash
sudo apt install curl
curl -fsSL get.docker.com -o get-docker.sh
sudo sh get-docker.sh --mirror Aliyun
~~~

## 启动docker服务

~~~bash
sudo systemctl enable docker
sudo systemctl start docker
~~~

## 建立docker用户组

这一步是必须的，并且必须将当前用户加入docker用户组，否则权限不够。

~~~bash
sudo groupadd docker
sudo usermod -aG docker $USER
~~~

然后log out注销当前ubuntu用户，再log in，使其生效。

## 换源加速

~~~bash
sudo vi /etc/docker/daemon.json
~~~

按i进入插入模式后，在其中添加如下代码

~~~json
{
    "registry-mirrors": [
        "https://registry.docker-cn.com"
    ]
}
~~~

再重新启动服务即可

~~~bash
sudo systemctl daemon-reload
sudo systemctl restart docker
~~~

## 将镜像pull到本地

以pwndocker为例，https://github.com/voidzhakul/pwndocker

~~~bash
docker pull registry.cn-shenzhen.aliyuncs.com/zhakul/docker:pwndocker
~~~

检查是否pull到本地，使用docker images命令查看本地镜像

~~~bash
$ docker images
REPOSITORY                                        TAG                 IMAGE ID            CREATED             SIZE
registry.cn-shenzhen.aliyuncs.com/zhakul/docker   pwndocker           cffec5c49ab5        2 months ago        1.66GB
~~~

## 将本地目录挂载到镜像中

将我们需要在docker中执行的文件挂载，并运行docker

~~~bash
docker run -it -v /home/dock/Downloads:/usr/Downloads images /bin/bash
~~~

通过`-v`参数，冒号前为宿主机目录，必须为绝对路径，冒号后为镜像内挂载的路径，images使用上述提到的`REPOSITORY:TAG`格式。

## 退出、进入容器

退出容器

~~~bash
root@c8cb9d4168c7:## exit
~~~

查看所有产生的容器

~~~bash
$ docker ps -a
CONTAINER ID        IMAGE                                                       COMMAND             CREATED             STATUS                      PORTS               NAMES
c8cb9d4168c7        registry.cn-shenzhen.aliyuncs.com/zhakul/docker:pwndocker   "/bin/bash"         16 minutes ago      Exited (0) 6 minutes ago                        crazy_kilby
f140ab8db11d        registry.cn-shenzhen.aliyuncs.com/zhakul/docker:pwndocker   "/bin/bash"         49 minutes ago      Exited (0) 46 minutes ago                       upbeat_davinci
b43caf8776df        registry.cn-shenzhen.aliyuncs.com/zhakul/docker:pwndocker   "/bin/bash"         59 minutes ago      Exited (0) 19 minutes ago                       frosty_easley
~~~

镜像是静态的。而容器是动态的，类似于镜像的一个实例。如果要重新进入某个容器crazy_kilby

~~~bash
docker start crazy_kilby
~~~

其容器会在后台运行，attach后即可交互

~~~bash
docker attach crazy_kilby
~~~



