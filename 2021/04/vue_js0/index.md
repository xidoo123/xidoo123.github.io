# Vue.js 初探


最近写应用程序感觉 python,java 的 gui 太丑了，咨询了一波web爷爷。在一星期内从零开始入门了前后端分离的开发框架，并成功赶在实验截止日期前套用，治好了我的强迫症. 在这个过程中不成体系且稀碎地顺手记录了一下，权当纪念这段爆肝的日子。

<!--more-->

技术栈如下，主要学习量为vue.js

* 前端
  * vue.js
  * element-ui
  * electron
* 后端
  * python flask

学习路线 (html, css, js) -> Vue.js

- [x] html 4.20
- [x] css 4.21
- [x] Javascript 4.22-4.23
- [x] vue、electron  4.24-4.25

整体来说对vue.js与electron还是一知半解，但也顺利地摸出了前端


## HTML

HyperText Markup Language

https://www.runoob.com/html/html-tutorial.html

- HTML 不是一种编程语言，而是一种**标记**语言
- 标记语言是一套**标记标签** (markup tag)
- Web浏览器用于读取HTML文件，不直接显示HTML标签，而是使用标签展示HTML页面内容
- vscode 安装open in browser插件，alt+b即可用默认游览器打开

![](https://i.loli.net/2021/04/20/UrNBaSPwpfqylY6.png)

**tips**

* 属性值本身就含有双引号，那么您必须使用单引号，例如：name='John "ShotGun" Nelson'
* 当显示页面时，浏览器会移除源代码中多余的空格和空行。所有连续的空格或空行都会被算作一个空格。
* 清华镜像站 bakground:\#22222  白:white  蓝:#6793cf
* 用&#x表示特定字符，x为其ascii码

## CSS

Cascading Style Sheets

https://www.runoob.com/css/css-intro.html

**tips**

* （内联样式）Inline style > （内部样式）Internal style sheet >（外部样式）External style sheet > 浏览器默认样式
* 1em和当前字体大小相等，=16px
* 盒子模型

![](https://i.loli.net/2021/04/22/UlkDeM4mvIG9Wdi.png)



## JavaScript

https://www.runoob.com/js/js-statements.html

**tips**

* 脚本语言，逐行执行，而不是先整体编译

* 注释、一行后面有；、function格式

```html
<script>
function myfuc(a, b)
{
	// document.getElementById("demo");
    alert(a + b);
    return 1;
}
</script>
```

* document.write()直接写到html上。如果网页已经加载完了再触发该函数（比如onclick），将覆盖整个html
* 大小写敏感，驼峰法的命名规则（eg. myFirstName）
* 重新声明值不会丢

```javascript
var carname="Volvo";
var carname;  // 仍然是"Volvo"
```

* 具有动态数据类型，

  * **值类型(基本类型)**：字符串（String）、数字(Number)、布尔(Boolean)、对空（Null）、未定义（Undefined）、Symbol。
  * **引用数据类型**：对象(Object)、数组(Array)、函数(Function)。

```javascript
    var x;               // x 为 undefined
    var x = 5;           // 现在 x 为数字
    var x = "John";      // 现在 x 为字符串
```

## Vue3+electron

开始摸实验了...

* python flask开后端服务器
* element ui组件库写前端组件
* electron打包

### Day1

- [x] 前端
  - [x] vue启动
  - [x] 注册、登录组件
  - [x] 注册、登录初级校验
  - [x] 传递参数给后端
  - [x] 后端返回参数
- [x] 后端
  - [x] flask启动
  - [x] 从前端接收参数
  - [x] 传输参数给后端
  - [x] 注册、登录数据库校验

axios POST到python后端成功

![](https://i.loli.net/2021/04/24/iguJQBm9VP4qnAE.png)



### Day2

- [x] 前端
- [x] 后端
- [x] 打包

把electron-quick-start git下来，进去修改main.js，直接把electron当作浏览器，先把vue跑起来，然后直接读这个端口。

```javascript
  // and load the index.html of the app.
  mainWindow.loadURL('http://127.0.0.1:8081')
```

如下命令跑起来

```
npm install
npm start
```

用electron读取网页变为应用程序

![](https://i.loli.net/2021/04/25/HIjxFbqUPzLWAgf.png)

下面我们把它彻底包成exe

安装electron-packager

```
npm install -g electron-packager
```

进入electron-quick-start目录

```
electron.packager .
```

得到了彻底前后端分离的高端产物

![](https://i.loli.net/2021/04/25/At3jk6LpdsHeIUJ.png)

至此，便完成了一整套开发流程。

更多见 https://github.com/xidoo123/cp-lab5


