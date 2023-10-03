# 软件构造（JAVA版）


HIT cources review, derivate from CMU and MIT *6.005*.

(1) concepts of design for complex systems

(2) object oriented programming

(3) techniques for robustness, including testing and static and dynamic analysis for programs

(4) concurrent software

<!--more-->

- [x] unit1，2  ---> 06/08
- [x] unit3 ---> 06/09,10
- [x] unit4 ---> 06/11 (06/12完成，咕得好哇)
- [x] unit5 ---> 06/12
- [x] unit6 ---> 06/13
- [x] unit7 ---> 06/14 

## Unit 1-2

### Target

- [x] <font color=red>软件构造的多维度视图</font>
- [x] 软件构造的阶段划分、各阶段的构造活动  
- [x] 内部/外部的质量指标  
- [x] 软件配置管理SCM与版本控制系统VCS  
- [x] <font color=red>Git的结构、工作原理</font>、基本指令  
- [x] GitHub  

### Context

#### <font color=red>软件构造的三个维度</font>

按阶段分：build time（编译阶段） / run time（运行阶段）

按时间分：moment （瞬间）/ period （一段时期）

按层次分： code（源代码）/ component（架构）

![](https://i.loli.net/2020/06/08/c4Qj2EIk1URDTK7.png)

#### Version Control System(VCS) 与 Software Configuration Item(SCI) 

SCM：软件配置管理，用来追踪和控制软件的变化的任务。

SCI：软件配置项，软件中发生变化的基本单元（例如：文件）

版本控制系统略，git为重点

#### Software Development Lifecycle (SDLC)  
planning->analysis->design->implementation->testing&integration->maintenance->planning...

#### 传统软件开发模板

Waterfall（线性，不迭代），像瀑布一样顺序开发

Incremental （不迭代），将整个系统分为许多小块，一点一点地设计、开发、测试，直至 整个完成

V-Model （相对测试而言），是Waterfall的延申，完成源码开发后完善测试用例等，形成一个V形

Prototyping（迭代），开发软件原型，确定需求->开发初始原型->回顾->修正原型

Spiral（迭代），风险驱动 ，确定目标->识别并解决风险->开发与测试->继续迭代 

#### Agile development

敏捷开发：把一个大项目分为多个相互联系，但也可独立运行的小项目，并分别完成，在此过程中软件一直处于可使用状态  

#### <font color=red>敏捷开发与螺旋开发的区别</font>

敏捷强调快速迭代，简单来说就是少些文档多做代码；螺旋本质上还是传统开放模式，要将文档写的很详细

敏捷的迭代速度要快于螺旋，通常一轮迭代也就1周；螺旋可能一两个月

#### 软件的质量目标

外部质量目标：正确性、健壮性、可扩展性、复用性、兼容性（与其他东西兼容）、有效性、可移植性（移植到其他平台）、易用性、功能性、及时性等

内部质量目标：可读性、复杂性、大小

>  此课程涉及到：
>
> 代码优雅易于理解 -> 代码的可理解性、函数规约；项目的可理解性
>
> 最大化复用 -> ADT/OOP; 接口与实现分离;继承/重载/重写;组合/代理; 多态; 子类型与泛型编程; OO设计模式
>
> 可维护性 -> 模块化设计; 聚合度/耦合度; SOLID; OO设计模式;
>
> 健壮性 -> 异常处理、单元测试等
>
> 程序表现 ->  多线程安全

#### <font color=red>Git结构</font>

本地.git文件夹：工作区

暂存区（Staged）：并不实际存在，只是文件的一个标识，比如如果是0在暂存区域，1就不在；这样能把很多东西都先放在暂存区，然后一次性commit

仓库：远程仓储，已提交

<img src="https://i.loli.net/2020/06/08/iFrWjY7qmvSnlzO.png" style="zoom: 67%;" />             |<img src="https://i.loli.net/2020/06/08/C4RMPbc3NVv2gjG.png" style="zoom: 67%;" />|<img src="https://i.loli.net/2020/06/08/SGsJIrMcTgBCUAV.png" style="zoom:67%;" />
:-------------------------:|:-------------------------: |:-------------------------:

#### <font color=red>Git与传统VCS的不同</font>

传统的VCS版本更新时只记录改变量与原版本文件；

Git每一个版本存的都是整个文件，但是不同版本相同的文件并不会复制一遍（多出一个指针指向原版本文件）

<img src="https://i.loli.net/2020/06/08/BaYMdxKJAUPiIyF.png" style="zoom: 67%;" />

<font color=red>Git存储的是文件，而不是文件的改变，这是与传统版本控制工具最大的区别</font>

#### Git命令

![](https://i.loli.net/2020/06/08/iPjsDEBk75R2n1W.png)

#### Github

略

## Unit 3

### Target

- [x] 基本数据类型、对象数据类型  
- [x] 静态类型检查、动态类型检查  
- [x] <font color=red>Mutable/Immutable</font>
- [x] <font color=red>值的改变、引用的改变    </font>
- [x] <font color=red>防御式拷贝 </font>
- [x] <font color=red>Snapshot diagram</font>
- [x] Specification、 前置/后置条件
- [x] <font color=red>行为等价性</font>
- [x] <font color=red>观察等价性</font>
- [x] <font color=red>规约的强度</font>
- [x]  ADT操作的四种类型
- [x] <font color=red>表示独立性</font>
- [x]  表示泄露
- [x] <font color=red>不变量、表示不变量RI</font>
- [x]  表示空间、抽象空间、 AF
- [x]  以注释的形式撰写AF、 RI
- [x]  接口、抽象类、具体类
- [x]  <font color=red>继承、 override</font>
- [x]  <font color=red>多态、 overload</font>
- [x]  泛型
- [x]  等价性equals()和==
- [x]  <font color=red>equals()的自反、传递、对称</font>
- [x]  hashCode()
- [x]  不可变对象的引用等价性、对象等价性
- [x]  可变对象的观察等价性、行为等价性

### Context

#### 基本数据类型、对象数据类型

java中所有变量类型分为两种（首字母大写的为对象数据类型，其余为基本类型）

| 基本数据类型                                         | 对象数据类型           |
| ---------------------------------------------------- | ---------------------- |
| int, long, byte, short, char, float, double, boolean | 类、结构、数组、枚举等 |
| 只有值，相互无法区分                                 | 既有值又有ID           |
| 不可变                                               | 可变/不可变            |
| 在栈中分配内存                                       | 在堆中分配内存         |
| 内存代价小                                           | 内存代价大             |

#### 静态类型检测、动态类型检测

静态类型检测：编译时检测类型，如语法、类名、函数名、函数参数、返回值类型等错误。检查类型。

动态类型检测：运行是检测类型，如非法的参数值（x/0）、非法的返回值、越界、空指针等。检查值。

不报错但是结果错误：整数溢出、double probability=1/5（0.0）等

#### <font color=red>Snapshot Diagram</font>

- 对于基本类型的值，使用单线箭头指向实际值，不需要表明数据类型。

![](https://i.loli.net/2020/06/10/19jWczLTvKnR8De.png)

- 如果是可变对象，使用单线椭圆，椭圆内写明对象的类型及对象内的值。

![](https://i.loli.net/2020/06/10/5qE9LQ3HspxXdbT.png)

- 如果是不可变对象，使用双线椭圆，椭圆内写明对象的类型及对象内的值。

![](https://i.loli.net/2020/06/10/rqWPGEJNx93tQSw.png)

* 如果是对象的不可变引用（final标记），使用双线箭头。eg：id
  如果是对象的可变引用，使用单线箭头。eg：age

![](https://i.loli.net/2020/06/10/XOFxGaPTNbproyL.png)

* 比较复杂的对象图

| Array、List                                            | Set                                                    | Map                                                    |
| ------------------------------------------------------ | ------------------------------------------------------ | ------------------------------------------------------ |
| ![](https://i.loli.net/2020/06/10/XkwT2NuylFx3Eto.png) | ![](https://i.loli.net/2020/06/10/PH9slJ1aRZCBnrq.png) | ![](https://i.loli.net/2020/06/10/frS71Auwla5M34o.png) |



#### <font color=red>可变与不可变类型</font>

不可变类型变量：变量的值无法改变，只能改变引用；对其频繁修改会产生大量的临时拷贝，但更安全

<font color=blue>注意String是不可变类型！Date是可变类型!</font>

![](https://i.loli.net/2020/06/10/iQmveKjuJIt9TOn.png)

可变类型变量：变量的值可以改变；最小化拷贝

StringBuilder是可变类型：

![](https://i.loli.net/2020/06/10/xSTt6CYX1RGF4i3.png)

考察下列代码：

```java
public static void main(String[] args){
        String s1 = "abc";
        List<String> list = new ArrayList<>();
        list.add(s1);
        s1 = s1.concat("d");
        System.out.println(list.get(0));		//abd
        String s2 = s1.concat("e");
        list.set(0, s2);
        System.out.println(list.get(0));		//abcde
    }
```

Snapshot与调试图如下，需要注意list.add以后并不是把s1直接放进list中，可以理解为做了拷贝

| snapshot                                               | 调试图                                                 |
| ------------------------------------------------------ | ------------------------------------------------------ |
| ![](https://i.loli.net/2020/06/10/NGKjWb6P8vVSkFt.png) | ![](https://i.loli.net/2020/06/10/zKnG3jyOrPc1L2g.png) |



#### <font color=red>值的改变与引用的改变</font>

改变引用：将变量指向另一个值的存储空间

改变值：将当前指向的值的存储空间中写入一个新的值

`final` 关键词：修饰的变量无法改变引用；属于静态类型检测。

所以如果用`final` 修饰不可变类型，则无法再次赋值

```java
final int a = 5;

a = 10; (×)
```

#### <font color=red>defensive copy</font>

为防止用户传入或者传出给用户一个不可变ADT里的可变类型的引用，进而让用户获得不可变ADT的改变能力，使用防御使拷贝，比如下列Date类型返回时的拷贝方式：

```java
return new Date(groundhogAnswer.getTime());
```

#### pre/post-condition

前置条件：对客户端的约束，在使用方法时必须满足的条件  

后置条件：对开发者的约束，方法结束时必须满足的条件  

Java的前置、后置条件写在规约的`@param` 与`@return` 中

* 前置条件满足，则后置条件必须满足  
* <font color=blue>前置条件不满足，则方法可做任何事情</font>  

#### 规约与<font color=red>规约的强度</font>

<font color=blue>注意静态类型声明也是规约！</font>

规约不能暴露具体实现，应该使用抽象类型如List等字眼而不是LinkedList

规约更强 ---> 更放松的前置条件，更严格的后置条件，意味着开发者的工作越重、使用者的责任越轻

用图形表示规约强弱，<font color=blue>更强的规约表现为更小的区域</font>

（可以把区域的大小想成是实现方法的个数，规约更强实现方法会更少，所以区域小）  

#### <font color=red>方法的行为等价性</font>

站在用户的角度，两个方法（功能、pre/post-condition）是否相等

> 比如在数组中找某个只出现一次的值，从头开始找和从尾开始找的方法具有行为等价性

#### <font color=red>对象的行为等价性</font>

所有方法都无法区分的两个对象是具有观察等价性的，一般这两个对象指向了同一块内存区域

#### <font color=red>对象的观察等价性</font>

observer无法区分的两个对象是具有观察等价性的

#### ADT操作的四种类型

抽象数据类型（ADT）是由操作决定的，操作分为：

- 构造器：由其他类型产生此ADT类型
- 生产器：由此ADT类型产生另一个此类型的对象
- 观察器：由此ADT类型产生其他类型的变量
- 变值器：改变对象属性的方法，通常返回void

比如：

Integer.valueOf()								   Creator
BigInteger.mod()								   Producer
List.addAll()String.toUpperCase()	   Producer
Set.contains()										 Observer
Map.keySet()										  Observer
Collections.unmodifiableList()			Producer
BufferedReader.readLine()				 Mutator   (改变了某个标记，表示当前位置)

<font color=blue>需要注意不可变类型可能有mutator（beneficent mutation  ），但必须在用户看来此ADT是不变的。</font>

#### <font color=red>Representation Independence</font>

表示独立性： client使用ADT时无需考虑其内部如何实现， ADT内部表示的变化不应影响外部spec和客户端 

下图违反了表示独立性，因为Family的规约中并没有指出people是List，所以客户端不能直接用f.people.get

（如果Family的内部实现变成了set，那么客户端也得跟着变）

应该将people改为private，然后利用getMembers()来访问。   

![](https://i.loli.net/2020/06/10/mrvhZfqT79RXHkV.png)

#### 表示暴露

ADT属性是public/返回了一个内部属性的引用给客户端/客户端传入了一个内部属性的引用

#### <font color=red>不变量</font>

每个ADT都需要能维持某个量在任何时候总是true，这个量成为不变量

>  比如对于不可变类型的ADT，不可变就是它的不变量

#### AF & RI

表示(R)空间：ADT内部所有的变量对象构成的空间

抽象(A)空间：用户看ADT表示的内容构成的空间

抽象函数(AF)：从R到A的映射，一定是满射，但不一定是单射

<font color=blue>R中的有可能有部分值并非合法的，在A中无映射值 </font> 

表示不变量(RI)：表示空间中的子集，指示表示空间中数据的合法条件，应始终成立

checkRep随时检查RI是否成立，示意图如下：

![](https://i.loli.net/2020/06/10/BUPbWOMaR7Ctzk5.png)

ADT的内部表示(私有属性)、R空间中的任何值、AF和RI应该对外部都应严格不可见  

#### 在注释中书写AF&RI&safe from rep

略，见实验

#### 接口、抽象类、具体类

接口：interface，被implements

抽象类：abstract，被extends

#### <font color=red>继承与重写</font>

严格继承：子类只能添加新方法，无法重写父类中的方法  

重写方法与父类名字、参数列表、返回值类型完全相同，<font color=blue>在运行阶段判断到底用哪个方法</font>

* final修饰方法， 则此方法不能被重写
* final修饰类，则此类不能被继承

构造子类用到super()时只能放在第一行

#### <font color=red>多态与重载</font>

java多态包括三种情况：

功能多态：函数重载

参数多态：泛型

子类型多态、包含多态：如果一个类有许多父类，则它代表了很多个父类

重载：多个方法具有同样的名字，但有不同的参数列表或返回值类型 ，<font color=blue>在编译阶段判断到底用哪个方法</font> 

重载也可以发生在子类与父类之间

<font color=blue>下图为一个易错的例子，说明对象类型得看声明，而不是new赋值的对象；特别需要注意3</font>

![](https://i.loli.net/2020/06/10/n6XA3UL2kvTmPBu.png)

#### 泛型

泛型接口可以用泛型类实现，也可以用具体类实现

~~~java
public interface Set<E>{...}
public class CharSet implements Set<Character>{...}
public class HashSet implements Set<E>{...}
~~~

通配符?只能在使用泛型时使用，不能在定义时使用

~~~java
List<?> list = new ArrayList<String>();
List<? extends Animal>
List<? super Animal>
~~~

<font color=blue>运行时泛型便消失了，被具体类型代替</font>

<font color=blue>不能产生泛型数组</font>

#### <font color=red>等价性</font>

等价关系需要满足自反、对称、传递

#### == vs. equals()

==比较判断基本类型就是判断值是否相等，比较对象类型是判断引用是否相等

equals()判断对象引用是否相等（是否指向了同一块区域），与==相同

> 但是我们一般会对equals()重写（注意是重写并利用instanceof判断，千万不要重载），
>
> 所以总的原则是<font color=blue>基本类型用==，对象类型用equals()</font>

equals()相等的对象hashcode()一定要相等

#### instance of is a bad thing

使用instanceof判断某个父类属于不同子类便有不同的操作是一件不好的事情，这意味着父类的抽象封装不够，应该让子类重写父类的方法。

> 比如父类Animal有move()，而子类Bird有fly()，Fish有swim()，利用instanceof判断具体类型再调用对应方法是不好的，正确做法应该是Bird与Fish重写Animal的move()

#### 可变对象的观察等价性、行为等价性    

对可变类型来说，无需重写这两个函数，直接继承Object的两个方法即可 ，使用行为等价性

因为如果使用观察等价性，可变类型改变以后原先相等的对象便不再相等，会造成某些问题

> 比如set中添加了一个list，当list改变时set.contains(list)会变成false

如果一定要判断两个可变对象看起来是否一致，最好定义一个新的方法 ，比如similar()

观察等价性用equals()判断，行为等价性用==判定

#### 不可变对象的引用等价性、对象等价性

不可变类型一定要重写这两个函数，使用对象等价性

引用等价性一般指用==判定，对象等价性用equals()判断

#### Autoboxing机制

比较饶人的几个例子：

~~~java
Integer a = new Integer(3);
Integer b = new Integer(3);
System.out.println(a==b);    // false
System.out.println(a.equals(b));	//true
System.out.println((int)a==(int b));	//true
~~~

a==b是判断两个是否指向一块区域，显然new了两个Interger，所以是false

a.equals(b)调试发现Integer重写了equals()，根据观察等价性判断(值是否相等），所以是true

~~~java
Map<String, Integer> a = new HashMap(),b = new HashMap();
a.put("c",130)
b.put("c",130)
System.out.println(a.get("c")==b.get("c"));    // false
System.out.println(a.get("c").equals(b.get("c")));	//true
~~~

Autoboxing机制将130打包为Integer，所以不相等，用equals()同上

~~~java
Map<String, Integer> a = new HashMap(),b = new HashMap();
a.put("c",1)
b.put("c",1)
System.out.println(a.get("c")==b.get("c"));    // true
System.out.println(a.get("c").equals(b.get("c")));	//true
~~~

<font color=blue>-128到127的整数只会自动打一个包</font>（当然可以手动打不止一个包），也就是说两个Integer(1)指向同一块地方

## Unit 4

### Target

- [x] Programing for/with reuse
- [x] <font color=red>LSP</font>
- [x] <font color=red>协变、反协变</font>
- [x] 数组的子类型化
- [x] <font color=red>泛型的子类型化</font>
- [x] 泛型中的通配符(?)
- [x] <font color=red>Delegation</font>
- [x] Comparator和Comparable
- [x] <font color=red>CRP原则</font>
- [ ] 接口的组合
- [x] 白盒框架的原理与实现
- [x] 黑盒框架的原理与实现
- [x] <font color=red>设计模式adapter、 decorator、façade、 strategy、 template、iterator/iterable </font> 

### Context

#### java复用层次

源代码级别的复用 

模块级别的复用：类/抽象类/接口  

库级别的复用： API/包  

系统级别的复用：框架（将framework看作是更大规模的API复用，除了提供可复用的API，还将这些模块之间的关系都确定下来，形成了整体应用的领域复用  ），比如.Net开发

#### java复用分类

白盒复用：源代码可见，可修改和扩展  ；复制已有代码 ，可进行修改  

黑盒复用：源代码不可见，不能修改；只能通过API接口来使用，无法修改代码  

#### 白盒框架的原理与实现

白盒框架：通过代码层面的继承进行框架，通过子类型与重写方法扩展  

#### 黑盒框架的原理与实现

黑盒框架：通过实现特定接口/delegation进行框架扩展  

#### <font color=red>Liskov替换原则（LSP）</font>

里氏替换原则通俗的来讲就是：子类可以扩展父类的功能，但不能改变父类原有的功能。

具体包括：

- 子类可以实现父类的抽象方法，但不能覆盖父类的非抽象方法。
- 子类中可以增加自己特有的方法。
- 当子类的方法重载父类的方法时，方法的前置条件（即方法的形参）要比父类方法的输入参数更宽松。
- 当子类的方法实现父类的抽象方法时，方法的后置条件（即方法的返回值）要比父类更严格。

注意正方形不是长方形的子类型的原因在于：

> 如果设定一个resize方法提供给用户改变长、宽的功能，那么这个函数对于正方形来说一定要求长与宽相等，而对于正方形的父类长方形来说并没有这个要求，导致子类型方法的前置条件更强，违反了LSP。但如果没有这些需求，正方形可以作为长方形的子类

同理：<font color=blue>长度大于1的所有正方形也不是正方形的子类型！</font>

下图才是一个标准的子类型，可以看到子类型应该可以完全替换父类型。

![](https://i.loli.net/2020/06/12/yZV5vpWraCbJxgl.png)

<font color=blue>那么长方形是不是正方形的子类型呢？</font>

显然也不是的，长方形（子类）的不变量比长方形（父类）弱。

#### <font color=red>协变、逆变（反协变）</font>

协变：类型更具体

逆变：类型更抽象

不厌其烦再强调一遍LSP，从父类型到子类型：

* 方法参数：逆变  
* 方法的返回值：协变  
* 异常类型：协变  

| 协变                                                   | 逆变                                                   |
| ------------------------------------------------------ | ------------------------------------------------------ |
| ![](https://i.loli.net/2020/06/12/mFcX38rWfkthKSv.png) | ![](https://i.loli.net/2020/06/12/lSWM5fesJFxnGbp.png) |

<font color=blue>需要注意Java并不能提供逆变，它会把上右图当作重载处理，所以在Java中应当忽略子类型的逆变要求。</font>

<font color=blue>同时注意上左图，Java不会当作重载处理</font>

#### 数组的子类型化

~~~java
// numbers是引用，类型为Number[]
Number[] numbers = new Number[2];
numbers[0] = new Integer(10);
numbers[1] = new Double(3.14); //不会报错

// myNumber是对象，与myInts类型相同，在运行时Java知道myNumber实际上是Integer[]
Integer[] myInts = {1,2,3,4};
Number[] myNumber = myInts;
myNumber[0] = 3.14; 	//run-time error!
~~~

区分：对象的类型 vs. 引用的类型

#### <font color=red>泛型的子类型化</font>与通配符

`ArrayList<String>` 是`List<String> `的子类型

`List<String>` 不是 `List<Object>`  的子类型

`List<Number>`是` List<?>`的子类型

`List<Number>`是`List<? extends Object>`的子类型

`List<Object>`是`List<? super String>  `的子类型

~~~java
List<Integer> myInts = new ArrayList<Integer>();
myInts.add(1);
myInts.add(2);
List<Number> myNums = myInts;	//compiler error！
myNums.add(3.14);
~~~

泛型的具体化不是协变，Java运行时会对泛型做类型擦除处理，如下图

| 源代码                                                 | 运行时                                                 |
| ------------------------------------------------------ | ------------------------------------------------------ |
| ![](https://i.loli.net/2020/06/12/vFPpIsj9d4uRQLy.png) | ![](https://i.loli.net/2020/06/12/KcSX62Pa8ECfZN5.png) |

#### <font color=red>委托机制</font>

委派/委托：一个对象请求另一个对象的功能  

一个类不需要继承另一个类的全部方法，通过委托机制调用部分方法，从而避免大量无用的方法；反之则用继承

“委托”发生在object层面，而“继承”发生在class层面

更多见实验，略。

#### Comparator/Comparable

方法一：自己实现

| if-else实现                                            | lambda表达式                                           |
| ------------------------------------------------------ | ------------------------------------------------------ |
| ![](https://i.loli.net/2020/06/12/ftWNMP8jpAykuLG.png) | ![](https://i.loli.net/2020/06/12/92tbhwXzQRpvaG1.png) |

方法二：实现Comparator接口并override compare()函数

~~~java
public class EdgeComparator	implements Comparator<Edge>{
@Override
public int compare(Edge o1, Edge o2) {
	if(o1.getWeight() > o2.getWeight())
	return 1;
	else if (.. == ..) return 0;
	else return -1;
	}
}

// 实现后需要新建一个Comparator
public void sort(List<Edge> edges) {
	Comparator comparator = new EdgeComparator();
	Collections.sort(edges, comparator);
}
~~~

方法三：实现Comparable接口并override compareTo() 方法  

~~~java
public class Edge implements Comparable<Edge> {
	Vertex s, t;
	double weight;
	...
	public int compareTo(Edge o) {
		if(this.getWeight() > o.getWeight())
			return 1;
		else if (.. == ..) return 0;
		else return -1;
	}
}

//	不需要构建新的Comparator类，比较代码放在ADT内部
public void sort(List<Edge> edges) {
	Collections.sort(edges);
}
~~~

#### <font color=red>CRP</font>

Composite/Aggregate Reuse Principle(CARP)：尽量使用合成/聚合达到复用，尽量少用继承

| 临时性的委托                                           | 合成的委托                                             | 聚合的委托                                             |
| ------------------------------------------------------ | ------------------------------------------------------ | ------------------------------------------------------ |
| ![](https://i.loli.net/2020/06/12/skTS28bN5E649UH.png) | ![](https://i.loli.net/2020/06/12/PI43xKtfeZJcauD.png) | ![](https://i.loli.net/2020/06/12/e9xwdWfguNH1BDK.png) |

#### 几种经典的面向复用的设计模式

Structural patterns 结构型模式： Adaptor、Decorator、Facade

Behavioral patterns 行为类模式 ：Strategy、Template method、Iterator

#### <font color=red>Adaptor模式</font>

适配器模式：将某个类/接口转换为client期望的其他形式  

实现方式：通过增加一个接口，将已存在的子类封装起来， client面向接口编程，从而隐藏了具体子类  

~~~java
class LegacyRectangle {
	void display(int x1, int y1, int w, int h) {... }
}

// 接口不匹配
class Client {
	public display() {
		new LegacyRectangle().display(x1, y1, x2, y2);
	}
}
~~~

添加Adaptor类Rectangle实现抽象接口，并完成适配

~~~java
interface Shape {
	void display(int x1, int y1, int x2, int y2);
}
// Adaptor
class Rectangle implements Shape {
	void display(int x1, int y1, int x2, int y2) {
		new LegacyRectangle().display(x1, y1, x2-x1, y2-y1);
	}
}

class LegacyRectangle {
	void display(int x1, int y1, int w, int h) {...}
}
class Client {
    // 适配
	Shape shape = new Rectangle();
	public display() {
		shape.display(x1, y1, x2, y2);
	}
}
~~~

#### <font color=red>Decorator模式</font>

装饰器模式：为对象增加不同侧面的特性  

实现方式：对每一个特性构造子类，通过委派机制增加到对象上  

~~~java
// 包装stack得到Decorator基本类
public abstract class StackDecorator implements Stack {
	protected final Stack stack;
	public StackDecorator(Stack stack) {
		this.stack = stack;
	}
	public void push(Item e) {
		stack.push(e);
	}
	public Item pop() {
		return stack.pop();
	}
	...
}

// 对其进行包装
public class UndoStack extends StackDecorator implements Stack {
	private final UndoLog log = new UndoLog();
	public UndoStack(Stack stack) {
		super(stack);
	}
	public void push(Item e) {
		log.append(UndoLog.PUSH, e); //新特性
		super.push(e);
	}
	public void undo() {
		//implement decorator behaviors on stack
	}
	...
}

//使用
Stack t = new UndoStack(new ArrayStack());
~~~

#### <font color=red>Facade模式</font>

外观（门面）模式：客户端需要通过一个简化的接口来访问复杂系统内的功能  

实现方式：提供一个统一的接口来取代一系列小接口调用，相当于对复杂系统做了一个封装，简化客户端使用

例子略

#### <font color=red>Strategy模式</font>

策略模式：有多种不同的算法来实现同一个任务，但需要client根据需要动态切换算法，而不是写死在代码里 

实现方式：为不同的实现算法构造抽象接口，利用delegation，运行时动态传入client倾向的算法类实例  

例子略

#### <font color=red>Template模式</font>

模板模式：不同的客户做事情的步骤一样，但具体方法有些相同有些不同  

实现方式：共性的步骤在抽象类内公共实现，差异化的步骤在各个子类中实现  

~~~java
// 抽象父类
public abstract class OrderProcessTemplate{
    public boolean isGift;
	public abstract void doSelect();
	public abstract void doPayment();
    // 相同的步骤操作在抽象父类中直接实现
	public final void giftWrap() {
		System.out.println("Gift wrap done.");
	}
	public abstract void doDelivery();
    // 步骤模板
	public final void processOrder() {
		doSelect();
		doPayment();
		if (isGift)
			giftWrap();
		doDelivery();
	}
}
// 子类重写父类的非公共操作
public class NetOrder extends OrderProcessTemplate {
	@Override
	public void doSelect() { … }
	@Override
	public void doPayment() { … }
	@Override
	public void doDelivery() { … }
}
~~~

#### <font color=red>Iterator模式</font>

迭代器模式：设计了一个容器/集合类的对象，提供一种方法访问一个容器（container）对象中各个元素，而又不需暴露该对象的内部细节

实现方式课间与网上资料有些不同：

实现Iterable接口，并实现自己的独特Iterator迭代器(hasNext, next, remove)，并允许客户端利用（ppt）

自己写实现Iterator（网上资料），如下

~~~java
// 接口
public interface Iterator {
	public Object next(); 
	public boolean hasNext();
}
// 实现Interator
public class ConcreteIterator implements Iterator {

    private List list = new ArrayList();
    private int cursor = 0;

    public ConcreteIterator(List list) {
        this.list = list;
    }

    @Override
    public Object next() {
        Object obj = null;
        if (this.hasNext()) {
            obj = this.list.get(cursor++);
        }
        return obj;
    }

    @Override
    public boolean hasNext() {
        if (cursor == list.size()) {
            return false;
        }
        return true;
    }
}
// 抽象容器
public interface Aggregate {
    public void add(Object obj);  
    public void remove(Object obj);  
    public Iterator iterator(); 
}
// 在容器中添加Iterator获取
public class ConcreteAggregate implements Aggregate {

    private List list = new ArrayList();  
    
    @Override
    public void add(Object obj) {
        list.add(obj);
    }
    @Override
    public void remove(Object obj) {
        list.remove(obj);
    }
    @Override
    public Iterator iterator() {
         return new ConcreteIterator(list); 
    }
}
// 客户端使用
public class Client {
    public static void main(String[] args) {
        Aggregate ag = new ConcreteAggregate();
        ag.add("小明");
        ag.add("小红");
        ag.add("小刚");
        Iterator it = ag.iterator();
        while (it.hasNext()) {
            String str = (String) it.next();
            System.out.println(str);
        }
      }
}
~~~

## Unit 5

### Target

- [x] 可维护性的常见度量指标
- [x] 聚合度与耦合度
- [x] SOLID
- [x] <font color=red>设计模式： factory method、abstract factory、 proxy、observer/observable、 visitor、statememento</font>
- [x] <font color=red>语法、正则表达式</font>

### Context

#### 可维护性的常见度量指标

圈复杂度CC = E-N+2  E表示控制流图中边的数量，N表示控制流图中节点的数量

Halstead Volume，略

可维护性指数越高可维护性越好，公式略

继承的层次数 、类之间的耦合度  、单元测试的覆盖度  

#### 聚合度与耦合度

耦合是两模块间独立性的量度，越低越独立

内聚是一个模块内方法或责任的相关性的亮度，越高越相关

模块化编程应当高内聚、低耦合

#### 面向对象编程原则：SOLID

* (SRP) The Single Responsibility Principle 单一责任原则：一个类，一个责任  

~~~java
// 两个责任：Connection Management 、Data Communication
interface Modem {
	public void dial(String pno);
	public void hangup();
    
	public void send(char c);
	public char recv();
}

// 应该分开
interface DataChannel {
	public void send(char c);
	public char recv();
}
interface Connection {
	public void dial(String phn);
	public char hangup();
}
~~~

* (OCP) The Open-Closed Principle 开放-封闭原则：模块行为是可扩展的，修改的时候不要修改原有的代码

>  比如有多种不同类型的Server，那么每出现一种新的Server，就需要修改Server内部代码；而如果使用抽象的Server类做父类，其中包含公共部分，而将特殊部分交给子类实现便可以实现OCP；

~~~ java
public void drawShape(Shape s) {
	if (s.m_type==1)		// if-else将导致扩展新行为时改变原有代码
		drawRectangle(s);
	else if (s.m_type==2)
	drawCircle(s);
}
	public void drawCircle(Circle r)
	{....}
	public void drawRectangle(Rectangle r)
	{....}
}

class Shape {
	int m_type;
}
class Rectangle extends Shape {
	Rectangle() {
		super.m_type=1;
	}
}
class Circle extends Shape {
	Circle() {
		super.m_type=2;
    }
}

// 将不同功能封装到不同形状中可以实现OCP
class GraphicEditor {
	public void drawShape(Shape s) {
		s.draw();
	}
}
class Shape {
	abstract void draw();
}
class Rectangle extends Shape {
	public void draw() {
	// draw the rectangle
	}
}
~~~

* (LSP) The Liskov Substitution Principle Liskov替换原则：略
* (DIP) The Dependency Inversion Principle 依赖转置原则：只对接口编程，依赖于抽象而不依赖于具体。

> 依赖倒置原则在java中表现就是，模块间依赖通过抽象发生，实现类之间不发生直接依赖关系，其依赖关系是通过接口或者抽象类产生的。如果类与类直接依赖细节，那么就会直接耦合。如此一来当修改时，就会同时修改依赖者代码，这样限制了可拓展性。

~~~java
//文学经典类
public class LiteraryClassic{
    //阅读文学经典
    public void read(){
       System.out.println("文学经典阅读，滋润自己的内心心灵");
    }
}
//小明类
public class XiaoMing{
    //阅读文学经典
    public void read(LiteraryClassic literaryClassic){
        literaryClassic.read();
    }
}
// 场景
public class Client{
   public static void main(Strings[] args){
      XiaoMing xiaoming = new XiaoMing();
      LiteraryClassic literaryClassic = new LiteraryClassic();
      //小明阅读文学经典
      xiaoming.read(literaryClassic);
   }
}

//但小明想看小说时，发现中委托实现依赖LiteraryClassic具体类
//小说类
public class Novel{
    //阅读小说
    public void read(){
       System.out.println("阅读小说，放松自己");
    }
}
//正确的做法应该是创建小说与文学经典的父类Book，小明委托Book中的read
~~~

* (ISP) The Interface Segregation Principle 接口聚合原则 ：使用多个隔离的接口，比使用单个“胖”接口要好

#### 几种经典的面向可维护性的设计模式  

Creational patterns ： Factory method、Abstract factory  

Structural patterns ：proxy

Behavioral patterns  ：observer、visitor

基于状态的构造模式：Memento、state

#### <font color=red>Factory Method pattern  </font>

工厂方法：定义一个用于创建对象的接口，让其子类来决定实例化哪一个类  

~~~java
// 产品接口
public interface Trace { // turn on and off debugging
	public void setDebug( boolean debug );
	// write out a debug message
	public void debug( String message );
    // write out an error message
	public void error( String message );
}
// 具体实现类1
public class FileTrace implements Trace {
    ...
}
// 具体实现类2
public class SystemTrace implements Trace {
    ...
}
// Client使用只能绑定到具体的类
Trace log = new SystemTrace();
log.debug( "entering log" );
Trace log2 = new FileTrace();
log.debug(“...”);

// 如果使用工厂方法
interface TraceFactory {
	public Trace getTrace();
	public Trace getTrace(String type);
	void otherOperation(){};
}
public class Factory implements TraceFactory {
	public Trace getTrace() {
		return new SystemTrace();
	}    
    public getTrace(String type) {
		if(type.equals(“file”)
			return new FileTrace();
		else if (type.equals(“system”)
			return new SystemTrace();
    }
}
              
// 客户端无需绑定到具体类
Trace log1 = new Factory1().getTrace();
log1.setDebug(true);
log1.debug( "entering log" );
Trace log2 = new Factory2().getTrace("system");
log2.setDebug(false);
log2.debug("...");
~~~

静态工厂方法略

抽象工厂方法：可以看到上述Factory中的if-else可能违反了开闭原则，所以通过定义抽象工厂父类，每个子类工厂实现某个具体产品类的创建，这便是抽象工厂方法。同时如果有多个顺序确定的产品需要创建，可利用工厂辅助类确定顺序

~~~java
// 抽象工厂
public interface AbstractWidgetFactory{
	public Window createWindow();
	public Scrollbar createScrollbar();
}
// 具体工厂1
public class WidgetFactory1 implements AbstractWidgetFactory{
	public Window createWindow(){
		...
	}
	public Scrollbar createScrollbar(){...}
}
// 具体工厂2
public class WidgetFactory2 implements AbstractWidgetFactory{
	public Window createWindow(){
		...
	}
	public Scrollbar createScrollbar(){...}
}
// 辅助类用来确定顺序
public class GUIBuilder{
	public void buildWindow(AbstractWidgetFactory widgetFactory){
        //先创建window
		Window window = widgetFactory.createWindow();
        //再创建scrollbar
		Scrollbar scrollbar = widgetFactory.createScrollbar();
		window.setTitle("New Window");
		window.addScrollbar(scrollbar);
	}
}
// Client
GUIBuilder builder = new GUIBuilder();
AbstractWidgetFactory widgetFactory = null;
if(“Motif”)
	widgetFactory = new WidgetFactory2();
else
	widgetFactory = new WidgetFactory1();
// 利用辅助类创建
builder.buildWindow(widgetFactory);
~~~

#### <font color=red>proxy pattern</font>

代理模式：某个对象比较“敏感” /“私密” /“贵重”，不希望被client直接访问到，在二者之间建立防火墙  

~~~java
public interface Image {
	void display();
}
public class RealImage implements Image {
	private String fileName;
	public RealImage(String fileName){
		this.fileName = fileName;
		loadFromDisk(fileName);
	}
	@Override
	public void display() {…}
	private void loadFromDisk(String fileName){…}
}
// 隐藏RealImage类
public class ProxyImage implements Image {
	private Image realImage;
	private String fileName;
	public ProxyImage(String fileName){
		this.fileName = fileName;
	}
	@Override
	public void display() {
		if(realImage == null){
		realImage = new RealImage(fileName);
	}
	realImage.display();
	}
}
//Client:
Image image = new ProxyImage(“pic.jpg");
image.display();
image.display();
~~~

#### <font color=red>Observer pattern  </font>

观察者模式：实现一对多广播

~~~java
// 广播者，偶像
public class Subject {
    // 粉丝
	private List<Observer> observers = new ArrayList<Observer>();
	private int state;
	public int getState() {return state;}
	public void setState(int state) {
		this.state = state;
		notifyAllObservers();
	}
    // 绑定粉丝
	public void attach(Observer observer){observers.add(observer);}
	private void notifyAllObservers(){ // 一对多广播
		for (Observer observer : observers) {
			// 通过委托实现
            observer.update();
		}
	}
}
// 接受广播者， 粉丝
public abstract class Observer {
	protected Subject subject;
	public abstract void update();
}
// 具体粉丝
public class BinaryObserver extends Observer{
    // 通过偶像创建
	public BinaryObserver(Subject subject){
		this.subject = subject;
		this.subject.attach(this);
	}
	@Override
	public void update() {
		System.out.println( "Binary String:"+Integer.toBinaryString(subject.getState()));
	}
}

// Client
Subject subject = new Subject();
new HexaObserver(subject);
new OctalObserver(subject);
new BinaryObserver(subject);
attach...
System.out.println("First state change: 15");
subject.setState(15);
System.out.println("Second state change: 10");
subject.setState(10);
~~~

Java里已经实现了该模式

* Observable 抽象类，直接派生子类 即可构造“偶像”
* Observer接口，实现该接口，构造“粉丝”  

#### <font color=red>Visitor pattern</font>

访问者模式：在特定ADT上执行某种特定操作，但该操作不在ADT内部实现，而是delegate到独立的visitor对象，客户端可灵活扩展/改变visitor的操作算法，而不影响ADT  

~~~java
// 数据结构
public interface ItemElement {
	public int accept(ShoppingCartVisitor visitor);
}
// 具体数据结构1
public class Book implements ItemElement{
	private double price;
	...
	int accept(ShoppingCartVisitor visitor) {
		// 委托ShoppingCartVisitor类
        visitor.visit(this);
	}
}
// 具体数据结构2
public class Fruit implements ItemElement{
	private double weight;
	...
	int accept(ShoppingCartVisitor visitor) {
        // 委托ShoppingCartVisitor类
		visitor.visit(this);
	}
}
// visitor抽象类
public interface ShoppingCartVisitor {
	int visit(Book book);
	int visit(Fruit fruit);
}
// visitor实现类，实现操作与数据结构的分离
public class ShoppingCartVisitorImpl implements ShoppingCartVisitor {
	public int visit(Book book) {
        // 操作细节
		int cost=0;
		if(book.getPrice() > 50){
			cost = book.getPrice()-5;
		}else
		cost = book.getPrice();
		System.out.println("Book ISBN::"+book.getIsbnNumber() + " cost ="+cost);
		return cost;
	}
	public int visit(Fruit fruit) {
		int cost = fruit.getPricePerKg()*fruit.getWeight();
		System.out.println(fruit.getName() + " cost = "+cost);
		return cost;
	}
}
~~~

#### <font color=red>Memento pattern</font>

备忘录模式：记住对象的历史状态，以便于“回滚”  

~~~java
// 
class Memento {
    private State state; 
	public Memento(State state) {
		this.state = state;
	}
	public State getState() {
		return state;
	}
}

class Originator {
	private State state;
	public void setState(State state) {
		System.out.println("Originator: Setting state to " + state.toString());
		this.state = state;
	}
	public Memento save() {
		System.out.println("Originator: Saving to Memento.");
		return new Memento(state);
	}
    // 恢复历史记录
	public void restore(Memento m) {
		state = m.getState();
		System.out.println("Originator: State after restoring from Memento: " + state);
	}
}

class Caretaker {
	private List<Memento> mementos	= new ArrayList<>();
	public void addMemento(Memento m) {
		mementos.add(m);
	}
	public Memento getMemento() {
		return mementos.get(?);  //具体需要回滚到那个版本
	}
}
// Client
public static void main(String[] args) {
	Caretaker caretaker = new Caretaker();
	Originator originator = new Originator();
	originator.setState("State1");
	originator.setState("State2");
    // 存档
	caretaker.addMemento( originator.save() );
	originator.setState("State3");
    // 存档
	caretaker.addMemento( originator.save() );
	originator.setState("State4");
    // 恢复
	originator.restore( caretaker.getMemento() );
}
~~~

#### <font color=red>State pattern</font>

略，见实验

#### <font color=red>语法</font>

语法解析树    非终止节点 \ 终止节点

常见操作：

* `x ::= y z`  ，连接
* `x ::= y | z` ，选择
* `x ::= y*`，0个或多个
* `x ::= y?`  ， 1个或0个
* `x ::= y+ ` ， 1个或多个
* `x ::= [a-c]`  ， 从a到c的某个字符
* `x ::= [aeiou]`，aeiou中的某个字符  
* `x ::= [^a-c]`，除了从a到c以外的某个字符

~~~java
root = (A B)+
A = [Aa] // 字符A与a
B = [Bb] 
    //aaaBBB ×
	//abababab √
	//aBAbabAB √
	//AbAbAbA ×
~~~

#### <font color=red>正则表达式</font>

* `.  `，代表任意一个字符
* `\d`  ，即`[0-9]`
* `\s`，任意空白符
* `\w`，即`[a-zA-Z_0-9]  `，包括下划线！
* 转义，`\. , \( , \) , \* , \+ , ...  `

## Unit 6

### Target

- [x] 健壮性和正确性
- [x] Throwable
- [x] Error/Runtime异常、其他异常
- [x] <font color=red>Checked异常、 Unchecked异常</font>
- [x] Checked异常的处理机制：
  – 声明、抛出、捕获、处理、清理现场、释放资源等
- [x] <font color=red>自定义异常类</font>
- [x] 断言的作用、 应用场合
- [x] 调试的基本过程和方法
- [x] <font color=red>黑盒测试用例的设计</font>
  – 等价类划分、边界值分析
- [x] 以注释的形式撰写测试策略
- [x] JUnit测试用例写法
- [x] 测试覆盖度  

### Context

#### 健壮性与正确性

健壮性：系统在不正常输入或不正常外部环境下仍能够表现正常的程度  

正确性：程序按照spec加以执行的能力，<font color=blue>是最重要的质量指标！  </font>

对外的接口，倾向于健壮；对内的实现，倾向于正确

#### Throwable

![](https://i.loli.net/2020/06/13/ohlJIrKEA1i5jmg.png)

#### Error/Runtime异常、其他异常

如上图所示

* Error类描述的是内部系统错误，很少发生，开发者也无需操心
* RuntimeException类是由程序员在代码里处理不当造成的，是开发者的锅，也是开发者可以改正的

* 其他异常不是开发者代码问题，而是由外部原因造成，需要捕获、处理 

> 比如数组越界异常，明明知道了是数组越界，说明是开发者自己代码写的有问题，当然应该修改代码，如果放任不管并捕获这个异常不是掩耳盗铃吗；而对于IO异常，开发者并不知道是因为什么，很可能是用户的错误输入，但开发者也没法保证这些异常一定不会出现，所以应该捕获并处理这个异常。

#### <font color=red>checked异常、unchecked异常</font>

unchecked异常=Runtime异常（程序源代码中引入的故障所造成的）+ Error

checked异常=非运行时异常，是程序员无法完全控制的外在问题所导致的，编译器可帮助检查你的程序是否已抛出或处理了可能的异常  

分类也不是绝对的，uncheck和check的区分就在于是否是程序员的错误还是外部带来的

#### checked异常的处理操作

try、catch、finally、throws、throw  

throws用于方法声明，注意要写进spec中，代表此方法只抛出而不处理某个异常，而是把它交给调用者处理；

在try中throw异常，会直接跳到catch代码块；可以一个try多个catch，也可以没有catch只有finally；也可以在catch中rethrow异常

~~~java
try {
	access the database...
}
catch (SQLException e) {
    // rethrow
	throw new ServletException("database error: " + e.getMessage());
}
~~~

finally代码块不管try中是否throw异常都会执行，甚至在return后也会执行

~~~java
try{
	...
	return true;
}finally{
    ...		//不管怎么样都会执行到finally，都会返回false
    return false;
}

int a=1;
try{
	...
	return true;
}finally{
    ...		//不管怎么样都会执行到finally，方法返回true，但是a会变为2
    a=2;
}
~~~

try-with-resource相当于finally中把resource关掉

~~~java
try (Scanner in = new Scanner(new FileInputStream("/dict/words")),"UTF-8") {
	while (in.hasNext())
	System.out.println(in.next());
}catch(){
    ...
}//结束后会自动调用in.close()
~~~

#### <font color=red> 自定义异常类</font>

通过继承Exception类或其子类来自定义异常

~~~java
public class FooException extends Exception {
	public FooException() { super(); }
	public FooException(String message) { super(message); }
	public FooException(String message, Throwable cause) {
		super(message, cause);
	}
	public FooException(Throwable cause) { super(cause); }
}
~~~

#### 断言的作用、 应用场合

断言：在开发阶段的代码中嵌入，检验某些“假设”是否成立。若成立，表明程序运行正常，否则表明存在错误  

<font color=blue>注意断言机制在产品中一般会被关闭，所以断言只是开发者在开发阶段用来调试内部bug的</font>

换句话说，断言即是对代码中程序员所做假设的文档化，也不会影响运行时性能。一般用于检测内部不变性、表示不变性、方法的前置条件、后置条件等。

~~~java
//两种格式
assert (something_should_be_true);
assert (something_should_be_true):"print something you want"
~~~

在开发阶段，使用异常来处理“预料到可以发生”的不正常情况；使用断言处理“绝不应该发生”的情况；如果参数来自于外部（不受自己控制），使用异常处理；如果来自于自己所写的其他代码，可以使用断言来帮助发现错误    

#### 调试的基本过程和方法

略（貌似都是废话？

#### 测试

按层次：单元测试  、集成测试  、系统测试

按动作：静态测试（用眼睛摁看） 、动态测试（用测试用例跑程序）

测试：发现是否存在错误  ；调试：识别错误根源，消除错误  

测试优先的编程  ：先写spec，再写符合spec的测试用例，最后写代码、执行测试、有问题再改、直到通过测试用例

#### JUNIT单元测试相关内容

略，见实验

#### <font color=red>黑盒测试及用例设计</font>

黑盒测试：用于检查代码的功能，不关心内部实现细节  

利用等价类划分来设计测试用例，<font color=blue>对方法的每个参数逐个考虑等价类</font>

~~~java
/**
* Reverses the end of a string.
*
* 012345 012345
* For example: reverseEnd("Hello, world", 5) returns "Hellodlrow ,"
* <-----> <----->
*
* With start == 0, reverses the entire text.
* With start == text.length(), reverses nothing.
*
* @param text non-null String that will have its end reversed
* @param start the index at which the remainder of the input is reversed,
* requires 0 <= start <= text.length()
* @return input text with the substring from start to the end of the string
* reversed
*/
public static String reverseEnd(String text, int start)
   //等价类划分
   //对于start参数：start = 0, 0 < start < text.length(), start = text.length()
   //对于text参数：text.length() = 0; text.length()-start is odd; text.length()-start is even
~~~

边界值分析是对等价类划分方法的补充  

~~~java
 max(int a,int b) : int × int → int
     //等价类划分
     // a,b间的关系：a>b;a<b;a==b
     //	a的值：a<0;a=0;a>0;a是最小整数、a是最大整数
     // b的值：b<0;b=0;b>0;b是最小整数、b是最大整数
     //  笛卡尔积测试：3*5*5个测试用例
     //	 非笛卡尔积测试：3+5+5个测试用例以内
~~~

测试用例的编写分为笛卡尔积（全覆盖），覆盖每个取值（每个维度的每个取值至少被1个测试用例覆盖一次）    

<font color=blue>不在规约范围内的数据不需要测试。但注意，在测试Exception的时候可能会故意输入错误数据，这也是测试的一部分。</font>这也并不矛盾，毕竟异常本就是规约的一部分。

#### 白盒测试

白盒测试：根据程序执行路径设计测试用例 ，是穷举路径的测试。

## Unit 7

### Target

- [x] <font color=red>进程和线程</font>
- [x] <font color=red>线程的创建和启动， runnable</font>
- [x] 内存共享模式、消息传递模式
- [x] <font color=red>时间分片、交错执行、竞争条件</font>
- [x] <font color=red>线程的休眠、中断</font>
- [x] <font color=red>线程安全threadsafe的四种策略</font>
  – Confinement、 Immutability、 ThreadSafe类型
  – Synchronization/Lock
- [x] 死锁
- [x] 以注释的形式撰写线程安全策略 (ThreadSafe Argument)  

### Context

#### <font color=red>进程与线程</font>

进程(Process)：粒度大，私有空间，彼此隔离  ，拥有整台计算机的资源，用fork创建新进程

线程(Thread)：粒度小，是程序内部的控制机制，多个线程共用一块内存

进程=虚拟机；线程=虚拟CPU  

多进程之间不共享内存 ，只能通过消息传递进行协作

多线程之间会自动共享内存 ，也可以创建消息队列在线程之间进行消息传递  

#### 并行编程的两大模板

内存共享模式：在内存中读写共享数据  

> 两个处理器，共享内存 ;同一台机器上的两个程序，共享文件系统  ;同一个Java程序内的两个线程，共享Java对象  

消息传递模式：通过channel交换消息  

> 网络上的两台计算机，通过网络连接通讯  ;浏览器和Web服务器， A请求页面， B发送页面数据给A;即时通讯软件的客户端和服务器;同一台计算机上的两个程序，通过管道连接进行通讯  

| Shared memory                                          | Message passing                                        |
| ------------------------------------------------------ | ------------------------------------------------------ |
| ![](https://i.loli.net/2020/06/14/FE8vXnqYPi61oB9.png) | ![](https://i.loli.net/2020/06/14/HmWAT5ByKwFQRDX.png) |

#### <font color=red>线程的创建和启动， runnable</font>

方法一：继承Thread类，重写Thread.run()即可开启新进程

~~~java
public class HelloThread extends Thread {
	// 只需重写run方法
    public void run() {
		System.out.println("Hello from a thread!");
	}
    
    //启动该线程的两个方式
	public static void main(String args[]) {
		HelloThread p = new HelloThread();
		p.start();
	}
	
	public static void main(String args[]) {
		(new HelloThread()).start();
	}
}
~~~

方法二：实现Runnable.run()，注意Runnable类启动线程的方式

~~~java
public class HelloRunnable implements Runnable {
	public void run() {
		System.out.println("Hello from a thread!");
	}
    
	public static void main(String args[]) {
        // 启动线程
		(new Thread(new HelloRunnable())).start();
	}
}

// 也可简写
new Thread(new Runnable() {
	public void run() {
		System.out.println("Hello");
	}
}).start();
~~~

<font color=blue>注意上述代码，写的是Runnable.run()，调用的是Thread.start()。</font>也很容易理解，如果直接调用Thread.run()它只会打印，可以看出start()中包含了启动线程的所有底层操作，其中也会调用run()来执行用户操作

#### <font color=red>时间分片、交错执行、竞争条件</font>

虽然有多线程，但只有一个核，每个时刻只能执行一个线程；即使是多核CPU，进程/线程的数目也往往大于核的数目；通过时间分片，在多个进程/线程之间共享处理器，它是由OS自动调度的。下图为两核三线程的例子，可以看到多个线程是交错执行的。

![](https://i.loli.net/2020/06/14/2m3MxjTUL7b9qcP.png)

条件竞争的产生原因：单行、单条语句都未必是原子的  （是否原子，由JVM确定  ）

~~~java
private static int x = 1;
public static void methodA() {
	x *= 2;
	x *= 3;
}
public static void methodB() {
	x *= 5;
}
//	x *= 2的原子操作为：
//		1.取出x放入寄存器
//		2.寄存器值*2
//		3.将寄存器的值写回x
//
// 并行运行A、B，最终x可能为5，6，10，30
//	5：B取出x=1 ---> A方法执行结束 ---> B寄存器值*5 ---> 写回x=5
//	6: A执行x*=2后x=2 ---> A取出x=2 ---> B方法执行结束 ---> A寄存器值*3 ---> 写回x=6
//	10: A执行x*=2后x=2 ---> B取出X=2 ---> A方法执行x*=3 ---> B寄存器值*5 ---> 写回x=10
//	30: 顺序执行即可
~~~

由于发送者在等待接受消息时并没有停止工作，所以消息传递机制也无法解决竞争条件问题  

很常见的问题就是Iterator，不能在用Iterator遍历的时候调用remove()

#### <font color=red>线程的休眠、中断</font>

* Thread.sleep(time)  调用方法的进程休眠time毫秒

* t.interrupt()  调用方法的进程向t进程发送中断信号

* t.isInterrupted() 检查t是否收到中断信号(中断位是否置上)  
* Thread.interrupted() 检测调用方法的进程中断位是否置上，<font color=blue>并会将中断位清零</font>

<font color=blue>但进程接收到中断信号并不会立即中断。正常运行期间，即使接收到中断信号，也不理会 ！</font>

~~~java
class Task implements Runnable{
	private double d = 0.0;
	public void run() {
		try{
			while (true) {
                // 正常运行时就算接收到中断信号也不理会，继续执行
				for (int i = 0; i < 900000; i++)
					d = d + (Math.PI + Math.E) / d;
                // 直到sleep()时才会检测是否收到中断信号，如果收到则自动抛出中断异常
				Thread.sleep(500);
                // 或者直接用Thread.interrupted或者isInterrupted检测
                //if (Thread.interrupted()) {
				//	throw new InterruptedException();
				//}
			}
          	//进入异常处理执行return后，线程才真正终止
		} catch(InterruptedException e) {return;}
	}
}

Thread t = new Thread(new Task());
t.start();
Thread.sleep(100); //当前线程休眠
t.interrupt(); //试图中断t线程
~~~

<font color=blue>需要注意的是，interrupt本身不会直接结束线程，它只是发个信号，在待中断线程中使用sleep或isInterrupted() 接受这个信号并抛出异常，并在异常处理中return才会结束这个进程</font>

* t.join() 调用方法的进程暂停，直到进程t执行结束

~~~java
public class JoinExample2 {
    // 三个进程操作之间的执行次序并不确定
	public static void main(String[] args) {
		Thread th1 = new Thread(new MyClass2(), "th1");
		Thread th2 = new Thread(new MyClass2(), "th2");
		Thread th3 = new Thread(new MyClass2(), "th3");
		th1.start();
		th2.start();
		th3.start();
		}
}

// 三个进程操作执行次序确定，th1所有操作顺序执行结束 --> th2... --> th3...
public class JoinExample {
	public static void main(String[] args) {
		Thread th1 = new Thread(new MyClass(), "th1");
		Thread th2 = new Thread(new MyClass(), "th2");
		Thread th3 = new Thread(new MyClass(), "th3");
        
		th1.start();
		try {
            // main进程不会继续执行，直到th1执行结束
            // join过程中也会接受中断信号并自动抛出异常
			th1.join();
		} catch (InterruptedException ie) {}
        
		th2.start();
		try {
			th2.join();
		} catch (InterruptedException ie) {}
        
		th3.start();
		try {
			th3.join();
		} catch (InterruptedException ie) {}
	}
}
~~~

#### <font color=red>线程安全threadsafe的四种策略</font>
Confinement、 Immutability、 ThreadSafe类型、Synchronization/Lock

#### <font color=red>Confinement  </font>

 Confinement：限制数据共享

核心思想：线程之间不共享mutable数据类型、避免全局变量  

将可变数据限制在单一线程内部，避免竞争，不允许任何其他线程直接读写该数据  

除非知道线程访问的所有数据，否则Confinement无法彻底保证线程安全    

#### <font color=red>Immutability</font>

Immutability ：共享数据为不可变类型、或是只能读不能写

鸡肋

#### <font color=red>Using Threadsafe Types  Data</font>
 如果必须要用mutable的数据类型在多线程之间共享数据，要使用线程安全的数据类型。 

 一般来说，JDK同时提供两个相同功能的类，一个是threadsafe，另一个不是。原因： threadsafe的类一般性能上受影响  

比如集合类都是线程不安全的。Java API提供了进一步的decorator。对它们的每一个操作调用，都以原子方式执行。但在使用synchronizedMap(hashMap)之后，不要再把参数hashMap共享给其他线程，不要保留别名，一定要彻底销毁        

~~~java
private static Map<Integer,Boolean> cache =Collections.synchronizedMap(new HashMap<>());
~~~

<font color=blue>但即使在线程安全的集合类上，使用iterator也是不安全的；即使是线程安全的collection类，仍可能产生竞争。</font>因为执行其上某个操作是threadsafe的，但如果多个操作放在一起，仍旧不安全      

~~~java
方法A:
if ( ! lst.isEmpty()) {
	String s = lst.get(0);
	...
}
方法B:
 //释放lst

//A与B并行时，A方法中判断lst非空后，B方法将其释放，在A方法get(0)就会访问空指针报错
//虽然lst是threadsafe的，但多个操作之间仍然不可靠，
~~~

#### <font color=red>Synchronization/Lock</font>

程序员来负责多线程之间对mutable数据的共享操作，通过“同步”策略，避免多线程同时访问数据 

Lock是Java语言提供的内嵌机制,<font color=blue>每个object都有相关联的lock</font>，拥有lock的线程可独占式的执行该部分代码。使用同一个lock的操作是线程互斥的，但同步机制给性能带来极大影响  

~~~ java
Object lock = new Object();

//方法A:
synchronized (lock) { // thread blocks here until lock is free
	// now this thread has the lock
	balance = balance + 1;
	// exiting the block releases the lock
}

//方法B:
synchronized (lock) {
    ...
}
// 类似于在lock对象的锁位上置1
// 如果先执行方法A的锁，方法B检测到lock已经被置1便无法执行，直到A执行结束，锁释放
~~~

Monitor模式： ADT所有方法都是互斥访问，并且用ADT自己做lock  

| 方法一                                                 | 方法二                                                 |
| ------------------------------------------------------ | ------------------------------------------------------ |
| ![](https://i.loli.net/2020/06/14/CP3ER9rzWcyO4ND.png) | ![](https://i.loli.net/2020/06/14/bQw347zshSWo2BI.png) |

<font color=blue>对静态方法按照方法二加缩意味着在class层面上锁！此时多个线程中所有此类型的对象的此静态方法均是并行互斥的。</font>

> 不过静态方法加锁锁住的只是static synchronized块，synchronized块锁不住，而不加锁的方法更加锁不住

注意只有两个加锁部分的代码块是互斥的，并不是说把充当锁的对象的操作都变成了并行互斥的。

~~~java
//Thread A
public void run() {
	…
	synchronized(lst) {
	… }
}

//Thread B
public void run() {
	…
	lst.add(…);
	lst.size();
}

// A、B线程可以并行
~~~



应该尽可能减小lock的范围，避免在方法spec中加synchronized，而是在方法代码内部更加精细的区分哪些代码行可能有threadsafe风险，为其加锁    

#### 以注释的形式撰写线程安全策略 (ThreadSafe Argument) 

在代码中以注释的形式增加说明：该ADT采取了什么设计决策来保证线程安全  

* 采取了四种方法中的哪一种？  
* 如果是后两种，还需考虑对数据的访问都是原子的，不存在interleaving  

| 不可变类型说明                                         | 加锁说明                                               |
| ------------------------------------------------------ | ------------------------------------------------------ |
| ![](https://i.loli.net/2020/06/14/jqIRTFNyXOHJ42Y.png) | ![](https://i.loli.net/2020/06/14/t4cXVLmZIJ8kR1s.png) |

#### 死锁

死锁：多个线程竞争lock，相互等待对方释放lock  

~~~java
// 如果进入到A，把a锁上的同时进入到B，把b锁上
// 这样方法A等待B释放b，方法B等待A释放a
// 就会造成死锁
Method A: synchronized(a){ synchronized(b){ … } }
Method B: synchronized(b){ synchronized(a){ … } }
~~~





