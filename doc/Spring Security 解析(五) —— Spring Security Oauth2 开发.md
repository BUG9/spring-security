##  Spring Security 解析(五) —— Spring Security Oauth2 开发

>  &emsp;&emsp;在学习Spring Cloud 时，遇到了授权服务oauth 相关内容时，总是一知半解，因此决定先把Spring Security 、Spring Security Oauth2 等权限、认证相关的内容、原理及设计学习并整理一遍。本系列文章就是在学习的过程中加强印象和理解所撰写的，如有侵权请告知。


> 项目环境:
> - JDK1.8
> - Spring boot 2.x
> - Spring Security 5.x

&emsp;&emsp;前面几篇文章基本上已经把Security的核心内容讲得差不多了，那么从本篇文章我们开始接触Spring Security Oauth2 相关的内容，这其中包括后面的 Spring Social （其本质也是基于Oauth2）。有一点要说明的是，我们是在原有的Spring-Security 项目上继续开发，存在一些必要的重构，但不影响前面Security的功能。
### 一、 Oauth2 与 Spring Security Oauth2

#### Oauth2
&emsp;&emsp;有关于Oauth2 的 资料，网上很多，但最值得推荐的还是 阮一峰老师的 [理解OAuth 2.0](http://www.ruanyifeng.com/blog/2014/05/oauth_2_0.html),在这里我就不重复描述Oauth2了，但我还是有必要提下其中的重要的点:
![http://ww1.sinaimg.cn/large/005Q13r0gy1g6wku1v2ccj30qc0d0tdy.jpg](http://ww1.sinaimg.cn/large/005Q13r0gy1g6wku1v2ccj30qc0d0tdy.jpg)
&emsp;&emsp;图片中展示的流程是授权码模式的流程，其中最核心正如图片展示的一样：
- 资源所有者（Resource Owner）： 可以理解为用户
- 服务提供商(Provider): 分为认证服务器(Authorization server)和 资源服务器(Resource server)。怎么理解认证、资源服务器呢，很简单，比如我们手机某个APP通过QQ来登陆，在我们跳转到一个QQ授权的页面以及登陆的操作都是在认证服务器上做的，后面我们登陆成功后能够看到我们的头像等信息，这些信息就是登陆成功后去资源服务器获取到的。
- 第三方应用: 可以理解就是我们正在使用的某个APP，用户通过这个APP发起QQ授权登陆。


#### Spring Security Oauth2
&emsp;&emsp; Spring 官方出品的 一个实现 Oauth2 协议的技术框架，后面的系列文章其实都是在解析它是如何实现Oauth2的。如果各位有时间的话可以看下[Spring Security Oauth2 官方文档](https://projects.spring.io/spring-security-oauth/docs/oauth2.html)，我的文章分析也是依靠文档来的。

&emsp;&emsp;最后，我个人总结这2者的区别： 
- Oauth2 不是一门技术框架， 而是一个协议，它仅仅只是制定好了协议的标准设计思想，你可以用Java实现，也可以用其他任何语言实现。
- Spring Security Oauth2 是一门技术框架，它是依据Oauth2协议开发出来的。


### 一、 Spring Security Oauth2 开发

&emsp;&emsp; 在微服务开发的过程中，一般会把授权服务器和资源服务器拆分成2个应用程序，所以本项目采用这种设计结构，不过在开发前，我们需要做一步重要得步骤，就是项目重构。

#### 一、 项目重构
 
&emsp;&emsp; 为什么要重构呢？因为我们是将授权和资源2个服务器拆分了，那么之前我们开发的一个可以公共的功能可以单独罗列出来，以及后面我们开发Spring Security Oauth2 得一些公共配置（比如Token相关配置）。 我们新建  security-core 子模块，将之前开发的短信等功能代码迁移到这个子模块中。最终得到以下项目结构：

![http://ww1.sinaimg.cn/large/005Q13r0gy1g6wqlrgoydj30di0jgt98.jpg](http://ww1.sinaimg.cn/large/005Q13r0gy1g6wqlrgoydj30di0jgt98.jpg)

&emsp;&emsp; 迁移完成后，原先项目模块更换模块名为 security-oauth2-authorization ，即 授权服务应用，并且 在pom.xml 中引用  security-core  依赖，迁移后该模块得鲜蘑菇结构如下：

![http://ww1.sinaimg.cn/large/005Q13r0gy1g6wqx4utumj30cp0dxgls.jpg](http://ww1.sinaimg.cn/large/005Q13r0gy1g6wqx4utumj30cp0dxgls.jpg)

&emsp;&emsp; 我们可以发现，迁移后的项目内部只有 Security相关的配置代码和测试接口，以及静态的html。 

#### 二、 授权服务器开发

##### 一、Maven依赖

&emsp;&emsp;在 security-core  模块的pom.xml 中引用 以下依赖：
```
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-security</artifactId>
        </dependency>
        <dependency>
            <groupId>org.springframework.security</groupId>
            <artifactId>spring-security-jwt</artifactId>
        </dependency>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-data-redis</artifactId>
        </dependency>
        <!-- 不是starter,手动配置 -->
        <dependency>
            <groupId>org.springframework.security.oauth</groupId>
            <artifactId>spring-security-oauth2</artifactId>
            <!--请注意下 spring-authorization-oauth2 的版本 务必高于 2.3.2.RELEASE，这是官方的一个bug:
            java.lang.NoSuchMethodError: org.springframework.data.redis.connection.RedisConnection.set([B[B)V
            要求必须大于2.3.5 版本，官方解释：https://github.com/BUG9/spring-security/network/alert/pom.xml/org.springframework.security.oauth:spring-security-oauth2/open
            -->
            <version>2.3.5.RELEASE</version>
        </dependency>
 ```
&emsp;&emsp;这里新增 spring-security-oauth2 依赖，一个针对token 的存储策略分别引用了 redis 和 jwt 依赖。

> 注意这里 spring-security-oauth2 版本必须高于 2.3.5 版本 ，否自使用 redis 存储token 策略会报出：
org.springframework.data.redis.connection.RedisConnection.set([B[B)V  异常


##### 二、配置授权认证 @EnableAuthorizationServer
