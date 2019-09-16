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
 
&emsp;&emsp; 为什么要重构呢？因为我们是将授权和资源2个服务器拆分了，之前开发的一些配置和功能是可以在2个服务器共用的，所以我们可以讲公共的配置和功能可以单独罗列出来，以及后面我们开发Spring Security Oauth2 得一些公共配置（比如Token相关配置）。 我们新建  security-core 子模块，将之前开发的短信等功能代码迁移到这个子模块中。最终得到以下项目结构：

![http://ww1.sinaimg.cn/large/005Q13r0gy1g6wqlrgoydj30di0jgt98.jpg](http://ww1.sinaimg.cn/large/005Q13r0gy1g6wqlrgoydj30di0jgt98.jpg)

&emsp;&emsp; 迁移完成后，原先项目模块更换模块名为 security-oauth2-authorization ，即 授权服务应用，并且 在pom.xml 中引用  security-core  依赖，迁移后该模块的项目结构如下：

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

&emsp;&emsp; security-oauth2-authorization 模块的 pom 引用 security-core ：
 ```
        <dependency>
            <groupId>mysql</groupId>
            <artifactId>mysql-connector-java</artifactId>
        </dependency>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-jdbc</artifactId>
        </dependency>
        <!-- 这里去掉 spring-security-oauth2 主要是其内部的版本是 低于2.3.5
        (security-core 本身 引用的就是 2.3.5 ，但为什么这边看到的却是低于其版本，暂时没找到原因，可能统一版本管理 platform-bom 的问题吧)
         ，为了防止出现异常这里去掉，再单独引用-->
        <dependency>
            <groupId>com.zhc</groupId>
            <artifactId>security-core</artifactId>
            <version>0.0.1-SNAPSHOT</version>
            <exclusions>
                <exclusion>
                    <groupId>org.springframework.security.oauth</groupId>
                    <artifactId>spring-security-oauth2</artifactId>
                </exclusion>
            </exclusions>
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
 

##### 二、配置授权认证 @EnableAuthorizationServer

&emsp;&emsp;在Spring Security Oauth2 中有一个 **@EnableAuthorizationServer** ，只要我们 在项目中引用到了这个注解，那么一个基本的授权服务就配置好了，但是实际项目中并不这样做。比如要配置redis和jwt 2种存储token策略共存，通过继承 **AuthorizationServerConfigurerAdapter** 来实现。 下列代码是我的一个个性化配置：

 ```
@Configuration
@EnableAuthorizationServer
public class AuthorizationServerConfiguration extends AuthorizationServerConfigurerAdapter {

    @Resource
    private AuthenticationManager authenticationManager;  // 1、引用 authenticationManager 支持 Password 授权模式

    private final Map<String, TokenStore> tokenStoreMap; // 2、获取到系统所有的 token存储策略对象 TokenStore ，这里我配置了 redisTokenStore 和 jwtTokenStore

    @Autowired(required = false)
    private AccessTokenConverter jwtAccessTokenConverter; // 3、 jwt token的增强器

    /**
     *  4、由于存储策略时根据配置指定的，当使用redis策略时，tokenEnhancerChain 是没有被注入的，所以这里设置成 required = false
      */
    @Autowired(required = false)
    private TokenEnhancerChain tokenEnhancerChain; // 5、token的增强器链

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Value("${spring.security.oauth2.storeType}")
    private String storeType = "jwt";  // 6、通过获取配置来判断当前使用哪种存储策略，默认jwt

    @Autowired
    public AuthorizationServerConfiguration(Map<String, TokenStore> tokenStoreMap) {
        this.tokenStoreMap = tokenStoreMap;
    }

    @Override
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
        //7、 配置一个客户端，支持客户端模式、密码模式和授权码模式
        clients.inMemory()  // 采用内存方式。也可以采用 数据库方式
                .withClient("client1") // clientId 
                .authorizedGrantTypes("client_credentials", "password", "authorization_code", "refresh_token") // 授权模式
                .scopes("read") // 权限范围 
                .redirectUris("http://localhost:8091/login") // 授权码模式返回code码的回调地址
                // 自动授权，无需人工手动点击 approve
                .autoApprove(true)  
                .secret(passwordEncoder.encode("123456"))
                .and()
                .withClient("client2")
                .authorizedGrantTypes("client_credentials", "password", "authorization_code", "refresh_token")
                .scopes("read")
                .redirectUris("http://localhost:8092/login")
                .autoApprove(true)
                .secret(passwordEncoder.encode("123456"));
    }

    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
        // 设置token存储方式，这里提供redis和jwt
        endpoints
                .tokenStore(tokenStoreMap.get(storeType + "TokenStore"))
                .authenticationManager(authenticationManager);
        if ("jwt".equalsIgnoreCase(storeType)) {
            endpoints.accessTokenConverter(jwtAccessTokenConverter)
                    .tokenEnhancer(tokenEnhancerChain);
        }
    }

    @Override
    public void configure(AuthorizationServerSecurityConfigurer oauthServer) throws Exception {
        oauthServer// 开启/oauth/token_key验证端口无权限访问
                .tokenKeyAccess("permitAll()")
                // 开启/oauth/check_token验证端口认证权限访问
                .checkTokenAccess("isAuthenticated()")
                //允许表单认证    请求/oauth/token的，如果配置支持allowFormAuthenticationForClients的，且url中有client_id和client_secret的会走ClientCredentialsTokenEndpointFilter
                .allowFormAuthenticationForClients();
    }
}
 ```
&emsp;&emsp;这里的配置分3部分：

- ClientDetailsServiceConfigurer： 配置客户端信息。 可以采用内存方式、JDBC方式等等，我们还可以像UserDetailsService一样定制ClientDetailsService。
- AuthorizationServerEndpointsConfigurer ： 配置 授权节点信息。这里主要配置 tokenStore 
- AuthorizationServerSecurityConfigurer： 授权节点的安全配置。 这里开启/oauth/token_key验证端口无权限访问（单点客户端启动时会调用该接口获取jwt的key，所以这里设置成无权限访问）以及 /oauth/token配置支持allowFormAuthenticationForClients（url中有client_id和client_secret的会走ClientCredentialsTokenEndpointFilter）
 

##### 三、配置 TokenStore
&emsp;&emsp;在配置授权认证时，依赖注入了 tokenStore 、jwtAccessTokenConverter、tokenEnhancerChain，但这些对象是如何配置并注入到Spring 容器的呢？且看下面代码：

 ```
@Configuration
public class TokenStoreConfig {
    /**
     * redis连接工厂
     */
    @Resource
    private RedisConnectionFactory redisConnectionFactory;

    /**
     * 使用redisTokenStore存储token
     *
     * @return tokenStore
     */
    @Bean
    @ConditionalOnProperty(prefix = "spring.security.oauth2", name = "storeType", havingValue = "redis")
    public TokenStore redisTokenStore() {
        return new RedisTokenStore(redisConnectionFactory);
    }

    @Bean
    PasswordEncoder passwordEncoder(){
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    /**
     * jwt的配置
     *
     * 使用jwt时的配置，默认生效
     */
    @Configuration
    @ConditionalOnProperty(prefix = "spring.security.oauth2", name = "storeType", havingValue = "jwt", matchIfMissing = true)
    public static class JwtTokenConfig {

        @Resource
        private SecurityProperties securityProperties;
        /**
         * 使用jwtTokenStore存储token
         * 这里通过 matchIfMissing = true 设置默认使用 jwtTokenStore
         *
         * @return tokenStore
         */
        @Bean
        public TokenStore jwtTokenStore() {
            return new JwtTokenStore(jwtAccessTokenConverter());
        }

        /**
         * 用于生成jwt
         *
         * @return JwtAccessTokenConverter
         */
        @Bean
        public JwtAccessTokenConverter jwtAccessTokenConverter() {
            JwtAccessTokenConverter accessTokenConverter = new JwtAccessTokenConverter();
            //生成签名的key,这里使用对称加密
            accessTokenConverter.setSigningKey(securityProperties.getOauth2().getJwtSigningKey());
            return accessTokenConverter;
        }

        /**
         * 用于扩展JWT
         *
         * @return TokenEnhancer
         */
        @Bean
        @ConditionalOnMissingBean(name = "jwtTokenEnhancer")
        public TokenEnhancer jwtTokenEnhancer() {
            return new JwtTokenEnhance();
        }

        /**
         * 自定义token扩展链
         *
         * @return tokenEnhancerChain
         */
        @Bean
        public TokenEnhancerChain tokenEnhancerChain() {
            TokenEnhancerChain tokenEnhancerChain = new TokenEnhancerChain();
            tokenEnhancerChain.setTokenEnhancers(Arrays.asList(new JwtTokenEnhance(), jwtAccessTokenConverter()));
            return tokenEnhancerChain;
        }
    }
}
 ```
 
 
 **&emsp;&emsp;注意： 该配置类适用于均适用于授权和资源服务器，所以该配置类是放在 security-core 模块**
 
 
##### 四、新增 application.yml 配置 
 ```
 spring:
   redis:
     host: 127.0.0.1
     port: 6379
   security:
     oauth2:
       storeType: redis
       jwt:
         SigningKey: oauth2
 ```

##### 五、启动测试

1、 **授权码模式**：grant_type=authorization_code

&emsp;&emsp;(1)浏览器上访问/oauth/authorize 获取授权码： 
 ```
http://localhost:9090/oauth/authorize?response_type=code&client_id=client1&scope=read&state=test&redirect_uri=http://localhost:8091/login
 ```
如果是没有登陆过，则跳转到登陆界面（这里账户密码登陆和短信验证码登陆均可），成功跳转到 我们设置的回调地址（我们这个是单点登陆客户端），我们可以从浏览器地址栏看到 code码

&emsp;&emsp;(2)Postman请求/oauth/token 获取token：
 ```
localhost:9090/oauth/token?grant_type=authorization_code&code=i4ge7B&redirect_uri=http://localhost:8091/login
 ```
 
![http://ww1.sinaimg.cn/large/005Q13r0ly1g716i8nvnxj30rm0ezq3r.jpg](http://ww1.sinaimg.cn/large/005Q13r0ly1g716i8nvnxj30rm0ezq3r.jpg) 

&emsp;&emsp; 注意在 Authorization 填写 client信息，下面是 curl 请求：
 
 ```
curl -X POST \
  'http://localhost:9090/oauth/token?grant_type=authorization_code&code=Q38nnC&redirect_uri=http://localhost:8091/login' \
  -H 'Accept: */*' \
  -H 'Accept-Encoding: gzip, deflate' \
  -H 'Authorization: Basic Y2xpZW50MToxMjM0NTY=' \
  -H 'Cache-Control: no-cache' \
  -H 'Connection: keep-alive' \
  -H 'Content-Length: ' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -H 'Cookie: remember-me=; JSESSIONID=F6F6DE2968113DDE4613091E998D77F4' \
  -H 'Host: localhost:9090' \
  -H 'Postman-Token: f37b9921-4efe-44ad-9884-f14e9bd74bce,3c80ffe3-9e1c-4222-a2e1-9694bff3510a' \
  -H 'User-Agent: PostmanRuntime/7.16.3' \
  -H 'cache-control: no-cache'
 ```
 &emsp;&emsp;  响应报文：
  ```
 {
     "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX25hbWUiOiI5MDAxIiwic2NvcGUiOlsicmVhZCJdLCJleHAiOjE1Njg2NDY0NzksImF1dGhvcml0aWVzIjpbImFkbWluIl0sImp0aSI6ImY5ZDBhNmZhLTAxOWYtNGU5Ny1iMmI4LWI1OTNlNjBiZjk0NiIsImNsaWVudF9pZCI6ImNsaWVudDEiLCJ1c2VybmFtZSI6IjkwMDEifQ.4BjG_LggZt2RJr0VzXTSmsk71EIUDGvrQsL_OPsg8VA",
     "token_type": "bearer",
     "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX25hbWUiOiI5MDAxIiwic2NvcGUiOlsicmVhZCJdLCJhdGkiOiJmOWQwYTZmYS0wMTlmLTRlOTctYjJiOC1iNTkzZTYwYmY5NDYiLCJleHAiOjE1NzExOTUyNzksImF1dGhvcml0aWVzIjpbImFkbWluIl0sImp0aSI6IjU1NTRmYjdkLTBhZGItNGI4MS1iOGNlLWIwOTk2NjM1OTI4MCIsImNsaWVudF9pZCI6ImNsaWVudDEiLCJ1c2VybmFtZSI6IjkwMDEifQ.TA1frc46XRkNgl3Y_n72rM0nZ5QceWH3zJFmR7CkHQ4",
     "expires_in": 43199,
     "scope": "read",
     "username": "9001",
     "jti": "f9d0a6fa-019f-4e97-b2b8-b593e60bf946"
 }
  ```

2、 **密码模式**: grant_type=password

Postman:
 ```
    http://localhost:9090/oauth/token?username=user&password=123456&grant_type=password&scope=read&client_id=client1&client_secret=123456
 ```
 
 curl：
 
 ```
 curl -X POST \
   'http://localhost:9090/oauth/token?username=user&password=123456&grant_type=password&scope=read&client_id=client1&client_secret=123456' \
   -H 'Accept: */*' \
   -H 'Accept-Encoding: gzip, deflate' \
   -H 'Cache-Control: no-cache' \
   -H 'Connection: keep-alive' \
   -H 'Content-Length: ' \
   -H 'Cookie: remember-me=; JSESSIONID=F6F6DE2968113DDE4613091E998D77F4' \
   -H 'Host: localhost:9090' \
   -H 'Postman-Token: f41c7e67-1127-4b65-87ed-21b3e00cfae3,08168e2e-1818-42f8-b4c4-cafd4aa0edc4' \
   -H 'User-Agent: PostmanRuntime/7.16.3' \
   -H 'cache-control: no-cache'
   
 ```
    
   
3、 **客户端模式** : grant_type=client_credentials 

Postman:

 ```
    localhost:9090/oauth/token?scope=read&grant_type=client_credentials
 ```
&emsp;&emsp; 注意在 Authorization 填写 client信息，下面是 curl 请求：

curl: 

 ```
 curl -X POST \
   'http://localhost:9090/oauth/token?scope=read&grant_type=client_credentials' \
   -H 'Accept: */*' \
   -H 'Accept-Encoding: gzip, deflate' \
   -H 'Authorization: Basic Y2xpZW50MToxMjM0NTY=' \
   -H 'Cache-Control: no-cache' \
   -H 'Connection: keep-alive' \
   -H 'Content-Length: 35' \
   -H 'Content-Type: application/x-www-form-urlencoded' \
   -H 'Cookie: remember-me=; JSESSIONID=F6F6DE2968113DDE4613091E998D77F4' \
   -H 'Host: localhost:9090' \
   -H 'Postman-Token: a8d3b4a2-7aee-4f0d-8959-caa99a412012,f5e41385-b2b3-48d2-aa65-8b1d1c075cab' \
   -H 'User-Agent: PostmanRuntime/7.16.3' \
   -H 'cache-control: no-cache' \
   -d 'username=zhoutaoo&password=password'
 
 ```
 

&emsp;&emsp; 授权服务开发，我们继续延用之前的security配置，包括 UserDetailsService及其登陆配置，在其基础上我们新增了授权配置，完成整个授权服务的搭建及测试。
 
 

#### 三、 资源服务器开发

&emsp;&emsp;由于资源服务器是个权限的应用程序，我们新建 security-oauth2-authentication 子模块作为资源服务器应用。

##### 一、Maven依赖

&emsp;&emsp; security-oauth2-authentication  模块 pom  引用 security-core：

 ```
        <dependency>
            <groupId>com.zhc</groupId>
            <artifactId>security-core</artifactId>
            <version>0.0.1-SNAPSHOT</version>
            <exclusions>
                <exclusion>
                    <groupId>org.springframework.security.oauth</groupId>
                    <artifactId>spring-security-oauth2</artifactId>
                </exclusion>
            </exclusions>
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

##### 二、配置授权服务 @EnableResourceServer

&emsp;&emsp;  整个资源服务的配置主要分3个点：

- @EnableResourceServer 必须的，是整个资源服务器的基础
- tokenStore 由于授权服务器采用了不同的tokenStore，所以我们解析token也得根据配置的存储策略来
- HttpSecurity 一般来说只要是资源服务器，其内部的接口均需要认证后才可访问，这里简单配置了以下。

 ```
@Configuration
@EnableResourceServer  // 1
public class ResourceServerConfiguration extends ResourceServerConfigurerAdapter {

    private final Map<String,TokenStore> tokenStoreMap;

    @Value("${spring.security.oauth2.storeType}")
    private String storeType = "jwt";

    @Autowired
    public ResourceServerConfiguration(Map<String, TokenStore> tokenStoreMap) {
        this.tokenStoreMap = tokenStoreMap;
    }

    @Override
    public void configure(ResourceServerSecurityConfigurer resources) {
        resources.tokenStore(tokenStoreMap.get(storeType + "TokenStore"));  //  2
    }

    @Override
    public void configure(HttpSecurity http) throws Exception {
        http
                .requestMatchers().anyRequest()
                .and()
                .anonymous()
                .and()
                .authorizeRequests()
                //配置oauth2访问（测试接口）控制，必须认证过后才可以访问
                .antMatchers("/oauth2/**").authenticated();  // 3 
    }
}
 ```
 
##### 三、配置 application.yml 
&emsp;&emsp;  由于授权服务器采用不同tokenStore，所以这里也要引用 其 配置：

 ```
spring:
  redis:
    host: 127.0.0.1
    port: 6379
  security:
    oauth2:
      storeType: jwt
      jwt:
        SigningKey: oauth2
 ```

##### 四、测试接口

 ```
 
 @RestController
 @RequestMapping("/oauth2")
 @EnableGlobalMethodSecurity(prePostEnabled = true)
 @Slf4j
 public class TestEndpoints {
 
     @GetMapping("/getUser")
     @PreAuthorize("hasAnyAuthority('user')")
     public String getUser() {
         Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
         return "User: " + authentication.getPrincipal().toString();
     }
 }
 
 ```
 

##### 五、启动测试

&emsp;&emsp;  我们将从授权服务器获取到的token进行访问测试接口：

Postman:
 ```
    http://localhost:8090/oauth2/getUser?access_token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzY29wZSI6WyJyZWFkIl0sImV4cCI6MTU2ODY0ODEyMCwianRpIjoiNDQ0NWQ1ZDktYWZlMC00N2Y1LTk0NGItZTEyNzI1NzI1M2M1IiwiY2xpZW50X2lkIjoiY2xpZW50MSIsInVzZXJuYW1lIjoiY2xpZW50MSJ9.pOnIcmjy2ex7jlXvAGslEN89EyFPYPbW-l4f_cyK17k
 ```
 
 curl:
  ```
  
 curl -X GET \
   'http://localhost:8090/oauth2/getUser?access_token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzY29wZSI6WyJyZWFkIl0sImV4cCI6MTU2ODY0ODEyMCwianRpIjoiNDQ0NWQ1ZDktYWZlMC00N2Y1LTk0NGItZTEyNzI1NzI1M2M1IiwiY2xpZW50X2lkIjoiY2xpZW50MSIsInVzZXJuYW1lIjoiY2xpZW50MSJ9.pOnIcmjy2ex7jlXvAGslEN89EyFPYPbW-l4f_cyK17k' \
   -H 'Accept: */*' \
   -H 'Accept-Encoding: gzip, deflate' \
   -H 'Cache-Control: no-cache' \
   -H 'Connection: keep-alive' \
   -H 'Cookie: remember-me=; JSESSIONID=F6F6DE2968113DDE4613091E998D77F4' \
   -H 'Host: localhost:8090' \
   -H 'Postman-Token: 07ec53c7-9051-439b-9603-ef0fe93664fa,e4a5b46e-feb7-4bf8-ab53-0c33aa44f661' \
   -H 'User-Agent: PostmanRuntime/7.16.3' \
   -H 'cache-control: no-cache'
  
  ```

#### 四、 个人总结

&emsp;&emsp; Spring security Oauth2 就是一套标准的Oauth2实现，我们可以通过开发进一步的了解Oauth2的，但整体上涉及到的技术还是很多的，比如redis、jwt等等。本文仅仅只是简单的演示Spring security Oauth2  Demo，希望对你有帮助，如果你还对想深入解析下Spring Security Oauth2，那么请继续关注我，后续会解析其原理。

&emsp;&emsp; 本文介绍Spring security Oauth2开发的代码可以访问代码仓库 ，项目的github 地址 : https://github.com/BUG9/spring-security 

&emsp;&emsp; &emsp;&emsp; &emsp;&emsp; **如果您对这些感兴趣，欢迎star、follow、收藏、转发给予支持！**


