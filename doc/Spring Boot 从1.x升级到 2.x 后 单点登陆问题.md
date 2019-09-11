##  解决Spring Boot 从1.x升级到 2.x 后 单点登陆(SSO)问题

>  &emsp;&emsp;在学习Spring Cloud 时，遇到了授权服务oauth 相关内容时，总是一知半解，因此决定先把Spring Security 、Spring Security Oauth2 等权限、认证相关的内容、原理及设计学习并整理一遍。本系列文章就是在学习的过程中加强印象和理解所撰写的，如有侵权请告知。


> 项目环境:
> - JDK1.8
> - Spring boot 2.x
> - Spring Security 5.x

&emsp;&emsp;前期基本上已经将 Spring Security相关的内容写得差不多了，所以最近在整理Spring Sexurity Oauh2 相关的内容，但在进行到单点登陆（OSS）时，有一个问题一直困扰了我很久，由于网上有关于Spring Boot 1.x 升级到Spring Boot 2.x 后单点登陆相关的问题解决资料很少，特此在这里专门列一篇文章来描述升级过程中遇到的一些问题、问题表现现象以及我是如何解决这些问题的。


###  问题一： spring boot 2 中去除了@EnableOAuth2Sso ？
&emsp;&emsp;首先很明确的告诉你，并没有！！但为什么引入了 **spring-security-oauth2** maven依赖 IDEA提示 @EnableOAuth2Sso 找不到呢？ 首先我们找到[官方Spring Boot 2.x 升级文档](https://github.com/spring-projects/spring-boot/wiki/Spring-Boot-2.0.0-M5-Release-Notes#oauth-20-support),我们会发现其中有关于Oauth2 相关的介绍：

> OAuth 2.0 Support
  Functionality from the Spring Security OAuth project is being migrated to core Spring Security. OAuth 2.0 client support has already been added and additional features will be migrated in due course.
 
> If you depend on Spring Security OAuth features that have not yet been migrated you will need to add org.springframework.security.oauth:spring-security-oauth2 and configure things manually. If you only need OAuth 2.0 client support you can use the **auto-configuration** provided by Spring Boot 2.0. We’re also continuing to support Spring Boot 1.5 so older applications can continue to use that until an upgrade path is provided.

&emsp;&emsp; 我们可以大致明白 官方 2.x 正在将 Spring Security OAuth项目的功能迁移到 Spring Security 中。 但最值得注意的是其中有这么一段话 If you only need OAuth 2.0 client support you can use the **auto-configuration** provided by Spring Boot 2.0.（如果你想要在Spring Boot 2.0（及以上）版本中使用 Oauth2 客户端 相关的功能 需要使用 **auto-configuration**）。

&emsp;&emsp;根据这个提示，我们找到 [官方 auto-configuration文档 ](https://docs.spring.io/spring-security-oauth2-boot/docs/current/reference/htmlsingle/),一进来 就告诉我们需要用到的最小maven依赖：

```
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-security</artifactId>
        </dependency>
        <dependency>
            <groupId>org.springframework.security.oauth.boot</groupId>
            <artifactId>spring-security-oauth2-autoconfigure</artifactId>
            <version>2.1.7.RELEASE</version>
        </dependency>
```
&emsp;&emsp;按照官方文档配置成功引用到了@EnableOAuth2Sso ，至此，该问题得到解决！


###  问题二： 单点登陆授权过程中回调到客户端却提示401(未授权)问题 ？

####一、 SSO 客户端相关配置

##### ClientSecurityConfig 配置

```
@Configuration
@EnableOAuth2Sso  // SSo自动配置引用
public class ClientSecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    public void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                .antMatchers("/").permitAll()
                .anyRequest().authenticated()
                .and()
                .csrf().disable();
    }

}
```
这个配置是按照 [官方 auto-configuration文档 ](https://docs.spring.io/spring-security-oauth2-boot/docs/current/reference/htmlsingle/) 推荐的配置。

##### application.yml 配置

```
auth-server: http://localhost:9090 # authorization服务地址


security:
  oauth2:
    client:
      user-authorization-uri: ${auth-server}/oauth/authorize #请求认证的地址
      access-token-uri: ${auth-server}/oauth/token #请求令牌的地址
    resource:
      jwt:
        key-uri: ${auth-server}/oauth/token_key #解析jwt令牌所需要密钥的地址,服务启动时会调用 授权服务该接口获取jwt key，所以务必保证授权服务正常
    sso:
      login-path: /login #指向登录页面的路径，即OAuth2授权服务器触发重定向到客户端的路径 ，默认为 /login
spring:
  profiles:
    active: client1
```

&emsp;&emsp;由于我们要多客户端单点测试，这里使用Spring boot 的多环境配置，这里有关授权服务的配置不在描述，以及默认搭建好了一个可用的授权服务（如果不清楚如何搭建Oauth2的授权服务和资源服务，可以关注我，后续会出相关文章）。

##### application-client1.yml 配置

```
    server:
      port: 8091
    
    security:
      oauth2:
        client:
          client-id: client1
          client-secret: 123456
```

##### 测试接口 

```
@RestController
@Slf4j
public class TestController {

    @GetMapping("/client/{clientId}")
    public String getClient(@PathVariable String clientId) {
        return clientId;
    }

}
```
&emsp;&emsp; 至此问我们完成了一个最基本的SSO客户端，启动项目。

####二、 问题描述及现象
&emsp;&emsp;浏览器上访问测试接口 localhost:8091/client/1 ,跳转到授权服务登陆界面，登陆成功后，跳转回到客户端的 /login 地址 （即 我们 配置的 spring.security.sso.login-path ），正常情况下会再次跳转到 localhost:8091/client/1(这次已经是认证成功后访问)。这整个流程就是Oauth2 的授权码模式流程。但现在有这么一个问题，在授权服务回调到客户端的 /login 地址时，浏览器显示 HTTP ERROR 401, 如下图：
![http://ww1.sinaimg.cn/large/005Q13r0gy1g6wkv5iktsj30oi0ffmxn.jpg](http://ww1.sinaimg.cn/large/005Q13r0gy1g6wkv5iktsj30oi0ffmxn.jpg)

&emsp;&emsp;从图中我们可以看到，授权服务成功的返回了授权码，但由于我们客户端存在问题，出现 401 ，导致整个授权码模式流程中断。 在看 [官方 auto-configuration文档 ](https://docs.spring.io/spring-security-oauth2-boot/docs/current/reference/htmlsingle/) 过程中，无意间发现

>Also note that since all endpoints are secure by default, this includes any default error handling endpoints, for example, the endpoint "/error". This means that if there is some problem during Single Sign On that requires the application to redirect to the "/error" page, then this can cause an infinite redirect between the identity provider and the receiving application.
>First, think carefully about making an endpoint insecure as you may find that the behavior is simply evidence of a different problem. However, this behavior can be addressed by configuring the application to permit "/error":
```
@Configuration
public class WebSecurityConfiguration extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
            .authorizeRequests()
                .antMatchers("/error").permitAll()
                .anyRequest().authenticated();
    }
}
```
&emsp;&emsp;大致意思就是：由于默认情况下所有端点都是安全的，因此这包括任何默认错误处理端点，例如端点“/ error”。这意味着如果单点登录期间存在某些问题，需要应用程序重定向到“/ error”页面，则这会导致身份提供程序和接收应用程序之间的无限重定向。

&emsp;&emsp;根据这个提示，我开始DEBUG，果然正如文档所说，单点登录期间存在某些问题重定向到了/error,所以我们将 /error 配置成无权限访问，重启再次访问测试接口，这次的错误界面提示就很明显了：
![http://ww1.sinaimg.cn/large/005Q13r0gy1g6wkvmpqe5j30my07jt94.jpg](http://ww1.sinaimg.cn/large/005Q13r0gy1g6wkvmpqe5j30my07jt94.jpg)

&emsp;&emsp;既然明显的提示 Unauthorized 了，那我们就来一步一步的DEBUG 看看单点期间出现的问题点是什么。


####三、 问题排查及解决方案
&emsp;&emsp;从之前的现象描述我们可以知道问题点在授权码回来后去调用获取token这里出现问题了，那么根据源码查看，获取token这块步骤在 OAuth2ClientAuthenticationProcessingFilter 过滤器内部，其关键代码如下：

```
    @Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
			throws AuthenticationException, IOException, ServletException {

		OAuth2AccessToken accessToken;
		try {
			accessToken = restTemplate.getAccessToken();  // 1 调用授权服务获取token 
		} catch (OAuth2Exception e) {
			BadCredentialsException bad = new BadCredentialsException("Could not obtain access token", e);
			publish(new OAuth2AuthenticationFailureEvent(bad));
			throw bad;			
		}
		try {
			OAuth2Authentication result = tokenServices.loadAuthentication(accessToken.getValue());  // 成功后从token中解析  OAuth2Authentication 信息
			if (authenticationDetailsSource!=null) {
				request.setAttribute(OAuth2AuthenticationDetails.ACCESS_TOKEN_VALUE, accessToken.getValue());
				request.setAttribute(OAuth2AuthenticationDetails.ACCESS_TOKEN_TYPE, accessToken.getTokenType());
				result.setDetails(authenticationDetailsSource.buildDetails(request));
			}
			publish(new AuthenticationSuccessEvent(result));
			return result;
		}
		catch (InvalidTokenException e) {
			BadCredentialsException bad = new BadCredentialsException("Could not obtain user details from token", e);
			publish(new OAuth2AuthenticationFailureEvent(bad));
			throw bad;			
		}

	}
```

&emsp;&emsp;我们把断点打到这里，Debug下，果然不出所料，在获取token时异常了，异常信息为 ： Possible CSRF detected - state parameter was required but no state could be found  ，debug截图如下：
![http://ww1.sinaimg.cn/large/005Q13r0gy1g6wkw0scuhj31ah0h0acq.jpg](http://ww1.sinaimg.cn/large/005Q13r0gy1g6wkw0scuhj31ah0h0acq.jpg)

&emsp;&emsp;查阅网上资料有一下说法：

> 本地开发，auth server与client都是localhost，造成JSESSIONID相互影响问题。可以通过配置client的context-path或者session名称来解决

&emsp;&emsp; 根据这个描述，我尝试通过修改 session名称来解决：

```
server:
  servlet:
    session:
      cookie:
        name: OAUTH2CLIENTSESSION  # 解决  Possible CSRF detected - state parameter was required but no state could be found  问题
```

&emsp;&emsp;  重启项目，测试SSO，完美解决！！！

