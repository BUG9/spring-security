##  Spring Security 解析(三) —— 个性化认证 以及 RememberMe 实现

>  &emsp;&emsp;在学习Spring Cloud 时，遇到了授权服务oauth 相关内容时，总是一知半解，因此决定先把Spring Security 、Spring Security Oauth2 等权限、认证相关的内容、原理及设计学习并整理一遍。本系列文章就是在学习的过程中加强印象和理解所撰写的，如有侵权请告知。


> 项目环境:
> - JDK1.8
> - Spring boot 2.x
> - Spring Security 5.x

### 一、个性化认证
    
#### （一） 配置登录

&emsp;&emsp; 在 授权过程 和 认证过程 中我们都是使用的 Security 默认的一个登录页面(/login)，那么如果我们想自定义一个登录页面该如何实现呢？其实很简单，我们新建 FormAuthenticationConfig 配置类，然后在configure(HttpSecurity http) 方法中实现以下设置： 


```
        http.formLogin()
                //可以设置自定义的登录页面 或者 （登录）接口
                // 注意1： 一般来说设置成（登录）接口后，该接口会配置成无权限即可访问，所以会走匿名filter, 也就意味着不会走认证过程了，所以我们一般不直接设置成接口地址
                // 注意2： 这里配置的 地址一定要配置成无权限访问，否则将出现 一直重定向问题（因为无权限后又会重定向到这里配置的登录页url）
                .loginPage(securityProperties.getLogin().getLoginPage())
                //.loginPage("/loginRequire")
                // 指定验证凭据的URL（默认为 /login） ,
                // 注意1：这里修改后的 url 会意味着  UsernamePasswordAuthenticationFilter 将 验证此处的 url
                // 注意2： 与 loginPage设置的接口地址是有 区别, 一但 loginPage 设置了的是访问接口url，那么此处配置将无任何意义
                // 注意3： 这里设置的 Url 是有默认无权限访问的
                .loginProcessingUrl(securityProperties.getLogin().getLoginUrl())
                //分别设置成功和失败的处理器
                .successHandler(customAuthenticationSuccessHandler)
                .failureHandler(customAuthenticationFailureHandler);
```
&emsp;&emsp;最后在 SpringSecurityConfig 的  configure(HttpSecurity http) 方法中 调用 formAuthenticationConfig.configure(http) 即可;

&emsp;&emsp; 正如看到的一样，我们通过 loginPage()设置 **登录页面** 或 **接口**, 通过 loginProcessingUrl() 设置 UsernamePasswordAuthenticationFilter 要匹配的 接口地址(**一定是Post**)（看过授权过程的同学应该都知道其默认的是/login）。 这里有以下几点值得注意：

> -  loginPage() 这里配置的 地址(不管是接口url还是登录页面)一定要配置成无权限访问，否则将出现 一直重定向问题（因为无权限后又会重定向到这里配置的登录页url
> -  loginPage() 一般来说不直接设置成（登录）接口，因为设置了接口会配置成无权限即可访问（当然设置成登录页面也需要配置无权限访问），所以会走匿名filter, 也就意味着不会走认证过程了，所以我们一般不直接设置成接口地址
> - loginProcessingUrl() 这里修改后的 url 会意味着  UsernamePasswordAuthenticationFilter 将 验证此处的 url 
> - loginProcessingUrl() 这里设置的 Url 是有默认无权限访问的,与 loginPage设置的接口地址是有 区别, 一但 loginPage 设置了的是接口url，那么此处配置将无任何意义
> - successHandler() 和 failureHandler 分别 设置认证成功处理器 和 认证失败处理器 (如果对这2个处理器没印象的话，建议回顾下授权过程)



#### （二） 配置成功和失败处理器

&emsp;&emsp; 在授权过程中，我们增简单提及到过这2个处理器，在Security中默认的处理器分别是SavedRequestAwareAuthenticationSuccessHandler 和 SimpleUrlAuthenticationFailureHandler ，这次我们自定义这2个处理器，分别为 CustomAuthenticationSuccessHandler ( extends SavedRequestAwareAuthenticationSuccessHandler )  重写 onAuthenticationSuccess() 方法 :



```
@Component("customAuthenticationSuccessHandler")
@Slf4j
public class CustomAuthenticationSuccessHandler extends SavedRequestAwareAuthenticationSuccessHandler {
    @Autowired
    private SecurityProperties securityProperties;

    private RequestCache requestCache = new HttpSessionRequestCache();

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws IOException, ServletException {
        logger.info("登录成功");
        // 如果设置了loginSuccessUrl，总是跳到设置的地址上
        // 如果没设置，则尝试跳转到登录之前访问的地址上，如果登录前访问地址为空，则跳到网站根路径上
        if (!StringUtils.isEmpty(securityProperties.getLogin().getLoginSuccessUrl())) {
            requestCache.removeRequest(request, response);
            setAlwaysUseDefaultTargetUrl(true);
            setDefaultTargetUrl(securityProperties.getLogin().getLoginSuccessUrl());
        }
        super.onAuthenticationSuccess(request, response, authentication);
    }

}
```
和  CustomAuthenticationFailureHandler( extends SimpleUrlAuthenticationFailureHandler)  重写 onAuthenticationFailure() 方法 :

```
@Component("customAuthenticationFailureHandler")
@Slf4j
public class CustomAuthenticationFailureHandler extends SimpleUrlAuthenticationFailureHandler {

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private SecurityProperties securityProperties;

    private RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();

    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
                                        AuthenticationException exception) throws IOException {

        logger.info("登录失败");
        if (StringUtils.isEmpty(securityProperties.getLogin().getLoginErrorUrl())){

            response.setStatus(HttpStatus.INTERNAL_SERVER_ERROR.value());
            response.setContentType("application/json;charset=UTF-8");
            response.getWriter().write(objectMapper.writeValueAsString(exception.getMessage()));

        } else {
            // 跳转设置的登陆失败页面
            redirectStrategy.sendRedirect(request,response,securityProperties.getLogin().getLoginErrorUrl());
        }

    }
}
```

#### （三） 自定义的登陆页面

这里就不再描述，直接贴代码：
```
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>登录</title>
</head>
<body>
<h2>登录页面</h2>
<form action="/loginUp" method="post">  
    <table>
        <tr>
            <td>用户名:</td>
            <td><input type="text" name="username"></td>
        </tr>
        <tr>
            <td>密码:</td>
            <td><input type="password" name="password"></td>
        </tr>
        <tr>
            <td colspan='2'><input name="remember-me" type="checkbox" value="true"/>记住我</td>
        </tr>
        <tr>
            <td colspan="2">
                <button type="submit">登录</button>
            </td>
        </tr>
    </table>
</form>
</body>
</html>
```

&emsp;&emsp;**注意这里请求的地址是  loginProcessingUrl() 配置的地址**


#### （四）测试验证
&emsp;&emsp;这里就不在贴结果图了，只要我们明白结果流程就行是这样的就可以：
 localhost:8080 ——> 点击 测试验证Security 权限控制 ————> 跳转到 我们自定义的 /loginUp.html 登录页,登录后 ————> 有配置loginSuccessUrl,则跳转到 loginSuccess.html;反之则直接跳转到 /get_user/test  接口返回结果。 整个流程就全面涉及到了我们自定义的登录页面、自定义的登录成功/失败处理器。
 
 
### 二、 RememberMe （记住我）功能解析

#### （一）RememberMe 功能实现配置

    首先我们一股脑的将rememberMe配置加上，然后看下现象：
    
1、 创建 persistent_logins 表，用于存储token和用户的关联信息：

```
create table persistent_logins (username varchar(64) not null, series varchar(64) primary key, token varchar(64) not null, last_used timestamp not null);
```

2 、 添加rememberMe配置 信息
```
    @Bean
    public PersistentTokenRepository persistentTokenRepository(){
        JdbcTokenRepositoryImpl tokenRepository = new JdbcTokenRepositoryImpl();
        tokenRepository.setDataSource(dataSource);
        // 如果token表不存在，使用下面语句可以初始化 persistent_logins（ddl在db目录下） 表；若存在，请注释掉这条语句，否则会报错。
        //tokenRepository.setCreateTableOnStartup(true);
        return tokenRepository;
    }
    
     @Override
    protected void configure(HttpSecurity http) throws Exception {

        formAuthenticationConfig.configure(http);
        http.   ....
                .and()
                // 开启 记住我功能，意味着 RememberMeAuthenticationFilter 将会 从Cookie 中获取token信息
                .rememberMe()
                // 设置 tokenRepository ，这里默认使用 jdbcTokenRepositoryImpl，意味着我们将从数据库中读取token所代表的用户信息
                .tokenRepository(persistentTokenRepository())
                // 设置  userDetailsService , 和 认证过程的一样，RememberMe 有专门的 RememberMeAuthenticationProvider ,也就意味着需要 使用UserDetailsService 加载 UserDetails 信息
                .userDetailsService(userDetailsService)
                // 设置 rememberMe 的有效时间，这里通过 配置来设置
                .tokenValiditySeconds(securityProperties.getLogin().getRememberMeSeconds())
                .and()
                .csrf().disable(); // 关闭csrf 跨站（域）攻击防控
    }
```
这里解释下配置：

- rememberMe() 开启 记住我功能，意味着 RememberMeAuthenticationFilter 将会 从Cookie 中获取token信息
- tokenRepository() 配置 token的获取策略，这里配置成从数据库中读取
- userDetailsService() 配置 UserDetaisService (如果不熟悉该对象，建议回顾认证过程)
- tokenValiditySeconds()  设置 rememberMe 的有效时间，这里通过 配置来设置

另一个重要的配置在登录页面，这里的 必须是 name="remember-me" ，rememberMe就是通过验证这个配置来开启remermberMe功能的。
```
<input name="remember-me" type="checkbox" value="true"/>记住我</td>
```

&emsp;&emsp;实操结果应该为：进入登陆页面 ——> 勾选记住我后登录 ——> 成功后，查看persistent_logins 表发现有一条数据——> 重启项目 ——> 重新访问需要登录才能访问的页面,发现无需登录即可访问——> 删除 persistent_logins 表数据，**等待token设置的有效时间过期**，然后重新刷新页面发现跳转到登陆页面。


#### （二） RembemberMe 实现源码解析
&emsp;&emsp; 首先我们查看UsernamePasswordAuthenticationFiler(AbstractAuthenticationProcessingFilter) 的 successfulAuthentication() 方法内部源码：

```
protected void successfulAuthentication(HttpServletRequest request,
			HttpServletResponse response, FilterChain chain, Authentication authResult)
			throws IOException, ServletException {
        
        // 1 设置 认证成功的Authentication对象到SecurityContext中
		SecurityContextHolder.getContext().setAuthentication(authResult);
        
        // 2 调用 RememberMe 相关service处理
		rememberMeServices.loginSuccess(request, response, authResult);

		// Fire event
		if (this.eventPublisher != null) {
			eventPublisher.publishEvent(new InteractiveAuthenticationSuccessEvent(
					authResult, this.getClass()));
		}
		//3 调用成功处理器
		successHandler.onAuthenticationSuccess(request, response, authResult);
	}
```

其中我们发现我们本次重点关注的一行代码：	**rememberMeServices.loginSuccess(request, response, authResult)**  , 查看这个方法内部源码：

```
@Override
	public final void loginSuccess(HttpServletRequest request,
			HttpServletResponse response, Authentication successfulAuthentication) {
        // 这里就在判断用户是否勾选了记住我
		if (!rememberMeRequested(request, parameter)) {
			logger.debug("Remember-me login not requested.");
			return;
		}

		onLoginSuccess(request, response, successfulAuthentication);
	}
```
通过 rememberMeRequested() 判断是否勾选了记住我。
onLoginSuccess() 方法 最终会调用到  **PersistentTokenBasedRememberMeServices**  的 onLoginSuccess() 方法，贴出其方法源码如下：

```
protected void onLoginSuccess(HttpServletRequest request,
			HttpServletResponse response, Authentication successfulAuthentication) {
	    // 1 获取账户名
		String username = successfulAuthentication.getName();
        
        // 2 创建  PersistentRememberMeToken 对象
		PersistentRememberMeToken persistentToken = new PersistentRememberMeToken(
				username, generateSeriesData(), generateTokenData(), new Date());
		try {
		    // 3 通过 tokenRepository 存储 persistentRememberMeToken 信息
			tokenRepository.createNewToken(persistentToken);
			// 4 将 persistentRememberMeToken 信息添加到Cookie中
			addCookie(persistentToken, request, response);
		}
		catch (Exception e) {
			logger.error("Failed to save persistent token ", e);
		}
	}
```
分析下源码步骤：
- 获取 账户信息  username
- 传入 username 创建 PersistentRememberMeToken 对象 
- 通过 tokenRepository 存储 persistentRememberMeToken信息
- 将 persistentRememberMeToken 信息添加到Cookie中

&emsp;&emsp;这里的  **tokenRepository** 就是我们配置 rememberMe功能所设置的。经过上面的解析我们看到了rememberServices 将 创建一个 token 信息，并存储到数据库（因为我们配置的是数据库存储方式 JdbcTokenRepositoryImpl ）中，并将token信息添加到Cookie中了。到这里，我们看到了RememberMe实现前的一些业务处理，那么后面如何实现RememberMe，我想大家心里大概都有个底了。这里直接抛出之前授权过程中我们没有提及到的 filter 类 **RememberMeAuthenticationFilter**，它是介于 UsernamePasswordAuthenticationFilter 和 AnonymousAuthenticationFilter 之间的一个filter，它主要负责的就是前面的filter都没有认证成功后从Cookie中获取token信息然后再通过tokenRepository 获取 登录用户名，然后UserDetailsServcie 加载 UserDetails 信息 ，最后创建 Authticaton（RememberMeAuthenticationToken） 信息再调用 AuthenticationManager.authenticate()  进行认证过程。


**RememberMeAuthenticationFilter**

&emsp;&emsp;我们来看下 RememberMeAuthenticationFilter 的dofiler方法源码：

```
public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain)
			throws IOException, ServletException {
		HttpServletRequest request = (HttpServletRequest) req;
		HttpServletResponse response = (HttpServletResponse) res;

		if (SecurityContextHolder.getContext().getAuthentication() == null) {
		    //  1 调用 rememberMeServices.autoLogin() 获取Authtication 信息
			Authentication rememberMeAuth = rememberMeServices.autoLogin(request,
					response);

			if (rememberMeAuth != null) {
				// Attempt authenticaton via AuthenticationManager
				try {
				    // 2 调用 authenticationManager.authenticate() 认证
					rememberMeAuth = authenticationManager.authenticate(rememberMeAuth);
                    
                    ......
					}

				}
				catch (AuthenticationException authenticationException) {
                .....
			}

			chain.doFilter(request, response);
		}
```
我们主要关注  rememberMeServices.autoLogin(request,response) 方法实现，查看器源码：



```
@Override
	public final Authentication autoLogin(HttpServletRequest request,
			HttpServletResponse response) {
		// 1 从Cookie 中获取 token 信息
		String rememberMeCookie = extractRememberMeCookie(request);

		if (rememberMeCookie == null) {
			return null;
		}
		
		if (rememberMeCookie.length() == 0) {
			cancelCookie(request, response);
			return null;
		}

		UserDetails user = null;

		try {
		    // 2 解析 token信息
			String[] cookieTokens = decodeCookie(rememberMeCookie);
			// 3 通过 token 信息 生成 Uerdetails 信息
			user = processAutoLoginCookie(cookieTokens, request, response);
			userDetailsChecker.check(user);

			logger.debug("Remember-me cookie accepted");
            // 4 通过 UserDetails 信息创建 Authentication 
			return createSuccessfulAuthentication(request, user);
		} 
		.....
	}
```
内部实现步骤：

- 从Cookie中获取 token 信息并解析 
- **通过 解析的token 生成 UserDetails （processAutoLoginCookie() 方法实现 ）**
- 通过 UserDetails 生成 Authentication  ( createSuccessfulAuthentication() 创建 RememberMeAuthenticationToken ) 

其中最关键的一部是  processAutoLoginCookie() 方法是如何生成UserDetails 对象的，我们查看这个方法源码实现：

```
protected UserDetails processAutoLoginCookie(String[] cookieTokens,
			HttpServletRequest request, HttpServletResponse response) {
		final String presentedSeries = cookieTokens[0];
		final String presentedToken = cookieTokens[1];
        // 1 通过 tokenRepository 加载数据库token信息
		PersistentRememberMeToken token = tokenRepository
				.getTokenForSeries(presentedSeries);

		PersistentRememberMeToken newToken = new PersistentRememberMeToken(
				token.getUsername(), token.getSeries(), generateTokenData(), new Date());
        // 2 判断 用户传入token和数据中的token是否一致，不一致可能存在安全问题
        if (!presentedToken.equals(token.getTokenValue())) {
			tokenRepository.removeUserTokens(token.getUsername());
			throw new CookieTheftException(
					messages.getMessage(
							"PersistentTokenBasedRememberMeServices.cookieStolen",
							"Invalid remember-me token (Series/token) mismatch. Implies previous cookie theft attack."));
		}
		try {
		    // 3 更新 token 并添加到Cookie中
			tokenRepository.updateToken(newToken.getSeries(), newToken.getTokenValue(),
					newToken.getDate());
			addCookie(newToken, request, response);
		}
		catch (Exception e) {
			throw new RememberMeAuthenticationException(
					"Autologin failed due to data access problem");
		}
        // 4 通过 UserDetailsService().loadUserByUsername() 方法加载UserDetails 信息并返回
		return getUserDetailsService().loadUserByUsername(token.getUsername());
	}
```
我们看下其内部步骤：

- **通过 tokenRepository 加载数据库token信息**
- 判断 用户传入token和数据中的token是否一致，不一致可能存在安全问题
- 更新 token 并添加到Cookie中
- **通过 UserDetailsService().loadUserByUsername() 方法加载UserDetails 信息并返回**
 
&emsp;&emsp; 看到这里相信大家以下就明白了，当初为啥在启用rememberMe功能时要配置 tokenRepository 和 UserDetailsService了。

这里我就不再演示整个实现的流程了，老规矩，上流程图：

![https://ws2.sinaimg.cn/large/006Xmmmgly1g6fqyzgo1rj30zn0e0q4y.jpg](https://ws2.sinaimg.cn/large/006Xmmmgly1g6fqyzgo1rj30zn0e0q4y.jpg)


&emsp;&emsp; 本文介绍个性化认证和RememberMe的代码可以访问代码仓库中的 security 模块 ，项目的github 地址 : https://github.com/BUG9/spring-security 

&emsp;&emsp; &emsp;&emsp; &emsp;&emsp; **如果您对这些感兴趣，欢迎star、follow、收藏、转发给予支持！**




    













