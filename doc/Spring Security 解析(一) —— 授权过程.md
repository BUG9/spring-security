##  Spring Security 解析(一) —— 授权过程 

>  &emsp;&emsp;在学习Spring Cloud 时，遇到了授权服务oauth 相关内容时，总是一知半解，因此决定先把Spring Security 、Spring Security Oauth2 等权限、认证相关的内容、原理及设计学习并整理一遍。本系列文章就是在学习的过程中加强印象和理解所撰写的，如有侵权请告知。


> 项目环境:
> - JDK1.8
> - Spring boot 2.x
> - Spring Security 5.x

### 一、 一个简单的Security Demo

#### 1、 自定义的UserDetailsService实现 
    
&emsp;&emsp;自定义MyUserDetailsUserService类，实现 UserDetailsService 接口的 loadUserByUsername()方法，这里就简单的返回一个Spring Security 提供的 User 对象。为了后面方便演示Spring Security 的权限控制，这里使用**AuthorityUtils.commaSeparatedStringToAuthorityList("admin")** 设置了user账号有一个admin的角色权限信息。实际项目中可以在这里通过访问数据库获取到用户及其角色、权限信息。

```
@Component
public class MyUserDetailsUserService implements UserDetailsService {
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        // 不能直接使用 创建 BCryptPasswordEncoder 对象来加密， 这种加密方式 没有 {bcrypt}  前缀，
        // 会导致在  matches 时导致获取不到加密的算法出现
        // java.lang.IllegalArgumentException: There is no PasswordEncoder mapped for the id "null"  问题
        // 问题原因是 Spring Security5 使用 DelegatingPasswordEncoder(委托)  替代 NoOpPasswordEncoder，
        // 并且 默认使用  BCryptPasswordEncoder 加密（注意 DelegatingPasswordEncoder 委托加密方法BCryptPasswordEncoder  加密前  添加了加密类型的前缀）  https://blog.csdn.net/alinyua/article/details/80219500
        return new User("user",  PasswordEncoderFactories.createDelegatingPasswordEncoder().encode("123456"), AuthorityUtils.commaSeparatedStringToAuthorityList("admin"));
    }
}
```
&emsp;&emsp;注意Spring Security 5 开始没有使用 **NoOpPasswordEncoder**作为其默认的密码编码器，而是默认使用 **DelegatingPasswordEncoder** 作为其密码编码器，其 encode 方法是通过 密码编码器的名称作为前缀 + 委托各类密码编码器来实现encode的。

```
public String encode(CharSequence rawPassword) {
        return "{" + this.idForEncode + "}" + this.passwordEncoderForEncode.encode(rawPassword);
    }
```

&emsp;&emsp;这里的 idForEncode 就是密码编码器的简略名称，可以通过
**PasswordEncoderFactories.createDelegatingPasswordEncoder()**
内部实现看到默认是使用的前缀是 bcrypt 也就是 BCryptPasswordEncoder

```
public class PasswordEncoderFactories {
    public static PasswordEncoder createDelegatingPasswordEncoder() {
        String encodingId = "bcrypt";
        Map<String, PasswordEncoder> encoders = new HashMap();
        encoders.put(encodingId, new BCryptPasswordEncoder());
        encoders.put("ldap", new LdapShaPasswordEncoder());
        encoders.put("MD4", new Md4PasswordEncoder());
        encoders.put("MD5", new MessageDigestPasswordEncoder("MD5"));
        encoders.put("noop", NoOpPasswordEncoder.getInstance());
        encoders.put("pbkdf2", new Pbkdf2PasswordEncoder());
        encoders.put("scrypt", new SCryptPasswordEncoder());
        encoders.put("SHA-1", new MessageDigestPasswordEncoder("SHA-1"));
        encoders.put("SHA-256", new MessageDigestPasswordEncoder("SHA-256"));
        encoders.put("sha256", new StandardPasswordEncoder());
        return new DelegatingPasswordEncoder(encodingId, encoders);
    }
}
```

#### 2、 设置Spring Security配置

&emsp;&emsp;定义SpringSecurityConfig 配置类，并继承**WebSecurityConfigurerAdapter**覆盖其configure(HttpSecurity http) 方法。

```
@Configuration
@EnableWebSecurity //1
public class SpringSecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.formLogin()  //2
            .and()
                .authorizeRequests() //3
                .antMatchers("/index","/").permitAll() //4
                .anyRequest().authenticated(); //6
    }
}
```

配置解析：

-  @EnableWebSecurity  查看其注解源码，主要是引用WebSecurityConfiguration.class 和 加入了@EnableGlobalAuthentication 注解 ，这里就不介绍了，我们只要明白添加 @EnableWebSecurity 注解将开启 Security 功能。
-  formLogin()  使用表单登录（默认请求地址为 /login）,在Spring Security 5 里其实已经将旧版本默认的  httpBasic() 更换成 formLogin() 了，这里为了表明表单登录还是配置了一次。
-  authorizeRequests() 开始请求权限配置
-  antMatchers() 使用Ant风格的路径匹配，这里配置匹配 / 和 /index
-  permitAll() 用户可任意访问
-  anyRequest() 匹配所有路径
-  authenticated() 用户登录后可访问

---
  

#### 3、 配置html 和测试接口

&emsp;&emsp; 在 resources/static 目录下新建 index.html ， 其内部定义一个访问测试接口的按钮


```
<!DOCTYPE html>
<html lang="en" >
<head>
    <meta charset="UTF-8">
    <title>欢迎</title>
</head>
<body>
        Spring Security 欢迎你！
        <p> <a href="/get_user/test">测试验证Security 权限控制</a></p>
</body>
</html>
```
&emsp;&emsp;创建 rest 风格的获取用户信息接口

```
@RestController
public class TestController {

    @GetMapping("/get_user/{username}")
    public String getUser(@PathVariable  String username){
        return username;
    }
}
```

#### 4、 启动项目测试

1、访问 localhost:8080 无任何阻拦直接成功

![image](https://ws1.sinaimg.cn/large/006Xmmmgly1g60nylgpj3j309e06hwek.jpg)

2、点击测试验证权限控制按钮 被重定向到了 Security默认的登录页面 
![](https://ws4.sinaimg.cn/large/006Xmmmgly1g60o18mr5gj30wq0d63yz.jpg)

3、使用 MyUserDetailsUserService定义的默认账户 user : 123456 进行登录后成功跳转到 /get_user 接口

![](https://ws2.sinaimg.cn/large/006Xmmmggy1g60o5lj5udj30cp05n0ss.jpg)


---

### 二、  @EnableWebSecurity 配置解析

&emsp;&emsp; 还记得之前讲过 @EnableWebSecurity 引用了 WebSecurityConfiguration 配置类 和 @EnableGlobalAuthentication 注解吗？  其中 WebSecurityConfiguration 就是与授权相关的配置，@EnableGlobalAuthentication 配置了 认证相关的我们下节再细讨。

&emsp;&emsp; 首先我们查看 WebSecurityConfiguration 源码，可以很清楚的发现 **springSecurityFilterChain()** 方法。
```
    @Bean(name = AbstractSecurityWebApplicationInitializer.DEFAULT_FILTER_NAME)
	public Filter springSecurityFilterChain() throws Exception {
		boolean hasConfigurers = webSecurityConfigurers != null
				&& !webSecurityConfigurers.isEmpty();
		if (!hasConfigurers) {
			WebSecurityConfigurerAdapter adapter = objectObjectPostProcessor
					.postProcess(new WebSecurityConfigurerAdapter() {
					});
			webSecurity.apply(adapter);
		}
		return webSecurity.build(); //1
	}
```
&emsp;&emsp;这个方法首先会判断 webSecurityConfigurers 是否为空，为空加载一个默认的 WebSecurityConfigurerAdapter对象，由于自定义的 SpringSecurityConfig 本身是继承 WebSecurityConfigurerAdapter对象 的，所以我们自定义的 Security 配置肯定会被加载进来的（如果想要了解如何加载进来可以看下WebSecurityConfiguration.setFilterChainProxySecurityConfigurer() 方法）。

&emsp;&emsp; 我们看下 webSecurity.build() 方法实现 实际调用的是 AbstractConfiguredSecurityBuilder.doBuild() 方法，其方法内部实现如下：

```
@Override
	protected final O doBuild() throws Exception {
		synchronized (configurers) {
			buildState = BuildState.INITIALIZING;

			beforeInit();
			init();

			buildState = BuildState.CONFIGURING;

			beforeConfigure();
			configure();

			buildState = BuildState.BUILDING;

			O result = performBuild(); // 1 实际调用 HttpSecurity 类该方法实现： 创建 DefaultSecurityFilterChain （Security Filter 责任链 ）

			buildState = BuildState.BUILT;

			return result;
		}
	}
```
&emsp;&emsp; 我们把关注点放到 **performBuild()** 方法，看其实现子类  HttpSecurity.performBuild() 方法，其内部排序 filters 并创建了  **DefaultSecurityFilterChain** 对象。


```
    @Override
	protected DefaultSecurityFilterChain performBuild() throws Exception {
		Collections.sort(filters, comparator);
		return new DefaultSecurityFilterChain(requestMatcher, filters);
	}
```

&emsp;&emsp; 查看DefaultSecurityFilterChain 的构造方法，我们可以看到有记录日志。
```
public DefaultSecurityFilterChain(RequestMatcher requestMatcher, List<Filter> filters) {
		logger.info("Creating filter chain: " + requestMatcher + ", " + filters); // 按照正常情况，我们可以看到控制台输出 这条日志 
		this.requestMatcher = requestMatcher;
		this.filters = new ArrayList<>(filters);
	}
```
&emsp;&emsp; 我们可以回头看下项目启动日志。可以看到下图明显打印了 这条日志，并且把所有 Filter名都打印出来了。==**（请注意这里打印的 filter 链，接下来我们的所有授权过程都是依靠这条filter 链展开 ）**==
![](https://ws3.sinaimg.cn/large/006Xmmmgly1g61hrwmux3j31ey05wq4j.jpg)

&emsp;&emsp;那么还有个疑问： HttpSecurity.performBuild() 方法中的 filters 是怎么加载的呢？ 这个时候需要查看 WebSecurityConfigurerAdapter.init() 方法，这个方法内部 调用 getHttp() 方法返回 HttpSecurity 对象（看到这里我们应该能想到 filters 就是这个方法中添加好了数据），具体如何加载的也就不介绍了。

```
public void init(final WebSecurity web) throws Exception {
		final HttpSecurity http = getHttp(); // 1 
		web.addSecurityFilterChainBuilder(http).postBuildAction(new Runnable() {
			public void run() {
				FilterSecurityInterceptor securityInterceptor = http
						.getSharedObject(FilterSecurityInterceptor.class);
				web.securityInterceptor(securityInterceptor);
			}
		});
	}
```
&emsp;&emsp; 用了这么长时间解析 @EnableWebSecurity ，**其实最关键的一点就是创建了  DefaultSecurityFilterChain** 也就是我们常 security  filter 责任链，接下来我们围绕这个 DefaultSecurityFilterChain 中 的 filters 进行授权过程的解析。


### 三、 授权过程解析
> &emsp;&emsp;Security的授权过程可以理解成各种 filter 处理最终完成一个授权。那么我们再看下之前 打印的filter 链，这里为了方便，再次贴出图片
![](https://ws3.sinaimg.cn/large/006Xmmmgly1g61hrwmux3j31ey05wq4j.jpg)

&emsp;&emsp;这里我们只关注以下几个重要的 filter ：
> - SecurityContextPersistenceFilter
> - UsernamePasswordAuthenticationFilter (AbstractAuthenticationProcessingFilter)
> - BasicAuthenticationFilter
> - AnonymousAuthenticationFilter
> - ExceptionTranslationFilter
> - FilterSecurityInterceptor

#### 1、SecurityContextPersistenceFilter

&emsp;&emsp;SecurityContextPersistenceFilter 这个filter的主要负责以下几件事：

> - 通过 (SecurityContextRepository)repo.loadContext()  方法从请求Session中获取 SecurityContext（Security 上下文 ，类似 ApplicaitonContext ） 对象，如果请求Session中没有默认创建一个 authentication(认证的关键对象，由于本节只讲授权，暂不介绍) 属性为 null 的 SecurityContext 对象
> - SecurityContextHolder.setContext() 将 SecurityContext 对象放入 SecurityContextHolder进行管理（SecurityContextHolder默认使用ThreadLocal 策略来存储认证信息）
> - 由于在 finally 里实现 会在最后通过 SecurityContextHolder.clearContext() 将 SecurityContext 对象 从 SecurityContextHolder中清除
> - 由于在 finally 里实现 会在最后通过 repo.saveContext() 将 SecurityContext 对象 放入Session中
    
```
HttpRequestResponseHolder holder = new HttpRequestResponseHolder(request,
				response);
		//从Session中获取SecurityContxt 对象，如果Session中没有则创建一个 authtication 属性为 null 的SecurityContext对象
		SecurityContext contextBeforeChainExecution = repo.loadContext(holder); 

		try {
		    // 将 SecurityContext 对象放入 SecurityContextHolder进行管理 （SecurityContextHolder默认使用ThreadLocal 策略来存储认证信息）
			 SecurityContextHolder.setContext(contextBeforeChainExecution);

			 chain.doFilter(holder.getRequest(), holder.getResponse());

		}
		finally {
			SecurityContext contextAfterChainExecution = SecurityContextHolder
					.getContext();
			
			// 将 SecurityContext 对象 从 SecurityContextHolder中清除
			SecurityContextHolder.clearContext();
			// 将 SecurityContext 对象 放入Session中
			repo.saveContext(contextAfterChainExecution, holder.getRequest(),
					holder.getResponse());
			request.removeAttribute(FILTER_APPLIED);

			if (debug) {
				logger.debug("SecurityContextHolder now cleared, as request processing completed");
			}
		}
```

&emsp;&emsp;我们在 SecurityContextPersistenceFilter 中打上断点，启动项目，访问 localhost:8080 , 来debug看下实现：

![](https://ws2.sinaimg.cn/large/006Xmmmggy1g61jvnvbpoj30u40hh76k.jpg)
&emsp;&emsp; 我们可以清楚的看到创建了一个authtication 为null 的 SecurityContext对象，并且可以看到请求调用的filter链具体有哪些。接下来看下 finally 内部处理

![](https://ws2.sinaimg.cn/large/006Xmmmgly1g61k8va2k4j30rh09bq3t.jpg)

&emsp;&emsp; 你会发现这里的SecurityContxt中的 authtication 是一个名为 anonymousUser （匿名用户）的认证信息，这是因为 请求调用到了 AnonymousAuthenticationFilter , Security默认创建了一个匿名用户访问。


#### 2、UsernamePasswordAuthenticationFilter (AbstractAuthenticationProcessingFilter)


&emsp;&emsp;看filter字面意思就知道这是一个通过获取请求中的账户密码来进行授权的filter，按照惯例，整理了这个filter的职责：
> - 通过 requiresAuthentication（）判断 是否以POST 方式请求 /login
> - 调用 attemptAuthentication() 方法进行认证，内部创建了 authenticated 属性为 false（即未授权）的UsernamePasswordAuthenticationToken 对象， 并传递给 AuthenticationManager().authenticate() 方法进行认证，认证成功后 返回一个 authenticated = true （即授权成功的)UsernamePasswordAuthenticationToken 对象 
> - 通过 sessionStrategy.onAuthentication() 将 Authentication  放入Session中
> - 通过 successfulAuthentication() 调用 AuthenticationSuccessHandler 的 onAuthenticationSuccess 接口 进行成功处理（ 可以 通过 继承 AuthenticationSuccessHandler 自行编写成功处理逻辑 ）successfulAuthentication(request, response, chain, authResult);
> - 通过 unsuccessfulAuthentication() 调用AuthenticationFailureHandler 的 onAuthenticationFailure 接口 进行失败处理（可以通过继承AuthenticationFailureHandler 自行编写失败处理逻辑 ）

&emsp;&emsp;我们再看下官方源码的处理逻辑：
  
```
// 1 AbstractAuthenticationProcessingFilter 的 doFilter 方法
public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain)
			throws IOException, ServletException {

		HttpServletRequest request = (HttpServletRequest) req;
		HttpServletResponse response = (HttpServletResponse) res;

        // 2 判断请求地址是否是  /login 和 请求方式为 POST  （UsernamePasswordAuthenticationFilter 构造方法 确定的）
		if (!requiresAuthentication(request, response)) {
			chain.doFilter(request, response);
			return;
		}
		Authentication authResult;
		try {
		    
		    // 3 调用 子类  UsernamePasswordAuthenticationFilter 的 attemptAuthentication 方法
		    // attemptAuthentication 方法内部创建了 authenticated 属性为 false （即未授权）的 UsernamePasswordAuthenticationToken 对象， 并传递给 AuthenticationManager().authenticate() 方法进行认证，
		    //认证成功后 返回一个 authenticated = true （即授权成功的） UsernamePasswordAuthenticationToken 对象 
			authResult = attemptAuthentication(request, response);
			if (authResult == null) {
				return;
			}
			// 4 将认证成功的 Authentication 存入Session中
			sessionStrategy.onAuthentication(authResult, request, response);
		}
		catch (InternalAuthenticationServiceException failed) {
		     // 5 认证失败后 调用 AuthenticationFailureHandler 的 onAuthenticationFailure 接口 进行失败处理（ 可以 通过 继承 AuthenticationFailureHandler 自行编写失败处理逻辑 ）
			unsuccessfulAuthentication(request, response, failed);
			return;
		}
		catch (AuthenticationException failed) {
		    // 5 认证失败后 调用 AuthenticationFailureHandler 的 onAuthenticationFailure 接口 进行失败处理（ 可以 通过 继承 AuthenticationFailureHandler 自行编写失败处理逻辑 ）
			unsuccessfulAuthentication(request, response, failed);
			return;
		}
		
        ......
         // 6 认证成功后 调用 AuthenticationSuccessHandler 的 onAuthenticationSuccess 接口 进行失败处理（ 可以 通过 继承 AuthenticationSuccessHandler 自行编写成功处理逻辑 ）
		successfulAuthentication(request, response, chain, authResult);
	}
```
&emsp;&emsp;从源码上看，整个流程其实是很清晰的：从判断是否处理，到认证，最后判断认证结果分别作出认证成功和认证失败的处理。

&emsp;&emsp;debug 调试下看 结果，这次我们请求 localhast:8080/get_user/test  , 由于没权限会直接跳转到登录界面，我们先输入错误的账号密码，看下认证失败是否与我们总结的一致。

![image](https://ws4.sinaimg.cn/large/006Xmmmggy1g657qg046cj315o0jvju7.jpg)

&emsp;&emsp;结果与预想时一致的，也许你会奇怪这里的提示为啥时中文，这就不得不说Security 5 开始支持 中文，说明咋中国程序员在世界上越来越有地位了！！！

&emsp;&emsp; 这次输入正确的密码, 看下返回的Authtication 对象信息：

![image](https://ws2.sinaimg.cn/large/006Xmmmggy1g657yvrbirj312a0jk773.jpg)

&emsp;&emsp; 可以看到这次成功返回一个 authticated = ture ，没有密码的 user账户信息，而且还包含我们定义的一个admin权限信息。放开断点，由于Security默认的成功处理器是SimpleUrlAuthenticationSuccessHandler ，这个处理器会重定向到之前访问的地址，也就是 localhast:8080/get_user/test。 至此整个流程结束。不，我们还差一个，Session，我们从浏览器Cookie中看到 Session：

![image](https://ws2.sinaimg.cn/large/006Xmmmggy1g658e9e6hgj30o50ddjs4.jpg)
    
    

#### 3、BasicAuthenticationFilter

&emsp;&emsp;BasicAuthenticationFilter 与UsernameAuthticationFilter类似，不过区别还是很明显，**BasicAuthenticationFilter 主要是从Header 中获取 Authorization 参数信息，然后调用认证，认证成功后最后直接访问接口，不像UsernameAuthticationFilter过程一样通过AuthenticationSuccessHandler 进行跳转**。这里就不在贴代码了，想了解的同学可以直接看源码。不过有一点要注意的是，BasicAuthenticationFilter 的 onSuccessfulAuthentication() 成功处理方法是一个空方法。

&emsp;&emsp; 为了试验BasicAuthenticationFilter, 我们需要将 SpringSecurityConfig 中的formLogin()更换成httpBasic()以支持BasicAuthenticationFilter，重启项目，同样访问
localhast:8080/get_user/test，这时由于没权限访问这个接口地址，页面上会弹出一个登陆框，熟悉Security4的同学一定很眼熟吧，同样，我们输入账户密码后，看下debug数据：

![image](https://ws4.sinaimg.cn/large/006Xmmmgly1g659766ve3j30m708gt9c.jpg)

&emsp;&emsp; 这时，我们就能够获取到 Authorization 参数，进而解析获取到其中的账户和密码信息，进行认证，我们查看认证成功后返回的Authtication对象信息其实是和UsernamePasswordAuthticationFilter中的一致，最后再次调用下一个filter，由于已经认证成功了会直接进入FilterSecurityInterceptor 进行权限验证。

#### 4、AnonymousAuthenticationFilter
&emsp;&emsp;这里为什么要提下 AnonymousAuthenticationFilter呢，主要是因为在Security中不存在没有账户这一说法（这里可能描述不是很清楚，但大致意思是这样的），针对这个Security官方专门指定了这个AnonymousAuthenticationFilter ，用于前面所有filter都认证失败的情况下，自动创建一个默认的匿名用户，拥有匿名访问权限。还记得 在讲解 SecurityContextPersistenceFilter 时我们看到得匿名 autication信息么？如果不记得还得回头看下哦，这里就不再叙述了。
    
    
#### 5、ExceptionTranslationFilter
&emsp;&emsp;ExceptionTranslationFilter 其实没有做任何过滤处理，但别小看它得作用，它最大也最牛叉之处就在于它捕获AuthenticationException 和AccessDeniedException，如果发生的异常是这2个异常 会调用 handleSpringSecurityException()方法进行处理。 我们模拟下 AccessDeniedException(无权限，禁止访问异常)情况，首先我们需要修改下 /get_user 接口：

- 在Controller 上添加 
@EnableGlobalMethodSecurity(prePostEnabled =true) 启用Security 方法级别得权限控制
- 在 接口上添加 @PreAuthorize("hasRole('user')")  只允许有user角色得账户访问（还记得我们默认得user 账户时admin角色么？）


```
@RestController
@EnableGlobalMethodSecurity(prePostEnabled =true)  // 开启方法级别的权限控制
public class TestController {

    @PreAuthorize("hasRole('user')") //只允许user角色访问
    @GetMapping("/get_user/{username}")
    public String getUser(@PathVariable  String username){
        return username;
    }
}
```

&emsp;&emsp;重启项目,重新访问 /get_user 接口，输入正确的账户密码，发现返回一个 403 状态的错误页面，这与我们之前将的流程时一致的。debug，看下处理：

![image](https://ws4.sinaimg.cn/large/006Xmmmggy1g65ag1aj1yj311k0emjtx.jpg)


&emsp;&emsp;可以明显的看到异常对象是 AccessDeniedException ，异常信息是不允许访问，我们再看下 AccessDeniedException 异常后的处理方法accessDeniedHandler.handle(),进入到了 AccessDeniedHandlerImpl 的handle()方法，这个方法会先判断系统是否配置了 errorPage (错误页面)，没有的话直接往 response 中设置403 状态码。

![image](https://ws4.sinaimg.cn/large/006Xmmmgly1g65akracrsj30u00gcq51.jpg)



#### 6、FilterSecurityInterceptor
&emsp;&emsp;FilterSecurityInterceptor 是整个Security filter链中的最后一个，也是最重要的一个，它的主要功能就是判断认证成功的用户是否有权限访问接口，其最主要的处理方法就是 调用父类（AbstractSecurityInterceptor）的 super.beforeInvocation(fi)，我们来梳理下这个方法的处理流程：

> - 通过 obtainSecurityMetadataSource().getAttributes() 获取 当前访问地址所需权限信息
> - 通过 authenticateIfRequired() 获取当前访问用户的权限信息
> - 通过 accessDecisionManager.decide() 使用 投票机制判权，判权失败直接抛出 AccessDeniedException 异常




```
protected InterceptorStatusToken beforeInvocation(Object object) {
	       
	    ......
	    
	    // 1 获取访问地址的权限信息 
		Collection<ConfigAttribute> attributes = this.obtainSecurityMetadataSource()
				.getAttributes(object);

		if (attributes == null || attributes.isEmpty()) {
		
		    ......
		    
			return null;
		}

        ......

        // 2 获取当前访问用户权限信息
		Authentication authenticated = authenticateIfRequired();

	
		try {
		    // 3  默认调用AffirmativeBased.decide() 方法, 其内部 使用 AccessDecisionVoter 对象 进行投票机制判权，判权失败直接抛出 AccessDeniedException 异常 
			this.accessDecisionManager.decide(authenticated, object, attributes);
		}
		catch (AccessDeniedException accessDeniedException) {
			publishEvent(new AuthorizationFailureEvent(object, attributes, authenticated,
					accessDeniedException));

			throw accessDeniedException;
		}

        ......
        return new InterceptorStatusToken(SecurityContextHolder.getContext(), false,
					attributes, object);
	}
```

&emsp;&emsp; 整个流程其实看起来不复杂，主要就分3个部分，首选获取访问地址的权限信息，其次获取当前访问用户的权限信息，最后通过投票机制判断出是否有权。






### 三、 个人总结

      整个授权流程核心的就在于这几次核心filter的处理，这里我用序列图来概况下这个授权流程
    
![image](https://ws2.sinaimg.cn/large/006Xmmmgly1g65blh3kezj323o0oawie.jpg)（PS： 如果图片展示不清楚，可访问项目的 github 地址）


&emsp;&emsp; 本文介绍授权过程的代码可以访问代码仓库中的 security 模块 ，项目的github 地址 : https://github.com/BUG9/spring-security 

&emsp;&emsp; &emsp;&emsp; &emsp;&emsp; **如果您对这些感兴趣，欢迎star、follow、收藏、转发给予支持！**
