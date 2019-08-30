##  Spring Security 解析(二) —— 认证过程
>  &emsp;&emsp;在学习Spring Cloud 时，遇到了授权服务oauth 相关内容时，总是一知半解，因此决定先把Spring Security 、Spring Security Oauth2 等权限、认证相关的内容、原理及设计学习并整理一遍。本系列文章就是在学习的过程中加强印象和理解所撰写的，如有侵权请告知。

> 项目环境:
> - JDK1.8
> - Spring boot 2.x
> - Spring Security 5.x

### 一、@EnableGlobalAuthentication 配置 解析
&emsp;&emsp;还记得上一篇讲解授权过程中提到@EnableWebSecurity 引用了 WebSecurityConfiguration 配置类 和 @EnableGlobalAuthentication 注解吗？ 当时只是讲解了下  WebSecurityConfiguration 配置类 ，这次该轮到  @EnableGlobalAuthentication  配置了。

&emsp;&emsp;查看 @EnableGlobalAuthentication 注解源码，我们可以看到其引用了AuthenticationConfiguration 配置类。其中有一个方法值得我们注意，那就是  getAuthenticationManager()  （**还记得授权过程中调用了 AuthenticationManager().authenticate() 进行认证么？**）,  我们来看下其源码内部大致逻辑：


```
public AuthenticationManager getAuthenticationManager() throws Exception {

        ......
        // 1 调用 authenticationManagerBuilder 方法获取 authenticationManagerBuilder 对象，用于 build  authenticationManager 对象
		AuthenticationManagerBuilder authBuilder = authenticationManagerBuilder(
				this.objectPostProcessor, this.applicationContext);
        .....
        // 2  build 方法调用同授权过程中的 webSecurity.build()  一样，都是通过父类 AbstractConfiguredSecurityBuilder.doBuild() 方法中的 performBuild() 方法进行 build, 只是这里不再是通过其子类 HttpSecurity.performBuild() ，而是通过 AuthenticationManagerBuilder.performBuild() 
		authenticationManager = authBuilder.build();

        .......
        
		return authenticationManager;
	}
```

根据源码我们可以概括其逻辑分2部分：

> - 1、 通过调用 authenticationManagerBuilder() 方法获取 authenticationManagerBuilder 对象 
> - 2、 调用authenticationManagerBuilder 对象的 build() 创建 authenticationManager 对象并返回

&emsp;&emsp;我们再详细看下这个build的过程，可以发现其 build 调用跟授权过程中build securityFilterChain 一样 都是通过 AbstractConfiguredSecurityBuilder.doBuild() 方法中的 performBuild() 进行构建， 不过这次不再是调用其子类  HttpSecurity.performBuild() 而是  AuthenticationManagerBuilder.performBuild() 。
我们来看下 AuthenticationManagerBuilder.performBuild() 方法内部实现：

```
protected ProviderManager performBuild() throws Exception {
		if (!isConfigured()) {
			logger.debug("No authenticationProviders and no parentAuthenticationManager defined. Returning null.");
			return null;
		}
		// 1  创建了一个包含  authenticationProviders  参数 的 ProviderManager 对象
		ProviderManager providerManager = new ProviderManager(authenticationProviders,
				parentAuthenticationManager);
		if (eraseCredentials != null) {
			providerManager.setEraseCredentialsAfterAuthentication(eraseCredentials);
		}
		if (eventPublisher != null) {
			providerManager.setAuthenticationEventPublisher(eventPublisher);
		}
		providerManager = postProcess(providerManager);
		return providerManager;
	}
```

&emsp;&emsp; 这里我们主要关注其内部 创建了一个包含  **authenticationProviders**  参数 的 **ProviderManager** （ProviderManager 是 AuthenticationManager 的实现类）对象并返回。  

回过头，我们来看下 AuthenticationManager 接口 源码：

```
public interface AuthenticationManager {
    // 认证接口
	Authentication authenticate(Authentication authentication)
			throws AuthenticationException;
}
```
&emsp;&emsp; 可以看到，内部就只有一个我们在授权过程中提到过的 authenticate()，其接口接收一个 **Authentication**（这个对象我们也不陌生，之前授权过程中提到过的 UsernamePasswordAuthrnticationToken 等都是其实现子类） 对象作为参数。




&emsp;&emsp;至此认证的**部分关键类或接口**已经浮出水面了，它们分别是 **AuthenticationManager 、ProviderManager、AuthenticationProvider、Authentication**， 接下来我们就围绕这几个类或接口进行剖析。


### 二、AuthenticationManager 

&emsp;&emsp;正如我们之前看到的一项，它是整个认证的入口，其定义的认证接口  authenticate()  接收一个 **Authentication** 对象作为参数。**AuthenticationManager** 它只是提供了一个认证接口方法，因为在实际使用中，我们不仅有账户密码的登录方式，还有短信验证码登录、邮箱登录等等，所以它本身不做任何认证，其具体做认证的是 **ProviderManager** 子类，但正如我们说过的认证方式有很多，如果仅仅依靠 ProviderManager 本身来实现 authenticate() 接口，那我们要支持这么多认证方式不得写多少个 if 判断，而且以后如果我们想要支持指纹登录，那又不得不在这个方法内部加个if，这种不利于系统扩展的写法肯定是不可取的，所以 ProviderManager 本身会维护一个List<**AuthenticationProvider**>列表 ，用于存放多种认证方式，然后通过委托的方式，调用 AuthenticationProvider 来真正实现认证逻辑的 。 而 **Authentication** 就是我们需要认证的信息（当然不仅仅只包括账户信息），通过authenticate() 接口认证成功后返回的 Authentication 就是一个被标识认证成功的对象 。 这里为什么要解释下 AuthenticationManager、ProviderManager、AuthenticationProvider 的关系，主要是一开始容易搞混它们，相信经过这样一段描述更容易理解了吧。。。 


### 三、Authentication
&emsp;&emsp; 如果 没有看过源码的同学可能会认为 Authentication 是一个类吧，可实际上它是一个 接口，其内部并未存在任何属性字段，它仅仅定义了和规范好了认证对象需要的接口方法，我们来看看其定义的接口方法有哪些，分别又什么作用：

```
public interface Authentication extends Principal, Serializable { 

    // 1  获取权限信息（不能仅仅理解未角色权限，还有菜单权限等等），默认是GrantedAuthority接口的实现类
	Collection<? extends GrantedAuthority> getAuthorities();

    // 2 获取用户密码信息 ，认证成功后会被删除掉
	Object getCredentials();
    
    // 3  主要存放访问着的ip等信息
	Object getDetails();

	// 4  重点！！ 最重要的身份信息。 大部分情况下是 UserDetails 接口的实现 类，比如 我们 之前配置的 User 对象   
	Object getPrincipal();

    // 5  是否认证（成功）
	boolean isAuthenticated();

    // 6  设置认证标识 
	void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException;
}
```
&emsp;&emsp; 既然 Authentication 定义了这些接口方法，那么其子类实现肯定都按照这个标准或者称之为规范定制了实现，这里就不罗列出其子类的具体实现了，有兴趣的同学可以去看下 我们最常用的 UsernamePasswordAuthenticationToken 实现（包括其 父类 AbstractAuthenticationToken）


### 四、ProviderManager
&emsp;&emsp; 它是 AuthenticationManager 的实现子类之一，也是我们最常用的一个实现。正如我们前面提到过的，其内部维护了 一个 List<**AuthenticationProvider**> 对象， 用于支持和扩展 多种形式的认证方式。我们来看下 其 实现 authenticate() 的源码：



```
public Authentication authenticate(Authentication authentication)
			throws AuthenticationException {
			
	    ......
	    
        // 1 通过 getProviders() 方法获取到内部维护的 List<AuthenticationProvider> 对象 并 通过遍历的方式 去 认证，只要认证成功 就 break 
		for (AuthenticationProvider provider : getProviders()) {
		    //  2 正如前面看到的有 很多 AuthenticationProvider 实现，如果每次都是验证失败后再掉用下一个 AuthenticationProvider 这种实现是不是很不高效？ 所以 这里通过  supports() 方法来验证是否可以使用 该 AuthenticationProvider 进行验证，不可以就直接换下一个 
			if (!provider.supports(toTest)) {
				continue;
			}
			try {
			    // 3  重点，这里是 调用真实的认证方法
				result = provider.authenticate(authentication);
				if (result != null) {
					copyDetails(authentication, result);
					break;
				}
			}
			catch (AccountStatusException e) {
				prepareException(e, authentication);
				throw e;
			}
			catch (InternalAuthenticationServiceException e) {
				prepareException(e, authentication);
				throw e;
			}
			catch (AuthenticationException e) {
				lastException = e;
			}
		}
        
		if (result == null && parent != null) {
			try {
			    // 4 前面都认证不成功，调用父类（严格意思不是调用父类，而是其他的 AuthenticationManager 实现类）认证方法
				result = parentResult = parent.authenticate(authentication);
			}
			catch (ProviderNotFoundException e) {
		
			}
			catch (AuthenticationException e) {
				lastException = parentException = e;
			}
		}

		if (result != null) {
			if (eraseCredentialsAfterAuthentication
					&& (result instanceof CredentialsContainer)) {
			    //  5  删除认证成功后的 密码信息，保证安全
				((CredentialsContainer) result).eraseCredentials();
			}
			if (parentResult == null) {
				eventPublisher.publishAuthenticationSuccess(result);
			}
			return result;
		}
        
		if (lastException == null) {
			lastException = new ProviderNotFoundException(messages.getMessage(
					"ProviderManager.providerNotFound",
					new Object[] { toTest.getName() },
					"No AuthenticationProvider found for {0}"));
		}
		if (parentException == null) {
			prepareException(lastException, authentication);
		}

		throw lastException;
	}
```
&emsp;&emsp; 梳理下整个方法内部实现逻辑：

> - 通过 getProviders() 方法获取到内部维护的 List<AuthenticationProvider> 对象 并 通过遍历的方式 去 认证
> - 通过 provider.supports()  方法 来验证是否可用当前的 AuthenticationProvider  进行验证，不可以就直接换下一个  ( 其实方法内部就是验证当前 的 Authentication 对象是不是其某个子类，比如 我们最常用到的 **DaoAuthenticationProvider** 的  supports 方法就是判断当前 的 Authentication 是不是 UsernamePasswordAuthenticationToken  ) 
> - 通过 provider.authenticate() 调用 其真正的认证实现 
> - 如果 前面的所有 AuthenticationProvider 均不能认证成功，尝试调用 parent.authenticate() 方法 ：调用父类（严格意思不是调用父类，而是其他的 AuthenticationManager 实现类）认证方法
> - 最后 通过 ((CredentialsContainer) result).eraseCredentials()  删除认证成功后的 密码信息，保证安全



### 五、AuthenticationProvider(DaoAuthenticationProvider)

&emsp;&emsp; 正如我们想象的一样，AuthenticationProvider 是一个接口，本身定义了一个 和 AuthenticationManager 一样的 authenticate 认证接口方法，外加一个 supports() 用于 判别当前 Authentication 是否可以进行处理。

```
public interface AuthenticationProvider {
    // 定义认证接口方法
	Authentication authenticate(Authentication authentication)
			throws AuthenticationException;
    // 定义判断是否可以认证处理的接口方法
	boolean supports(Class<?> authentication);
}
```
&emsp;&emsp; 这里我们就拿我们用得最多的一个 AuthenticationProvider 实现类 DaoAuthenticationProvider(注意，这里和UsernamePasswordAuthenticationFilter 类似，都是通过父类来实现接口，然后内部处理方法再调用 其 子类进行处理) 来看其内部 这2个抽象方法的实现：

- supports 实现：


```
public boolean supports(Class<?> authentication) {
		return (UsernamePasswordAuthenticationToken.class
				.isAssignableFrom(authentication));
	}
```
&emsp;&emsp; 可以看到仅仅只是判断当前的 authentication 是否为 UsernamePasswordAuthenticationToken（或其子类）
    
- authrnticate 实现

```
// 1 注意这里的实现方法是 DaoAuthenticationProvider 的父类 AbstractUserDetailsAuthenticationProvider 实现的
public Authentication authenticate(Authentication authentication)
			throws AuthenticationException {
	
	    // 2 从 authentication 中获取 用户名
		String username = (authentication.getPrincipal() == null) ? "NONE_PROVIDED"
				: authentication.getName();

		boolean cacheWasUsed = true;
		
		// 3 根据username 从缓存中获取 认证成功的 UserDetails 信息
		UserDetails user = this.userCache.getUserFromCache(username);

		if (user == null) {
			cacheWasUsed = false;

			try {
			    // 4 如果缓存中没有用户信息 需要 获取用户信息（由 DaoAuthenticationProvider 实现 ） 
				user = retrieveUser(username,
						(UsernamePasswordAuthenticationToken) authentication);
			}
			catch (UsernameNotFoundException notFound) {
			    ......
			}
		}

		try {
		    // 5 前置检查账户是否锁定，过期，冻结（由DefaultPreAuthenticationChecks类实现）
			preAuthenticationChecks.check(user);
			// 6 主要是验证 获取到的用户密码与传入的用户密码是否一致
			additionalAuthenticationChecks(user,
					(UsernamePasswordAuthenticationToken) authentication);
		}
		catch (AuthenticationException exception) {
		    // 这里官方发现缓存可能导致了某些问题，又重新去认证一次
			if (cacheWasUsed) {
				// There was a problem, so try again after checking
				// we're using latest data (i.e. not from the cache)
				cacheWasUsed = false;
				user = retrieveUser(username,
						(UsernamePasswordAuthenticationToken) authentication);
				preAuthenticationChecks.check(user);
				additionalAuthenticationChecks(user,
						(UsernamePasswordAuthenticationToken) authentication);
			}
			else {
				throw exception;
			}
		}
        // 7 后置检查用户密码是否 过期
		postAuthenticationChecks.check(user);
        
        // 8 验证成功后的用户信息存入缓存
		if (!cacheWasUsed) {
			this.userCache.putUserInCache(user);
		}

		Object principalToReturn = user;

		if (forcePrincipalAsString) {
			principalToReturn = user.getUsername();
		}
        // 9 重新创建一个 authenticated 为true （即认证成功）的 UsernamePasswordAuthenticationToken 对象并返回 
		return createSuccessAuthentication(principalToReturn, authentication, user);
	}
```

&emsp;&emsp; 梳理下authenticate（这里的方法的实现是由 AbstractUserDetailsAuthenticationProvider 提供的）方法内部实现逻辑：

> - 从 入参 authentication 对象中获取到 username 信息
> - **（这里忽略缓存的处理） 调用 retrieveUser() 方法（由 DaoAuthenticationProvider 实现）根据 username 获取到 系统（一般来说是从数据库中） 中获取到 **UserDetails** 对象**
> - 通过 preAuthenticationChecks.check() 方法检测 当前获取到的 **UserDetails** 是否过期、冻结、锁定（如果任意一个条件 为 true 将抛出 相应 的异常）
> - **通过 additionalAuthenticationChecks() （由 DaoAuthenticationProvider 实现） 判断 密码是否一致**
> - 通过 	postAuthenticationChecks.check() 检测 **UserDetails** 的密码是否过期
> - 最后通过 createSuccessAuthentication() 重新创建一个 authenticated 为true （即认证成功）的 UsernamePasswordAuthenticationToken 对象并返回 

&emsp;&emsp;虽然我们知道其验证逻辑， 但其内部很多方法我们不清楚其内部实现，以及这里新增的一个 关键认证类 **UserDetails** 是怎么设计的，如何验证其是否过期等等。


### 六、 UserDetailsService  和 UserDetails

&emsp;&emsp;继续深入看下 retrieveUser() 方法，首先我们注意到其返回对象是一个 UserDetails,那么我们先从 UserDetails 入手。
    

#### UserDetails：

&emsp;&emsp; 我们先来看下 UserDetails 源码：


```
public interface UserDetails extends Serializable {
	
	// 1 与 Authentication 的 一样，都是获取 权限信息 
	Collection<? extends GrantedAuthority> getAuthorities();

    // 2 获取用户正确的密码   
	String getPassword();

    // 3 获取账户名
	String getUsername();

    // 4 账户是否过期
	boolean isAccountNonExpired();

    // 5 账户是否锁定
	boolean isAccountNonLocked();

    // 6 密码是否过期 
	boolean isCredentialsNonExpired();

    // 7 账户是否冻结
	boolean isEnabled();
}
```


&emsp;&emsp; 从上面的 4，5，6，7 接口我们就能够知道  preAuthenticationChecks.check() 和 postAuthenticationChecks.check() 是如何检测的了，这里2个方法的检测细节就不再深究了，有兴趣的同学可以看看源码，我们只要知道检测失败会抛出异常就行了。

&emsp;&emsp;咋呼一看，这个UserDetails 和 Authentication  很相似，其实它们之间还真有关系，在createSuccessAuthentication() 传教Authentication 对象时，它的authorities 就是UserDetails 传入的。

##### UserDetailsService：

&emsp;&emsp;retrieveUser() 方法是系统通过传入的账户名获取对应的账户信息的唯一方法，我们来看下其内部源码逻辑：


```
protected final UserDetails retrieveUser(String username,
			UsernamePasswordAuthenticationToken authentication)
			throws AuthenticationException {
		prepareTimingAttackProtection();
		try {
		
		    // 通过 UserDetailsService 的loadUserByUsername 方法 获取用户信息
			UserDetails loadedUser = this.getUserDetailsService().loadUserByUsername(username);
			if (loadedUser == null) {
				throw new InternalAuthenticationServiceException(
						"UserDetailsService returned null, which is an interface contract violation");
			}
			return loadedUser;
		}
		catch (UsernameNotFoundException ex) {
		    ......
		}
	}
```
&emsp;&emsp; 相信看到这里，一切都关联上了，这里的 UserDetailsService.loadUserByUsername() 就是我们在 上一篇 授权过程中 我们自己实现的。 这里就不再 贴出UserDetailsService 源码了。




&emsp;&emsp; 还有additionalAuthenticationChecks() 密码验证没有讲到，这里简单提下，其内部就是通过 PasswordEncoder.matches() 方法进行密码匹配的。不过这里要注意一下，这里的 PasswordEncoder 在 Security 5 开始默认 替换成了 DelegatingPasswordEncoder 这里也是和我们之前 讨论 loadUserByUsername 方法内部创建User （UserDeatails 实现类之一）是一定要用到  PasswordEncoderFactories.createDelegatingPasswordEncoder().encode() 加密是相应的。





### 七、个人总结

&emsp;&emsp;  认证的顶级管理员 **AuthenticationManager** 为我们提供了 认证入口( authenticate()接口)，但是呢，我们也知道大老板一般不直接参与实质的工作，所以它把任务安排给它的下属，也就是我们的 **ProviderManager** 部门领导 ，部门领导 肩负起 认证的工作（authenticate() 认证的实现），其实呢，我们也知道部门领导也是 直接参数 认证工作的，它都是将实际任务安排给小组长的， 也就是我们的 **AuthrnticationProvider** ，部门领导 开个会议，聚集了所有小组长 ，让它们自行判断（通过
support()） 大老板交下来的任务 该由谁来完成， 小组长  领到任务后，就把任务 分发给各个小组成员，比如 成员1(**UserDetailsService**)  只需要 完成 retrieveUser() 的工作，然后成员2 完成 additionalAuthenticationChecks() 的工作，最后由项目经理 ( createSuccessAuthentication()  ) 将结果汇报给小组长，然后小组长汇报给部门领导，部门领导 审核一下结果，觉得小组长做得不够好，然后又做了一些操作 （ eraseCredentials() 擦除密码信息 ），最后认为 结果 可以了就汇报给老板，老板呢，也不多看，直接将结果给了客户(filter)。 

&emsp;&emsp; 按照惯例，上流程图：
    
![](https://ws4.sinaimg.cn/large/006Xmmmgly1g68rvpqf26j30k60fm0sx.jpg)


&emsp;&emsp; 本文介绍认证过程的代码可以访问代码仓库中的 security 模块 ，项目的github 地址 : https://github.com/BUG9/spring-security 

&emsp;&emsp; &emsp;&emsp; &emsp;&emsp; **如果您对这些感兴趣，欢迎star、follow、收藏、转发给予支持！**
    










