##  Spring Security 解析(七) —— Spring Security Oauth2 源码解析

>  &emsp;&emsp;在学习Spring Cloud 时，遇到了授权服务oauth 相关内容时，总是一知半解，因此决定先把Spring Security 、Spring Security Oauth2 等权限、认证相关的内容、原理及设计学习并整理一遍。本系列文章就是在学习的过程中加强印象和理解所撰写的，如有侵权请告知。


> 项目环境:
> - JDK1.8
> - Spring boot 2.x
> - Spring Security 5.x

&emsp;&emsp;在解析Spring Security Oauth2 源码前，我们先看下 [Spring Security Oauth2 官方文档](https://projects.spring.io/spring-security-oauth/docs/oauth2.html) ，其中有这么一段描述：

> The provider role in OAuth 2.0 is actually split between Authorization Service and Resource Service, and while these sometimes reside in the same application, with Spring Security OAuth you have the option to split them across two applications, and also to have multiple Resource Services that share an Authorization Service. The requests for the tokens are handled by Spring MVC controller endpoints, and access to protected resources is handled by standard Spring Security request filters. The following endpoints are required in the Spring Security filter chain in order to implement OAuth 2.0 Authorization Server:
   
> - AuthorizationEndpoint is used to service requests for authorization. Default URL: /oauth/authorize.
> - TokenEndpoint is used to service requests for access tokens. Default URL: /oauth/token.


> The following filter is required to implement an OAuth 2.0 Resource Server:

> - The OAuth2AuthenticationProcessingFilter is used to load the Authentication for the request given an authenticated access token.

&emsp;&emsp;翻译后：

&emsp;&emsp;实现OAuth 2.0授权服务器，Spring Security过滤器链中需要以下端点：

- **AuthorizationEndpoint** 用于服务于授权请求。预设地址：/oauth/authorize。
- **TokenEndpoint** 用于服务访问令牌的请求。预设地址：/oauth/token。

&emsp;&emsp;实现OAuth 2.0资源服务器，需要以下过滤器：

-  **OAuth2AuthenticationProcessingFilter** 用于加载给定的认证访问令牌请求的认证。

&emsp;&emsp;按照官方提示，我们开始源码解析。（个人建议: 在看源码前最好先去看下官方文档，能够减少不必要的时间）


### 一 @EnableAuthorizationServer 解析

&emsp;&emsp;我们都知道 一个授权认证服务器最最核心的就是 @EnableAuthorizationServer ， 那么 @EnableAuthorizationServer 主要做了什么呢？ 我们看下   @EnableAuthorizationServer 源码：


  ```
  @Target(ElementType.TYPE)
  @Retention(RetentionPolicy.RUNTIME)
  @Documented
  @Import({AuthorizationServerEndpointsConfiguration.class, AuthorizationServerSecurityConfiguration.class})
  public @interface EnableAuthorizationServer {
  
  }
  ```
  
&emsp;&emsp; 我们可以看到其源码内部导入了  **AuthorizationServerEndpointsConfiguration**  和  **AuthorizationServerSecurityConfiguration** 这2个配置类。 接下来我们分别看下这2个配置类具体做了什么。

#### 一  AuthorizationServerEndpointsConfiguration

&emsp;&emsp; 从这个配置类的名称我们不难想象其内部肯定存在官方文档中介绍的  **AuthorizationEndpoint** 和  **TokenEndpoint** ，那么我们通过源码来印证下吧：


  ```
  @Configuration
  @Import(TokenKeyEndpointRegistrar.class)
  public class AuthorizationServerEndpointsConfiguration {
  
    // 省略 其他相关配置代码
    ....
    
    // 1、 AuthorizationEndpoint 创建
  	@Bean
  	public AuthorizationEndpoint authorizationEndpoint() throws Exception {
  		AuthorizationEndpoint authorizationEndpoint = new AuthorizationEndpoint();
  		FrameworkEndpointHandlerMapping mapping = getEndpointsConfigurer().getFrameworkEndpointHandlerMapping();
  		authorizationEndpoint.setUserApprovalPage(extractPath(mapping, "/oauth/confirm_access"));
  		authorizationEndpoint.setProviderExceptionHandler(exceptionTranslator());
  		authorizationEndpoint.setErrorPage(extractPath(mapping, "/oauth/error"));
  		authorizationEndpoint.setTokenGranter(tokenGranter());
  		authorizationEndpoint.setClientDetailsService(clientDetailsService);
  		authorizationEndpoint.setAuthorizationCodeServices(authorizationCodeServices());
  		authorizationEndpoint.setOAuth2RequestFactory(oauth2RequestFactory());
  		authorizationEndpoint.setOAuth2RequestValidator(oauth2RequestValidator());
  		authorizationEndpoint.setUserApprovalHandler(userApprovalHandler());
  		authorizationEndpoint.setRedirectResolver(redirectResolver());
  		return authorizationEndpoint;
  	}
  
    // 2、 TokenEndpoint 创建
  	@Bean
  	public TokenEndpoint tokenEndpoint() throws Exception {
  		TokenEndpoint tokenEndpoint = new TokenEndpoint();
  		tokenEndpoint.setClientDetailsService(clientDetailsService);
  		tokenEndpoint.setProviderExceptionHandler(exceptionTranslator());
  		tokenEndpoint.setTokenGranter(tokenGranter());
  		tokenEndpoint.setOAuth2RequestFactory(oauth2RequestFactory());
  		tokenEndpoint.setOAuth2RequestValidator(oauth2RequestValidator());
  		tokenEndpoint.setAllowedRequestMethods(allowedTokenEndpointRequestMethods());
  		return tokenEndpoint;
  	}
  	
  	// 省略 其他相关配置代码
  	....

  ```
&emsp;&emsp; 通过源码我们可以很明确的知道： 
- **AuthorizationEndpoint** 用于服务于授权请求。预设地址：/oauth/authorize。
- **TokenEndpoint** 用于服务访问令牌的请求。预设地址：/oauth/token。

&emsp;&emsp; 这里就不先解析  AuthorizationEndpoint 和  TokenEndpoint 源码了，在下面我会专门解析的。

#### 二  AuthorizationServerSecurityConfiguration

&emsp;&emsp;  AuthorizationServerSecurityConfiguration 由于配置相对复杂，这里就不再贴源码了介绍了。但其中最主要的配置  **ClientDetailsService**  、  **ClientDetailsUserDetailsService**  以及 **ClientCredentialsTokenEndpointFilter** 还是得讲一讲。 
&emsp;&emsp; 这里介绍下 ClientDetailsUserDetailsService 、UserDetailsService、ClientDetailsService 3者之间的关系：

- ClientDetailsService ： 内部仅有 loadClientByClientId 方法。从方法名我们就可知其是通过 clientId 来获取 Client 信息， 官方提供 JdbcClientDetailsService、InMemoryClientDetailsService 2个实现类，我们也可以像UserDetailsService 一样编写自己的实现类。
- UserDetailsService ： 内部仅有 loadUserByUsername 方法。这个类不用我再介绍了吧。不清楚得同学可以看下我之前得文章。
- ClientDetailsUserDetailsService ： UserDetailsService子类，内部维护了 ClientDetailsService 。其 loadUserByUsername 方法重写后调用ClientDetailsService.loadClientByClientId（）。


&emsp;&emsp;**ClientCredentialsTokenEndpointFilter** 作用与 UserNamePasswordAuthenticationFilter 类似，通过拦截 /oauth/token 地址，获取到 clientId 和 clientSecret 信息并创建 UsernamePasswordAuthenticationToken 作为 AuthenticationManager.authenticate() 参数 调用认证过程。**整个认证过程唯一最大得区别在于 DaoAuthenticationProvider.retrieveUser() 获取认证用户信息时调用的是 ClientDetailsUserDetailsService，根据前面讲述的其内部其实是调用ClientDetailsService 获取到客户端信息**。
 
 

### 二 @EnableResourceServer 解析

&emsp;&emsp;像授权认证服务器一样，资源服务器也有一个最核心的配置 @EnableResourceServer  ， 那么 @EnableResourceServer 主要做了什么呢？ 我们 一样先看下  @EnableResourceServer 源码：

  ```
@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
@Documented
@Import(ResourceServerConfiguration.class)
public @interface EnableResourceServer {

}
  ```
  
&emsp;&emsp; 从源码中我们可以看到其导入了 ResourceServerConfiguration 配置类，这个配置类最核心的配置是 应用了 **ResourceServerSecurityConfigurer** ，我这边贴出 ResourceServerSecurityConfigurer 源码 最核心的配置代码如下：
 
 
   ```
   
   
   	@Override
   	public void configure(HttpSecurity http) throws Exception {
        // 1、 创建 OAuth2AuthenticationManager  对象
   		AuthenticationManager oauthAuthenticationManager = oauthAuthenticationManager(http);
   		// 2、 创建 OAuth2AuthenticationProcessingFilter 过滤器
   		resourcesServerFilter = new OAuth2AuthenticationProcessingFilter();
   		resourcesServerFilter.setAuthenticationEntryPoint(authenticationEntryPoint);
   		resourcesServerFilter.setAuthenticationManager(oauthAuthenticationManager);
   		if (eventPublisher != null) {
   			resourcesServerFilter.setAuthenticationEventPublisher(eventPublisher);
   		}
   		if (tokenExtractor != null) {
   			resourcesServerFilter.setTokenExtractor(tokenExtractor);
   		}
   		if (authenticationDetailsSource != null) {
   			resourcesServerFilter.setAuthenticationDetailsSource(authenticationDetailsSource);
   		}
   		resourcesServerFilter = postProcess(resourcesServerFilter);
   		resourcesServerFilter.setStateless(stateless);
   
   		// @formatter:off
   		http
   			.authorizeRequests().expressionHandler(expressionHandler)
   		.and()
   			.addFilterBefore(resourcesServerFilter, AbstractPreAuthenticatedProcessingFilter.class) // 3、 将 OAuth2AuthenticationProcessingFilter 过滤器加载到过滤器链上
   			.exceptionHandling()
   				.accessDeniedHandler(accessDeniedHandler)
   				.authenticationEntryPoint(authenticationEntryPoint);
   		// @formatter:on
   	}
   	
	private AuthenticationManager oauthAuthenticationManager(HttpSecurity http) {
		OAuth2AuthenticationManager oauthAuthenticationManager = new OAuth2AuthenticationManager();
		if (authenticationManager != null) {
			if (authenticationManager instanceof OAuth2AuthenticationManager) {
				oauthAuthenticationManager = (OAuth2AuthenticationManager) authenticationManager;
			}
			else {
				return authenticationManager;
			}
		}
		oauthAuthenticationManager.setResourceId(resourceId);
		oauthAuthenticationManager.setTokenServices(resourceTokenServices(http));
		oauthAuthenticationManager.setClientDetailsService(clientDetails());
		return oauthAuthenticationManager;
	}   	
   	
   	
   ```
   
&emsp;&emsp; 源码中最核心的 就是 官方文档中介绍的 OAuth2AuthenticationProcessingFilter 过滤器， 其配置分3步：

- 1、 创建 OAuth2AuthenticationProcessingFilter 过滤器 对象
- 2、 创建 OAuth2AuthenticationManager  对象 对将其作为参数设置到 OAuth2AuthenticationProcessingFilter 中
- 3、 将 OAuth2AuthenticationProcessingFilter 过滤器添加到过滤器链上


 ### 三  AuthorizationEndpoint 解析
 
 
 
 
 
 ### 四  TokenEndpoint 解析
 
 
  




















