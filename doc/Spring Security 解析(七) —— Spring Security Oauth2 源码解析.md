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


### 一、 @EnableAuthorizationServer 解析

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


#### （一）、  AuthorizationServerEndpointsConfiguration

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

#### （二）、  AuthorizationServerSecurityConfiguration

&emsp;&emsp;  AuthorizationServerSecurityConfiguration 由于配置相对复杂，这里就不再贴源码了介绍了。但其中最主要的配置  **ClientDetailsService**  、  **ClientDetailsUserDetailsService**  以及 **ClientCredentialsTokenEndpointFilter** 还是得讲一讲。 
&emsp;&emsp; 这里介绍下 ClientDetailsUserDetailsService 、UserDetailsService、ClientDetailsService 3者之间的关系：

- ClientDetailsService ： 内部仅有 loadClientByClientId 方法。从方法名我们就可知其是通过 clientId 来获取 Client 信息， 官方提供 JdbcClientDetailsService、InMemoryClientDetailsService 2个实现类，我们也可以像UserDetailsService 一样编写自己的实现类。
- UserDetailsService ： 内部仅有 loadUserByUsername 方法。这个类不用我再介绍了吧。不清楚得同学可以看下我之前得文章。
- ClientDetailsUserDetailsService ： UserDetailsService子类，内部维护了 ClientDetailsService 。其 loadUserByUsername 方法重写后调用ClientDetailsService.loadClientByClientId（）。


&emsp;&emsp;**ClientCredentialsTokenEndpointFilter** 作用与 UserNamePasswordAuthenticationFilter 类似，通过拦截 /oauth/token 地址，获取到 clientId 和 clientSecret 信息并创建 UsernamePasswordAuthenticationToken 作为 AuthenticationManager.authenticate() 参数 调用认证过程。**整个认证过程唯一最大得区别在于 DaoAuthenticationProvider.retrieveUser() 获取认证用户信息时调用的是 ClientDetailsUserDetailsService，根据前面讲述的其内部其实是调用ClientDetailsService 获取到客户端信息**。
 
 

### 二、 @EnableResourceServer 解析

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


 ### 三、  AuthorizationEndpoint 解析
 
&emsp;&emsp; 正如前面介绍一样，AuthorizationEndpoint  本身 最大的功能点就是实现了  /oauth/authorize  ， 那么我们这次就来看看它是如何实现的：

   ```
   
    @RequestMapping(value = "/oauth/authorize")
	public ModelAndView authorize(Map<String, Object> model, @RequestParam Map<String, String> parameters,
			SessionStatus sessionStatus, Principal principal) {

		//  1、 通过 OAuth2RequestFactory 从 参数中获取信息创建 AuthorizationRequest 授权请求对象
		AuthorizationRequest authorizationRequest = getOAuth2RequestFactory().createAuthorizationRequest(parameters);

		Set<String> responseTypes = authorizationRequest.getResponseTypes();

		if (!responseTypes.contains("token") && !responseTypes.contains("code")) {
			throw new UnsupportedResponseTypeException("Unsupported response types: " + responseTypes);
		}

		if (authorizationRequest.getClientId() == null) {
			throw new InvalidClientException("A client id must be provided");
		}

		try {
            // 2、 判断  principal 是否 已授权 ： /oauth/authorize 设置为无权限访问 ，所以要判断，如果 判断失败则抛出 InsufficientAuthenticationException （AuthenticationException 子类），其异常会被 ExceptionTranslationFilter 处理 ，最终跳转到 登录页面，这也是为什么我们第一次去请求获取 授权码时会跳转到登陆界面的原因
			if (!(principal instanceof Authentication) || !((Authentication) principal).isAuthenticated()) {
				throw new InsufficientAuthenticationException(
						"User must be authenticated with Spring Security before authorization can be completed.");
			}

            // 3、 通过 ClientDetailsService.loadClientByClientId() 获取到 ClientDetails 客户端信息
			ClientDetails client = getClientDetailsService().loadClientByClientId(authorizationRequest.getClientId());

			// 4、 获取参数中的回调地址并且与系统配置的回调地址对比
			String redirectUriParameter = authorizationRequest.getRequestParameters().get(OAuth2Utils.REDIRECT_URI);
			String resolvedRedirect = redirectResolver.resolveRedirect(redirectUriParameter, client);
			if (!StringUtils.hasText(resolvedRedirect)) {
				throw new RedirectMismatchException(
						"A redirectUri must be either supplied or preconfigured in the ClientDetails");
			}
			authorizationRequest.setRedirectUri(resolvedRedirect);

			//  5、 验证 scope 
			oauth2RequestValidator.validateScope(authorizationRequest, client);

			//  6、 检测该客户端是否设置自动 授权（即 我们配置客户端时配置的 autoApprove(true)  ）
			authorizationRequest = userApprovalHandler.checkForPreApproval(authorizationRequest,
					(Authentication) principal);
			boolean approved = userApprovalHandler.isApproved(authorizationRequest, (Authentication) principal);
			authorizationRequest.setApproved(approved);

			if (authorizationRequest.isApproved()) {
				if (responseTypes.contains("token")) {
					return getImplicitGrantResponse(authorizationRequest);
				}
				if (responseTypes.contains("code")) {
				    // 7 调用 getAuthorizationCodeResponse() 方法生成code码并回调到设置的回调地址
					return new ModelAndView(getAuthorizationCodeResponse(authorizationRequest,
							(Authentication) principal));
				}
			}
			model.put(AUTHORIZATION_REQUEST_ATTR_NAME, authorizationRequest);
			model.put(ORIGINAL_AUTHORIZATION_REQUEST_ATTR_NAME, unmodifiableMap(authorizationRequest));

			return getUserApprovalPageResponse(model, authorizationRequest, (Authentication) principal);

		}
		catch (RuntimeException e) {
			sessionStatus.setComplete();
			throw e;
		}

	}
   

   ```

&emsp;&emsp; 我们来大致解析下这段逻辑：

-  1、 通过 OAuth2RequestFactory 从 参数中获取信息创建 AuthorizationRequest 授权请求对象
-  2、 判断  principal 是否 已授权 ： /oauth/authorize 设置为无权限访问 ，所以要判断，如果 判断失败则抛出 InsufficientAuthenticationException （AuthenticationException 子类），其异常会被 ExceptionTranslationFilter 处理 ，最终跳转到 登录页面，这也是为什么我们第一次去请求获取 授权码时会跳转到登陆界面的原因
-  3、 通过 ClientDetailsService.loadClientByClientId() 获取到 ClientDetails 客户端信息
-  4、 获取参数中的回调地址并且与系统配置的回调地址（步骤3获取到的client信息）对比
-  5、 与步骤4一样 验证 scope 
-  6、 检测该客户端是否设置自动 授权（即 我们配置客户端时配置的 autoApprove(true)）
-  7、 由于我们设置  autoApprove(true) 则 调用 getAuthorizationCodeResponse() 方法生成code码并回调到设置的回调地址
-  8、 真实生成Code 的方法时 generateCode(AuthorizationRequest authorizationRequest, Authentication authentication) 方法： 其内部是调用 authorizationCodeServices.createAuthorizationCode()方法生成code的
 
&emsp;&emsp;生成授权码的整个逻辑其实是相对简单的，真正复杂的是token的生成逻辑，那么接下来我们就看看token的生成。
  
 ### 四、  TokenEndpoint 解析
 
 &emsp;&emsp; 对于使用oauth2 的用户来说，最最不可避免的就是token 的获取，话不多说，源码解析贴上：
 
   ```
 	
 	@RequestMapping(value = "/oauth/token", method=RequestMethod.POST)
 	public ResponseEntity<OAuth2AccessToken> postAccessToken(Principal principal, @RequestParam
 	Map<String, String> parameters) throws HttpRequestMethodNotSupportedException {
 
        // 1、 验证 用户信息 （正常情况下会经过 ClientCredentialsTokenEndpointFilter 过滤器认证后获取到用户信息 ）
 		if (!(principal instanceof Authentication)) {
 			throw new InsufficientAuthenticationException(
 					"There is no client authentication. Try adding an appropriate authentication filter.");
 		}
 
        // 2、 通过 ClientDetailsService().loadClientByClientId() 获取系统配置客户端信息
 		String clientId = getClientId(principal);
 		ClientDetails authenticatedClient = getClientDetailsService().loadClientByClientId(clientId);
 
        // 3、 通过客户端信息生成 TokenRequest 对象
 		TokenRequest tokenRequest = getOAuth2RequestFactory().createTokenRequest(parameters, authenticatedClient);
 
        ......
        
        // 4、 调用 TokenGranter.grant()方法生成 OAuth2AccessToken 对象（即token）
 		OAuth2AccessToken token = getTokenGranter().grant(tokenRequest.getGrantType(), tokenRequest);
 		if (token == null) {
 			throw new UnsupportedGrantTypeException("Unsupported grant type: " + tokenRequest.getGrantType());
 		}
        // 5、 返回token
 		return getResponse(token);
 
 	}
   ``` 
   
 &emsp;&emsp; 简单概括下来，整个生成token 的逻辑如下：
 
-  1、 验证 用户信息 （正常情况下会经过 ClientCredentialsTokenEndpointFilter 过滤器认证后获取到用户信息 ）
-  2、 通过 ClientDetailsService().loadClientByClientId() 获取系统配置的客户端信息
-  3、 通过客户端信息生成 **TokenRequest** 对象
-  **4、 将步骤3获取到的 TokenRequest 作为TokenGranter.grant() 方法参照 生成 OAuth2AccessToken 对象（即token）**
-  5、 返回 token

&emsp;&emsp; 其中 步骤 4 是整个token生成的核心，我们来看下  TokenGranter.grant() 方法源码：


   ``` 

    public class CompositeTokenGranter implements TokenGranter {
    
    	private final List<TokenGranter> tokenGranters;
    
    	public OAuth2AccessToken grant(String grantType, TokenRequest tokenRequest) {
    		for (TokenGranter granter : tokenGranters) {
    			OAuth2AccessToken grant = granter.grant(grantType, tokenRequest);
    			if (grant!=null) {
    				return grant;
    			}
    		}
    		return null;
    	}
    	
    	.....
    }

   ``` 

&emsp;&emsp; 官方默认调用 **CompositeTokenGranter** 的 grant()方法，从源码中我们可以看到其聚合了 TokenGranter ，采用遍历的方式一个一个的去尝试，由于Oauth2 有4种模式外加token刷新，所以 官方目前有5个子类。
&emsp;&emsp; Debug 看下 tokenGranters ：
![http://ww1.sinaimg.cn/large/005Q13r0gy1g7bpn79kv3j30up0ejdhw.jpg](http://ww1.sinaimg.cn/large/005Q13r0gy1g7bpn79kv3j30up0ejdhw.jpg)
&emsp;&emsp;从截图中可以看出分别是： AuthorizationCodeTokenGranter、ClientCredentialsTokenGranter、ImplicitTokenGranter、RefreshTokenGranter、ResourceOwnerPasswordTokenGranter ，当然还有一个他们共同的 父类 AbstractTokenGranter。
其中除了 ClientCredentialsTokenGranter 重写了 AbstractTokenGranter.grant() 方法以外，其他4中都是直接调用   AbstractTokenGranter.grant()   进行处理。 我们来看下 AbstractTokenGranter.grant()  其方法内部实现：

   ``` 

    public OAuth2AccessToken grant(String grantType, TokenRequest tokenRequest) {

        // 1、 判断 grantType 是否匹配
		if (!this.grantType.equals(grantType)) {
			return null;
		}
		
		// 2、 获取  ClientDetails 信息 并验证 grantType 
		String clientId = tokenRequest.getClientId();
		ClientDetails client = clientDetailsService.loadClientByClientId(clientId);
		validateGrantType(grantType, client);

		if (logger.isDebugEnabled()) {
			logger.debug("Getting access token for: " + clientId);
		}

        // 3、 调用 getAccessToken() 方法生成token并返回
		return getAccessToken(client, tokenRequest);

	}

   ``` 
&emsp;&emsp; AbstractTokenGranter.grant()  方法内部逻辑分3步：

- 1、 判断 grantType 是否匹配
- 2、 获取  ClientDetails 信息 并验证 grantType
- 3、 调用 getAccessToken() 方法生成token并返回 

&emsp;&emsp; 到目前 我们还没有看到token具体生成的逻辑，那么接下来我们就来揭开这层面纱：

   ``` 
	protected OAuth2AccessToken getAccessToken(ClientDetails client, TokenRequest tokenRequest) {
		return tokenServices.createAccessToken(getOAuth2Authentication(client, tokenRequest));
	}
   ``` 

&emsp;&emsp; 这里分2个步骤：

- 1、 通过 getOAuth2Authentication() 方法（子类重写）获取到  **OAuth2Authentication** 对象
- 2、 将步骤1 获取到的 OAuth2Authentication 作为 tokenServices.createAccessToken() 方法入参生成token


&emsp;&emsp; 由于授权码模式最为复杂，那么我们就以为例，查看 其 getOAuth2Authentication()  源码：

   ``` 

    @Override
	protected OAuth2Authentication getOAuth2Authentication(ClientDetails client, TokenRequest tokenRequest) {
        
        // 1、 从TokenRequest 中 获取 code 码 、 回调url
		Map<String, String> parameters = tokenRequest.getRequestParameters();
		String authorizationCode = parameters.get("code");
		String redirectUri = parameters.get(OAuth2Utils.REDIRECT_URI);

		if (authorizationCode == null) {
			throw new InvalidRequestException("An authorization code must be supplied.");
		}
        // 2、 调用 authorizationCodeServices.consumeAuthorizationCode(authorizationCode) 方法通过 Code码 获取 OAuth2Authentication 对象
		OAuth2Authentication storedAuth = authorizationCodeServices.consumeAuthorizationCode(authorizationCode);
		if (storedAuth == null) {
			throw new InvalidGrantException("Invalid authorization code: " + authorizationCode);
		}
        // 3、 从 OAuth2Authentication 对象中获取 OAuth2Request 对象并验证回调url、clientId
		OAuth2Request pendingOAuth2Request = storedAuth.getOAuth2Request();
		String redirectUriApprovalParameter = pendingOAuth2Request.getRequestParameters().get(
				OAuth2Utils.REDIRECT_URI);

		if ((redirectUri != null || redirectUriApprovalParameter != null)
				&& !pendingOAuth2Request.getRedirectUri().equals(redirectUri)) {
			throw new RedirectMismatchException("Redirect URI mismatch.");
		}

		String pendingClientId = pendingOAuth2Request.getClientId();
		String clientId = tokenRequest.getClientId();
		if (clientId != null && !clientId.equals(pendingClientId)) {
			throw new InvalidClientException("Client ID mismatch");
		}
        // 4、 创建一个全新的 OAuth2Request，并从OAuth2Authentication 中获取到 Authentication 对象
		Map<String, String> combinedParameters = new HashMap<String, String>(pendingOAuth2Request
				.getRequestParameters());
		combinedParameters.putAll(parameters);
		OAuth2Request finalStoredOAuth2Request = pendingOAuth2Request.createOAuth2Request(combinedParameters);
		
		Authentication userAuth = storedAuth.getUserAuthentication();
		
		// 5、 创建一个全新的 OAuth2Authentication 对象
		return new OAuth2Authentication(finalStoredOAuth2Request, userAuth);

	}
	
   ```

&emsp;&emsp; 我们从源码中可以看到，整个 getOAuth2Authentication  分5个步骤：

- 1、 从TokenRequest 中 获取 code 码 、 回调url
- 2、 调用 authorizationCodeServices.consumeAuthorizationCode(authorizationCode) 方法通过 Code码 获取 OAuth2Authentication 对象
- 3、 从 OAuth2Authentication 对象中获取 OAuth2Request 对象并验证回调url、clientId
- 4、 创建一个全新的 **OAuth2Request**，并从OAuth2Authentication 中获取到 **Authentication** 对象
- 5、 通过步骤4 的OAuth2Request 和  Authentication  创建一个全新的 **OAuth2Authentication** 对象 

&emsp;&emsp; 这里可能有人会问怎么不直接使用原本通过code 获取的 OAuth2Authentication 对象，这里我也不清楚，如果有同学清楚麻烦告知以下，谢谢！！

OAuth2Authentication 对象生成后会调用 tokenServices.createAccessToken()，我们来看下 官方默认提供 的 DefaultTokenServices(AuthorizationServerTokenServices 实现类) 的 createAccessToken 方法内部实现源码：

   ```
    @Transactional
	public OAuth2AccessToken createAccessToken(OAuth2Authentication authentication) throws AuthenticationException {
        // 1、 通过 tokenStore 获取到之前存在的token 并判断是否为空、过期，不为空且未过期则直接返回原有存在的token （由于我们常用Jwt 所以这里是 JwtTokenStore ，且 existingAccessToken 永远为空，即每次请求获取token的值均不同，这与RedisTokenStore 是有区别的）
		OAuth2AccessToken existingAccessToken = tokenStore.getAccessToken(authentication);
		OAuth2RefreshToken refreshToken = null;
		if (existingAccessToken != null) {
			if (existingAccessToken.isExpired()) {
				if (existingAccessToken.getRefreshToken() != null) {
					refreshToken = existingAccessToken.getRefreshToken();
					tokenStore.removeRefreshToken(refreshToken);
				}
				tokenStore.removeAccessToken(existingAccessToken);
			}
			else {
				tokenStore.storeAccessToken(existingAccessToken, authentication);
				return existingAccessToken;
			}
		}
        // 2、 调用 createRefreshToken 方法生成 refreshToken
		if (refreshToken == null) {
			refreshToken = createRefreshToken(authentication);
		}else if (refreshToken instanceof ExpiringOAuth2RefreshToken) {
			ExpiringOAuth2RefreshToken expiring = (ExpiringOAuth2RefreshToken) refreshToken;
			if (System.currentTimeMillis() > expiring.getExpiration().getTime()) {
				refreshToken = createRefreshToken(authentication);
			}
		}
        
        // 3、 调用  createAccessToken(authentication, refreshToken) 方法获取 token
		OAuth2AccessToken accessToken = createAccessToken(authentication, refreshToken);
		tokenStore.storeAccessToken(accessToken, authentication);
		// 4、 重新覆盖原有的刷新token（原有的 refreshToken 为UUID 数据，覆盖为 jwtToken）
		refreshToken = accessToken.getRefreshToken();
		if (refreshToken != null) {
			tokenStore.storeRefreshToken(refreshToken, authentication);
		}
		return accessToken;

	}
	
   ```
&emsp;&emsp; 我们从源码中可以看到，整个 createAccessToken  分4个步骤：

- 1、 通过 tokenStore 获取到之前存在的token 并判断是否为空、过期，不为空且未过期则直接返回原有存在的token （由于我们常用Jwt 所以这里是 JwtTokenStore ，且 existingAccessToken 永远为空，即每次请求获取token的值均不同，这与RedisTokenStore 是有区别的）
- 2、 调用 createRefreshToken 方法生成 refreshToken
- **3、 调用  createAccessToken(authentication, refreshToken) 方法获取 token**
- 4、 重新覆盖原有的刷新token（原有的 refreshToken 为UUID 数据，覆盖为 jwtToken）并返回token


&emsp;&emsp; 在现在为止我们还没有看到token的生成代码，不要灰心，立马就能看到了 ，我们在看下步骤3 其 重载方法 createAccessToken(authentication, refreshToken) 源码：


   ```
	private OAuth2AccessToken createAccessToken(OAuth2Authentication authentication, OAuth2RefreshToken refreshToken) {
	    // 1、 通过 UUID 创建  DefaultOAuth2AccessToken  并设置上有效时长等信息
		DefaultOAuth2AccessToken token = new DefaultOAuth2AccessToken(UUID.randomUUID().toString());
		int validitySeconds = getAccessTokenValiditySeconds(authentication.getOAuth2Request());
		if (validitySeconds > 0) {
			token.setExpiration(new Date(System.currentTimeMillis() + (validitySeconds * 1000L)));
		}
		token.setRefreshToken(refreshToken);
		token.setScope(authentication.getOAuth2Request().getScope());
        // 2、 判断 是否存在 token增强器 accessTokenEnhancer ，存在则调用增强器增强方法
		return accessTokenEnhancer != null ? accessTokenEnhancer.enhance(token, authentication) : token;
	}
   ```
&emsp;&emsp;  从源码来看，其实token就是通过UUID生成的，且生成过程很简单，但 如果我们配置了token增强器 （TokenEnhancer）（对于jwtToken来说，其毋庸置疑的使用了增强器实现），所以我们还得看下增强器是如何实现的，不过在讲解增强器的实现时，我们还得回顾下之前我们在TokenStoreConfig 配置过以下代码：

   ```
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
   ```
&emsp;&emsp;  这段代码  配置了 tokenEnhancerChain  （TokenEnhancer实现类），并且在 tokenEnhancerChain对象中添加了2个   TokenEnhance ，分别是 JwtAccessTokenConverter 以及一个我们自定义的 增强器 JwtTokenEnhance ，所以看到这里应该能够明白 最终会调用 tokenEnhancerChain ，不用想，tokenEnhancerChain肯定会遍历 其内部维护的 TokenEnhanceList进行token增强，查看 tokenEnhancerChain 源码如下：
 
   ```
public class TokenEnhancerChain implements TokenEnhancer {

	private List<TokenEnhancer> delegates = Collections.emptyList();

	/**
	 * @param delegates the delegates to set
	 */
	public void setTokenEnhancers(List<TokenEnhancer> delegates) {
		this.delegates = delegates;
	}

	/**
	 * Loop over the {@link #setTokenEnhancers(List) delegates} passing the result into the next member of the chain.
	 * 
	 * @see org.springframework.security.oauth2.provider.token.TokenEnhancer#enhance(org.springframework.security.oauth2.common.OAuth2AccessToken,
	 * org.springframework.security.oauth2.provider.OAuth2Authentication)
	 */
	public OAuth2AccessToken enhance(OAuth2AccessToken accessToken, OAuth2Authentication authentication) {
		OAuth2AccessToken result = accessToken;
		for (TokenEnhancer enhancer : delegates) {
			result = enhancer.enhance(result, authentication);
		}
		return result;
	}

}
   ```
   
&emsp;&emsp; 至于其增强器实现代码这里就不再贴出了。至此，个人觉得整个获取token的源码解析基本上完成。如果非得要总结的话 请看下图：

![http://ww1.sinaimg.cn/large/005Q13r0gy1g7bi1lotm8j31bo0o014l.jpg](http://ww1.sinaimg.cn/large/005Q13r0gy1g7bi1lotm8j31bo0o014l.jpg)



### 五、 OAuth2AuthenticationProcessingFilter （资源服务器认证）解析

&emsp;&emsp;通过前面的解析我们最终获取到了token，但获取token 不是我们最终目的，我们最终的目的时拿到资源信息，所以我们还得通过获取到的token去调用资源服务器接口获取资源数据。那么接下来我们就来解析资源服务器是如何通过传入token去辨别用户并允许返回资源信息的。我们知道资源服务器在过滤器链新增了 OAuth2AuthenticationProcessingFilter 来拦截请求并认证，那就这个过滤器的实现：

   ```
	public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain) throws IOException,
			ServletException {

		final boolean debug = logger.isDebugEnabled();
		final HttpServletRequest request = (HttpServletRequest) req;
		final HttpServletResponse response = (HttpServletResponse) res;

		try {
            // 1、 调用 tokenExtractor.extract() 方法从请求中解析出token信息并存放到 authentication 的  principal 字段 中
			Authentication authentication = tokenExtractor.extract(request);
			
			if (authentication == null) {
				if (stateless && isAuthenticated()) {
					if (debug) {
						logger.debug("Clearing security context.");
					}
					SecurityContextHolder.clearContext();
				}
				if (debug) {
					logger.debug("No token in request, will continue chain.");
				}
			}
			else {
				request.setAttribute(OAuth2AuthenticationDetails.ACCESS_TOKEN_VALUE, authentication.getPrincipal());
				if (authentication instanceof AbstractAuthenticationToken) {
					AbstractAuthenticationToken needsDetails = (AbstractAuthenticationToken) authentication;
					needsDetails.setDetails(authenticationDetailsSource.buildDetails(request));
				}
				// 2、 调用  authenticationManager.authenticate() 认证过程： 注意此时的  authenticationManager 是 OAuth2AuthenticationManager 
				Authentication authResult = authenticationManager.authenticate(authentication);

				if (debug) {
					logger.debug("Authentication success: " + authResult);
				}

				eventPublisher.publishAuthenticationSuccess(authResult);
				SecurityContextHolder.getContext().setAuthentication(authResult);

			}
		}
		catch (OAuth2Exception failed) {
			SecurityContextHolder.clearContext();
			eventPublisher.publishAuthenticationFailure(new BadCredentialsException(failed.getMessage(), failed),
					new PreAuthenticatedAuthenticationToken("access-token", "N/A"));
					
			authenticationEntryPoint.commence(request, response,
					new InsufficientAuthenticationException(failed.getMessage(), failed));

			return;
		}
        
		chain.doFilter(request, response);
	}
   ```
   
&emsp;&emsp; 整个filter步骤最核心的是下面2个：

- 1、 调用 tokenExtractor.extract() 方法从请求中解析出token信息并存放到 authentication 的  principal 字段 中
- **2、 调用  authenticationManager.authenticate() 认证过程： 注意此时的  authenticationManager 是 OAuth2AuthenticationManager **

&emsp;&emsp; 在解析@EnableResourceServer 时我们讲过 OAuth2AuthenticationManager 与 OAuth2AuthenticationProcessingFilter 的关系，这里不再重述，我们直接看下 OAuth2AuthenticationManager 的 authenticate() 方法实现：

 
   ```   
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {

		if (authentication == null) {
			throw new InvalidTokenException("Invalid token (token not found)");
		}
		// 1、 从 authentication 中获取 token
		String token = (String) authentication.getPrincipal();
		// 2、 调用 tokenServices.loadAuthentication() 方法  通过 token 参数获取到 OAuth2Authentication 对象 ，这里的tokenServices 就是我们资源服务器配置的。
		OAuth2Authentication auth = tokenServices.loadAuthentication(token);
		if (auth == null) {
			throw new InvalidTokenException("Invalid token: " + token);
		}

		Collection<String> resourceIds = auth.getOAuth2Request().getResourceIds();
		if (resourceId != null && resourceIds != null && !resourceIds.isEmpty() && !resourceIds.contains(resourceId)) {
			throw new OAuth2AccessDeniedException("Invalid token does not contain resource id (" + resourceId + ")");
		}
        // 3、 检测客户端信息，由于我们采用授权服务器和资源服务器分离的设计，所以这个检测方法实际没有检测
		checkClientDetails(auth);

		if (authentication.getDetails() instanceof OAuth2AuthenticationDetails) {
			OAuth2AuthenticationDetails details = (OAuth2AuthenticationDetails) authentication.getDetails();
			// Guard against a cached copy of the same details
			if (!details.equals(auth.getDetails())) {
				// Preserve the authentication details from the one loaded by token services
				details.setDecodedDetails(auth.getDetails());
			}
		}
		// 4、 设置认证成功标识并返回
		auth.setDetails(authentication.getDetails());
		auth.setAuthenticated(true);
		return auth;

	}
	
   ```
   
&emsp;&emsp;  整个   认证逻辑分4步：

- 1、 从 authentication 中获取 token
- 2、 调用 tokenServices.loadAuthentication() 方法  通过 token 参数获取到 OAuth2Authentication 对象 ，这里的tokenServices 就是我们资源服务器配置的。
- 3、 检测客户端信息，由于我们采用授权服务器和资源服务器分离的设计，所以这个检测方法实际没有检测
- 4、 设置认证成功标识并返回 ，注意返回的是  OAuth2Authentication （Authentication 子类）。

&emsp;&emsp; 后面的授权过程就是原汁原味的Security授权，所以至此整个资源服务器 通过获取到的token去调用接口获取资源数据  的解析完成。


### 六、 重写登陆，实现登录接口直接返回jwtToken

&emsp;&emsp; 前面，我们花了大量时间讲解，那么肯定得实践实践一把。 相信大家平时的登录接口都是直接返回token的，但是由于Security 最原本的设计原因，登陆后都是跳转回到之前求情的接口，这种方式仅仅适用于PC端，那如果是APP呢？所以我们想要在原有的登陆接口上实现当非PC请求时返回token的功能。还记得之前提到过的 AuthenticationSuccessHandler 认证成功处理器，我们的功能实现就在这里面。

&emsp;&emsp; 我们重新回顾下  /oauth/authorize  实现 token，模仿实现后的代码如下：

   ```
   
@Component("customAuthenticationSuccessHandler")
@Slf4j
public class CustomAuthenticationSuccessHandler extends SavedRequestAwareAuthenticationSuccessHandler {

    @Resource
    private SecurityProperties securityProperties;

    @Resource
    private ObjectMapper objectMapper;

    @Resource
    private PasswordEncoder passwordEncoder;

    private ClientDetailsService clientDetailsService = null;

    private AuthorizationServerTokenServices authorizationServerTokenServices = null;

    private RequestCache requestCache = new HttpSessionRequestCache();

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws IOException, ServletException {
        logger.info("登录成功");
        // 重构后使得成功处理器能够根据不同的请求来区别是返回token还是调用原来的逻辑（比如授权模式就需要跳转）
        // 获取请求头中的Authorization

        String header = request.getHeader("Authorization");
        // 是否以Basic开头
        if (header == null || !header.startsWith("Basic ")) {
            // 为了授权码模式 登陆正常跳转，这里就不再跳转到自定义的登陆成功页面了
//            // 如果设置了loginSuccessUrl，总是跳到设置的地址上
//            // 如果没设置，则尝试跳转到登录之前访问的地址上，如果登录前访问地址为空，则跳到网站根路径上
//            if (!StringUtils.isEmpty(securityProperties.getLogin().getLoginSuccessUrl())) {
//                requestCache.removeRequest(request, response);
//                setAlwaysUseDefaultTargetUrl(true);
//                setDefaultTargetUrl(securityProperties.getLogin().getLoginSuccessUrl());
//            }
            super.onAuthenticationSuccess(request, response, authentication);
        } else {

            // 这里为什么要通过 SpringContextUtil 获取bean，
            // 主要原因是如果直接在 依赖注入 会导致 AuthorizationServerConfiguration 和 SpringSecurityConfig 配置加载顺序混乱
            // 最直接的表现在 AuthorizationServerConfiguration 中 authenticationManager 获取到 为null，因为这个时候 SpringSecurityConfig 还没加载创建
            // 这里采用这种方式会有一定的性能问题，但也是无赖之举  有兴趣的同学可以看下： https://blog.csdn.net/qq_36732557/article/details/80338570 和 https://blog.csdn.net/forezp/article/details/84313907
            if (clientDetailsService == null && authorizationServerTokenServices == null) {
                clientDetailsService = SpringContextUtil.getBean(ClientDetailsService.class);
                authorizationServerTokenServices = SpringContextUtil.getBean(AuthorizationServerTokenServices.class);
            }

            String[] tokens = extractAndDecodeHeader(header, request);
            assert tokens.length == 2;

            String clientId = tokens[0];

            String clientSecret = tokens[1];

            ClientDetails clientDetails = clientDetailsService.loadClientByClientId(clientId);

            if (clientDetails == null) {
                throw new UnapprovedClientAuthenticationException("clientId对应的配置信息不存在:" + clientId);
            } else if (!passwordEncoder.matches(clientSecret, clientDetails.getClientSecret())) {
                throw new UnapprovedClientAuthenticationException("clientSecret不匹配:" + clientId);
            }

            TokenRequest tokenRequest = new TokenRequest(MapUtils.EMPTY_MAP,
                    clientId,
                    clientDetails.getScope(),
                    "custom");

            OAuth2Request oAuth2Request = tokenRequest.createOAuth2Request(clientDetails);

            OAuth2Authentication oAuth2Authentication = new OAuth2Authentication(oAuth2Request,
                    authentication);

            OAuth2AccessToken token = authorizationServerTokenServices.createAccessToken(oAuth2Authentication);

            response.setContentType("application/json;charset=UTF-8");
            response.getWriter().write(objectMapper.writeValueAsString(token));
        }

    }

    /**
     * 解析请求头拿到clientid  client secret的数组
     *
     * @param header
     * @param request
     * @return
     * @throws IOException
     */
    private String[] extractAndDecodeHeader(String header, HttpServletRequest request) throws IOException {

        byte[] base64Token = header.substring(6).getBytes("UTF-8");
        byte[] decoded;
        try {
            decoded = Base64.decode(base64Token);
        } catch (IllegalArgumentException e) {
            throw new BadCredentialsException("Failed to decode basic authentication token");
        }

        String token = new String(decoded, "UTF-8");

        int delim = token.indexOf(":");

        if (delim == -1) {
            throw new BadCredentialsException("Invalid basic authentication token");
        }
        return new String[]{token.substring(0, delim), token.substring(delim + 1)};
    }

}

   ```
   
&emsp;&emsp; 回顾下创建token 需要的 几个必要类：** clientDetailsService 、 authorizationServerTokenServices、 ClientDetails 、 TokenRequest 、OAuth2Request、 authentication、OAuth2Authentication **。 了解这几个类之间的关系很有必要。对于clientDetailsService 、 authorizationServerTokenServices 我们可以直接从Spring 容器中获取，ClientDetails 我们可以从请求参数中获取，有了 ClientDetails 就有了 TokenRequest，有了 TokenRequest 和 authentication(认证后肯定有的) 就有了 OAuth2Authentication ，有了OAuth2Authentication 就能够生成 OAuth2AccessToken。
至此，我们通过直接请求登陆接口（注意在请求头中添加ClientDetails信息）就可以实现获取到token了，那么有同学会问，如果我是手机登陆方式呢？其实不管你什么登陆方式，只要你设置的登陆成功处理器是上面那个就可支持，下图是我测试的手机登陆获取token截图：

![http://ww1.sinaimg.cn/large/005Q13r0gy1g7brramsjqj30rl0huwft.jpg](http://ww1.sinaimg.cn/large/005Q13r0gy1g7brramsjqj30rl0huwft.jpg)


curl：

   ```
    curl -X POST \
      'http://localhost/loginByMobile?mobile=15680659123&smsCode=215672' \
      -H 'Accept: */*' \
      -H 'Accept-Encoding: gzip, deflate' \
      -H 'Authorization: Basic Y2xpZW50MToxMjM0NTY=' \
      -H 'Cache-Control: no-cache' \
      -H 'Connection: keep-alive' \
      -H 'Content-Length: 0' \
      -H 'Content-Type: application/json' \
      -H 'Host: localhost' \
      -H 'Postman-Token: 412722f9-b303-4d5d-b4a4-72b1dcb47f44,572f537f-c2f7-4c9c-a0e9-5e0eb07a3ec5' \
      -H 'User-Agent: PostmanRuntime/7.17.1' \
      -H 'cache-control: no-cache'
   ```
   
&emsp;&emsp;  **注意： 请求头中添加ClientDetails信息** 


### 七、 个人总结

&emsp;&emsp; 个人觉得官方的这段描述是最好的总结：

实现OAuth 2.0授权服务器，Spring Security过滤器链中需要以下端点：
             
- **AuthorizationEndpoint** 用于服务于授权请求。预设地址：/oauth/authorize。
- **TokenEndpoint** 用于服务访问令牌的请求。预设地址：/oauth/token。
             
 &emsp;&emsp;实现OAuth 2.0资源服务器，需要以下过滤器：
             
-  **OAuth2AuthenticationProcessingFilter** 用于加载给定的认证访问令牌请求的认证。

&emsp;&emsp; 源码解析的话，只要理解了下图中所有涉及到的类的作用即出发场景就基本上算是明白了：

![http://ww1.sinaimg.cn/large/005Q13r0gy1g7bi1lotm8j31bo0o014l.jpg](http://ww1.sinaimg.cn/large/005Q13r0gy1g7bi1lotm8j31bo0o014l.jpg)



&emsp;&emsp; 本文介绍  Spring Security Oauth2 源码解析  可以访问代码仓库中的 security 模块 ，项目的github 地址 : https://github.com/BUG9/spring-security 

&emsp;&emsp; &emsp;&emsp; &emsp;&emsp; **如果您对这些感兴趣，欢迎star、follow、收藏、转发给予支持！**
