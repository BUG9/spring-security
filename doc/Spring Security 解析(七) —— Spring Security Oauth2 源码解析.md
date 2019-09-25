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
  
 ### 四  TokenEndpoint 解析
 
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

&emsp;&emsp; 官方默认调用 **CompositeTokenGranter** 的 grant()方法，从源码中我们可以看到其聚合了 TokenGranter ，采用遍历的方式一个一个的去尝试，由于Oauth2 有4种模式外加token刷新，所以 官方目前有5个子类，分别是： AuthorizationCodeTokenGranter、ClientCredentialsTokenGranter、ImplicitTokenGranter、RefreshTokenGranter、ResourceOwnerPasswordTokenGranter ，以及一个他们共同实现的 AbstractTokenGranter。
其中除了 ClientCredentialsTokenGranter 重写了 AbstractTokenGranter.grant() 方法以外，其他4中都是直接调用   AbstractTokenGranter.grant()   进行处理。 物品们来看下 AbstractTokenGranter.grant()  其方法内部实现：

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

OAuth2Authentication 对象生成后会调用 tokenServices.createAccessToken()，我们来看下 官方默认提供 的 DefaultTokenServices 的 createAccessToken 方法内部实现源码：

   ```
    @Transactional
	public OAuth2AccessToken createAccessToken(OAuth2Authentication authentication) throws AuthenticationException {

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
				// Re-store the access token in case the authentication has changed
				tokenStore.storeAccessToken(existingAccessToken, authentication);
				return existingAccessToken;
			}
		}

		// Only create a new refresh token if there wasn't an existing one
		// associated with an expired access token.
		// Clients might be holding existing refresh tokens, so we re-use it in
		// the case that the old access token
		// expired.
		if (refreshToken == null) {
			refreshToken = createRefreshToken(authentication);
		}
		// But the refresh token itself might need to be re-issued if it has
		// expired.
		else if (refreshToken instanceof ExpiringOAuth2RefreshToken) {
			ExpiringOAuth2RefreshToken expiring = (ExpiringOAuth2RefreshToken) refreshToken;
			if (System.currentTimeMillis() > expiring.getExpiration().getTime()) {
				refreshToken = createRefreshToken(authentication);
			}
		}

		OAuth2AccessToken accessToken = createAccessToken(authentication, refreshToken);
		tokenStore.storeAccessToken(accessToken, authentication);
		// In case it was modified
		refreshToken = accessToken.getRefreshToken();
		if (refreshToken != null) {
			tokenStore.storeRefreshToken(refreshToken, authentication);
		}
		return accessToken;

	}
	
   ```




   
 













  




















