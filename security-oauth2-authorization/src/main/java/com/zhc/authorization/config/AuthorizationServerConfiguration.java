package com.zhc.authorization.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.token.AccessTokenConverter;
import org.springframework.security.oauth2.provider.token.TokenEnhancerChain;
import org.springframework.security.oauth2.provider.token.TokenStore;

import javax.annotation.Resource;
import java.util.Map;

/**
 * @author zhc
 * @date 2019/8/30
 * 授权服务配置
 */
@Configuration
@EnableAuthorizationServer
public class AuthorizationServerConfiguration extends AuthorizationServerConfigurerAdapter {

    @Resource
    private AuthenticationManager authenticationManager;

    private final Map<String, TokenStore> tokenStoreMap;

    @Autowired(required = false)
    private AccessTokenConverter jwtAccessTokenConverter;

    /**
     *  由于存储策略时根据配置指定的，当使用redis策略时，tokenEnhancerChain 是没有被注入的，所以这里设置成 required = false
      */
    @Autowired(required = false)
    private TokenEnhancerChain tokenEnhancerChain;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Value("${spring.security.oauth2.storeType}")
    private String storeType = "jwt";

    @Autowired
    public AuthorizationServerConfiguration(Map<String, TokenStore> tokenStoreMap) {
        this.tokenStoreMap = tokenStoreMap;
    }

    @Override
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
        //配置一个客户端，支持客户端模式、密码模式和授权码模式
        clients.inMemory()
                .withClient("client1")
                .authorizedGrantTypes("client_credentials", "password", "authorization_code", "refresh_token")
                .scopes("read")
                .redirectUris("http://localhost:8091/login")
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
