package com.zhc.authentication.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configurers.ResourceServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.token.TokenStore;

import java.util.Map;

/**
 * @author zhc
 * @date 2019/8/30
 * 资源服务配置
 */
@Configuration
@EnableResourceServer
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
        resources.tokenStore(tokenStoreMap.get(storeType + "TokenStore"));
    }

    @Override
    public void configure(HttpSecurity http) throws Exception {
        http
                .requestMatchers().anyRequest()
                .and()
                .anonymous()
                .and()
                .authorizeRequests()
                //配置oauth2访问控制，必须认证过后才可以访问
                .antMatchers("/oauth2/**").authenticated();
    }
}
