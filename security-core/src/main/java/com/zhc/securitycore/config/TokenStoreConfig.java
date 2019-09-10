package com.zhc.securitycore.config;

import com.zhc.securitycore.token.JwtTokenEnhance;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.provider.token.TokenEnhancer;
import org.springframework.security.oauth2.provider.token.TokenEnhancerChain;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;
import org.springframework.security.oauth2.provider.token.store.redis.RedisTokenStore;

import javax.annotation.Resource;
import java.util.Arrays;

/**
 * @author zhc
 * @date 2019/9/5
 */
@Configuration
public class TokenStoreConfig {
    /**
     * redis连接工厂
     */
    @Resource
    private RedisConnectionFactory redisConnectionFactory;

    @Value("${spring.security.oauth2.jwt.SigningKey}")
    private String signingKey = "oauth2";

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
     * 使用jwtTokenStore存储token
     * 这里通过 matchIfMissing = true 设置默认使用 jwtTokenStore
     * @return tokenStore
     */
    @Bean
    @ConditionalOnProperty(prefix = "spring.security.oauth2", name = "storeType", havingValue = "jwt", matchIfMissing = true)
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
        accessTokenConverter.setSigningKey(signingKey);
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

