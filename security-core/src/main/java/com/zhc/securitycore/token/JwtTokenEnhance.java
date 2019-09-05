package com.zhc.securitycore.token;

import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.TokenEnhancer;

import java.util.HashMap;
import java.util.Map;

/**
 * @author zhc
 * @date 2019/9/5
 */
public class JwtTokenEnhance implements TokenEnhancer {
    @Override
    public OAuth2AccessToken enhance(OAuth2AccessToken accessToken, OAuth2Authentication authentication) {
        Map<String, Object> tokenInfo = new HashMap<>(16);
        //扩展返回的token 信息
        tokenInfo.put("username", authentication.getName());
        ((DefaultOAuth2AccessToken) accessToken).setAdditionalInformation(tokenInfo);
        return accessToken;
    }
}
