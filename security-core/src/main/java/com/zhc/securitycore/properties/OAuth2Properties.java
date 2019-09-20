package com.zhc.securitycore.properties;



import lombok.Data;
import lombok.EqualsAndHashCode;
import org.springframework.boot.autoconfigure.security.oauth2.client.OAuth2ClientProperties;
/**
 * @author zhc
 * @date 2019/9/12
 * oauth2配置
 */
@Data
@EqualsAndHashCode
public class OAuth2Properties {

    /**
     * 客户端配置
     */
    private OAuth2ClientProperties[] clients = {};

    /**
     * jwt的签名
     */
    private String jwtSigningKey = "oauth2";

    /**
     * socialFilter 拦截地址
     */
    private String filterProcessesUrl = "/login";
}