package com.zhc.securitycore.properties;


import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

/**
 * @author zhc
 * @date 2019/8/14
 */

@Configuration
@ConfigurationProperties(prefix = "authorization")
@Data
public class SecurityProperties {

    private LoginProperties login = new LoginProperties();

    private SmsProperties sms = new SmsProperties();

    private OAuth2Properties oauth2 = new OAuth2Properties();

}
