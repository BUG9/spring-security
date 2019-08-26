package com.zhc.security.properties;


import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Configuration
@ConfigurationProperties(prefix = "security")
@Data
public class SecurityProperties {

    private LoginProperties login = new LoginProperties();

}
