package com.zhc.authorization;

import com.zhc.securitycore.properties.SecurityProperties;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.ComponentScan;

/**
 * @author zhc
 * 授权服务
 * 这里 @ComponentScan(basePackages = "com.zhc") 加载Security-core的配置
 */
@SpringBootApplication
@EnableConfigurationProperties(SecurityProperties.class)
@ComponentScan(basePackages = "com.zhc")
public class AuthorizationApplication {

    public static void main(String[] args) {
        SpringApplication.run(AuthorizationApplication.class, args);
    }

}
