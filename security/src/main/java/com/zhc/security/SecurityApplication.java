package com.zhc.security;

import com.zhc.securitycore.properties.SecurityProperties;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.ComponentScan;

/**
 * @author zhc
 */
@SpringBootApplication
@EnableConfigurationProperties(SecurityProperties.class)
@ComponentScan(basePackages = "com.zhc")  // 用于加载其他模块
public class SecurityApplication {

    public static void main(String[] args) {
        SpringApplication.run(SecurityApplication.class, args);
    }

}
