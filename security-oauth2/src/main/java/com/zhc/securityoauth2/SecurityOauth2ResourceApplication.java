package com.zhc.securityoauth2;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.ComponentScan;

/**
 * @author zhc
 */
@SpringBootApplication
@ComponentScan(basePackages = "com.zhc")
public class SecurityOauth2ResourceApplication {

    public static void main(String[] args) {
        SpringApplication.run(SecurityOauth2ResourceApplication.class, args);
    }

}
