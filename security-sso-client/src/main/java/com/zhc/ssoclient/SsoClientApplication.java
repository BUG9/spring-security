package com.zhc.ssoclient;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.oauth2.client.EnableOAuth2Sso;

/**
 * @author zhc
 * @date 2019/9/6
 */
@SpringBootApplication
public class SsoClientApplication {
    public static void main(String[] args) {
        SpringApplication.run(SsoClientApplication.class, args);
    }
}
