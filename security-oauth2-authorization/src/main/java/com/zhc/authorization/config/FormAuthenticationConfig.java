package com.zhc.authorization.config;

import com.zhc.securitycore.authentication.handler.CustomAuthenticationFailureHandler;
import com.zhc.securitycore.authentication.handler.CustomAuthenticationSuccessHandler;
import com.zhc.securitycore.properties.SecurityProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.stereotype.Component;

import javax.annotation.Resource;

/**
 * @author zhc
 * @date 2019/8/14
 */

@Configuration
public class FormAuthenticationConfig {

    @Resource
    private SecurityProperties securityProperties;

    @Resource
    private CustomAuthenticationSuccessHandler customAuthenticationSuccessHandler;

    @Resource
    private CustomAuthenticationFailureHandler customAuthenticationFailureHandler;

    public void configure(HttpSecurity http) throws Exception {
        http.formLogin()
                //可以设置自定义的登录页面 或者 （登录）接口
                // 注意1： 一般来说设置成登录接口后，该接口会配置成无权限即可访问，所以会走匿名filter, 也就意味着不会走认证过程了，所以我们一般不直接设置成接口地址
                // 注意2： 这里配置的 地址一定要配置成无权限访问，否则将出现 一至重定向问题（因为无权限后又会重定向到这里配置的登录页url）
                .loginPage(securityProperties.getLogin().getLoginPage())
                //.loginPage("/loginRequire")
                // 指定验证凭据的URL（默认为 /login） ,
                // 注意1：这里修改后的 url 会意味着  UsernamePasswordAuthenticationFilter 将 验证此处的 url
                // 注意2： 与 loginPage设置的接口地址是有 区别, 一但 loginPage 设置了的是访问接口url，那么此处配置将无任何意义
                // 注意3： 这里设置的 Url 是有默认无权限访问的
                .loginProcessingUrl(securityProperties.getLogin().getLoginUrl())
                //分别设置成功和失败的处理器
                // 成功处理器重构后可支持
                .successHandler(customAuthenticationSuccessHandler)
                .failureHandler(customAuthenticationFailureHandler);
    }

}

