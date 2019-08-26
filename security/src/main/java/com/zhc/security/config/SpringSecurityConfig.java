package com.zhc.security.config;

import com.zhc.security.authentication.CustomAuthenticationFailureHandler;
import com.zhc.security.authentication.CustomAuthenticationSuccessHandler;
import com.zhc.security.properties.SecurityProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

import javax.annotation.Resource;

/**
 * @author zhc
 * @date 2019/8/14
 */
@Configuration
@EnableWebSecurity
public class SpringSecurityConfig extends WebSecurityConfigurerAdapter {

    @Resource
    private SecurityProperties securityProperties;

    @Resource
    private FormAuthenticationConfig formAuthenticationConfig;

    @Override
    protected void configure(HttpSecurity http) throws Exception {

        formAuthenticationConfig.configure(http);

        http.authorizeRequests()
                .antMatchers("/index", "/", "/loginRequire",
                        securityProperties.getLogin().getLoginPage(),
                        securityProperties.getLogin().getLoginErrorUrl(),
                        securityProperties.getLogin().getLoginSuccessUrl()).permitAll()
                .anyRequest().authenticated()
                .and()
                .csrf().disable();
    }
}
