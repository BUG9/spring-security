package com.zhc.authorization.config;

import com.zhc.securitycore.authentication.sms.SmsCodeAuthenticationSecurityConfig;
import com.zhc.securitycore.authentication.sms.ValidateCodeFilter;
import com.zhc.securitycore.properties.SecurityConstants;
import com.zhc.securitycore.properties.SecurityProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.SecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;
import org.springframework.security.web.authentication.rememberme.JdbcTokenRepositoryImpl;
import org.springframework.security.web.authentication.rememberme.PersistentTokenRepository;
import org.springframework.social.security.SpringSocialConfigurer;

import javax.annotation.Resource;
import javax.sql.DataSource;

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

    @Resource
    private DataSource dataSource;

    @Resource
    private UserDetailsService userDetailsService;

    @Resource
    private ValidateCodeFilter validateCodeFilter;

    @Resource
    private SmsCodeAuthenticationSecurityConfig smsCodeAuthenticationSecurityConfig;

    @Resource
    private SpringSocialConfigurer  securitySpringSocialConfigurer;


    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    @Bean
    public PersistentTokenRepository persistentTokenRepository() {
        JdbcTokenRepositoryImpl tokenRepository = new JdbcTokenRepositoryImpl();
        tokenRepository.setDataSource(dataSource);
        // 如果token表不存在，使用下面语句可以初始化 persistent_logins（ddl在db目录下） 表；若存在，请注释掉这条语句，否则会报错。
        //tokenRepository.setCreateTableOnStartup(true);
        return tokenRepository;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {

        formAuthenticationConfig.configure(http);

        http.addFilterBefore(validateCodeFilter, AbstractPreAuthenticatedProcessingFilter.class)
                .apply(smsCodeAuthenticationSecurityConfig)
                .and()
                // social 社交登陆配置引入
                .apply(securitySpringSocialConfigurer)
                .and()
                .authorizeRequests()
                .antMatchers(SecurityConstants.DEFAULT_PAGE_URL,
                        SecurityConstants.DEFAULT_LOGIN_PAGE_URL,
                        "/send/sms/**","/oauth/**","/socialRegister",
                        securityProperties.getLogin().getLoginErrorUrl()).permitAll()
                .anyRequest().authenticated()
                .and()
                // 开启 记住我功能，意味着 RememberMeAuthenticationFilter 将会 从Cookie 中获取token信息
                .rememberMe()
                // 设置 tokenRepository ，这里默认使用 jdbcTokenRepositoryImpl，意味着我们将从数据库中读取token所代表的用户信息
                .tokenRepository(persistentTokenRepository())
                // 设置  userDetailsService , 和 认证过程的一样，RememberMe 有专门的 RememberMeAuthenticationProvider ,也就意味着需要 使用UserDetailsService 加载 UserDetails 信息
                .userDetailsService(userDetailsService)
                // 设置 rememberMe 的有效时间，这里通过 配置来设置
                .tokenValiditySeconds(securityProperties.getLogin().getRememberMeSeconds())
                .and()
                .csrf().disable();
    }
}
