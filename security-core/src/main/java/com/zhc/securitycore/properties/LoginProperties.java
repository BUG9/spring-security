package com.zhc.securitycore.properties;

import lombok.Data;

/**
 * @author zhc
 * @date 2019/8/14
 */
@Data
public class LoginProperties {
    /**
     * 登录页
     */
    private String loginPage = "/loginUp.html";

    /**
     * 登录接口，即UsernamePasswordAuthenticationFilter 需要匹配的的地址（security默认是/login）
     */
    private String LoginUrl = "/loginUp";

    /**
     * 登录成功跳转Url
     * 注意这里 loginSuccessUrl 不能 为 null 或者 空字符串
     * 为什么呢？ 因为我们在  security的 antMatchers设置无权限访问配置时读取了这个属性值，
     * 如果没有设置默认值，会导致系统报异常
     */
    private String loginSuccessUrl = "/loginSuccess.html";

    /**
     *  记住我有效时间，默认 3600 （ms）
     */
    private int rememberMeSeconds = 3600;

    /**
     * 登录失败跳转Url
     */
    private String loginErrorUrl = "/loginError.html";
}
