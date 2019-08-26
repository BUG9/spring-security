package com.zhc.security.properties;

import lombok.Data;

@Data
public class LoginProperties {
    /**
     * 登录页
     */
    private String loginPage = "/loginUp.html";

    /**
     * 登录成功跳转Url
     */
    private String loginSuccessUrl = "/loginSuccess.html";


    /**
     * 登录失败跳转Url
     */
    private String loginErrorUrl = "/loginError.html";
}
