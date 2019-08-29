package com.zhc.security.properties;

public interface SecurityConstants {

    /**
     * 默认登录页面
     */
    String DEFAULT_LOGIN_PAGE_URL = "/loginUp.html";

    /**
     * 默认系统首页url
     */
    String DEFAULT_PAGE_URL = "/";

    /**
     * 默认的用户名密码登录请求处理url
     */
    String DEFAULT_LOGIN_PROCESSING_URL_FORM = "/loginUp";

    /**
     * 发送短信验证码 或 验证短信验证码时，传递手机号的参数的名称
     */
    String DEFAULT_PARAMETER_NAME_MOBILE = "mobile";

    /**
     * 默认的手机验证码登录请求处理url
     */
    String DEFAULT_LOGIN_PROCESSING_URL_MOBILE = "/loginByMobile";

}
