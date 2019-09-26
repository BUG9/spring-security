package com.zhc.securitycore.properties;

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
     * 验证短信验证码时，http请求中默认的携带短信验证码信息的参数的名称
     */
    String DEFAULT_PARAMETER_NAME_CODE_SMS = "smsCode";

    /**
     * 默认的手机验证码登录请求处理url
     */
    String DEFAULT_LOGIN_PROCESSING_URL_MOBILE = "/loginByMobile";

    /**
     * 默认的集成第三方登陆请求处理url
     */
    String DEFAULT_INTEGRATION_PROCESSING_URL = "/integrationLogin/**";

}
