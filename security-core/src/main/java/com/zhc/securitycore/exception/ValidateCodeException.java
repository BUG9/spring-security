package com.zhc.securitycore.exception;


import org.springframework.security.core.AuthenticationException;

/**
 * 验证码异常
 * <p>
 * 继承身份验证异常的基类
 */
public class ValidateCodeException extends AuthenticationException {

    private static final long serialVersionUID = 1L;

    /**
     * 实现一个父类的构造方法
     *
     * @param msg
     */
    public ValidateCodeException(String msg) {
        super(msg);
    }
}
