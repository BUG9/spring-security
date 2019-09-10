package com.zhc.securitycore.authentication.handler;


import com.fasterxml.jackson.databind.ObjectMapper;
import com.zhc.securitycore.properties.SecurityProperties;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;


@Component("customAuthenticationFailureHandler")
@Slf4j
public class CustomAuthenticationFailureHandler extends SimpleUrlAuthenticationFailureHandler {

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private SecurityProperties securityProperties;


    private RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();

    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
                                        AuthenticationException exception) throws IOException {

        logger.info("登录失败");
        String header = request.getHeader("Authorization");
        // 是否以Basic开头
        if (header == null || !header.startsWith("Basic ")) {
            if (StringUtils.isEmpty(securityProperties.getLogin().getLoginErrorUrl())) {

                response.setStatus(HttpStatus.INTERNAL_SERVER_ERROR.value());
                response.setContentType("application/json;charset=UTF-8");
                response.getWriter().write(objectMapper.writeValueAsString(exception.getMessage()));

            } else {
                // 跳转设置的登陆失败页面
                redirectStrategy.sendRedirect(request, response, securityProperties.getLogin().getLoginErrorUrl());
            }
        } else {
            response.setContentType("application/json;charset=UTF-8");
            response.getWriter().write("{\"success\":\"false\",\"errMsg\":\"登陆失败，请检查验证码或手机号是否正确\"}");
        }

    }
}
