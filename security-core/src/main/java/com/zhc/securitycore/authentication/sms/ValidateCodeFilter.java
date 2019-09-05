package com.zhc.securitycore.authentication.sms;


import com.zhc.securitycore.exception.ValidateCodeException;
import com.zhc.securitycore.properties.SecurityConstants;
import com.zhc.securitycore.properties.SecurityProperties;
import org.apache.commons.lang.StringUtils;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.annotation.Resource;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

/**
 * 验证码过滤器
 */
@Component
public class ValidateCodeFilter extends OncePerRequestFilter implements InitializingBean {

    /**
     * 验证码校验失败处理器
     */
    @Autowired
    private AuthenticationFailureHandler authenticationFailureHandler;
    /**
     * 系统配置信息
     */
    @Autowired
    private SecurityProperties securityProperties;

    @Resource
    private StringRedisTemplate stringRedisTemplate;


    /**
     * 存放所有需要校验验证码的url
     */
    private Map<String, String> urlMap = new HashMap<>();
    /**
     * 验证请求url与配置的url是否匹配的工具类
     */
    private AntPathMatcher pathMatcher = new AntPathMatcher();

    /**
     * 初始化要拦截的url配置信息
     */
    @Override
    public void afterPropertiesSet() throws ServletException {
        super.afterPropertiesSet();

        urlMap.put(SecurityConstants.DEFAULT_LOGIN_PROCESSING_URL_MOBILE, SecurityConstants.DEFAULT_PARAMETER_NAME_CODE_SMS);
        addUrlToMap(securityProperties.getSms().getSendSmsUrl(), SecurityConstants.DEFAULT_PARAMETER_NAME_CODE_SMS);
    }

    /**
     * 讲系统中配置的需要校验验证码的URL根据校验的类型放入map
     *
     * @param urlString
     * @param smsParam
     */
    protected void addUrlToMap(String urlString, String smsParam) {
        if (StringUtils.isNotBlank(urlString)) {
            String[] urls = StringUtils.splitByWholeSeparatorPreserveAllTokens(urlString, ",");
            for (String url : urls) {
                urlMap.put(url, smsParam);
            }
        }
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {

        String code = request.getParameter(getValidateCode(request));
        if (code != null) {
            try {
                String oldCode = stringRedisTemplate.opsForValue().get(request.getParameter(SecurityConstants.DEFAULT_PARAMETER_NAME_MOBILE));
                if (StringUtils.equalsIgnoreCase(oldCode,code)) {
                    logger.info("验证码校验通过");
                } else {
                    throw new ValidateCodeException("验证码失效或错误！");
                }
            } catch (AuthenticationException e) {
                authenticationFailureHandler.onAuthenticationFailure(request, response, e);
                return;
            }
        }
        chain.doFilter(request, response);
    }

    /**
     * 获取校验码
     *
     * @param request
     * @return
     */
    private String getValidateCode(HttpServletRequest request) {
        String result = null;
        if (!StringUtils.equalsIgnoreCase(request.getMethod(), "get")) {
            Set<String> urls = urlMap.keySet();
            for (String url : urls) {
                if (pathMatcher.match(url, request.getRequestURI())) {
                    result = urlMap.get(url);
                }
            }
        }
        return result;
    }

}
