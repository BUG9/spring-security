package com.zhc.securitycore.authentication.integration;


import com.zhc.securitycore.authentication.integration.provider.IntegrationAuthenticationProvider;
import com.zhc.securitycore.properties.SecurityConstants;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.stereotype.Component;

import javax.annotation.Resource;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Map;

/**
 * @author zhc
 * @date 2019/9/26
 */
@EqualsAndHashCode(callSuper = true)
@Data
@Slf4j
@Component
public class IntegrationAuthenticationProcessingFilter extends AbstractAuthenticationProcessingFilter {

    @Resource
    private Map<String,IntegrationAuthenticationProvider> providerMap;

    public IntegrationAuthenticationProcessingFilter() {
        super(new AntPathRequestMatcher(SecurityConstants.DEFAULT_INTEGRATION_PROCESSING_URL, "GET"));
    }

    protected IntegrationAuthenticationProcessingFilter(String defaultFilterProcessesUrl) {
        super(defaultFilterProcessesUrl);
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException, IOException, ServletException {

        return null;
    }
}
