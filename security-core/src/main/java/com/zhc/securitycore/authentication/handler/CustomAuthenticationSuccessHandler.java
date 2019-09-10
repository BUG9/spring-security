package com.zhc.securitycore.authentication.handler;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.zhc.securitycore.properties.SecurityProperties;
import com.zhc.securitycore.utils.SpringContextUtil;
import lombok.Builder;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.collections.MapUtils;
import org.apache.commons.lang.StringUtils;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.codec.Base64;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.exceptions.UnapprovedClientAuthenticationException;
import org.springframework.security.oauth2.provider.*;
import org.springframework.security.oauth2.provider.token.AuthorizationServerTokenServices;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.stereotype.Component;

import javax.annotation.Resource;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Component("customAuthenticationSuccessHandler")
@Slf4j
public class CustomAuthenticationSuccessHandler extends SavedRequestAwareAuthenticationSuccessHandler {

    @Resource
    private SecurityProperties securityProperties;

    @Resource
    private ObjectMapper objectMapper;

    @Resource
    private PasswordEncoder passwordEncoder;

    private ClientDetailsService clientDetailsService = null;

    private AuthorizationServerTokenServices authorizationServerTokenServices = null;

    private RequestCache requestCache = new HttpSessionRequestCache();

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws IOException, ServletException {
        logger.info("登录成功");
        // 重构后使得成功处理器能够根据不同的请求来区别是返回token还是调用原来的逻辑（比如授权模式就需要跳转）
        // 获取请求头中的Authorization

        String header = request.getHeader("Authorization");
        // 是否以Basic开头
        if (header == null || !header.startsWith("Basic ")) {
            // 为了授权码模式 登陆正常跳转，这里就不再跳转到自定义的登陆成功页面了
//            // 如果设置了loginSuccessUrl，总是跳到设置的地址上
//            // 如果没设置，则尝试跳转到登录之前访问的地址上，如果登录前访问地址为空，则跳到网站根路径上
//            if (!StringUtils.isEmpty(securityProperties.getLogin().getLoginSuccessUrl())) {
//                requestCache.removeRequest(request, response);
//                setAlwaysUseDefaultTargetUrl(true);
//                setDefaultTargetUrl(securityProperties.getLogin().getLoginSuccessUrl());
//            }
            super.onAuthenticationSuccess(request, response, authentication);
        } else {

            // 这里为什么要通过 SpringContextUtil 获取bean，
            // 主要原因是如果直接在 依赖注入 会导致 AuthorizationServerConfiguration 和 SpringSecurityConfig 配置加载顺序混乱
            // 最直接的表现在 AuthorizationServerConfiguration 中 authenticationManager 获取到 为null，因为这个时候 SpringSecurityConfig 还没加载创建
            // 这里采用这种方式会有一定的性能问题，但也是无赖之举  有兴趣的同学可以看下： https://blog.csdn.net/qq_36732557/article/details/80338570 和 https://blog.csdn.net/forezp/article/details/84313907
            if (clientDetailsService == null && authorizationServerTokenServices == null) {
                clientDetailsService = SpringContextUtil.getBean(ClientDetailsService.class);
                authorizationServerTokenServices = SpringContextUtil.getBean(AuthorizationServerTokenServices.class);
            }

            String[] tokens = extractAndDecodeHeader(header, request);
            assert tokens.length == 2;

            String clientId = tokens[0];

            String clientSecret = tokens[1];

            ClientDetails clientDetails = clientDetailsService.loadClientByClientId(clientId);

            if (clientDetails == null) {
                throw new UnapprovedClientAuthenticationException("clientId对应的配置信息不存在:" + clientId);
            } else if (!passwordEncoder.matches(clientSecret, clientDetails.getClientSecret())) {
                throw new UnapprovedClientAuthenticationException("clientSecret不匹配:" + clientId);
            }

            TokenRequest tokenRequest = new TokenRequest(MapUtils.EMPTY_MAP,
                    clientId,
                    clientDetails.getScope(),
                    "custom");

            OAuth2Request oAuth2Request = tokenRequest.createOAuth2Request(clientDetails);

            OAuth2Authentication oAuth2Authentication = new OAuth2Authentication(oAuth2Request,
                    authentication);

            OAuth2AccessToken token = authorizationServerTokenServices.createAccessToken(oAuth2Authentication);

            response.setContentType("application/json;charset=UTF-8");
            response.getWriter().write(objectMapper.writeValueAsString(token));
        }

    }

    /**
     * 解析请求头拿到clientid  client secret的数组
     *
     * @param header
     * @param request
     * @return
     * @throws IOException
     */
    private String[] extractAndDecodeHeader(String header, HttpServletRequest request) throws IOException {

        byte[] base64Token = header.substring(6).getBytes("UTF-8");
        byte[] decoded;
        try {
            decoded = Base64.decode(base64Token);
        } catch (IllegalArgumentException e) {
            throw new BadCredentialsException("Failed to decode basic authentication token");
        }

        String token = new String(decoded, "UTF-8");

        int delim = token.indexOf(":");

        if (delim == -1) {
            throw new BadCredentialsException("Invalid basic authentication token");
        }
        return new String[]{token.substring(0, delim), token.substring(delim + 1)};
    }

}
