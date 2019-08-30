package com.zhc.securityoauth2.rest;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * @author zhc
 * @date 2019/8/30
 */
@RestController
@RequestMapping("/oauth2")
@Slf4j
public class TestEndpoints {

    @GetMapping("/getUser")
    public String getUser() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        return "User: " + authentication.getPrincipal().toString();
    }
}
