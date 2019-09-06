package com.zhc.authentication.rest;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
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
@EnableGlobalMethodSecurity(prePostEnabled = true)
@Slf4j
public class TestEndpoints {

    @GetMapping("/getUser")
    @PreAuthorize("hasAnyAuthority('admin')")
    public String getUser() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        return "User: " + authentication.getPrincipal().toString();
    }
}
