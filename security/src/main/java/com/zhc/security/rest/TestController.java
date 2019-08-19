package com.zhc.security.rest;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

/**
 * @author zhc
 * @date 2019/8/14
 */
@RestController
@EnableGlobalMethodSecurity(prePostEnabled =true)
public class TestController {

    @PreAuthorize("hasRole('user')")
    @GetMapping("/get_user/{username}")
    public String getUser(@PathVariable  String username){
        return username;
    }
}
