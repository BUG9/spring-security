package com.zhc.security.rest;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

/**
 * @author zhc
 * @date 2019/8/14
 */
@RestController
public class TestController {

    @GetMapping("/get_user/{username}")
    public String getUser(@PathVariable  String username){
        return username;
    }
}
