package com.zhc.ssoclient.rest;

import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;


/**
 * @author zhc
 * @date 2019/9/06
 */
@RestController
@Slf4j
public class TestController {

    @GetMapping("/client/{clientId}")
    public String getClient(@PathVariable String clientId) {
        return clientId;
    }

}
