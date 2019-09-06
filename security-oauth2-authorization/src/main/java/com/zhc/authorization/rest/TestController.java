package com.zhc.authorization.rest;

import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang.RandomStringUtils;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

import javax.annotation.Resource;
import java.util.concurrent.TimeUnit;

/**
 * @author zhc
 * @date 2019/8/14
 */
@RestController
@EnableGlobalMethodSecurity(prePostEnabled = true)
@Slf4j
public class TestController {

    @Resource
    private StringRedisTemplate stringRedisTemplate;

    @PreAuthorize("hasAnyAuthority('user')")
    @GetMapping("/get_user/{username}")
    public String getUser(@PathVariable String username) {
        return username;
    }

    @GetMapping("/send/sms/{mobile}")
    public void sendSms(@PathVariable String mobile) {
        // 随机生成 6 位的数字串
        String code = RandomStringUtils.randomNumeric(6);
        stringRedisTemplate.opsForValue().set(mobile, code, 60 * 5, TimeUnit.SECONDS);
        // 模拟发送短信验证码
        log.info("向手机： " + mobile + " 发送短信验证码是： " + code);
    }

    @GetMapping("/loginRequire")
    public String loginRequire() {
        return "自定义登录接口，也就意味着不走认证过程了";
    }
}
