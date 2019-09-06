package com.zhc.authorization.security;

import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.stereotype.Component;

/**
 * @author zhc
 * @date 2019/8/14
 */
@Component("myUserDetailsService")
public class MyUserDetailsUserService implements UserDetailsService {

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        // 不能直接使用 创建 BCryptPasswordEncoder 对象来加密， 这种加密方式 没有 {bcrypt}  前缀，
        // 会导致在  matches 时导致获取不到加密的算法出现
        // java.lang.IllegalArgumentException: There is no PasswordEncoder mapped for the id "null"  问题
        // 问题原因是 Spring Security5 使用 DelegatingPasswordEncoder(委托)  替代 NoOpPasswordEncoder，
        // 并且 默认使用  BCryptPasswordEncoder 加密（注意 DelegatingPasswordEncoder 委托加密方法BCryptPasswordEncoder  加密前  添加了加密类型的前缀）  https://blog.csdn.net/alinyua/article/details/80219500
        return new User(username,  PasswordEncoderFactories.createDelegatingPasswordEncoder().encode("123456"), AuthorityUtils.commaSeparatedStringToAuthorityList("admin"));
    }
}
