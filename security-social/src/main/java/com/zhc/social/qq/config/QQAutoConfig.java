package com.zhc.social.qq.config;

import com.zhc.social.qq.conect.QQConnectionFactory;
import lombok.Data;
import lombok.EqualsAndHashCode;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.social.config.annotation.ConnectionFactoryConfigurer;
import org.springframework.social.config.annotation.SocialConfigurerAdapter;
import org.springframework.social.connect.ConnectionFactory;


@EqualsAndHashCode(callSuper = true)
@Configuration
@ConditionalOnProperty(prefix = "spring.security.social.qq", name = "app-id")
@Data
public class QQAutoConfig extends SocialConfigurerAdapter {

    /**
     * provider id.
     */
    private String providerId = "qq";

    /**
     * Application id.
     */
    @Value("${spring.security.social.qq.app-id}")
    private String appId;

    /**
     * Application secret.
     */
    @Value("${spring.security.social.qq.app-secret}")
    private String appSecret;

    @Override
    public void addConnectionFactories(ConnectionFactoryConfigurer configurer, Environment environment) {
        configurer.addConnectionFactory(createConnectionFactory());
    }

    /**
     * qq连接工厂
     */
    protected ConnectionFactory<?> createConnectionFactory() {
        return new QQConnectionFactory(
                providerId,
                appId,
                appSecret);
    }
}
