package com.zhc.social.qq.conect;

import com.zhc.social.qq.api.QQ;
import com.zhc.social.qq.api.QQUserInfo;
import org.springframework.social.connect.ApiAdapter;
import org.springframework.social.connect.ConnectionValues;
import org.springframework.social.connect.UserProfile;

/**
 * @author zhc
 * @date 2019/9/10
 */
public class QQAdapter implements ApiAdapter<QQ> {

    /**
     * 判断请求是否成功
     *
     * @param api
     * @return
     */
    @Override
    public boolean test(QQ api) {
        return true;
    }

    /**
     * 将服务提供商提供的用户信息设置到标准的用户信息上
     * @param api
     * @param values
     */
    @Override
    public void setConnectionValues(QQ api, ConnectionValues values) {

        QQUserInfo qqUserInfo = api.getUserInfo();

        // 设置显示用户名
        values.setDisplayName(qqUserInfo.getNickname());
        // 设置头像url
        values.setImageUrl(qqUserInfo.getFigureurl_qq_1());
        // qq没有个人主页，所以设置为空
        values.setProfileUrl(null);
        // 设置服务商的id  openid
        values.setProviderUserId(qqUserInfo.getOpenId());

    }

    @Override
    public UserProfile fetchUserProfile(QQ api) {
        return null;
    }

    @Override
    public void updateStatus(QQ api, String message) {

    }
}
