package com.interview.core.shiro;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AccountException;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.mindrot.jbcrypt.BCrypt;
import org.springframework.beans.factory.annotation.Autowired;

import com.interview.user.entity.User;
import com.interview.user.service.UserService;

public class CustomRealm extends AuthorizingRealm {

	@Autowired
	private UserService userService;

	@Override
	protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection arg0) {
		String username = (String) SecurityUtils.getSubject().getPrincipal();
		SimpleAuthorizationInfo info = new SimpleAuthorizationInfo();

		// 获得该用户角色
		List<String> roleLst = userService.selectRolesByUser(username);

		Set<String> set = new HashSet<>();
		// 需要将 role 封装到 Set 作为 info.setRoles() 的参数
		set.addAll(roleLst);
		// 设置该用户拥有的角色
		info.setRoles(set);
		return info;
	}

	@Override
	protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken authenticationToken)
			throws AuthenticationException {
		UsernamePasswordToken token = (UsernamePasswordToken) authenticationToken;

		User user = new User();
		user.setUserName(token.getUsername());

		// 获得该用户角色
		User loginUser = userService.login(user);

		if (null == loginUser) {
			throw new AccountException("用户名不正确");
			
		} else if (!BCrypt.checkpw(new String((char[]) token.getCredentials()), loginUser.getPassword())) {
			throw new AccountException("密码不正确");
		}
		return new SimpleAuthenticationInfo(token.getPrincipal(), new String((char[]) token.getCredentials()), getName());
	}

}
