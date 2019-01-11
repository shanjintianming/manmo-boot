package com.interview.core.shiro;

import java.util.LinkedHashMap;
import java.util.Map;

import javax.servlet.Filter;

import org.apache.shiro.codec.Base64;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.spring.web.ShiroFilterFactoryBean;
import org.apache.shiro.web.mgt.CookieRememberMeManager;
import org.apache.shiro.web.mgt.DefaultWebSecurityManager;
import org.apache.shiro.web.servlet.SimpleCookie;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class ShiroConfiguration {
	@Bean
	public ShiroFilterFactoryBean shirFilter(org.apache.shiro.mgt.SecurityManager securityManager) {
		ShiroFilterFactoryBean shiroFilterFactoryBean = new ShiroFilterFactoryBean();

		// 必须设置 SecurityManager
		shiroFilterFactoryBean.setSecurityManager(securityManager);

		// setLoginUrl 如果不设置值，默认会自动寻找Web工程根目录下的"/login.jsp"页面 或 "/login" 映射
		shiroFilterFactoryBean.setLoginUrl("/login");
		
		// 设置无权限时跳转的 url;
		shiroFilterFactoryBean.setUnauthorizedUrl("/notRole");

		Map<String, Filter> filterMap = shiroFilterFactoryBean.getFilters();
		filterMap.put("perms", new ShiroCustomFilter());
		
		// 设置拦截器
		Map<String, String> filterChainDefinitionMap = new LinkedHashMap<>();
		// 静态资源，开发权限
		filterChainDefinitionMap.put("/static/**", "anon");
		// 游客，开发权限
		filterChainDefinitionMap.put("/resume/add", "anon");
		filterChainDefinitionMap.put("/resume/login", "anon");
		filterChainDefinitionMap.put("/resume/WXACode", "anon");
		filterChainDefinitionMap.put("/add", "anon");
		
//		// 用户，需要角色权限 “user”
//		filterChainDefinitionMap.put("/user/**", "roles[user]");
//		// 管理员，需要角色权限 “admin”
//		filterChainDefinitionMap.put("/admin/**", "roles[admin]");
		// 开放登陆接口
		filterChainDefinitionMap.put("/login", "anon");
		filterChainDefinitionMap.put("/logout", "logout");
		// 其余接口一律拦截
		// 主要这行代码必须放在所有权限设置的最后，不然会导致所有 url 都被拦截
		// filterChainDefinitionMap.put("/**", "authc");
		filterChainDefinitionMap.put("/**", "perms");

		shiroFilterFactoryBean.setFilterChainDefinitionMap(filterChainDefinitionMap);
		return shiroFilterFactoryBean;
	}

	/**
	 * 注入 securityManager
	 */
	@Bean
	public SecurityManager securityManager() {
		DefaultWebSecurityManager securityManager = new DefaultWebSecurityManager();
		// 设置realm.
		securityManager.setRealm(customRealm());

		// 注入记住我管理器
		securityManager.setRememberMeManager(rememberMeManager());
		return securityManager;
	}

	/**
	 * 自定义身份认证 realm;
	 * <p>
	 * 必须写这个类，并加上 @Bean 注解，目的是注入 CustomRealm， 否则会影响 CustomRealm类 中其他类的依赖注入
	 */
	@Bean
	public CustomRealm customRealm() {
		return new CustomRealm();
	}

	@Bean
	public SimpleCookie rememberMeCookie() {
		// System.out.println("ShiroConfiguration.rememberMeCookie()");
		// 这个参数是cookie的名称，对应前端的checkbox的name = rememberMe
		SimpleCookie simpleCookie = new SimpleCookie("rememberMe");
		// <!-- 记住我cookie生效时间30天 ,单位秒;-->
		simpleCookie.setMaxAge(259200);
		return simpleCookie;
	}

	@Bean
	public CookieRememberMeManager rememberMeManager() {
		// System.out.println("ShiroConfiguration.rememberMeManager()");
		CookieRememberMeManager cookieRememberMeManager = new CookieRememberMeManager();
		cookieRememberMeManager.setCookie(rememberMeCookie());
		// rememberMe cookie加密的密钥 建议每个项目都不一样 默认AES算法 密钥长度(128 256 512 位)
		cookieRememberMeManager.setCipherKey(Base64.decode("2AvVhdsgUs0FSA3SDFAdag=="));
		return cookieRememberMeManager;
	}
}