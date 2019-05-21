package com.cloud.core.shiro;

import java.io.PrintWriter;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;

import org.apache.shiro.web.filter.authc.UserFilter;

import com.google.gson.Gson;

public class ShiroCustomFilter extends UserFilter {
	/**
	 * 所有请求都会经过的方法。
	 */
	@Override
	protected boolean onAccessDenied(ServletRequest request,
			ServletResponse response) throws Exception {

        	if ("XMLHttpRequest"
					.equalsIgnoreCase(((HttpServletRequest) request)
							.getHeader("X-Requested-With"))) {
        		Gson gson = new Gson();
        		response.setCharacterEncoding("UTF-8");
        		response.setContentType("application/json; charset=utf-8");
				PrintWriter out = response.getWriter();
				
				Map<String, String> result = new HashMap<String, String>();
				result.put("code", "300");
				out.println(gson.toJson(result));
				out.flush();
				out.close();
            } else {
            	saveRequestAndRedirectToLogin(request, response);
			}
            return false;
	}
}
