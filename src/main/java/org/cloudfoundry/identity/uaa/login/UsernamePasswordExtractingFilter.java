/*
 * Cloud Foundry 2012.02.03 Beta
 * Copyright (c) [2009-2012] VMware, Inc. All Rights Reserved.
 *
 * This product is licensed to you under the Apache License, Version 2.0 (the "License").
 * You may not use this product except in compliance with the License.
 *
 * This product includes a number of subcomponents with
 * separate copyright notices and license terms. Your use of these
 * subcomponents is subject to the terms and conditions of the
 * subcomponent's license, as noted in the LICENSE file.
 */

package org.cloudfoundry.identity.uaa.login;

import java.io.IOException;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

/**
 * Authentication filter translating a generic Authentication into a UsernamePasswordAuthenticationToken.
 * 
 * @author Dave Syer
 * 
 */
public class UsernamePasswordExtractingFilter implements Filter {

	protected final Log logger = LogFactory.getLog(getClass());

	/**
	 * Populates the Spring Security context with a {@link UsernamePasswordAuthenticationToken} referring to the client
	 * that authenticates using the basic authorization header.
	 */
	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException,
			ServletException {
		
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

		if (authentication == null || authentication instanceof UsernamePasswordAuthenticationToken) {
			chain.doFilter(request, response);
			return;
		}
		
		UsernamePasswordAuthenticationToken output = new UsernamePasswordAuthenticationToken(authentication, authentication.getCredentials(), authentication.getAuthorities());
		output.setAuthenticated(false);
		SecurityContextHolder.getContext().setAuthentication(output);

		chain.doFilter(request, response);

	}

	@Override
	public void init(FilterConfig filterConfig) throws ServletException {
	}

	@Override
	public void destroy() {
	}

}
