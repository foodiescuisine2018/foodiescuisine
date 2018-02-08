package com.foodies.web.configuration;

import java.util.Arrays;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import static com.foodies.common.lookup.Permission.ADMIN;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.security.web.csrf.HttpSessionCsrfTokenRepository;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

@Configuration
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

	@Override
	public void configure(WebSecurity web) throws Exception {
		web.ignoring().antMatchers("/static/**", "*.png", "/**/*.css");
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http
		.httpBasic().and()
		.authorizeRequests()
		.antMatchers("/*.*").permitAll()
		.antMatchers("/admin*").hasRole(ADMIN.name()).and()
		.cors().and()
		.csrf()
			.csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse());
	}

	private CsrfTokenRepository csrfTokenRepository() {
		return new HttpSessionCookieCsrfTokenRepository();
	}

	@Bean
	CorsConfigurationSource corsConfigurationSource() {
		CorsConfiguration configuration = new CorsConfiguration();
		configuration.setAllowedOrigins(Arrays.asList("https://localhost:4300"));
		configuration.setAllowedMethods(Arrays.asList("GET","POST"));
		UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
		source.registerCorsConfiguration("/**", configuration);
		return source;
	}
	
	private class HttpSessionCookieCsrfTokenRepository implements CsrfTokenRepository {

		static final String XSRF_COOKIE_NAME = "XSRF-TOKEN";

		static final String XSRF_HEADER_NAME = "X-XSRF-TOKEN";

		private final HttpSessionCsrfTokenRepository mHttpSessionCsrfTokenRepository = new HttpSessionCsrfTokenRepository();

		public HttpSessionCookieCsrfTokenRepository() {
			mHttpSessionCsrfTokenRepository.setHeaderName(XSRF_HEADER_NAME);
		}

		@Override
		public CsrfToken generateToken(HttpServletRequest request) {
			return mHttpSessionCsrfTokenRepository.generateToken(request);
		}

		@Override
		public void saveToken(CsrfToken token, HttpServletRequest request, HttpServletResponse response) {
			mHttpSessionCsrfTokenRepository.saveToken(token, request, response);

			String tokenValue = token == null ? "" : token.getToken();
			Cookie cookie = new Cookie(XSRF_COOKIE_NAME, tokenValue);
			cookie.setSecure(request.isSecure());
			cookie.setPath("/");
			int expiry = (token == null) ? 0 : -1;
			cookie.setMaxAge(expiry);
			if ("/admin/login".equals(request.getPathInfo()) && (token == null)) {
				return;
			}

			response.addCookie(cookie);
		}

		@Override
		public CsrfToken loadToken(HttpServletRequest request) {
			return mHttpSessionCsrfTokenRepository.loadToken(request);
		}

	}
}
