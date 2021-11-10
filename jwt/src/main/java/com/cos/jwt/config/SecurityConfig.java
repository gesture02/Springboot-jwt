package com.cos.jwt.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.context.SecurityContextPersistenceFilter;
import org.springframework.web.filter.CorsFilter;

import com.cos.jwt.config.jwt.JwtAuthenticationFilter;
import com.cos.jwt.filter.MyFilter1;
import com.cos.jwt.filter.MyFilter3;

import lombok.RequiredArgsConstructor;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig extends WebSecurityConfigurerAdapter{
	
	private final CorsFilter corsFilter;
	
	//jwt세팅
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		////이 필터가 먼저 실행된다. (시큐리티 필터가 우선)
		////security filter chain이 내가 만든 필터보다 먼저 동작한다.
		////security보다 먼저 동작하게 하고싶으면 before를 걸어야함->securityContextPersistenceFilter가 가장위이므로 가장먼저 동작하게 하고싶으면 그거이전에 실행하도록하면됨
		//http.addFilterBefore(new MyFilter3(), SecurityContextPersistenceFilter.class);
		
		http.csrf().disable();
		//세션 안씀
		http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
		.and()
		
		.addFilter(corsFilter)//cors 정책에서 벗어날 수 있음 : cross origin 요청이 와도 다 허용됨
		//RestApiController에 @CrossOrigin(인증 없을때), 필터에 등록해줘야함(인증 있을때)
		
		.formLogin().disable()//form태그 만들어서 로그인 하는거 안씀
		
		.httpBasic().disable()//기본적인 http로그인 방식 안씀 // header에 authorization에 id, pw를 담고가는것->암호화x -> https를 써야함
		//대신 authorization영역에 토큰을 실어보내는 방식 사용
		//(id, pw를 통해 토큰을 만듬-> 토큰으로 요청-> Bearer방식 
		.addFilter(new JwtAuthenticationFilter(authenticationManager()))//파라미터 : AuthenticationManager
		.authorizeRequests()
		.antMatchers("/api/v1/user/**")
		.access("hasRole('ROLE_USER') or hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
		.antMatchers("/api/v1/manager/**")
		.access("hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
		.antMatchers("/api/v1/admin/**")
		.access("hasRole('ROLE_ADMIN')")
		.anyRequest().permitAll();
	}
}
