package com.cos.jwt.config.jwt;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import lombok.RequiredArgsConstructor;

//스프링 시큐리티에서 UsernamePasswordAuthenticationFilter가 있음
// /login 요청해서 username, password 전송하면(post로)
// UsernamePasswordAuthenticationFilter가 동작함
// 지금 동작 안하는 이유는 formLogin을 disable해버렸기때문
// 이 필터를 security에 등록시켜줘야한다.

@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter{
	
	private final AuthenticationManager authenticationManager;
	
	// /login 요청을 하면 로그인 시도를 위해 실행되는 함수
	@Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
			throws AuthenticationException {
		System.out.println("JwtAuthenticationFilter : 로그인 시도중");
		
		// 1.username, password 받아서
		// 2.정상인지 로그인 시도를 해봄 authenticationManager로 로그인 시도를 하면
		// principalDetailService가 호출, loadByUswername()함수 실행됨.
		
		// 3. PrincipalDetails를 세션에 담고 -> 세션에 안담으면 권한 관리가 안됨(권한 관리 안할거면 안만들어도됨)
		
		// 4. JWT 토큰을 만들어서 응답
		return super.attemptAuthentication(request, response);
	}
	
}
