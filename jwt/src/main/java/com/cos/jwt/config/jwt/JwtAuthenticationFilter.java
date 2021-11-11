package com.cos.jwt.config.jwt;

import java.io.IOException;
import java.util.Date;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.cos.jwt.config.auth.PrincipalDetails;
import com.cos.jwt.model.User;
import com.fasterxml.jackson.databind.ObjectMapper;

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
		
		try {
//			BufferedReader br = request.getReader();
//			
//			String input = null;
//			while((input = br.readLine()) != null) {
//				System.out.println(input);
//			}
			
			ObjectMapper om = new ObjectMapper();
			User user = om.readValue(request.getInputStream(), User.class);
			
			System.out.println(user);
			
			UsernamePasswordAuthenticationToken authenticationToken =
					new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword());
			
			//PrincipalDetailsService의 loadUserByUsername()실행된 후 정상이면 authenticaiton이 리턴됨
			// 1. DB에 있는 username과 password가 일치함
			Authentication authentication = 
					authenticationManager.authenticate(authenticationToken);
			
			
			PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();
			System.out.println("로그인 완료됨 : " + principalDetails.getUser().getUsername());// 2. 이게 출력되면 로그인 정상적으로 되었다는 뜻
			
			//3. Authentication 객체가 session영역에 저장을 해야하고 그방법은 return해주면됨
			//리턴의 이유는 권한 관리를 security가 대신 해주기 때문에 편하려고
			//굳이 JWT 토큰을 사용하면서 세션을 만들 이유가 없음
			
			return authentication;
			
		} catch (IOException e) {
			e.printStackTrace();
		}
		return null;
	}
	// attemptAuthentication 실행 후 인증이 정상적으로 되었으면 successfulAuthentication 함수가 실행됨
	// JWT 토큰을 만들어서 request 요청한 사용자에게 JWT 토큰을 response해주면됨
	@Override
	protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
			Authentication authResult) throws IOException, ServletException {
		System.out.println("successfulAuthentication 실행됨 : 인증 완료되었다는 뜻");
		
		PrincipalDetails principalDetails = (PrincipalDetails) authResult.getPrincipal();
		
		// RSA방식은 아니고 Hash암호방식
		String jwtToken = JWT.create()
				.withSubject("토오큰")
				.withExpiresAt(new Date(System.currentTimeMillis() + (60000*10)))
				.withClaim("id", principalDetails.getUser().getId())// 비공개 클레임 : 내가 넣고싶은 값
				.withClaim("username", principalDetails.getUser().getUsername())
				.sign(Algorithm.HMAC512("cos"));
		// HMAC512 : 서버만 알고있는 시크릿 필요
		
		response.addHeader("Authorization", "Bearer "+jwtToken);
	}
}
