package com.tenco.csr_blog_v1.core;

import com.tenco.csr_blog_v1.core.filter.JwtAuthorizationFilter;
import com.tenco.csr_blog_v1.core.util.JwtProvider;
import com.tenco.csr_blog_v1.core.util.RespFilter;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.List;

@Configuration
@RequiredArgsConstructor
public class SecurityConfig {

    private final JwtProvider jwtProvider;

    @Value("${app.cors.allowed-origins}")
    private String allowedOrigins;

    @Bean
    public BCryptPasswordEncoder encodePwd() {
        return new BCryptPasswordEncoder();
    }

    // [CORS 가 필요한 이유]
    // 브라우저는 보안상 다른 출처 (포트 번호 * 도메인)로 보내는 요청을 기본적으로 가로막는다.
    // React(localhost:5733) -> Sptring boot (localhost: 8080) 요청 --> 브라우저가 기본적으로 차단
    // 서버가 이 출처에서 오는 요청을 허용한다 라고 응답 헤더에 명시를 해야 통과할 수 있다.
    public CorsConfigurationSource corsConfigurationSource() {

        CorsConfiguration config = new CorsConfiguration();

        // 어떤 요청 헤더던 허용한다.
        // JWT 를 담은 Authorization 헤더, 데이터 형식을 알리는 Content-Type 헤더 등을 보낼 수 있도록 허용
        config.addAllowedHeader("*");

        // 다른 출처에서 들어옿는 HTTP 메서드를 지정한다.
        config.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "OPTIONS"));

        // 허용할 출처를 등록한다.
        // localhost:5713, localhost:6743 미리 출처를 등록해서 사용하기도함
        config.setAllowedOriginPatterns(List.of(allowedOrigins.split(",")));

        // 이 프로젝트는 로그인 정보를 쿠키에 담아서 보내는 세션 기반이 아니라
        // JWT 헤더로 토큰을 주고 받는 프로젝트이다. // 쿠키 사용 안함 설정
        config.setAllowCredentials(false);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/api/**", config);
        return source;
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        // 1. H2 Console 허용
         http.headers(headers ->
                 headers.frameOptions(frameOptions -> frameOptions.sameOrigin()));

        // 2. 스프링이 기본으로 제공하는 로그인 폼 화면을 끈다.
        http.formLogin(
                form -> form.disable());

        // 3. Http Basic 인증 끈다
        // HTTP Basic 이란 브라우저가 자동으로 팝업창을 띄워서 아이디/비밀번호를 입력 받는 방식을 말한다.
        // 우리는 JWT 리액트를 사용할 예정이라 필요없음
        http.httpBasic(
                basic -> basic.disable());

        // 4. CSRF 보안을 끈다.
        // CSRF 는 쿠키를 이용한 공격 방식이지만, 이 프로젝트는 쿠키를 사용하지 않음
        http.csrf(csrf -> csrf.disable());

        // 5. 서버가 세션을 만들지 않도록 설정 (JWT 사용)
        http.sessionManagement(session
                -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));

        // 6. JWT 인증 필터를 등록한다.
        // 모든 요청이 들어올 때 JWTAuthorizationFilter 가 먼저 실행된다
        // 즉, UsernamePasswordAuthenticationFilter 동작하기 전에 앞에 끼워 넣어야 우리가 원하는 방식으로 동작함
        http.addFilterBefore(new JwtAuthorizationFilter(jwtProvider), UsernamePasswordAuthenticationFilter.class);

        // 7. 위에서 만든 CORS 규칙을 시큐리티 필터에 등록한다.
        http.cors(cors ->
                cors.configurationSource(corsConfigurationSource()));

        // 8. 인증, 권한 오류 발생 시 기본 설정이 아닌 우리가 정의한 내용으로 처리한다.
        // 401, 403 발생 했을 경우 필터에서 걸러지기 때문에 기본적인 오류 메세지가 날라간다.
        // 우리는 이것을 가공해서 정의된 규칙에 코드로 내려 주어야한다.
        http.exceptionHandling(ex ->
                ex.authenticationEntryPoint(
                        (request, response, authException) ->
                                RespFilter.fail(response, 401, "로그인 후 이용해주세요."))
                        .accessDeniedHandler((request, response, accessDeniedException) ->
                                RespFilter.fail(response, 403, "권한이 없습니다."))
                );


        // 9. URL 별 접근 권한 설정
        // 경로 설정 시 순서는 위에서 적용이 되며, 따라서 구체적인 규칙을 위에, 범위가 넣은 규칙을 아래에 작성해야한다.
        http.authorizeHttpRequests(
                authorizationManagerRequestMatcherRegistry ->
                        // 여기 경로는 ADMIN 만 들어올 수 있다.
                        authorizationManagerRequestMatcherRegistry.requestMatchers("/api/admin/**").hasRole("ADMIN")
                                // 게시글 목록, 상세보기(GET) 은 로그인 없이 누구나 허용
                                .requestMatchers(HttpMethod.GET, "api/boards/**").permitAll()
                                // 게시글 수정, 삭제, 작성, 댓글, 마이페이지는 로그인한 사용자만 가능
                                // USER, ADMIN
                                .requestMatchers("/api/users/**", "/api/boards/**", "/api/replies/**").hasAnyRole("USER", "ADMIN")
                                // 위 경로에 걸리지 않은 나머지 모든 요청은 허용한다.
                                .anyRequest().permitAll()


        );

        return http.build();
    }


}
