package org.koreait.global.configs;

import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.koreait.member.jwt.filters.LoginFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.filter.CorsFilter;

@Configuration
@EnableWebSecurity // 기본 보안 정책 활성화
@EnableMethodSecurity // @PreAuthorize, @PostAuthorize
@RequiredArgsConstructor
public class SecurityConfig {

    private final CorsFilter corsFilter;
    private final LoginFilter loginFilter;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        /*
         SessionCreationPolicy
            - ALWAYS : 서버가 시작되었을때 부터 세션 생성, 세션 아이디
            - IF_REQUIRED : 세션이 필요한 시점에 세션 을 생성(기본값)
            - NEVER : 세션 생성 X, 기존에 세션이 존재하면 그거는 사용
            - STATELESS : 세션 생성 X, 기본 생성된 세션도 사용 X
         */

        http.csrf(c -> c.disable())
                .sessionManagement(c -> c.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .addFilterBefore(corsFilter, UsernamePasswordAuthenticationFilter.class)
                .addFilterBefore(loginFilter, UsernamePasswordAuthenticationFilter.class)
                .exceptionHandling(c -> {
                    c.authenticationEntryPoint((req, res, e) -> {
                        res.sendError(HttpServletResponse.SC_UNAUTHORIZED);
                    }); // 미로그인 상태에서 접근 한 경우
                    c.accessDeniedHandler((req, res, e) -> {
                        res.sendError(HttpServletResponse.SC_UNAUTHORIZED);
                    }); // 로그인 후 권한이 없는 경우
                })
                .authorizeHttpRequests(c -> {
                    c.requestMatchers(
                                    "/join", // /api/v1/member/join
                                    "/login",
                                    "/apidocs.html",
                                    "/swagger-ui*/**",
                                    "/api-docs/**").permitAll()
                            .requestMatchers("/admin/**").hasAnyAuthority("ADMIN")
                            .anyRequest().authenticated();
                });


        return http.build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}