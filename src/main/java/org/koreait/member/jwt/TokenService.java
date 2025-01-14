package org.koreait.member.jwt;

import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.HttpServletRequest;
import org.koreait.global.exceptions.UnAuthorizedException;
import org.koreait.global.libs.Utils;
import org.koreait.member.MemberInfo;
import org.koreait.member.services.MemberInfoService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Lazy;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import java.security.Key;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.stream.Collectors;

@Lazy
@Service
@EnableConfigurationProperties(JwtProperties.class)
public class TokenService {

    private final JwtProperties properties;
    private final MemberInfoService infoService;

    @Autowired
    private Utils utils;

    private Key key;

    public TokenService(JwtProperties properties, MemberInfoService infoService) {
        this.properties = properties;
        this.infoService = infoService;

        byte[] keyBytes = Decoders.BASE64.decode(properties.getSecret());
        this.key = Keys.hmacShaKeyFor(keyBytes);
    }

    /**
     * JWT 토큰 생성
     *
     * @param email
     * @return
     */
    public String create(String email) {
        MemberInfo memberInfo = (MemberInfo)infoService.loadUserByUsername(email); // 이메일로 접근가능하게!

        String authorities = memberInfo.getAuthorities().stream().map(a -> a.getAuthority()).collect(Collectors.joining("||")); // 문자열로 권한명칭을 다 넣어주고 토큰에 실어서 보냄
        int validTime = properties.getValidTime() * 1000; // 1000곱한건 날짜를 계산할려고 넣은거
        Date date = new Date((new Date()).getTime() + validTime); // 15분 뒤의 시간(만료 시간) // 겟타임은 에포크타임
        // 15분뒤에 예외가 발생할거임

        return Jwts.builder()
                .setSubject(memberInfo.getEmail())
                .claim("authorities", authorities)
                .signWith(key, SignatureAlgorithm.HS512) // 사인키를 만드는 구문 / HMAC방식임 == HS512
                .setExpiration(date)
                .compact();
    } // 토큰을 만드는 기능임
    // 토큰을 실어나를때 쿠키에도 넣어줘야함

    /**
     * 토큰으로 인증 처리(로그인 처리)
     *
     * 요청 헤더:
     *      Authorization: Bearer 토큰
     * @param token
     * @return
     */
    public Authentication authenticate(String token) {
    // 토큰이 넘어왔음 / 토큰을 다시 원래형태로 바꿔줘야함/parser를 써야함
        // 토큰만료시 갱신하는 방식으로 만들꺼

        // 토큰 유효성 검사
        validate(token);

        Claims claims = Jwts.parser()
                .setSigningKey(key) // 위변조가 있는지 검증해야함 / 키값!
                .build()
                .parseClaimsJws(token)
                .getPayload();

        String email = claims.getSubject();
        String authorities = (String) claims.get("authorities");
        List<SimpleGrantedAuthority> _authorities = Arrays.stream(authorities.split("\\|\\|")).map(SimpleGrantedAuthority::new).toList();
        System.out.println("authorities:" + authorities);
        System.out.println("_authorities:" + _authorities);

        MemberInfo memberInfo = (MemberInfo) infoService.loadUserByUsername(email);
        memberInfo.setAuthorities(_authorities);

        UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(memberInfo, null, _authorities);

        SecurityContextHolder.getContext().setAuthentication(authentication); // 로그인 처리

        return authentication;
    }

    public Authentication authenticate(HttpServletRequest request) {
        String authHeader = request.getHeader("Authorization");

        if (!StringUtils.hasText(authHeader)) {
            return null; // 회원가입 또는 로그인 시
        }

        String token = authHeader.substring(7);

        return authenticate(token);
    }

    /**
     * 토큰 검증
     *
     * @param token
     */
    public void validate(String token) {
        String errorCode = null;
        Exception error = null;
        try {
            Jwts.parser().setSigningKey(key).build().parseClaimsJws(token).getPayload();
        } catch (io.jsonwebtoken.security.SecurityException | MalformedJwtException e) {
            errorCode = "JWT.malformed";
            error = e;
        } catch (ExpiredJwtException e) { // 토큰 만료
            errorCode = "JWT.expired";
            error = e;
        } catch (UnsupportedJwtException e) {
            errorCode = "JWT.unsupported";
            error = e;
        } catch (Exception e) {
            errorCode = "JWT.error";
            error = e;
        }

        if (StringUtils.hasText(errorCode)) {
            throw new UnAuthorizedException(utils.getMessage(errorCode));
        }

        if (error != null) {
            error.printStackTrace();
        }
    }
}