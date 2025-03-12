package com.fitpos.security;

import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import jakarta.annotation.PostConstruct;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import io.jsonwebtoken.security.Keys;
import java.security.Key;
import java.util.Base64;
import java.util.Date;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


@Component
public class JwtUtil {

    private static final Logger logger = LoggerFactory.getLogger(JwtUtil.class);

    //secret_key 설정 properties에서 가져오기(JWT 서명할 때 사용되는 비밀키)
    @Value("${jwt.secret}")
    private String SECRET_KEY;

    //JWT 서명할 때 사용할 키를 KEY객체로 저장
    private Key signingKey;

    //토큰 만료기간 1시간
    private final long EXPIRATION_TIME = 1000 * 60 * 60; // 1시간 (밀리초 단위)

    //init() : JWT 서명 키를 초기화 함.
    //@PostConstruct=> Spring이 객체 생성한 후 자동으로 실행=> 초기화하는 역할
    @PostConstruct
    public void init() {
        if (SECRET_KEY == null || SECRET_KEY.isEmpty()) {
            logger.error("🚨 JWT Secret Key가 설정되지 않았습니다! 서버를 종료합니다.");
            throw new IllegalStateException("JWT Secret Key가 설정되지 않았습니다!");
        }
        //Base64 디코딩해서 보안 키 객체로 변환
        try {
            byte[] keyBytes = Base64.getDecoder().decode(SECRET_KEY);
            this.signingKey = Keys.hmacShaKeyFor(keyBytes);
        } catch (IllegalArgumentException e) {
            logger.error("🚨 잘못된 JWT Secret Key 형식입니다! Base64 인코딩된 값을 사용해야 합니다.");
            throw new IllegalStateException("잘못된 JWT Secret Key 형식입니다!", e);
        }
    }

    //저장된 서명 키 반환
    private Key getSigningKey() {
        return signingKey;
    }

    // 🔹 JWT 생성
    public String generateToken(String id) {
        return Jwts.builder()
                .setSubject(id) //jwt에 사용자 id 저장
                .setIssuedAt(new Date()) // 토큰 발행 시간
                .setExpiration(new Date(System.currentTimeMillis() + EXPIRATION_TIME)) // 1시간 후 만료
                .signWith(getSigningKey(), SignatureAlgorithm.HS256) // HMAC-SHA256 알고리즘으로 서명
                .compact(); //최종적으로 JWT 문자열 생성
    }

    //JWT 검증 =>위조 검사
    public boolean validateToken(String token) {
        try {
            Jwts.parserBuilder().setSigningKey(getSigningKey()).build().parseClaimsJws(token);
            return true;
            //검증 실패시
        } catch (JwtException e) {
            logger.error("JWT 검증 실패: {}", e.getMessage());
            return false;
        }
    }

    //JWT 에서 사용자 ID 가져오기
    public String extractId(String token) {
        if (!validateToken(token)) {
            logger.warn("JWT ID 추출 실패: 유효하지 않은 토큰");
            throw new JwtException("유효하지 않은 JWT 토큰입니다.");
        }

        return Jwts.parserBuilder()
                .setSigningKey(getSigningKey())
                .build()
                .parseClaimsJws(token)
                .getBody()
                .getSubject();
    }


}
