package com.fitpos.security;

import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import io.jsonwebtoken.security.Keys;
import java.security.Key;
import java.util.Base64;
import java.util.Date;


@Component
public class JwtUtil {
    //secret_key 설정 properties에서 가져오기
    @Value("${jwt.secret}")
    private String SECRET_KEY;

    //키 생성(Base 64 디코딩 후 Key 객체로 변환)
    private Key getSigningKey() {
        byte[] keyBytes = Base64.getDecoder().decode(SECRET_KEY);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    // 🔹 JWT 생성
    public String generateToken(String id) {
        return Jwts.builder()
                .setSubject(id)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 60)) // 1시간 후 만료
                .signWith(getSigningKey(), SignatureAlgorithm.HS256) // HMAC-SHA256
                .compact();
    }

    //JWT 검증 =>위조 검사
    public boolean validateToken(String token) {
        try {
            Jwts.parserBuilder().setSigningKey(getSigningKey()).build().parseClaimsJws(token);
            return true;
        } catch (JwtException e) {
            return false; // 유효하지 않은 토큰
        }
    }

    //JWT 에서 사용자 정보 가져오기
    public String extractUsername(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(getSigningKey())  // SECRET_KEY로 서명 검증
                .build()
                .parseClaimsJws(token)  // JWT 분석
                .getBody()
                .getSubject();  // 사용자 id 반환
    }


}
