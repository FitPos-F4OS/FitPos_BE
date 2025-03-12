package com.fitpos.user;

import com.fitpos.security.JwtUtil;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;


import java.util.Optional;

@RestController
@RequestMapping("/user")
public class UserController {
    private final JwtUtil jwtUtil;
    private final UserRepository userRepository;  // 🔹 DB에서 사용자 조회
    private final PasswordEncoder passwordEncoder;  // 🔹 비밀번호 검증


    public UserController(JwtUtil jwtUtil, UserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.jwtUtil = jwtUtil;
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @PostMapping("/login")
    public ResponseEntity<Object> login(@RequestBody LoginRequest loginRequest) {
        // 🔹 ID로 사용자 조회 (findByCustomId 사용)
        Optional<UserEntity> userOptional = userRepository.findByCustomId(loginRequest.getId());

        if (userOptional.isEmpty()) {
            return ResponseEntity.status(401).body("존재하지 않는 사용자입니다.");
        }

        UserEntity user = userOptional.get();

        // 🔹 입력한 비밀번호가 DB에 저장된 해시된 비밀번호와 일치하는지 확인
        if (!passwordEncoder.matches(loginRequest.getPassword(), user.getPassword())) {
            return ResponseEntity.status(401).body("비밀번호가 일치하지 않습니다.");
        }

        // 🔹 인증 성공 → JWT 발급
        String token = jwtUtil.generateToken(user.getId());
        return ResponseEntity.ok().body("JWT: " + token);

    }


}
