package com.fitpos.user;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class CustomUserDetailsService implements UserDetailsService {
    private final UserRepository userRepository;

    public CustomUserDetailsService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String id) throws UsernameNotFoundException {
        Optional<UserEntity> userOptional = userRepository.findByCustomId(id);

        UserEntity user = userOptional.orElseThrow(() ->
                new UsernameNotFoundException("사용자를 찾을 수 없습니다: " + id));

        return org.springframework.security.core.userdetails.User.builder()
                .username(user.getId())  // 사용자 ID
                .password(user.getPassword())  // 암호화된 비밀번호
                .roles(user.getRole().name())  // 역할(권한)
                .build();
    }

    //loadUserByUsername는 이름 변경 불가 그래서 새로운 함수로 변경해줌.
    public UserDetails loadUserById(String id) {
        return loadUserByUsername(id); //
    }
}
