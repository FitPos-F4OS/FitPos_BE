package com.fitpos.user;

import lombok.*;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class UserDTO {
    private String id;  // 사용자 ID
    private String name;  // 사용자 이름
    private String email;  // 이메일
    private String role;  // 사용자 역할
    private int point;  // 사용자 포인트
}