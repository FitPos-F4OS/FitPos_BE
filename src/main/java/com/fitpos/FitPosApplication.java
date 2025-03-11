package com.fitpos;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.ComponentScan;

@SpringBootApplication
@ComponentScan(basePackages = {"com.fitpos.security", "com.fitpos.user"})  // ✅ 명시적으로 패키지 추가
public class FitPosApplication {
    public static void main(String[] args) {
        SpringApplication.run(FitPosApplication.class, args);
    }
}