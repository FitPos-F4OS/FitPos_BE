package com.fitpos.user;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.Optional;

public interface UserRepository extends JpaRepository<UserEntity, String> {

    //id기반으로 사용자 조회
    @Query("SELECT u FROM UserEntity u WHERE u.id = :id")
    Optional<UserEntity> findByCustomId(@Param("id") String id);


    //id기반으로 포인트 조회
    @Query("SELECT u.point FROM UserEntity u WHERE u.id = :id")
    int findUserPointById(String id);
}
