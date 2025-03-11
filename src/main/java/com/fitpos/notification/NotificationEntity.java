package com.fitpos.notification;

import com.fitpos.user.UserEntity;
import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;

@Entity
@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@Builder
@Table(name = "notifications")
public class NotificationEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long NotificationId;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "userId", nullable = false)
    private UserEntity user;

    @Column(nullable = false, length = 1000)
    private String message;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private NotificationType type;

    @Column
    private LocalDateTime notificationDate = LocalDateTime.now();

    public enum NotificationType {
        LOW_STOCK, EXPIRY
    }
}
