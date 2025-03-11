package com.fitpos.sales;

import com.fitpos.product.ProductEntity;
import com.fitpos.user.UserEntity;
import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;

@jakarta.persistence.Entity
@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@Builder
@Table(name = "sales")
public class SalesEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long salesId;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "userId", nullable = false)
    private UserEntity user;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "productId", nullable = false)
    private ProductEntity product;

    @Column(nullable = false)
    private int soldQuantity;

    @Column(nullable = false)
    private int totalPrice;

    @Column
    private LocalDateTime soldStamp = LocalDateTime.now();

}
