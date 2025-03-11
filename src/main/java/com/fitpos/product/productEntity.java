package com.fitpos.product;

import jakarta.persistence.*;
import lombok.*;
import java.time.LocalDateTime;

@Entity
@Table(name = "Products")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class productEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long productId;

    @Column(nullable = false, length = 100)
    private String pName;

    @Column(nullable = false, length = 100)
    private String pCategory;

    @Column(nullable = false)
    private int pPrice;

    @Column(nullable = false)
    private int pStock;

    @Column(nullable = false, updatable = false)
    private LocalDateTime pRegDate = LocalDateTime.now();

    private LocalDateTime pExpDate;
}
