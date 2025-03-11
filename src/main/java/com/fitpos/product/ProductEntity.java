package com.fitpos.product;

import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;

@jakarta.persistence.Entity
@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@Builder
@Table(name = "products")

public class ProductEntity {

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

    @Column
    private LocalDateTime pRegDate = LocalDateTime.now();

    @Column
    private LocalDateTime pExpDate;


}
