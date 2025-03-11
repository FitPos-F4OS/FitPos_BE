package com.fitpos.salesSum;

import com.fitpos.product.ProductEntity;
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
@Table(name = "sales_summary", uniqueConstraints = {
        @UniqueConstraint(columnNames = {"userId", "date"})
})
public class SalesSumEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long summaryId;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "userId", nullable = false)
    private UserEntity user;

    @Column(nullable = false)
    private LocalDateTime date;

    @Column(nullable = false)
    private int dailySales;

    @Column(nullable = false)
    private int weeklySales;

    @Column(nullable = false)
    private int monthlySales;

}
