package com.fitpos.product;

import lombok.*;
import org.apache.ibatis.type.Alias;

import java.time.LocalDateTime;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class productDTO {
    private Long productId;
    private String pName;
    private String pCategory;
    private int pPrice;
    private int pStock;
    private LocalDateTime pRegDate;
    private LocalDateTime pExpDate;
}
