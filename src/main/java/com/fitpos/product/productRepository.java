package com.fitpos.product;

import com.fitpos.product.productEntity;
import org.springframework.data.jpa.repository.JpaRepository;

public interface productRepository extends JpaRepository<productDTO, Integer> {
}
