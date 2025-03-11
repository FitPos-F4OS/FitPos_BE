package com.fitpos.product;

import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.List;

@Service
@RequiredArgsConstructor
@Transactional
public class productServiceImpl implements productService {
    private final productRepository productRepository;

    @Override
    public productDTO createProduct(productDTO productDTO) {
        productEntity product = productEntity.builder()
                .pName(productDTO.getPName())
                .pCategory(productDTO.getPCategory())
                .pPrice(productDTO.getPPrice())
                .pStock(productDTO.getPStock())
                .pExpDate(productDTO.getPExpDate())
                .build();

        productDTO savedProduct = productRepository.save(productDTO);
        System.out.println("Saved Product: " + savedProduct);  // 디버깅용 로그 추가
        return mapToDTO(savedProduct);
    }

    @Override
    public productDTO getProductById(Long productId) {
        return null;
    }

    @Override
    public List<productDTO> getAllProducts() {
        return List.of();
    }

    @Override
    public productDTO updateProduct(Long productId, productDTO productDTO) {
        return null;
    }

    @Override
    public void deleteProduct(Long productId) {

    }

    private productDTO mapToDTO(productDTO product) {
        if (product == null) {
            throw new IllegalArgumentException("Product 객체가 null입니다.");
        }
        return productDTO.builder()
                .productId(product.getProductId())
                .pName(product.getPName())
                .pCategory(product.getPCategory())
                .pPrice(product.getPPrice())
                .pStock(product.getPStock())
                .pRegDate(product.getPRegDate() != null ? product.getPRegDate() : LocalDateTime.now())  // Null 방지
                .pExpDate(product.getPExpDate())
                .build();
    }

}
