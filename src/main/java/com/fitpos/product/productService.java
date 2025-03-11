package com.fitpos.product;

import java.util.List;

public interface productService {
    productDTO createProduct(productDTO productDTO);
    productDTO getProductById(Long productId);
    List<productDTO> getAllProducts();
    productDTO updateProduct(Long productId, productDTO productDTO);
    void deleteProduct(Long productId);

}
