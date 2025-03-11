package com.fitpos.product;

import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/products")
@RequiredArgsConstructor
public class productController {
    
    private final productService productService;

    @PostMapping
    public ResponseEntity<productDTO> createProduct(@RequestBody productDTO productDTO) {
        return ResponseEntity.ok().body(productService.createProduct(productDTO));
    }

    @GetMapping("/{id}")
    public ResponseEntity<productDTO> getProductById(@PathVariable Long id) {
        return ResponseEntity.ok().body(productService.getProductById(id));
    }

    @PutMapping("/{id}")
    public ResponseEntity<productDTO> updateProduct(@PathVariable Long id, @RequestBody productDTO productDTO) {
        return ResponseEntity.ok().body(productService.updateProduct(id, productDTO));
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Void> deleteProduct(@PathVariable Long id) {
        productService.deleteProduct(id);
        return ResponseEntity.noContent().build();
    }

//    @GetMapping("/{id}/stock")
//    public ResponseEntity<Integer> getProductStock(@PathVariable Long id) {
//        int stock = productService.getProductStock(id);
//        return ResponseEntity.ok().body(stock);
//    }
//
//    @PostMapping("/{id}/stock/increase")
//    public ResponseEntity<Void> increaseStock(@PathVariable Long id, @RequestBody productDTO productDTO) {}




}
