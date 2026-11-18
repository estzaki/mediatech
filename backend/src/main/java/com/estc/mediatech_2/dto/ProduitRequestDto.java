package com.estc.mediatech_2.dto;

import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Positive;
import jakarta.validation.constraints.Size;
import lombok.Data;
import java.math.BigDecimal;

@Data
public class ProduitRequestDto {
    @NotBlank(message = "Product reference is required")
    @Size(min = 2, max = 50, message = "Product reference must be between 2 and 50 characters")
    private String ref_produit;

    @NotBlank(message = "Product label is required")
    @Size(min = 2, max = 100, message = "Product label must be between 2 and 100 characters")
    private String libelle_produit;

    @NotNull(message = "Unit price is required")
    @Positive(message = "Unit price must be strictly positive")
    private BigDecimal prix_unitaire;

    @NotNull(message = "Stock quantity is required")
    @Min(value = 0, message = "Stock quantity cannot be negative")
    private Integer qte_stock;

    @Size(max = 500, message = "Image URL must not exceed 500 characters")
    private String imageUrl;
}
