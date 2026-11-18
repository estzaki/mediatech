package com.estc.mediatech_2.dto;

import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Positive;
import lombok.Data;

@Data
public class LigneFactureRequestDto {
    @NotNull(message = "Product ID is required")
    @Positive(message = "Product ID must be positive")
    private Long id_produit;

    @NotNull(message = "Quantity is required")
    @Positive(message = "Quantity must be positive")
    @Min(value = 1, message = "Quantity must be at least 1")
    private Integer qte;
}
