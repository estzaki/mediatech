package com.estc.mediatech_2.dto;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Positive;
import lombok.Data;
import java.util.List;

@Data
public class FactureRequestDto {
    @NotNull(message = "Client ID is required")
    @Positive(message = "Client ID must be positive")
    private Long id_client;

    @NotEmpty(message = "Invoice must contain at least one line item")
    @Valid
    private List<LigneFactureRequestDto> ligneFactures;
}
