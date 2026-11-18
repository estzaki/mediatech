package com.estc.mediatech_2.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Data;

@Data
public class ClientRequestDto {
    @NotBlank(message = "Client last name is required")
    @Size(min = 2, max = 50, message = "Last name must be between 2 and 50 characters")
    private String nom_client;

    @NotBlank(message = "Client first name is required")
    @Size(min = 2, max = 50, message = "First name must be between 2 and 50 characters")
    private String prenom_client;

    @NotBlank(message = "Phone number is required")
    @Size(min = 8, max = 20, message = "Phone number must be between 8 and 20 characters")
    private String telephone;
}
