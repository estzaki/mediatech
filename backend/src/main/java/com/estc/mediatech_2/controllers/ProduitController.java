package com.estc.mediatech_2.controllers;

import com.estc.mediatech_2.dto.ProduitRequestDto;
import com.estc.mediatech_2.dto.ProduitResponseDto;
import com.estc.mediatech_2.service.ProduitService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * Contrôleur de gestion du catalogue produits sécurisé (OWASP A01:2025 - Broken Access Control).
 * Empêche un compte CLIENT de modifier les prix, d'ajouter de faux produits ou de supprimer le stock.
 */
@RestController
@RequestMapping("/api/produits")
@RequiredArgsConstructor
public class ProduitController {

    private final ProduitService produitService;

    // Modif sécurité (A01:2025) : Seuls l'ADMIN et le VENDEUR peuvent ajouter un produit au catalogue
    @PostMapping
    @PreAuthorize("hasAnyAuthority('ADMIN', 'VENDEUR')")
    public ResponseEntity<ProduitResponseDto> createProduit(@RequestBody ProduitRequestDto request) {
        return ResponseEntity.ok(produitService.save(request));
    }

    // Lecture du catalogue autorisée pour tous les utilisateurs authentifiés (y compris CLIENT)
    @GetMapping
    @PreAuthorize("hasAnyAuthority('ADMIN', 'VENDEUR', 'CLIENT')")
    public ResponseEntity<List<ProduitResponseDto>> getAllProduits() {
        return ResponseEntity.ok(produitService.findAll());
    }

    // Consultation des détails d'un produit autorisée pour ADMIN, VENDEUR et CLIENT
    @GetMapping("/{id}")
    @PreAuthorize("hasAnyAuthority('ADMIN', 'VENDEUR', 'CLIENT')")
    public ResponseEntity<ProduitResponseDto> getProduit(@PathVariable Long id) {
        ProduitResponseDto produit = produitService.findById(id);
        return produit != null ? ResponseEntity.ok(produit) : ResponseEntity.notFound().build();
    }

    // Modif sécurité (A01:2025) : Empêche un CLIENT de modifier le prix unitaire (ex: passer un PC à 0.01 DH)
    @PutMapping("/{id}")
    @PreAuthorize("hasAnyAuthority('ADMIN', 'VENDEUR')")
    public ResponseEntity<ProduitResponseDto> updateProduit(@PathVariable Long id,
            @RequestBody ProduitRequestDto request) {
        ProduitResponseDto updated = produitService.update(request, id);
        return updated != null ? ResponseEntity.ok(updated) : ResponseEntity.notFound().build();
    }

    // Modif sécurité (A01:2025) : Suppression d'un produit strictement réservée à l'ADMIN
    @DeleteMapping("/{id}")
    @PreAuthorize("hasAuthority('ADMIN')")
    public ResponseEntity<Void> deleteProduit(@PathVariable Long id) {
        produitService.delete(id);
        return ResponseEntity.noContent().build();
    }
}
