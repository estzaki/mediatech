package com.estc.mediatech_2.controllers;

import com.estc.mediatech_2.dao.ClientDao;
import com.estc.mediatech_2.dto.ClientRequestDto;
import com.estc.mediatech_2.dto.ClientResponseDto;
import com.estc.mediatech_2.exception.InsecureDirectObjectReferenceException;
import com.estc.mediatech_2.models.ClientEntity;
import com.estc.mediatech_2.security.validator.IDORValidator;
import com.estc.mediatech_2.service.ClientService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

/**
 * Contrôleur de gestion des clients sécurisé (OWASP A01:2025 - Broken Access Control).
 * Ajout du contrôle d'accès par rôle (@PreAuthorize) et protection anti-IDOR pour les clients.
 */
@RestController
@RequestMapping("/api/clients")
@RequiredArgsConstructor
public class ClientController {

    private final ClientService clientService;
    // Ajout de ClientDao et IDORValidator pour vérifier qu'un client ne consulte que son propre profil
    private final ClientDao clientDao;
    private final IDORValidator idorValidator;

    // Modif sécurité (A01:2025) : Seuls l'ADMIN et le VENDEUR peuvent créer une fiche client manuellement
    @PostMapping
    @PreAuthorize("hasAnyAuthority('ADMIN', 'VENDEUR')")
    public ResponseEntity<ClientResponseDto> createClient(@RequestBody ClientRequestDto request) {
        return ResponseEntity.ok(clientService.save(request));
    }

    // Modif sécurité (A01:2025) : Interdiction pour un simple CLIENT de lister toute la base clients
    @GetMapping
    @PreAuthorize("hasAnyAuthority('ADMIN', 'VENDEUR')")
    public ResponseEntity<List<ClientResponseDto>> getAllClients() {
        return ResponseEntity.ok(clientService.findAll());
    }

    // Modif sécurité (A01:2025 - Protection IDOR) : Un CLIENT ne peut consulter que son propre id_client
    @GetMapping("/{id}")
    @PreAuthorize("hasAnyAuthority('ADMIN', 'VENDEUR', 'CLIENT')")
    public ResponseEntity<ClientResponseDto> getClient(@PathVariable Long id, Authentication auth) {
        String role = idorValidator.extractPrimaryRole(auth);
        if ("CLIENT".equals(role)) {
            Long authenticatedClientId = clientDao.findByUser_Username(auth.getName())
                    .map(ClientEntity::getId_client)
                    .orElse(null);
            idorValidator.validateClientOwnership(id, authenticatedClientId);
        }

        ClientResponseDto client = clientService.findById(id);
        return client != null ? ResponseEntity.ok(client) : ResponseEntity.notFound().build();
    }

    // Modif sécurité (A01:2025) : Recherche par numéro de téléphone réservée au personnel (ADMIN / VENDEUR)
    @GetMapping("/search")
    @PreAuthorize("hasAnyAuthority('ADMIN', 'VENDEUR')")
    public ResponseEntity<ClientResponseDto> getClientByTel(@RequestParam String tel) {
        ClientResponseDto client = clientService.findByTel(tel);
        return client != null ? ResponseEntity.ok(client) : ResponseEntity.notFound().build();
    }

    // Modif sécurité (A01:2025) : Modification d'un client réservée à l'ADMIN et au VENDEUR
    @PutMapping("/{id}")
    @PreAuthorize("hasAnyAuthority('ADMIN', 'VENDEUR')")
    public ResponseEntity<ClientResponseDto> updateClient(@PathVariable Long id,
            @RequestBody ClientRequestDto request) {
        ClientResponseDto updated = clientService.update(request, id);
        return updated != null ? ResponseEntity.ok(updated) : ResponseEntity.notFound().build();
    }

    // Modif sécurité (A01:2025) : La suppression d'un client est strictement réservée à l'ADMIN
    @DeleteMapping("/{id}")
    @PreAuthorize("hasAuthority('ADMIN')")
    public ResponseEntity<Void> deleteClient(@PathVariable Long id) {
        clientService.delete(id);
        return ResponseEntity.noContent().build();
    }

    // Renvoie 403 Forbidden si un client tente d'accéder à l'ID d'un autre client (IDOR)
    @ExceptionHandler(InsecureDirectObjectReferenceException.class)
    public ResponseEntity<Map<String, String>> handleIdorException(InsecureDirectObjectReferenceException ex) {
        return ResponseEntity.status(HttpStatus.FORBIDDEN)
                .body(Map.of("error", ex.getMessage()));
    }
}
