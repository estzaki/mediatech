package com.estc.mediatech_2.controllers;

import com.estc.mediatech_2.dao.ClientDao;
import com.estc.mediatech_2.dao.FactureDao;
import com.estc.mediatech_2.dto.FactureRequestDto;
import com.estc.mediatech_2.dto.FactureResponseDto;
import com.estc.mediatech_2.exception.InsecureDirectObjectReferenceException;
import com.estc.mediatech_2.models.ClientEntity;
import com.estc.mediatech_2.models.FactureEntity;
import com.estc.mediatech_2.security.validator.IDORValidator;
import com.estc.mediatech_2.service.FactureService;
import com.estc.mediatech_2.service.PdfService;
import com.estc.mediatech_2.service.SecurityAuditService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.io.InputStreamResource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.io.ByteArrayInputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Secured Facture Controller with Method-Level Security
 * 
 * OWASP References:
 * - A01:2025 – Broken Access Control (Protection anti-IDOR sur lecture, création et PDF)
 * - A08:2025 – Software or Data Integrity Failures (Verrouillage des factures VALIDEE & hash SHA-256 du PDF)
 */
@RestController
@RequestMapping("/api/factures")
@RequiredArgsConstructor
@Slf4j
public class SecuredFactureController {

    // Liste blanche stricte des statuts autorisés pour éviter l'injection de statuts invalides (A08:2025)
    private static final Set<String> ALLOWED_STATUSES = Set.of("EN_ATTENTE", "VALIDEE", "REFUSEE");

    private final FactureService factureService;
    private final PdfService pdfService;
    private final FactureDao factureDao;
    // Injection du DAO client, du validateur IDOR et du service d'audit de sécurité
    private final ClientDao clientDao;
    private final IDORValidator idorValidator;
    private final SecurityAuditService securityAuditService;

    /**
     * Create Facture - ADMIN, VENDEUR and CLIENT
     * 
     * Security: Role-based access control + vérification anti-usurpation d'identité client (IDOR)
     */
    @PostMapping
    @PreAuthorize("hasAnyAuthority('ADMIN', 'VENDEUR', 'CLIENT')")
    public ResponseEntity<FactureResponseDto> createFacture(@RequestBody FactureRequestDto request) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        log.info("User {} creating facture", auth.getName());

        // Modif sécurité (A01:2025) : Si l'utilisateur connecté est un CLIENT, on vérifie qu'il
        // crée bien la facture pour son propre id_client et non au nom d'un autre client
        String role = idorValidator.extractPrimaryRole(auth);
        if ("CLIENT".equals(role)) {
            Long authenticatedClientId = clientDao.findByUser_Username(auth.getName())
                    .map(ClientEntity::getId_client)
                    .orElse(null);
            idorValidator.validateClientOwnership(request.getId_client(), authenticatedClientId);
        }

        // Input validation happens in service layer
        FactureResponseDto response = factureService.createFacture(request);

        log.info("Facture created with ID: {} by user: {}", response.getId_facture(), auth.getName());
        return ResponseEntity.ok(response);
    }

    /**
     * Get All Factures - Role-based filtering
     * 
     * Security: Users only see their own factures unless ADMIN/VENDEUR
     */
    @GetMapping
    @PreAuthorize("hasAnyAuthority('ADMIN', 'VENDEUR', 'CLIENT')")
    public ResponseEntity<List<FactureResponseDto>> getAllFactures() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        boolean hasAdminOrVendeurRole = auth.getAuthorities().stream()
                .anyMatch(a -> a.getAuthority().equals("ADMIN") || a.getAuthority().equals("VENDEUR"));

        List<FactureResponseDto> factures;

        if (hasAdminOrVendeurRole) {
            // Admin and Vendeur can see all factures
            factures = factureService.getAllFactures();
        } else {
            // Clients only see their own factures
            factures = factureService.getFacturesByUsername(auth.getName());
        }

        return ResponseEntity.ok(factures);
    }

    /**
     * Get Single Facture - With authorization check
     * 
     * Security: Users can only access their own factures
     */
    @GetMapping("/{id}")
    @PreAuthorize("hasAnyAuthority('ADMIN', 'VENDEUR', 'CLIENT')")
    public ResponseEntity<?> getFacture(@PathVariable Long id) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();

        FactureResponseDto facture = factureService.getFacture(id);

        if (facture == null) {
            return ResponseEntity.notFound().build();
        }

        // Authorization check: verify user can access this facture
        if (!canAccessFacture(auth, facture)) {
            log.warn("Unauthorized access attempt to facture {} by user {}", id, auth.getName());
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                    .body(Map.of("error", "You are not authorized to access this facture"));
        }

        return ResponseEntity.ok(facture);
    }

    /**
     * Update Facture Status - ADMIN and VENDEUR only
     * OWASP A08:2025 : Contrôle d'intégrité du workflow de validation des factures
     */
    @PutMapping("/{id}/status")
    @PreAuthorize("hasAnyAuthority('ADMIN', 'VENDEUR')")
    public ResponseEntity<?> updateStatus(
            @PathVariable Long id,
            @RequestBody Map<String, String> statusMap) {

        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        String status = statusMap != null ? statusMap.get("status") : null;

        // Modif sécurité (A08:2025) : On vérifie que le statut demandé fait partie des valeurs autorisées
        if (status == null || !ALLOWED_STATUSES.contains(status)) {
            return ResponseEntity.badRequest().body(Map.of(
                    "error", "Integrity Error",
                    "message", "Statut invalide. Valeurs autorisees: EN_ATTENTE, VALIDEE, REFUSEE"
            ));
        }

        // Modif sécurité (A08:2025) : Une facture déjà VALIDEE est verrouillée (le stock a déjà été déduit),
        // on interdit de la repasser en EN_ATTENTE ou REFUSEE pour protéger l'intégrité comptable
        FactureResponseDto currentFacture = factureService.getFacture(id);
        if (currentFacture != null && "VALIDEE".equals(currentFacture.getStatus()) && !"VALIDEE".equals(status)) {
            securityAuditService.logUnauthorizedAccess(
                    auth.getName(),
                    "Facture#" + id,
                    "PUT",
                    "127.0.0.1",
                    "Tentative de retour en arrière sur une facture déjà VALIDEE vers " + status);
            return ResponseEntity.status(HttpStatus.CONFLICT).body(Map.of(
                    "error", "Data Integrity Violation (OWASP A08:2025)",
                    "message", "Une facture VALIDEE est verrouillee et ne peut plus etre modifiee"
            ));
        }

        log.info("User {} updating facture {} status to {}", auth.getName(), id, status);

        return ResponseEntity.ok(factureService.updateStatus(id, status));
    }

    /**
     * Generate and Download PDF - Secured with authorization & SHA-256 integrity hash
     */
    @GetMapping("/{id}/pdf")
    @PreAuthorize("hasAnyAuthority('ADMIN', 'VENDEUR', 'CLIENT')")
    public ResponseEntity<?> generatePdf(@PathVariable Long id) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();

        // Validate ID to prevent injection
        if (id == null || id <= 0) {
            return ResponseEntity.badRequest()
                    .body(Map.of("error", "Invalid facture ID"));
        }

        // Fetch facture
        FactureEntity facture = factureDao.findById(id).orElse(null);
        if (facture == null) {
            log.warn("PDF download attempt for non-existent facture {} by user {}", id, auth.getName());
            return ResponseEntity.notFound().build();
        }

        // Authorization check (utilise maintenant la vraie vérification de propriétaire client)
        FactureResponseDto factureDto = factureService.getFacture(id);
        if (!canAccessFacture(auth, factureDto)) {
            log.warn("Unauthorized PDF download attempt for facture {} by user {}", id, auth.getName());
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                    .body(Map.of("error", "You are not authorized to download this PDF"));
        }

        // Status validation
        if (!"VALIDEE".equals(facture.getStatus())) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                    .body(Map.of("error", "Only validated invoices can be downloaded"));
        }

        try {
            // Generate PDF (service handles input sanitization)
            ByteArrayInputStream bis = pdfService.factureReport(facture);
            // Modif sécurité (A08:2025) : Calcul de l'empreinte SHA-256 du fichier PDF généré
            // pour garantir que le document n'a pas été altéré ou tronqué pendant le téléchargement
            byte[] pdfBytes = bis.readAllBytes();
            String sha256Checksum = computeSha256Hex(pdfBytes);

            // Secure headers - prevent inline execution in some browsers
            HttpHeaders headers = new HttpHeaders();

            // Sanitize filename to prevent injection
            String safeFilename = sanitizeFilename("facture_" + facture.getRef_facture() + ".pdf");
            headers.add("Content-Disposition", "inline; filename=" + safeFilename);
            headers.add("X-Document-SHA256", sha256Checksum);

            // Security headers
            headers.add("X-Content-Type-Options", "nosniff");
            headers.add("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'");

            log.info("PDF downloaded for facture {} by user {} (SHA-256: {})", id, auth.getName(), sha256Checksum);

            return ResponseEntity
                    .ok()
                    .headers(headers)
                    .contentType(MediaType.APPLICATION_PDF)
                    .body(new InputStreamResource(new ByteArrayInputStream(pdfBytes)));

        } catch (Exception e) {
            log.error("Error generating PDF for facture {}: {}", id, e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("error", "Error generating PDF"));
        }
    }

    /**
     * Check if authenticated user can access a facture
     * 
     * Authorization Rules:
     * - ADMIN and VENDEUR: Can access all factures
     * - CLIENT: Can only access their own factures
     */
    private boolean canAccessFacture(Authentication auth, FactureResponseDto facture) {
        boolean hasAdminOrVendeurRole = auth.getAuthorities().stream()
                .anyMatch(a -> a.getAuthority().equals("ADMIN") || a.getAuthority().equals("VENDEUR"));

        if (hasAdminOrVendeurRole) {
            return true; // Admin and Vendeur can access all
        }

        // Correction critique IDOR (A01:2025) : remplacement du 'return true; // TODO'
        // On compare l'id_client de la facture avec l'id_client rattaché au compte connecté
        Long requestedClientId = (facture != null && facture.getClient() != null)
                ? facture.getClient().getId_client()
                : null;
        Long authenticatedClientId = clientDao.findByUser_Username(auth.getName())
                .map(ClientEntity::getId_client)
                .orElse(null);

        try {
            idorValidator.validateClientOwnership(requestedClientId, authenticatedClientId);
            return true;
        } catch (InsecureDirectObjectReferenceException ex) {
            return false;
        }
    }

    /**
     * Calcule le hash SHA-256 en hexadécimal pour vérifier l'intégrité du PDF (OWASP A08:2025)
     */
    private String computeSha256Hex(byte[] data) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return HexFormat.of().formatHex(digest.digest(data));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("Algorithme SHA-256 indisponible", e);
        }
    }

    /**
     * Gestionnaire local pour renvoyer un code 403 Forbidden en cas de détection d'IDOR
     */
    @ExceptionHandler(InsecureDirectObjectReferenceException.class)
    public ResponseEntity<Map<String, String>> handleIdorException(InsecureDirectObjectReferenceException ex) {
        return ResponseEntity.status(HttpStatus.FORBIDDEN)
                .body(Map.of("error", ex.getMessage()));
    }

    /**
     * Sanitize filename to prevent path traversal and injection
     * 
     * Security: Removes potentially dangerous characters
     */
    private String sanitizeFilename(String filename) {
        if (filename == null) {
            return "document.pdf";
        }

        // Remove path traversal attempts and special characters
        return filename.replaceAll("[^a-zA-Z0-9._-]", "_");
    }
}
