package com.estc.mediatech_2.security.validator;

import com.estc.mediatech_2.exception.InsecureDirectObjectReferenceException;
import com.estc.mediatech_2.service.SecurityAuditService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

/**
 * IDOR (Insecure Direct Object Reference) Validator
 * 
 * Prevents users from accessing resources they don't own
 * 
 * Protection Strategy:
 * - Verify object ownership before access
 * - Check authorization for each resource access
 * - Log suspicious access attempts
 * 
 * OWASP: A01:2025 – Broken Access Control
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class IDORValidator {

    // Ajout du service d'audit pour enregistrer les tentatives d'accès non autorisées en base
    private final SecurityAuditService securityAuditService;

    /**
     * Méthode utilitaire pour récupérer le rôle principal de l'utilisateur connecté.
     * Par sécurité (fail-closed), on retourne ANONYMOUS si l'authentification est absente.
     */
    public String extractPrimaryRole(Authentication auth) {
        if (auth == null || auth.getAuthorities() == null) {
            return "ANONYMOUS";
        }
        return auth.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .findFirst()
                .orElse("CLIENT");
    }

    /**
     * Validate that the authenticated user owns the specified client
     */
    public void validateClientOwnership(Long requestedClientId, Long authenticatedClientId) {
        // Correction bug A01:2025 : on vérifie d'abord que les IDs ne sont pas null
        // pour éviter un NullPointerException (erreur 500) et bloquer proprement l'accès (403)
        if (requestedClientId == null || authenticatedClientId == null
                || !requestedClientId.equals(authenticatedClientId)) {
            String username = getCurrentUsername();
            String attemptedResource = "client/" + requestedClientId;

            log.error("🚨 IDOR ATTEMPT DETECTED - User: {}, ClientId: {}, Attempted: {}",
                    username, authenticatedClientId, requestedClientId);

            // On trace l'incident dans la table security_events
            securityAuditService.logUnauthorizedAccess(
                    username,
                    attemptedResource,
                    "IDOR_CHECK",
                    "127.0.0.1",
                    "Tentative d'accès horizontal au profil ou à la ressource d'un autre client");

            throw new InsecureDirectObjectReferenceException(username, attemptedResource);
        }
    }

    /**
     * Validate that the authenticated user has permission to access a facture
     * 
     * Rules:
     * - ADMIN and VENDEUR can access any facture
     * - CLIENT can only access their own factures
     */
    public void validateFactureAccess(String factureOwnerUsername, String requestedBy, String userRole) {
        // Admin et Vendeur ont le droit de consulter toutes les factures
        if ("ADMIN".equals(userRole) || "VENDEUR".equals(userRole)
                || "ROLE_ADMIN".equals(userRole) || "ROLE_VENDEUR".equals(userRole)) {
            return;
        }

        // Pour un client, on vérifie strictement qu'il est bien le propriétaire de la facture
        if (factureOwnerUsername == null || requestedBy == null
                || !requestedBy.equals(factureOwnerUsername)) {
            log.error(
                    "🚨 IDOR ATTEMPT - CLIENT trying to access another client's facture: {} tried to access {}'s facture",
                    requestedBy, factureOwnerUsername);

            securityAuditService.logUnauthorizedAccess(
                    requestedBy,
                    "facture owned by " + factureOwnerUsername,
                    "GET",
                    "127.0.0.1",
                    "Tentative d'accès IDOR sur la facture d'un autre client");

            throw new InsecureDirectObjectReferenceException(requestedBy,
                    "facture owned by " + factureOwnerUsername);
        }
    }

    /**
     * Validate generic resource ownership
     */
    public void validateOwnership(String resourceType, Long resourceId, String ownerUsername) {
        String currentUsername = getCurrentUsername();

        if (!currentUsername.equals(ownerUsername)) {
            log.error("🚨 IDOR ATTEMPT - User: {} tried to access {}/{} owned by {}",
                    currentUsername, resourceType, resourceId, ownerUsername);

            throw new InsecureDirectObjectReferenceException(currentUsername, resourceType + "/" + resourceId);
        }
    }

    /**
     * Validate that a user can only modify their own data
     */
    public void validateSelfModification(String targetUsername) {
        String currentUsername = getCurrentUsername();

        if (!currentUsername.equals(targetUsername) && !isAdmin()) {
            log.error("🚨 IDOR ATTEMPT - User: {} tried to modify user: {}",
                    currentUsername, targetUsername);

            throw new InsecureDirectObjectReferenceException(currentUsername, "user/" + targetUsername);
        }
    }

    /**
     * Check if current user is admin
     */
    private boolean isAdmin() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        return auth != null && auth.getAuthorities().stream()
                .anyMatch(a -> a.getAuthority().equals("ADMIN"));
    }

    /**
     * Get current authenticated username
     */
    private String getCurrentUsername() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        return auth != null ? auth.getName() : "anonymous";
    }

    /**
     * Log unauthorized access attempt (for analytics)
     */
    public void logUnauthorizedAttempt(String resourceType, Object resourceId) {
        String username = getCurrentUsername();
        log.warn("⚠️  Unauthorized access attempt - User: {}, Resource: {}/{}",
                username, resourceType, resourceId);
    }
}
