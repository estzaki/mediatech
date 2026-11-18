package com.estc.mediatech_2.controllers;

import com.estc.mediatech_2.dto.DashboardStatsDto;
import com.estc.mediatech_2.service.DashboardService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Contrôleur des statistiques du tableau de bord administrateur.
 * OWASP A01:2025 - Broken Access Control
 */
@RestController
@RequestMapping("/api/dashboard")
@RequiredArgsConstructor
public class DashboardController {

    private final DashboardService dashboardService;

    // Modif sécurité (A01:2025) : Activation du contrôle d'accès (qui était commenté)
    // et utilisation de hasAuthority('ADMIN') car nos rôles en base ne portent pas le préfixe ROLE_
    @GetMapping("/admin")
    @PreAuthorize("hasAuthority('ADMIN')")
    public ResponseEntity<DashboardStatsDto> getAdminStats() {
        return ResponseEntity.ok(dashboardService.getAdminStats());
    }
}
