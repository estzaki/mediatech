package com.estc.mediatech_2.controllers;

import com.estc.mediatech_2.dto.DependencyReportDTO;
import com.estc.mediatech_2.services.DependencyAnalysisService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

/**
 * Controller pour l'analyse des dépendances et vulnérabilités
 *
 * OWASP: A03:2025 - Software Supply Chain Failures (SBOM CycloneDX)
 * Accès réservé aux administrateurs uniquement
 */
@RestController
@RequestMapping("/api/dependencies")
@RequiredArgsConstructor
@PreAuthorize("hasAuthority('ADMIN')")
@Slf4j
public class DependencyController {

    private static final String SBOM_RESOURCE = "META-INF/sbom/application.cdx.json";

    private final DependencyAnalysisService dependencyAnalysisService;

    /**
     * Obtenir le rapport complet des dépendances et vulnérabilités
     */
    @GetMapping("/report")
    public ResponseEntity<DependencyReportDTO> getDependencyReport() {
        log.info("Admin accessing dependency report");

        DependencyReportDTO report = dependencyAnalysisService.generateDependencyReport();

        log.info("Dependency report generated: {} total, {} vulnerable",
                report.getTotalDependencies(),
                report.getVulnerableDependencies());

        return ResponseEntity.ok(report);
    }

    /**
     * Obtenir le SBOM (Software Bill of Materials) au format CycloneDX JSON.
     * Le fichier est généré à la compilation par cyclonedx-maven-plugin.
     */
    @GetMapping("/sbom")
    public ResponseEntity<String> getSbom() throws IOException {
        log.info("Admin accessing SBOM");

        Resource sbom = new ClassPathResource(SBOM_RESOURCE);
        if (!sbom.exists()) {
            log.warn("SBOM file not found on classpath: {}", SBOM_RESOURCE);
            return ResponseEntity.status(404)
                    .contentType(MediaType.APPLICATION_JSON)
                    .body("{\"error\":\"SBOM non genere\"}");
        }

        try (InputStream in = sbom.getInputStream()) {
            String json = new String(in.readAllBytes(), StandardCharsets.UTF_8);
            return ResponseEntity.ok()
                    .contentType(MediaType.APPLICATION_JSON)
                    .body(json);
        }
    }
}
