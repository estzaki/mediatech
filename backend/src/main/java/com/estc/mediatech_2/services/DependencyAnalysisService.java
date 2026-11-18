package com.estc.mediatech_2.services;

import com.estc.mediatech_2.dto.DependencyDTO;
import com.estc.mediatech_2.dto.DependencyReportDTO;
import com.estc.mediatech_2.dto.VulnerabilityDTO;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.time.Instant;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Service pour analyser les dépendances et leurs vulnérabilités à partir du SBOM CycloneDX.
 * 
 * OWASP: A06:2021 – Vulnerable and Outdated Components
 */
@Service
@Slf4j
public class DependencyAnalysisService {

    public DependencyReportDTO generateDependencyReport() {
        log.info("🔍 Génération du rapport de dépendances depuis le SBOM CycloneDX...");

        List<DependencyDTO> dependencies = analyzeDependencies();

        int totalDeps = dependencies.size();
        int vulnerableDeps = (int) dependencies.stream()
                .filter(d -> d.getVulnerabilityCount() != null && d.getVulnerabilityCount() > 0)
                .count();

        Map<String, Integer> vulnerabilityCountBySeverity = calculateSeverityDistribution(dependencies);
        Map<String, Integer> dependenciesByCategory = dependencies.stream()
                .collect(Collectors.groupingBy(
                        d -> d.getCategory() != null ? d.getCategory() : "compile",
                        Collectors.collectingAndThen(Collectors.counting(), Long::intValue)));

        int critical = vulnerabilityCountBySeverity.getOrDefault("CRITICAL", 0);
        int high = vulnerabilityCountBySeverity.getOrDefault("HIGH", 0);
        int medium = vulnerabilityCountBySeverity.getOrDefault("MEDIUM", 0);
        int low = vulnerabilityCountBySeverity.getOrDefault("LOW", 0);

        String overallRisk = calculateOverallRisk(critical, high, medium, low);

        return DependencyReportDTO.builder()
                .generatedAt(Instant.now())
                .totalDependencies(totalDeps)
                .vulnerableDependencies(vulnerableDeps)
                .vulnerabilityCountBySeverity(vulnerabilityCountBySeverity)
                .dependenciesByCategory(dependenciesByCategory)
                .dependencies(dependencies)
                .criticalCount(critical)
                .highCount(high)
                .mediumCount(medium)
                .lowCount(low)
                .overallRiskLevel(overallRisk)
                .build();
    }

    private List<DependencyDTO> analyzeDependencies() {
        List<DependencyDTO> dependencies = new ArrayList<>();

        try {
            // Chargement direct depuis le classpath (où Maven place le SBOM compilé)
            InputStream inputStream = getClass().getResourceAsStream("/META-INF/sbom/application.cdx.json");

            if (inputStream == null) {
                // Fallback sur les chemins fichiers si exécuté hors classpath
                File sbomFile = findSbomFile();
                if (sbomFile != null && sbomFile.exists()) {
                    inputStream = new FileInputStream(sbomFile);
                }
            }

            if (inputStream == null) {
                log.warn("❌ Fichier SBOM introuvable, utilisation du fallback");
                return getHardcodedDependencies();
            }

            ObjectMapper mapper = new ObjectMapper();
            JsonNode rootNode = mapper.readTree(inputStream);
            JsonNode componentsNode = rootNode.get("components");

            if (componentsNode != null && componentsNode.isArray()) {
                for (JsonNode comp : componentsNode) {
                    String groupId = comp.has("group") ? comp.get("group").asText() : "unknown.group";
                    String artifactId = comp.has("name") ? comp.get("name").asText() : "unknown.artifact";
                    String version = comp.has("version") ? comp.get("version").asText() : "N/A";
                    String scope = "compile";

                    List<VulnerabilityDTO> vulnerabilities = checkVulnerabilities(groupId, artifactId, version);
                    String riskLevel = determineRiskLevel(vulnerabilities);

                    dependencies.add(DependencyDTO.builder()
                            .groupId(groupId)
                            .artifactId(artifactId)
                            .version(version)
                            .scope(scope)
                            .category(categorizeScope(scope))
                            .vulnerabilities(vulnerabilities)
                            .vulnerabilityCount(vulnerabilities.size())
                            .riskLevel(riskLevel)
                            .build());
                }
            }

            log.info("✅ {} dépendances chargées depuis le SBOM CycloneDX", dependencies.size());

        } catch (Exception e) {
            log.error("❌ Erreur lors de la lecture du SBOM: {}", e.getMessage(), e);
            return getHardcodedDependencies();
        }

        return dependencies;
    }

    private File findSbomFile() {
        String[] possiblePaths = {
                "target/classes/META-INF/sbom/application.cdx.json",
                "backend/target/classes/META-INF/sbom/application.cdx.json",
                "target/bom.json",
                "target/cyclonedx/bom.json",
                "backend/target/bom.json",
                "backend/target/cyclonedx/bom.json",
                "bom.json"
        };

        for (String path : possiblePaths) {
            File file = new File(path);
            if (file.exists()) {
                return file;
            }
        }
        return null;
    }

    private List<VulnerabilityDTO> checkVulnerabilities(String groupId, String artifactId, String version) {
        List<VulnerabilityDTO> vulnerabilities = new ArrayList<>();
        if (version == null) version = "N/A";

        if (artifactId.contains("itextpdf") || groupId.contains("itextpdf")) {
            if (version.startsWith("5.5.13") && !version.equals("5.5.13.5")) {
                vulnerabilities.add(VulnerabilityDTO.builder()
                        .cveId("CVE-2017-9096")
                        .severity("MEDIUM")
                        .cvssScore(5.3)
                        .description("iText PDF contains a vulnerability allowing signature validation bypass.")
                        .affectedVersions("5.5.13.4 and below")
                        .fixedVersion("7.x")
                        .reference("https://nvd.nist.gov/vuln/detail/CVE-2017-9096")
                        .build());
            }
        }

        if (artifactId.contains("jjwt") || groupId.contains("jsonwebtoken")) {
            if (version.startsWith("0.11.") || version.startsWith("0.10.") || version.startsWith("0.9.")) {
                vulnerabilities.add(VulnerabilityDTO.builder()
                        .cveId("CVE-2023-XXXX")
                        .severity("HIGH")
                        .cvssScore(7.5)
                        .description("Older JJWT version vulnerable to key parsing/security issues.")
                        .affectedVersions("< 0.12.6")
                        .fixedVersion("0.12.6")
                        .reference("https://github.com/jwtk/jjwt")
                        .build());
            }
        }

        return vulnerabilities;
    }

    private String determineRiskLevel(List<VulnerabilityDTO> vulnerabilities) {
        if (vulnerabilities.isEmpty()) return "NONE";
        for (VulnerabilityDTO v : vulnerabilities) {
            if ("CRITICAL".equalsIgnoreCase(v.getSeverity())) return "CRITICAL";
        }
        for (VulnerabilityDTO v : vulnerabilities) {
            if ("HIGH".equalsIgnoreCase(v.getSeverity())) return "HIGH";
        }
        for (VulnerabilityDTO v : vulnerabilities) {
            if ("MEDIUM".equalsIgnoreCase(v.getSeverity())) return "MEDIUM";
        }
        return "LOW";
    }

    private String categorizeScope(String scope) {
        return (scope == null || scope.isEmpty()) ? "compile" : scope;
    }

    private Map<String, Integer> calculateSeverityDistribution(List<DependencyDTO> dependencies) {
        Map<String, Integer> distribution = new HashMap<>();
        distribution.put("CRITICAL", 0);
        distribution.put("HIGH", 0);
        distribution.put("MEDIUM", 0);
        distribution.put("LOW", 0);

        for (DependencyDTO dep : dependencies) {
            if (dep.getVulnerabilities() != null) {
                for (VulnerabilityDTO v : dep.getVulnerabilities()) {
                    String severity = v.getSeverity() != null ? v.getSeverity().toUpperCase() : "LOW";
                    distribution.put(severity, distribution.getOrDefault(severity, 0) + 1);
                }
            }
        }
        return distribution;
    }

    private String calculateOverallRisk(int critical, int high, int medium, int low) {
        if (critical > 0) return "CRITICAL";
        if (high > 0) return "HIGH";
        if (medium > 0) return "MEDIUM";
        if (low > 0) return "LOW";
        return "NONE";
    }

    private List<DependencyDTO> getHardcodedDependencies() {
        List<DependencyDTO> deps = new ArrayList<>();
        deps.add(DependencyDTO.builder()
                .groupId("org.springframework.boot")
                .artifactId("spring-boot-starter-web")
                .version("3.2.2")
                .scope("compile")
                .category("compile")
                .vulnerabilities(new ArrayList<>())
                .vulnerabilityCount(0)
                .riskLevel("NONE")
                .build());
        return deps;
    }
}