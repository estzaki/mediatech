package com.estc.mediatech_2.service;

import lombok.Builder;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

/**
 * Service de supervision système sécurisé contre le scan de ports arbitraire (SSRF).
 * Dans l'OWASP Top 10:2025, la catégorie SSRF (A10:2021) a été fusionnée dans A01:2025 (Broken Access Control).
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class SystemMonitoringService {

    // Modif sécurité (A01:2025 - Anti-SSRF) : Liste blanche stricte des ports applicatifs autorisés
    // pour interdire l'énumération arbitraire des 65535 ports du système hôte
    private static final Set<Integer> ALLOWED_MONITORED_PORTS = Set.of(80, 443, 3306, 4200, 8080, 8090);

    private final SecurityAuditService securityAuditService;

    @Data
    @Builder
    public static class PortStatus {
        private int port;
        private boolean isOpen;
        private String service; // Educated guess
    }

    /**
     * Vérifie uniquement l'état des ports présents dans la liste blanche (allowlist)
     * compris dans la plage [startPort, endPort] sur l'interface loopback locale.
     */
    public List<PortStatus> scanLocalPorts(int startPort, int endPort) {
        log.info("🔍 Starting allowlisted port health check: {}-{}", startPort, endPort);

        // Journalisation de l'action de diagnostic dans la table d'audit security_events
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        String username = (auth != null) ? auth.getName() : "system";
        securityAuditService.logSecurityAction(
                username,
                "LOCAL_PORT_HEALTHCHECK",
                String.format("Vérification des ports autorisés dans la plage [%d - %d]", startPort, endPort));

        List<PortStatus> results = new ArrayList<>();

        // On ne teste que les ports de la liste blanche compris dans l'intervalle demandé
        for (int port : ALLOWED_MONITORED_PORTS.stream().sorted().toList()) {
            if (port < startPort || port > endPort) {
                continue;
            }
            results.add(checkPort("127.0.0.1", port));
        }

        log.info("✅ Allowlisted port check completed. Checked {} ports ({} open).",
                results.size(),
                results.stream().filter(PortStatus::isOpen).count());
        return results;
    }

    private PortStatus checkPort(String host, int port) {
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(host, port), 200);
            return PortStatus.builder()
                    .port(port)
                    .isOpen(true)
                    .service(guessService(port))
                    .build();
        } catch (IOException e) {
            return PortStatus.builder()
                    .port(port)
                    .isOpen(false)
                    .service(guessService(port))
                    .build();
        }
    }

    private String guessService(int port) {
        switch (port) {
            case 80:
                return "HTTP";
            case 443:
                return "HTTPS";
            case 3306:
                return "MySQL";
            case 8080:
                return "HTTP-ALT";
            case 8090:
                return "MediaTech-Backend";
            case 4200:
                return "MediaTech-Frontend";
            case 22:
                return "SSH";
            case 21:
                return "FTP";
            default:
                return "Unknown";
        }
    }
}
