package com.estc.mediatech_2.service;

import com.estc.mediatech_2.dao.SecurityEventDao;
import com.estc.mediatech_2.models.SecurityEventEntity;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Async;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Collections;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * Security Audit Service for Forensic Analysis & Active SOC Alerting
 * 
 * Features:
 * - Structured security event logging
 * - Severity classification (INFO, WARN, CRITICAL)
 * - Asynchronous logging for performance
 * - Forensic analysis support
 * - Automatic cleanup of old events
 * - Active Real-Time SOC Alerting & Acknowledgment (Phase 9 - A09:2025)
 * 
 * OWASP: A09:2021 / A09:2025 – Security Logging and Alerting Failures
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class SecurityAuditService {

    private final SecurityEventDao securityEventDao;
    private final EmailService emailService;

    /**
     * In-memory registry of active real-time security alerts (Thread-safe)
     */
    private final List<ActiveSecurityAlert> activeAlerts = new CopyOnWriteArrayList<>();

    /**
     * Model representing an active alert in the SOC console
     */
    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class ActiveSecurityAlert {
        private String id;
        private Long eventId;
        private String eventType;
        private String severity;
        private String username;
        private String ipAddress;
        private String resource;
        private String details;
        private Instant timestamp;
        private boolean acknowledged;
        private Instant acknowledgedAt;
        private String acknowledgedBy;
    }

    /**
     * Log unauthorized access attempts
     * Severity: WARN
     */
    @Async
    public void logUnauthorizedAccess(String username, String resource, String method,
            String ipAddress, String details) {
        SecurityEventEntity event = SecurityEventEntity.builder()
                .eventType("UNAUTHORIZED_ACCESS")
                .severity("WARN")
                .username(username != null ? username : "anonymous")
                .resource(resource)
                .ipAddress(ipAddress)
                .method(method)
                .details(details)
                .timestamp(Instant.now())
                .build();

        securityEventDao.save(event);

        log.warn("⚠️  SECURITY EVENT - Type: UNAUTHORIZED_ACCESS, User: {}, Resource: {}, IP: {}",
                username, resource, ipAddress);
    }

    /**
     * Log authentication failures
     * Severity: WARN
     */
    @Async
    public void logAuthenticationFailure(String username, String ipAddress,
            String reason, String userAgent) {
        SecurityEventEntity event = SecurityEventEntity.builder()
                .eventType("AUTHENTICATION_FAILURE")
                .severity("WARN")
                .username(username)
                .ipAddress(ipAddress)
                .details("Reason: " + reason + ", UserAgent: " + userAgent)
                .timestamp(Instant.now())
                .build();

        securityEventDao.save(event);

        log.warn("🔒 SECURITY EVENT - Type: AUTHENTICATION_FAILURE, User: {}, IP: {}, Reason: {}",
                username, ipAddress, reason);
    }

    /**
     * Log suspicious activities
     * Severity: WARN
     */
    @Async
    public void logSuspiciousActivity(String username, String activityType,
            String ipAddress, String details) {
        SecurityEventEntity event = SecurityEventEntity.builder()
                .eventType("SUSPICIOUS_ACTIVITY")
                .severity("WARN")
                .username(username)
                .ipAddress(ipAddress)
                .details(activityType + ": " + details)
                .timestamp(Instant.now())
                .build();

        securityEventDao.save(event);

        log.warn("⚡ SECURITY EVENT - Type: SUSPICIOUS_ACTIVITY, User: {}, Activity: {}, IP: {}",
                username, activityType, ipAddress);
    }

    /**
     * Log security incidents
     * Severity: CRITICAL
     */
    @Async
    public void logSecurityIncident(String username, String incidentType,
            String resource, String ipAddress, String details) {
        SecurityEventEntity event = SecurityEventEntity.builder()
                .eventType(incidentType)
                .severity("CRITICAL")
                .username(username)
                .resource(resource)
                .ipAddress(ipAddress)
                .details(details)
                .timestamp(Instant.now())
                .build();

        SecurityEventEntity saved = securityEventDao.save(event);

        log.error("🚨 CRITICAL SECURITY INCIDENT - Type: {}, User: {}, Resource: {}, IP: {}, Details: {}",
                incidentType, username, resource, ipAddress, details);

        // Trigger active alerting for SOC
        triggerSecurityAlert(saved);
    }

    /**
     * Log critical security incidents (highest severity)
     * Severity: CRITICAL
     */
    @Async
    public void logCriticalSecurityIncident(String username, String incidentType,
            String resource, String ipAddress, String details) {
        SecurityEventEntity event = SecurityEventEntity.builder()
                .eventType(incidentType)
                .severity("CRITICAL")
                .username(username)
                .resource(resource)
                .ipAddress(ipAddress)
                .details(details)
                .timestamp(Instant.now())
                .build();

        SecurityEventEntity saved = securityEventDao.save(event);

        log.error("🚨🚨🚨 CRITICAL SECURITY INCIDENT - Type: {}, User: {}, Resource: {}, IP: {}",
                incidentType, username, resource, ipAddress);

        // Trigger active alerting for SOC
        triggerSecurityAlert(saved);
    }

    /**
     * Log successful security-relevant actions
     * Severity: INFO
     */
    @Async
    public void logSecurityAction(String username, String action, String details) {
        SecurityEventEntity event = SecurityEventEntity.builder()
                .eventType(action)
                .severity("INFO")
                .username(username)
                .details(details)
                .timestamp(Instant.now())
                .build();

        securityEventDao.save(event);

        log.info("ℹ️  SECURITY ACTION - Type: {}, User: {}, Details: {}",
                action, username, details);
    }

    /**
     * Cleanup old security events (retention: 90 days)
     * Runs daily at 1:00 AM
     */
    @Scheduled(cron = "0 0 1 * * *")
    public void cleanupOldSecurityEvents() {
        Instant cutoff = Instant.now().minus(90, ChronoUnit.DAYS);
        long deletedCount = securityEventDao.deleteByTimestampBefore(cutoff);

        log.info("🧹 Security Event Cleanup - Deleted {} events older than 90 days", deletedCount);
    }

    /**
     * Trigger security alerts for critical incidents (Phase 9 - A09:2025)
     * - Retains active alerts in-memory for the SOC dashboard
     * - Dispatches email notification via EmailService
     */
    public void triggerSecurityAlert(SecurityEventEntity event) {
        String alertId = UUID.randomUUID().toString();
        ActiveSecurityAlert alert = ActiveSecurityAlert.builder()
                .id(alertId)
                .eventId(event.getId())
                .eventType(event.getEventType())
                .severity(event.getSeverity())
                .username(event.getUsername() != null ? event.getUsername() : "anonymous")
                .ipAddress(event.getIpAddress())
                .resource(event.getResource())
                .details(event.getDetails())
                .timestamp(event.getTimestamp() != null ? event.getTimestamp() : Instant.now())
                .acknowledged(false)
                .build();

        // 1. Enregistrer dans la liste des alertes actives (les plus récentes en tête)
        activeAlerts.add(0, alert);
        if (activeAlerts.size() > 200) {
            activeAlerts.remove(activeAlerts.size() - 1);
        }

        // 2. Envoi d'alerte mail via EmailService
        try {
            emailService.sendSecurityAlertEmail(
                    "soc-admin@mediatech.com",
                    event.getEventType(),
                    event.getSeverity(),
                    event.getUsername(),
                    event.getIpAddress(),
                    event.getDetails());
        } catch (Exception e) {
            log.warn("Notice: Impossible d'envoyer l'alerte email : {}", e.getMessage());
        }

        log.error("🔔 ACTIVE SOC ALERT TRIGGERED [ID: {}] - Type: {}, User: {}, IP: {}",
                alertId, event.getEventType(), event.getUsername(), event.getIpAddress());
    }

    /**
     * Get all active security alerts for the SOC dashboard
     */
    public List<ActiveSecurityAlert> getActiveAlerts() {
        return Collections.unmodifiableList(activeAlerts);
    }

    /**
     * Acknowledge an active security alert by ID
     */
    public boolean acknowledgeAlert(String alertId, String acknowledgedBy) {
        for (ActiveSecurityAlert alert : activeAlerts) {
            if (alert.getId().equals(alertId)) {
                alert.setAcknowledged(true);
                alert.setAcknowledgedAt(Instant.now());
                alert.setAcknowledgedBy(acknowledgedBy);
                log.info("✅ SOC Alert [{}] acknowledged by {}", alertId, acknowledgedBy);
                return true;
            }
        }
        return false;
    }
}
