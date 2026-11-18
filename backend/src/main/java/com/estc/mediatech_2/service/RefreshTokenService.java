package com.estc.mediatech_2.service;

import com.estc.mediatech_2.dao.RefreshTokenDao;
import com.estc.mediatech_2.models.RefreshTokenEntity;
import com.estc.mediatech_2.models.UserEntity;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.HexFormat;
import java.util.UUID;

/**
 * Service for managing JWT Refresh Tokens
 *
 * Security Features:
 * - Token rotation on refresh
 * - Automatic expiration
 * - Token revocation
 * - Cleanup of expired tokens
 * - Only the SHA-256 hash of a refresh token is stored in the database
 *   (the raw token is only ever known by the client)
 *
 * OWASP Reference: A04:2025 - Cryptographic Failures
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class RefreshTokenService {

    private final RefreshTokenDao refreshTokenDao;

    @Value("${application.security.jwt.refresh-token.expiration:604800000}") // 7 days default
    private Long refreshTokenDurationMs;

    /**
     * Create a new refresh token for a user.
     *
     * Security: the database stores ONLY the SHA-256 hash of the token.
     * The returned entity carries the RAW token (so the controller can send it
     * to the client), but it is a detached copy and is never persisted.
     */
    @Transactional
    public RefreshTokenEntity createRefreshToken(UserEntity user) {
        String rawToken = UUID.randomUUID().toString();

        RefreshTokenEntity refreshToken = new RefreshTokenEntity();
        refreshToken.setUser(user);
        refreshToken.setToken(hashToken(rawToken)); // hash stored in database
        refreshToken.setExpiryDate(Instant.now().plusMillis(refreshTokenDurationMs));
        refreshToken.setCreatedAt(Instant.now());
        refreshToken.setRevoked(false);

        RefreshTokenEntity saved = refreshTokenDao.save(refreshToken);

        // Detached copy (NOT managed by JPA) that exposes the raw token to the caller.
        // Do not modify the managed entity: JPA would write the raw token to the database.
        RefreshTokenEntity result = new RefreshTokenEntity();
        result.setId(saved.getId());
        result.setUser(saved.getUser());
        result.setToken(rawToken);
        result.setExpiryDate(saved.getExpiryDate());
        result.setCreatedAt(saved.getCreatedAt());
        result.setRevoked(saved.isRevoked());
        result.setRevokedAt(saved.getRevokedAt());
        return result;
    }

    /**
     * Find and validate a refresh token (the client sends the raw token,
     * the lookup is done on its SHA-256 hash)
     */
    public RefreshTokenEntity verifyRefreshToken(String token) {
        if (token == null || token.isBlank()) {
            throw new RuntimeException("Refresh token not found");
        }

        RefreshTokenEntity refreshToken = refreshTokenDao.findByToken(hashToken(token))
                .orElseThrow(() -> new RuntimeException("Refresh token not found"));

        if (!refreshToken.isValid()) {
            refreshTokenDao.delete(refreshToken);
            throw new RuntimeException("Refresh token expired or revoked. Please login again.");
        }

        return refreshToken;
    }

    /**
     * Rotate refresh token: revoke old, create new
     *
     * Security Best Practice: Token rotation prevents token reuse attacks
     */
    @Transactional
    public RefreshTokenEntity rotateRefreshToken(String oldToken) {
        RefreshTokenEntity oldRefreshToken = verifyRefreshToken(oldToken);

        // Revoke the old token
        oldRefreshToken.setRevoked(true);
        oldRefreshToken.setRevokedAt(Instant.now());
        refreshTokenDao.save(oldRefreshToken);

        // Create new token (returns the raw token for the client)
        return createRefreshToken(oldRefreshToken.getUser());
    }

    /**
     * Revoke all refresh tokens for a user (e.g., on password change, logout all
     * devices)
     */
    @Transactional
    public void revokeAllUserTokens(UserEntity user) {
        refreshTokenDao.revokeAllUserTokens(user, Instant.now());
        log.info("Revoked all refresh tokens for user: {}", user.getUsername());
    }

    /**
     * Cleanup expired and revoked tokens - runs daily at 3 AM
     *
     * Performance: Prevents database bloat
     */
    @Scheduled(cron = "0 0 3 * * *")
    @Transactional
    public void cleanupExpiredTokens() {
        refreshTokenDao.deleteExpiredOrRevokedTokens(Instant.now());
        log.info("Cleaned up expired and revoked refresh tokens");
    }

    /**
     * SHA-256 hash of a token, as 64 hexadecimal characters.
     * A UUID v4 has 122 bits of randomness, so an unsalted hash is sufficient here
     * (the token cannot be guessed or brute-forced from its hash).
     */
    private String hashToken(String token) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return HexFormat.of().formatHex(digest.digest(token.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 algorithm not available", e);
        }
    }
}
