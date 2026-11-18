package com.estc.mediatech_2.security.validator;

import com.estc.mediatech_2.dto.ClientRequestDto;
import com.estc.mediatech_2.dto.LoginRequestDto;
import com.estc.mediatech_2.dto.ProduitRequestDto;
import com.estc.mediatech_2.dto.UserRequestDto;
import com.estc.mediatech_2.exception.PotentialSQLInjectionException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.ConstraintViolation;
import jakarta.validation.ConstraintViolationException;
import jakarta.validation.Valid;
import jakarta.validation.Validator;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.MethodParameter;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpInputMessage;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.servlet.HandlerInterceptor;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;
import org.springframework.web.servlet.mvc.method.annotation.RequestBodyAdviceAdapter;

import java.lang.reflect.Type;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * SQL Injection Validator (Global Controller Advice + Service Validator)
 * 
 * Detects and blocks potential SQL injection attempts in user input
 * and enforces Jakarta Bean Validation on request DTOs.
 * 
 * OWASP: A05:2025 – Injection (migrated from A03:2021)
 */
@Component
@RestControllerAdvice
@Order(Ordered.HIGHEST_PRECEDENCE)
@Slf4j
public class SQLInjectionValidator extends RequestBodyAdviceAdapter implements WebMvcConfigurer {

    @Autowired(required = false)
    private Validator beanValidator;

    // Common SQL injection patterns
    private static final Pattern[] SQL_INJECTION_PATTERNS = {
            Pattern.compile("('.*(--|;|/\\*|\\*/|xp_|sp_|0x).*')", Pattern.CASE_INSENSITIVE),
            Pattern.compile("(\\bUNION\\b.*\\bSELECT\\b)", Pattern.CASE_INSENSITIVE),
            Pattern.compile("(\\bSELECT\\b.*\\bFROM\\b.*\\bWHERE\\b)", Pattern.CASE_INSENSITIVE),
            Pattern.compile("(\\bINSERT\\b.*\\bINTO\\b.*\\bVALUES\\b)", Pattern.CASE_INSENSITIVE),
            Pattern.compile("(\\bUPDATE\\b.*\\bSET\\b)", Pattern.CASE_INSENSITIVE),
            Pattern.compile("(\\bDELETE\\b.*\\bFROM\\b)", Pattern.CASE_INSENSITIVE),
            Pattern.compile("(\\bDROP\\b.*\\bTABLE\\b)", Pattern.CASE_INSENSITIVE),
            Pattern.compile("(\\bEXEC\\b|\\bEXECUTE\\b)", Pattern.CASE_INSENSITIVE),
            Pattern.compile("('\\s*OR\\s*'?1'?\\s*=\\s*'?1)", Pattern.CASE_INSENSITIVE),
            Pattern.compile("('\\s*OR\\s*.*\\s*=\\s*.*)", Pattern.CASE_INSENSITIVE),
            Pattern.compile("(CHAR\\(|CHR\\(|ASCII\\()", Pattern.CASE_INSENSITIVE),
            Pattern.compile("(WAITFOR\\s+DELAY)", Pattern.CASE_INSENSITIVE),
            Pattern.compile("(BENCHMARK\\()", Pattern.CASE_INSENSITIVE),
            Pattern.compile("(SLEEP\\()", Pattern.CASE_INSENSITIVE)
    };

    /**
     * Global Query Parameter Validation (e.g. /api/clients/search?tel=..., /api/auth/verify?code=...)
     */
    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        registry.addInterceptor(new HandlerInterceptor() {
            @Override
            public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) {
                for (Map.Entry<String, String[]> entry : request.getParameterMap().entrySet()) {
                    String paramName = entry.getKey();
                    for (String value : entry.getValue()) {
                        validateInput(paramName, value);
                    }
                }
                return true;
            }
        }).addPathPatterns("/api/**");
    }

    /**
     * Global @RequestBody interception for SQLi + Jakarta @Valid DTO validation
     */
    @Override
    public boolean supports(MethodParameter methodParameter, Type targetType,
            Class<? extends HttpMessageConverter<?>> converterType) {
        return true;
    }

    @Override
    public Object afterBodyRead(Object body, HttpInputMessage inputMessage, MethodParameter parameter,
            Type targetType, Class<? extends HttpMessageConverter<?>> converterType) {
        // 1. Validate SQL injection patterns FIRST on controller inputs (/api/auth/login, /api/auth/register, etc.)
        if (body instanceof LoginRequestDto dto) {
            validateLoginRequest(dto);
        } else if (body instanceof UserRequestDto dto) {
            validateUserRequest(dto);
        } else if (body instanceof ClientRequestDto dto) {
            validateClientRequest(dto);
        } else if (body instanceof ProduitRequestDto dto) {
            validateProduitRequest(dto);
        } else if (body instanceof Map<?, ?> map) {
            map.forEach((k, v) -> {
                if (v instanceof String s) {
                    validateInput(String.valueOf(k), s);
                }
            });
        }

        // 2. Enforce Jakarta Bean Validation (@NotBlank, @Size, @Email, @Positive, @Min(1), @Valid)
        if (beanValidator != null && !parameter.hasParameterAnnotation(Valid.class)) {
            Set<ConstraintViolation<Object>> violations = beanValidator.validate(body);
            if (!violations.isEmpty()) {
                throw new ConstraintViolationException(violations);
            }
        }

        return body;
    }

    @ExceptionHandler(ConstraintViolationException.class)
    public ResponseEntity<Map<String, Object>> handleConstraintViolation(ConstraintViolationException ex) {
        String details = ex.getConstraintViolations().stream()
                .map(v -> v.getPropertyPath() + ": " + v.getMessage())
                .collect(Collectors.joining("; "));
        Map<String, Object> response = new HashMap<>();
        response.put("timestamp", Instant.now());
        response.put("status", HttpStatus.BAD_REQUEST.value());
        response.put("error", "Validation Failed");
        response.put("message", details);
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(response);
    }

    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<Map<String, Object>> handleIllegalArgument(IllegalArgumentException ex) {
        Map<String, Object> response = new HashMap<>();
        response.put("timestamp", Instant.now());
        response.put("status", HttpStatus.BAD_REQUEST.value());
        response.put("error", "Invalid Request");
        response.put("message", ex.getMessage());
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(response);
    }

    @ExceptionHandler(IllegalStateException.class)
    public ResponseEntity<Map<String, Object>> handleVelocityLimit(IllegalStateException ex) {
        Map<String, Object> response = new HashMap<>();
        response.put("timestamp", Instant.now());
        response.put("status", HttpStatus.TOO_MANY_REQUESTS.value());
        response.put("error", "Business Velocity Limit Exceeded");
        response.put("message", ex.getMessage());
        return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS).body(response);
    }

    /**
     * Validate LoginRequestDto fields
     */
    public void validateLoginRequest(LoginRequestDto request) {
        if (request == null) return;
        validateInput("username", request.getUsername());
        validateInput("password", request.getPassword());
    }

    /**
     * Validate UserRequestDto fields
     */
    public void validateUserRequest(UserRequestDto request) {
        if (request == null) return;
        validateInput("username", request.getUsername());
        if (request.getEmail() != null && !request.getEmail().trim().isEmpty()) {
            validateInput("email", request.getEmail());
            validateEmail(request.getEmail());
        }
        validateInput("password", request.getPassword());
        validateInput("role", request.getRole());
    }

    /**
     * Validate ClientRequestDto fields
     */
    public void validateClientRequest(ClientRequestDto request) {
        if (request == null) return;
        validateInput("nom_client", request.getNom_client());
        validateInput("prenom_client", request.getPrenom_client());
        validateInput("telephone", request.getTelephone());
    }

    /**
     * Validate ProduitRequestDto fields
     */
    public void validateProduitRequest(ProduitRequestDto request) {
        if (request == null) return;
        validateInput("ref_produit", request.getRef_produit());
        validateInput("libelle_produit", request.getLibelle_produit());
        validateInput("imageUrl", request.getImageUrl());
    }

    /**
     * Validate input for SQL injection patterns
     * 
     * @param fieldName Name of the field being validated
     * @param input     User input to validate
     * @throws PotentialSQLInjectionException if suspicious patterns detected
     */
    public void validateInput(String fieldName, String input) {
        if (input == null || input.trim().isEmpty()) {
            return; // Empty input is safe
        }

        for (Pattern pattern : SQL_INJECTION_PATTERNS) {
            if (pattern.matcher(input).find()) {
                log.error("🚨 SQL INJECTION PATTERN DETECTED - Field: {}, Pattern: {}, Input: {}",
                        fieldName, pattern.pattern(), sanitizeForLog(input));
                throw new PotentialSQLInjectionException(fieldName, input);
            }
        }
    }

    /**
     * Validate multiple inputs at once
     */
    public void validateInputs(String... inputs) {
        for (int i = 0; i < inputs.length; i++) {
            if (inputs[i] != null) {
                validateInput("param_" + i, inputs[i]);
            }
        }
    }

    /**
     * Check if input contains suspicious characters
     */
    public boolean containsSuspiciousCharacters(String input) {
        if (input == null)
            return false;

        // Check for SQL comment markers
        if (input.contains("--") || input.contains("/*") || input.contains("*/")) {
            return true;
        }

        // Check for common SQL injection attempts
        return input.matches(".*[';\"\\\\].*");
    }

    /**
     * Sanitize string for safe logging (prevent log injection)
     */
    private String sanitizeForLog(String input) {
        if (input == null)
            return "null";
        // Truncate and remove newlines/tabs to prevent log injection
        String sanitized = input.length() > 100 ? input.substring(0, 100) + "..." : input;
        return sanitized.replaceAll("[\\r\\n\\t]", " ");
    }

    /**
     * Strict alphanumeric validation (for IDs, usernames, etc.)
     */
    public void validateAlphanumeric(String fieldName, String input) {
        if (input != null && !input.matches("^[a-zA-Z0-9_-]+$")) {
            log.warn("⚠️  Non-alphanumeric input detected - Field: {}, Input: {}",
                    fieldName, sanitizeForLog(input));
            throw new PotentialSQLInjectionException(fieldName, input);
        }
    }

    /**
     * Validate email format (prevent injection via email field)
     */
    public void validateEmail(String email) {
        if (email != null && !email.matches("^[A-Za-z0-9+_.-]+@[A-Za-z0-9.-]+$")) {
            log.warn("⚠️  Invalid email format - Email: {}", sanitizeForLog(email));
            throw new PotentialSQLInjectionException("email", email);
        }
    }
}
