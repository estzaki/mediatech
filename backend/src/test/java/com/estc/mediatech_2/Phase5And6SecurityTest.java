package com.estc.mediatech_2;

import com.estc.mediatech_2.dao.*;
import com.estc.mediatech_2.dto.*;
import com.estc.mediatech_2.exception.MassAssignmentException;
import com.estc.mediatech_2.exception.PotentialSQLInjectionException;
import com.estc.mediatech_2.models.ClientEntity;
import com.estc.mediatech_2.models.FactureEntity;
import com.estc.mediatech_2.models.UserEntity;
import com.estc.mediatech_2.security.validator.MassAssignmentValidator;
import com.estc.mediatech_2.security.validator.SQLInjectionValidator;
import com.estc.mediatech_2.service.*;
import jakarta.validation.ConstraintViolation;
import jakarta.validation.Validation;
import jakarta.validation.Validator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import java.lang.reflect.Proxy;
import java.math.BigDecimal;
import java.time.LocalDateTime;
import java.util.*;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Automated Verification Suite for OWASP 2025 Migration (Java 25 compatible):
 * - Phase 5: A05:2025 – Injection (Jakarta Bean Validation + SQLInjectionValidator)
 * - Phase 6: A06:2025 – Insecure Design (MassAssignmentValidator + Active Invoice Velocity Limit)
 */
class Phase5And6SecurityTest {

    private Validator beanValidator;
    private SQLInjectionValidator sqlInjectionValidator;
    private MassAssignmentValidator massAssignmentValidator;

    private List<FactureEntity> storedFactures;
    private Map<Long, ClientEntity> storedClients;
    private Map<Long, UserEntity> storedUsers;
    private List<String> auditedActivities;

    private ClientServiceImpl clientService;
    private ProduitServiceImpl produitService;
    private FactureServiceImpl factureService;
    private UserServiceImpl userService;

    @SuppressWarnings("unchecked")
    private <T> T createDaoStub(Class<T> iface, java.lang.reflect.InvocationHandler handler) {
        return (T) Proxy.newProxyInstance(iface.getClassLoader(), new Class<?>[] { iface }, handler);
    }

    @BeforeEach
    void setUp() {
        beanValidator = Validation.buildDefaultValidatorFactory().getValidator();
        sqlInjectionValidator = new SQLInjectionValidator();
        massAssignmentValidator = new MassAssignmentValidator();

        storedFactures = new ArrayList<>();
        storedClients = new HashMap<>();
        storedUsers = new HashMap<>();
        auditedActivities = new ArrayList<>();

        ClientDao clientDao = createDaoStub(ClientDao.class, (proxy, method, args) -> {
            if ("findById".equals(method.getName())) {
                return Optional.ofNullable(storedClients.get((Long) args[0]));
            }
            if ("findByTelephone".equals(method.getName())) {
                return Optional.empty();
            }
            return null;
        });

        ProduitDao produitDao = createDaoStub(ProduitDao.class, (proxy, method, args) -> null);

        FactureDao factureDao = createDaoStub(FactureDao.class, (proxy, method, args) -> {
            if ("findAll".equals(method.getName())) {
                return storedFactures;
            }
            return null;
        });

        UserDao userDao = createDaoStub(UserDao.class, (proxy, method, args) -> {
            if ("findById".equals(method.getName())) {
                return Optional.ofNullable(storedUsers.get((Long) args[0]));
            }
            if ("findByUsername".equals(method.getName())) {
                return Optional.empty();
            }
            return null;
        });

        SecurityEventDao securityEventDao = createDaoStub(SecurityEventDao.class, (proxy, method, args) -> null);

        EmailService emailService = new EmailService() {
            @Override
            public void sendVerificationEmail(String to, String code) {
                // no-op for unit tests
            }

            @Override
            public void sendSecurityAlertEmail(String toEmail, String eventType, String severity, String user, String ipAddress, String details) {
                // no-op for unit tests
            }
        };

        SecurityAuditService securityAuditService = new SecurityAuditService(securityEventDao, emailService) {
            @Override
            public void logSuspiciousActivity(String username, String activityType, String ipAddress, String details) {
                auditedActivities.add(username + ":" + activityType + ":" + details);
            }
        };

        clientService = new ClientServiceImpl(clientDao, sqlInjectionValidator, massAssignmentValidator);
        produitService = new ProduitServiceImpl(produitDao, sqlInjectionValidator, massAssignmentValidator);
        factureService = new FactureServiceImpl(
                factureDao, clientDao, produitDao, userDao,
                massAssignmentValidator, sqlInjectionValidator, securityAuditService);
        userService = new UserServiceImpl(
                userDao, clientDao, new BCryptPasswordEncoder(), emailService,
                sqlInjectionValidator, massAssignmentValidator);

        SecurityContextHolder.getContext().setAuthentication(
                new UsernamePasswordAuthenticationToken(
                        "c1", "password", List.of(new SimpleGrantedAuthority("CLIENT"))));
    }

    // =========================================================================
    // PHASE 5: A05:2025 – INJECTION (Jakarta Bean Validation & SQLi Protection)
    // =========================================================================

    @Test
    @DisplayName("Phase 5: Jakarta Bean Validation rejects invalid DTOs and cascades @Valid on FactureRequestDto")
    void testJakartaBeanValidationOnAllRequestDtos() {
        // 1. LoginRequestDto: blank fields rejected
        LoginRequestDto invalidLogin = new LoginRequestDto();
        invalidLogin.setUsername("");
        invalidLogin.setPassword("12");
        assertFalse(beanValidator.validate(invalidLogin).isEmpty());

        // 2. UserRequestDto: invalid email and short password rejected
        UserRequestDto invalidUser = new UserRequestDto();
        invalidUser.setUsername("john");
        invalidUser.setEmail("not-an-email");
        invalidUser.setPassword("123");
        Set<ConstraintViolation<UserRequestDto>> userViolations = beanValidator.validate(invalidUser);
        assertEquals(2, userViolations.size());

        // 3. ClientRequestDto: blank phone / short name rejected
        ClientRequestDto invalidClient = new ClientRequestDto();
        invalidClient.setNom_client("A");
        invalidClient.setPrenom_client("");
        invalidClient.setTelephone("123");
        assertEquals(4, beanValidator.validate(invalidClient).size());

        // 4. ProduitRequestDto: negative price (@Positive) and negative stock (@Min(0)) rejected
        ProduitRequestDto invalidProduit = new ProduitRequestDto();
        invalidProduit.setRef_produit("REF-01");
        invalidProduit.setLibelle_produit("Laptop");
        invalidProduit.setPrix_unitaire(BigDecimal.valueOf(-10));
        invalidProduit.setQte_stock(-1);
        assertEquals(2, beanValidator.validate(invalidProduit).size());

        // 5. FactureRequestDto + cascading @Valid on LigneFactureRequestDto (qte <= 0 rejected)
        LigneFactureRequestDto invalidLine = new LigneFactureRequestDto();
        invalidLine.setId_produit(1L);
        invalidLine.setQte(0);

        FactureRequestDto invalidFacture = new FactureRequestDto();
        invalidFacture.setId_client(1L);
        invalidFacture.setLigneFactures(List.of(invalidLine));
        assertFalse(beanValidator.validate(invalidFacture).isEmpty());
    }

    @Test
    @DisplayName("Phase 5: SQLInjectionValidator blocks SQLi payloads in login, register, client search, and services")
    void testSqlInjectionBlockedAcrossInputs() {
        // 1. /api/clients/search -> clientService.findByTel
        assertThrows(PotentialSQLInjectionException.class,
                () -> clientService.findByTel("06000000' OR '1'='1"));

        // 2. /api/auth/login -> sqlInjectionValidator.validateLoginRequest
        LoginRequestDto maliciousLogin = new LoginRequestDto();
        maliciousLogin.setUsername("admin' OR '1'='1");
        maliciousLogin.setPassword("password");
        assertThrows(PotentialSQLInjectionException.class,
                () -> sqlInjectionValidator.validateLoginRequest(maliciousLogin));

        // 3. /api/auth/register -> userService.createUser
        UserRequestDto maliciousRegister = new UserRequestDto();
        maliciousRegister.setUsername("attacker'; DROP TABLE users;--");
        maliciousRegister.setEmail("attacker@test.com");
        maliciousRegister.setPassword("secret123");
        maliciousRegister.setRole("CLIENT");
        assertThrows(PotentialSQLInjectionException.class,
                () -> userService.createUser(maliciousRegister));

        // 4. Product creation -> produitService.save
        ProduitRequestDto maliciousProduct = new ProduitRequestDto();
        maliciousProduct.setRef_produit("P1 UNION SELECT username, password FROM users");
        maliciousProduct.setLibelle_produit("Laptop");
        maliciousProduct.setPrix_unitaire(BigDecimal.TEN);
        maliciousProduct.setQte_stock(5);
        assertThrows(PotentialSQLInjectionException.class,
                () -> produitService.save(maliciousProduct));
    }

    // =========================================================================
    // PHASE 6: A06:2025 – INSECURE DESIGN (Mass Assignment & Velocity Limits)
    // =========================================================================

    @Test
    @DisplayName("Phase 6: MassAssignmentValidator blocks privilege escalation and protected fields")
    void testMassAssignmentProtection() {
        // Non-admin user ("c1" with CLIENT authority) tries to escalate role to ADMIN during user update
        UserEntity existingUser = new UserEntity();
        existingUser.setId_user(10L);
        existingUser.setUsername("c1");
        existingUser.setRole("CLIENT");
        storedUsers.put(10L, existingUser);

        UserRequestDto escalateDto = new UserRequestDto();
        escalateDto.setUsername("c1");
        escalateDto.setRole("ADMIN");

        assertThrows(MassAssignmentException.class,
                () -> userService.updateUser(10L, escalateDto));

        // Direct protected field checks for client, facture, user
        assertThrows(MassAssignmentException.class,
                () -> massAssignmentValidator.validateClientUpdate(List.of("nom_client", "user")));
        assertThrows(MassAssignmentException.class,
                () -> massAssignmentValidator.validateFactureUpdate(List.of("status", "vendeur")));
    }

    @Test
    @DisplayName("Phase 6: FactureServiceImpl rejects zero/negative quantities and logs suspicious activity")
    void testFactureRejectsZeroOrNegativeQuantity() {
        LigneFactureRequestDto line = new LigneFactureRequestDto();
        line.setId_produit(1L);
        line.setQte(0);

        FactureRequestDto request = new FactureRequestDto();
        request.setId_client(1L);
        request.setLigneFactures(List.of(line));

        assertThrows(IllegalArgumentException.class, () -> factureService.createFacture(request));
        assertTrue(auditedActivities.stream()
                .anyMatch(a -> a.contains("c1:INVALID_INVOICE_QUANTITY") && a.contains("0")));
    }

    @Test
    @DisplayName("Phase 6: FactureServiceImpl enforces active velocity limit (> 5 pending invoices/day) and audits anomaly")
    void testFactureVelocityLimitEnforcedAndAudited() {
        ClientEntity client = new ClientEntity();
        client.setId_client(1L);
        client.setNom_client("Demo");
        storedClients.put(1L, client);

        // Simulate 5 existing EN_ATTENTE invoices created today for client 1
        for (int i = 0; i < 5; i++) {
            FactureEntity f = new FactureEntity();
            f.setId_facture((long) (i + 1));
            f.setClient(client);
            f.setDate_facture(LocalDateTime.now());
            f.setStatus("EN_ATTENTE");
            storedFactures.add(f);
        }

        LigneFactureRequestDto line = new LigneFactureRequestDto();
        line.setId_produit(1L);
        line.setQte(2);

        FactureRequestDto sixthInvoice = new FactureRequestDto();
        sixthInvoice.setId_client(1L);
        sixthInvoice.setLigneFactures(List.of(line));

        // 6th invoice on the same day must be blocked actively with IllegalStateException
        IllegalStateException ex = assertThrows(
                IllegalStateException.class,
                () -> factureService.createFacture(sixthInvoice));
        assertTrue(ex.getMessage().contains("Velocity limit exceeded"));

        // Verify SecurityAuditService logged the anomaly
        assertTrue(auditedActivities.stream()
                .anyMatch(a -> a.contains("c1:VELOCITY_LIMIT_EXCEEDED") && a.contains("Client ID 1")));
    }
}
