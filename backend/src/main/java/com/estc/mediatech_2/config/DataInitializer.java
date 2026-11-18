package com.estc.mediatech_2.config;

import com.estc.mediatech_2.dao.ClientDao;
import com.estc.mediatech_2.dao.UserDao;
import com.estc.mediatech_2.models.ClientEntity;
import com.estc.mediatech_2.models.UserEntity;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
@RequiredArgsConstructor
@Slf4j
public class DataInitializer {

    private final UserDao userDao;
    private final ClientDao clientDao;
    private final PasswordEncoder passwordEncoder;

    // Identifiants de démonstration : lus depuis des variables d'environnement
    // (valeurs par défaut conservées pour que l'application reste utilisable en local).
    // Pour changer un mot de passe sans toucher au code :
    //   $env:ADMIN_PASSWORD="nouveau_mot_de_passe"
    @Value("${app.init.admin.username:fatihaa}")
    private String adminUsername;

    @Value("${app.init.admin.password:${ADMIN_PASSWORD:fatiha1233}}")
    private String adminPassword;

    @Value("${app.init.vendeur.username:vendeur}")
    private String vendeurUsername;

    @Value("${app.init.vendeur.password:${VENDEUR_PASSWORD:vendeur123}}")
    private String vendeurPassword;

    @Value("${app.init.client.username:c1}")
    private String clientUsername;

    @Value("${app.init.client.password:${CLIENT_PASSWORD:1234567}}")
    private String clientPassword;

    @Bean
    CommandLineRunner initDatabase() {
        return args -> {
            log.info("Initialisation des utilisateurs par défaut...");

            updateOrCreateUser(adminUsername, adminPassword, UserEntity.ROLE_ADMIN);
            updateOrCreateUser(vendeurUsername, vendeurPassword, UserEntity.ROLE_VENDEUR);
            UserEntity clientUser = updateOrCreateUser(clientUsername, clientPassword, UserEntity.ROLE_CLIENT);
            createClientProfileIfNotExists(clientUser);

            log.info("Initialisation terminée : comptes ADMIN, VENDEUR et CLIENT prêts");
        };
    }

    private UserEntity updateOrCreateUser(String username, String password, String role) {
        UserEntity user = userDao.findByUsername(username).orElse(new UserEntity());
        user.setUsername(username);

        // Aucun log de mot de passe ni de hash (OWASP A04:2025 - Cryptographic Failures)
        user.setPassword(passwordEncoder.encode(password));
        user.setRole(role);
        user.setEnabled(true);

        UserEntity saved = userDao.save(user);
        log.info("Utilisateur {} (rôle {}) sauvegardé en base", username, role);

        return saved;
    }

    private void createClientProfileIfNotExists(UserEntity user) {
        if (clientDao.findByUser_Username(user.getUsername()).isEmpty()) {
            ClientEntity clientSpec = new ClientEntity();
            clientSpec.setNom_client("Client Demo");
            clientSpec.setPrenom_client("Test");
            clientSpec.setTelephone("0600000000");
            clientSpec.setUser(user);
            clientDao.save(clientSpec);
            log.info("Profil Client créé pour {}", user.getUsername());
        }
    }
}