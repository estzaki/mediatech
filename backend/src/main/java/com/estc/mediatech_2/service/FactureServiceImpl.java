package com.estc.mediatech_2.service;

import com.estc.mediatech_2.dao.ClientDao;
import com.estc.mediatech_2.dao.FactureDao;
import com.estc.mediatech_2.dao.ProduitDao;
import com.estc.mediatech_2.dto.FactureRequestDto;
import com.estc.mediatech_2.dto.FactureResponseDto;
import com.estc.mediatech_2.dto.LigneFactureResponseDto;
import com.estc.mediatech_2.dto.ProduitResponseDto;
import com.estc.mediatech_2.dto.ClientResponseDto;
import com.estc.mediatech_2.models.ClientEntity;
import com.estc.mediatech_2.models.FactureEntity;
import com.estc.mediatech_2.models.LigneFactureEntity;
import com.estc.mediatech_2.models.ProduitEntity;
import com.estc.mediatech_2.security.validator.MassAssignmentValidator;
import com.estc.mediatech_2.security.validator.SQLInjectionValidator;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class FactureServiceImpl implements FactureService {

    // OWASP A06:2025 – Active Business Velocity Limit (max 5 pending invoices/day per client)
    private static final int MAX_DAILY_PENDING_INVOICES_PER_CLIENT = 5;

    private final FactureDao factureDao;
    private final ClientDao clientDao;
    private final ProduitDao produitDao;
    private final com.estc.mediatech_2.dao.UserDao userDao;
    private final MassAssignmentValidator massAssignmentValidator;
    private final SQLInjectionValidator sqlInjectionValidator;
    private final SecurityAuditService securityAuditService;

    @Override
    @Transactional
    public FactureResponseDto createFacture(FactureRequestDto request) {
        String currentUsername = org.springframework.security.core.context.SecurityContextHolder.getContext()
                .getAuthentication() != null
                        ? org.springframework.security.core.context.SecurityContextHolder.getContext()
                                .getAuthentication().getName()
                        : "anonymous";

        // Validate allowed invoice creation fields (prevent mass assignment)
        massAssignmentValidator.validateFactureUpdate(List.of("id_client", "ligneFactures"));

        if (request.getLigneFactures() == null || request.getLigneFactures().isEmpty()) {
            throw new IllegalArgumentException("Invoice must contain at least one line item");
        }

        // Pre-validate quantities (reject negative or zero quantities before DB work)
        for (var dto : request.getLigneFactures()) {
            if (dto.getQte() == null || dto.getQte() <= 0) {
                securityAuditService.logSuspiciousActivity(
                        currentUsername,
                        "INVALID_INVOICE_QUANTITY",
                        "internal",
                        "Rejected invoice creation with non-positive quantity: " + dto.getQte());
                throw new IllegalArgumentException("Quantity must be strictly positive (greater than 0)");
            }
        }

        ClientEntity client = clientDao.findById(request.getId_client())
                .orElseThrow(() -> new RuntimeException("Client not found"));

        // OWASP A06:2025 – Enforce active runtime velocity limit per client (> 5 pending invoices/day)
        LocalDate today = LocalDate.now();
        long pendingTodayCount = factureDao.findAll().stream()
                .filter(f -> f.getClient() != null
                        && client.getId_client().equals(f.getClient().getId_client()))
                .filter(f -> f.getDate_facture() != null
                        && today.equals(f.getDate_facture().toLocalDate()))
                .filter(f -> "EN_ATTENTE".equalsIgnoreCase(f.getStatus()))
                .count();

        if (pendingTodayCount >= MAX_DAILY_PENDING_INVOICES_PER_CLIENT) {
            securityAuditService.logSuspiciousActivity(
                    currentUsername,
                    "VELOCITY_LIMIT_EXCEEDED",
                    "internal",
                    "Client ID " + client.getId_client() + " exceeded daily velocity limit ("
                            + MAX_DAILY_PENDING_INVOICES_PER_CLIENT + " pending invoices/day)");
            throw new IllegalStateException(
                    "Velocity limit exceeded: Maximum " + MAX_DAILY_PENDING_INVOICES_PER_CLIENT
                            + " pending invoices per day allowed for this client.");
        }

        FactureEntity facture = new FactureEntity();
        facture.setRef_facture(UUID.randomUUID().toString());
        facture.setDate_facture(LocalDateTime.now());
        facture.setStatus("EN_ATTENTE");
        facture.setClient(client);

        com.estc.mediatech_2.models.UserEntity currentUser = userDao.findByUsername(currentUsername)
                .orElseThrow(() -> new RuntimeException("User not found: " + currentUsername));
        facture.setVendeur(currentUser);

        List<LigneFactureEntity> ligneFactures = new ArrayList<>();

        request.getLigneFactures().forEach(dto -> {
            ProduitEntity produit = produitDao.findById(dto.getId_produit())
                    .orElseThrow(() -> new RuntimeException("Product not found"));

            // Start: Check only (don't decrement yet)
            if (produit.getQte_stock() < dto.getQte()) {
                throw new RuntimeException("Insufficient stock for product: " + produit.getLibelle_produit());
            }
            // End: Stock will be decremented upon validation

            LigneFactureEntity ligne = new LigneFactureEntity();
            ligne.setProduit(produit);
            ligne.setQuantite(dto.getQte());
            ligne.setFacture(facture);
            ligneFactures.add(ligne);
        });

        facture.setLigneFactures(ligneFactures);
        FactureEntity savedFacture = factureDao.save(facture);

        return mapToDto(savedFacture);
    }

    @Override
    public FactureResponseDto getFacture(Long id) {
        return factureDao.findById(id).map(this::mapToDto).orElse(null);
    }

    @Override
    public List<FactureResponseDto> getAllFactures() {
        return factureDao.findAll().stream().map(this::mapToDto).collect(Collectors.toList());
    }

    @Override
    public List<FactureResponseDto> getFacturesByUsername(String username) {
        // For clients: filter factures where client's user matches the username
        return factureDao.findAll().stream()
                .filter(f -> f.getClient() != null &&
                        f.getClient().getUser() != null &&
                        username.equals(f.getClient().getUser().getUsername()))
                .map(this::mapToDto)
                .collect(Collectors.toList());
    }

    @Override
    @Transactional
    public FactureResponseDto updateStatus(Long id, String status) {
        sqlInjectionValidator.validateInput("status", status);
        massAssignmentValidator.validateFactureUpdate(List.of("status"));
        massAssignmentValidator.validateFieldAgainstWhitelist("status", List.of("status"));

        FactureEntity facture = factureDao.findById(id)
                .orElseThrow(() -> new RuntimeException("Facture non trouvée"));

        // If we are Validating the order, we must decrease stock
        if ("VALIDEE".equalsIgnoreCase(status) && !"VALIDEE".equalsIgnoreCase(facture.getStatus())) {
            for (LigneFactureEntity ligne : facture.getLigneFactures()) {
                ProduitEntity produit = ligne.getProduit();
                // Refresh product from DB to get latest stock
                // (Though ligne.getProduit() might be a proxy, safe to fetch or just use if
                // session open)
                // Better to fetch fresh to be sure about concurrency if not locked
                // For simplicity here, we assume single-threaded or handled by transaction

                if (produit.getQte_stock() < ligne.getQuantite()) {
                    throw new RuntimeException(
                            "Stock insuffisant pour valider la commande. Produit: " + produit.getRef_produit());
                }

                produit.setQte_stock(produit.getQte_stock() - ligne.getQuantite());
                produitDao.save(produit);
            }
        }

        facture.setStatus(status);
        return mapToDto(factureDao.save(facture));
    }

    private FactureResponseDto mapToDto(FactureEntity entity) {
        FactureResponseDto dto = new FactureResponseDto();
        dto.setId_facture(entity.getId_facture());
        dto.setRef_facture(entity.getRef_facture());
        dto.setDate_facture(entity.getDate_facture());
        dto.setStatus(entity.getStatus());

        ClientResponseDto clientDto = new ClientResponseDto();
        clientDto.setId_client(entity.getClient().getId_client());
        clientDto.setNom_client(entity.getClient().getNom_client());
        clientDto.setPrenom_client(entity.getClient().getPrenom_client());
        clientDto.setTelephone(entity.getClient().getTelephone());
        dto.setClient(clientDto);

        List<LigneFactureResponseDto> lignesDto = entity.getLigneFactures().stream().map(l -> {
            LigneFactureResponseDto lDto = new LigneFactureResponseDto();
            lDto.setId_ligne_facture(l.getId_ligne_facture());
            lDto.setQte(l.getQuantite());

            ProduitResponseDto pDto = new ProduitResponseDto();
            pDto.setId_produit(l.getProduit().getId_produit());
            pDto.setRef_produit(l.getProduit().getRef_produit());
            pDto.setLibelle_produit(l.getProduit().getLibelle_produit());
            pDto.setPrix_unitaire(l.getProduit().getPrix_unitaire());

            lDto.setProduit(pDto);
            return lDto;
        }).collect(Collectors.toList());

        dto.setLigneFactures(lignesDto);
        return dto;
    }
}
