package com.estc.mediatech_2.service;

import com.estc.mediatech_2.models.FactureEntity;
import com.estc.mediatech_2.models.LigneFactureEntity;
import com.itextpdf.text.*;
import com.itextpdf.text.pdf.PdfPCell;
import com.itextpdf.text.pdf.PdfPTable;
import com.itextpdf.text.pdf.PdfWriter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.math.BigDecimal;
import java.math.RoundingMode;
import java.util.stream.Stream;

/**
 * Service de génération de factures PDF avec garanties d'intégrité (OWASP A08:2025).
 */
@Service
@Slf4j
public class PdfService {

    public ByteArrayInputStream factureReport(FactureEntity facture) {
        // Modif sécurité (A08:2025) : Vérification préalable des données pour éviter de générer un PDF corrompu
        if (facture == null || facture.getRef_facture() == null) {
            throw new IllegalArgumentException("Données de facture incomplètes : génération PDF refusée.");
        }

        Document document = new Document();
        ByteArrayOutputStream out = new ByteArrayOutputStream();

        try {
            PdfWriter.getInstance(document, out);
            document.open();

            // Modif sécurité (A08:2025) : Ajout des métadonnées d'intégrité et de traçabilité dans le document PDF
            document.addTitle("Facture " + facture.getRef_facture());
            document.addSubject("Facture officielle MediaTech - Statut: " + facture.getStatus());
            document.addAuthor("MediaTech Security System");
            document.addCreator("MediaTech OWASP 2025 Engine");
            document.addCreationDate();

            // Add Header
            Font font = FontFactory.getFont(FontFactory.COURIER, 14, BaseColor.BLACK);
            Paragraph para = new Paragraph("Facture: " + facture.getRef_facture(), font);
            para.setAlignment(Element.ALIGN_CENTER);
            document.add(para);
            document.add(Chunk.NEWLINE);

            // Client Info & Statut de la facture
            if (facture.getClient() != null) {
                document.add(new Paragraph(
                        "Client: " + facture.getClient().getNom_client() + " " + facture.getClient().getPrenom_client()));
                document.add(new Paragraph("Téléphone: " + facture.getClient().getTelephone()));
            }
            document.add(new Paragraph("Date: " + facture.getDate_facture().toString()));
            document.add(new Paragraph("Statut: " + (facture.getStatus() != null ? facture.getStatus() : "EN_ATTENTE")));
            document.add(Chunk.NEWLINE);

            // Table
            PdfPTable table = new PdfPTable(4);
            table.setWidthPercentage(100);
            Stream.of("Produit", "Quantité", "Prix Unitaire", "Total")
                    .forEach(headerTitle -> {
                        PdfPCell header = new PdfPCell();
                        Font headFont = FontFactory.getFont(FontFactory.HELVETICA_BOLD);
                        header.setBackgroundColor(BaseColor.LIGHT_GRAY);
                        header.setHorizontalAlignment(Element.ALIGN_CENTER);
                        header.setBorderWidth(2);
                        header.setPhrase(new Phrase(headerTitle, headFont));
                        table.addCell(header);
                    });

            // Modif sécurité (A08:2025) : Calcul exact du Total Global avec BigDecimal pour garantir l'intégrité financière
            BigDecimal grandTotal = BigDecimal.ZERO;
            if (facture.getLigneFactures() != null) {
                for (LigneFactureEntity ligne : facture.getLigneFactures()) {
                    BigDecimal prixUnitaire = ligne.getProduit().getPrix_unitaire();
                    BigDecimal quantite = new BigDecimal(ligne.getQuantite());
                    BigDecimal totalLigne = prixUnitaire.multiply(quantite).setScale(2, RoundingMode.HALF_UP);

                    table.addCell(ligne.getProduit().getLibelle_produit());
                    table.addCell(ligne.getQuantite().toString());
                    table.addCell(prixUnitaire.toString());
                    table.addCell(totalLigne.toString());

                    grandTotal = grandTotal.add(totalLigne);
                }
            }

            document.add(table);
            document.add(Chunk.NEWLINE);

            Font totalFont = FontFactory.getFont(FontFactory.HELVETICA_BOLD, 12, BaseColor.BLACK);
            Paragraph totalPara = new Paragraph("Total Global: " + grandTotal.setScale(2, RoundingMode.HALF_UP) + " DH", totalFont);
            totalPara.setAlignment(Element.ALIGN_RIGHT);
            document.add(totalPara);

            document.close();

        } catch (DocumentException e) {
            // Correction bug A08:2025 : Au lieu d'ignorer l'erreur avec e.printStackTrace() et de renvoyer
            // un flux PDF vide ou corrompu en 200 OK, on lève une exception explicite
            log.error("Erreur lors de la génération du PDF pour la facture {}", facture.getRef_facture(), e);
            throw new IllegalStateException("Erreur d'intégrité lors de la génération du PDF de la facture", e);
        }

        return new ByteArrayInputStream(out.toByteArray());
    }
}
