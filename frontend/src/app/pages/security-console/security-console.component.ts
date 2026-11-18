import { Component, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { SecurityService, UserRiskProfile, InvoiceStats, VulnerabilityReport, SecurityAlert } from '../../services/security.service';

@Component({
    selector: 'app-security-console',
    standalone: true,
    imports: [CommonModule],
    templateUrl: './security-console.component.html',
    styleUrls: ['./security-console.component.css']
})
export class SecurityConsoleComponent implements OnInit {
    alerts: SecurityAlert[] = [];
    riskyUsers: UserRiskProfile[] = [];
    invoiceStats: InvoiceStats | null = null;
    vulnerabilities: VulnerabilityReport[] = [];
    loading = true;
    acknowledgingId: string | null = null;

    constructor(private securityService: SecurityService) { }

    ngOnInit() {
        this.loadData();
    }

    loadData() {
        this.loading = true;

        // Phase 9: Real-Time Active SOC Alerts
        this.securityService.getActiveAlerts().subscribe({
            next: (data) => this.alerts = data,
            error: (e) => console.error('Error fetching alerts:', e)
        });

        this.securityService.getRiskyUsers().subscribe({
            next: (data) => this.riskyUsers = data,
            error: (e) => console.error(e)
        });

        this.securityService.getInvoiceStats().subscribe({
            next: (data) => this.invoiceStats = data,
            error: (e) => console.error(e)
        });

        this.securityService.getVulnerabilities().subscribe({
            next: (data) => this.vulnerabilities = data,
            error: (e) => console.error(e),
            complete: () => this.loading = false
        });
    }

    refreshAlerts() {
        this.securityService.getActiveAlerts().subscribe({
            next: (data) => this.alerts = data,
            error: (e) => console.error('Failed to refresh alerts:', e)
        });
    }

    acknowledgeAlert(alert: SecurityAlert) {
        this.acknowledgingId = alert.id;
        this.securityService.acknowledgeAlert(alert.id).subscribe({
            next: () => {
                alert.acknowledged = true;
                alert.acknowledgedBy = 'ADMIN';
                alert.acknowledgedAt = new Date().toISOString();
                this.acknowledgingId = null;
            },
            error: (err) => {
                console.error('Error acknowledging alert:', err);
                this.acknowledgingId = null;
            }
        });
    }

    getSeverityClass(level: string): string {
        switch (level) {
            case 'CRITICAL': return 'bg-red-600 text-white';
            case 'HIGH': return 'bg-orange-500 text-white';
            case 'MEDIUM': return 'bg-yellow-500 text-black';
            case 'LOW': return 'bg-blue-500 text-white';
            default: return 'bg-gray-500';
        }
    }
}
