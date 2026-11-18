import { Injectable } from '@angular/core';
import { HttpClient, HttpHeaders } from '@angular/common/http';
import { Observable } from 'rxjs';

export interface UserRiskProfile {
    username: string;
    riskScore: number;
    riskLevel: string;
    incidentCount: number;
    abnormalInvoiceCount: number;
    topRiskFactor: string;
    recommendations: string[];
}

export interface InvoiceStats {
    totalInvoices: number;
    highValueFlagged: number;
    suspiciousTransactions: any[];
}

export interface VulnerabilityReport {
    component: string;
    cveId: string;
    severity: string;
    description: string;
    remediation: string;
}

export interface SecurityAlert {
    id: string;
    eventId?: number;
    eventType: string;
    severity: string;
    username: string;
    ipAddress: string;
    resource?: string;
    details: string;
    timestamp: string;
    acknowledged: boolean;
    acknowledgedAt?: string;
    acknowledgedBy?: string;
}

@Injectable({
    providedIn: 'root'
})
export class SecurityService {
    private apiUrl = 'http://localhost:8090/api/admin/security';
    private socApiUrl = 'http://localhost:8090/api/security';

    constructor(private http: HttpClient) { }

    private getHeaders(): HttpHeaders {
        const token = localStorage.getItem('token') || localStorage.getItem('accessToken');
        return new HttpHeaders().set('Authorization', `Bearer ${token}`);
    }

    getRiskyUsers(limit: number = 10): Observable<UserRiskProfile[]> {
        return this.http.get<UserRiskProfile[]>(`${this.apiUrl}/risky-users?limit=${limit}`, { headers: this.getHeaders() });
    }

    getInvoiceStats(): Observable<InvoiceStats> {
        return this.http.get<InvoiceStats>(`${this.apiUrl}/invoice-stats`, { headers: this.getHeaders() });
    }

    getVulnerabilities(): Observable<VulnerabilityReport[]> {
        return this.http.get<VulnerabilityReport[]>(`${this.apiUrl}/vulnerabilities`, { headers: this.getHeaders() });
    }

    /**
     * Real-time SOC Alerts (Phase 9 - A09:2025)
     */
    getActiveAlerts(): Observable<SecurityAlert[]> {
        return this.http.get<SecurityAlert[]>(`${this.socApiUrl}/alerts`, { headers: this.getHeaders() });
    }

    /**
     * Acknowledge an active security alert (Phase 9 - A09:2025)
     */
    acknowledgeAlert(alertId: string): Observable<any> {
        return this.http.post<any>(`${this.socApiUrl}/alerts/${alertId}/acknowledge`, {}, { headers: this.getHeaders() });
    }
}
