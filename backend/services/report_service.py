"""
Report Service
Generates threat intelligence reports
"""

import logging
from typing import Dict

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class ReportService:
    """
    Service for generating threat intelligence reports
    """

    def generate_analysis(self, scan_data: Dict) -> Dict[str, str]:
        """
        Generate human-readable analysis from scan data
        Args:
            scan_data: Complete scan result dictionary
        Returns:
            Dictionary of analysis sections
        """
        analysis = {}

        # ML Analysis
        ml_score = scan_data.get("ml_score", 0)
        prediction = scan_data.get("prediction", "unknown")

        if prediction == "phishing":
            analysis["ml_analysis"] = f"Machine learning model detected phishing with {ml_score*100:.1f}% probability. This URL exhibits suspicious characteristics."
        else:
            analysis["ml_analysis"] = f"Machine learning model classified as legitimate with {(1-ml_score)*100:.1f}% confidence."

        # VirusTotal Analysis
        vt_data = scan_data.get("threat_intelligence", {}).get("virustotal", {})
        malicious = vt_data.get("malicious", 0)

        if malicious > 0:
            analysis["virustotal_analysis"] = f"VirusTotal flagged this URL as malicious by {malicious} security vendors. HIGH RISK."
        elif vt_data.get("status") == "analyzed":
            analysis["virustotal_analysis"] = "VirusTotal found no malicious flags from security vendors."
        else:
            analysis["virustotal_analysis"] = "VirusTotal data not available."

        # URLhaus Analysis
        urlhaus_data = scan_data.get("threat_intelligence", {}).get("urlhaus", {})
        if urlhaus_data.get("found"):
            threat = urlhaus_data.get("threat", "unknown")
            analysis["urlhaus_analysis"] = f"URL found in URLhaus malware database. Threat type: {threat}. HIGH RISK."
        else:
            analysis["urlhaus_analysis"] = "URL not found in URLhaus malware database."

        # WHOIS Analysis
        whois_data = scan_data.get("threat_intelligence", {}).get("whois", {})
        domain_age = whois_data.get("domain_age_days")

        if domain_age is not None:
            if domain_age < 30:
                analysis["whois_analysis"] = f"Domain is only {domain_age} days old. Very recently registered domains are often used in phishing. SUSPICIOUS."
            elif domain_age < 365:
                analysis["whois_analysis"] = f"Domain is {domain_age} days old (less than 1 year). Moderately recent registration."
            else:
                years = domain_age // 365
                analysis["whois_analysis"] = f"Domain is {years} year(s) old. Established domain age is a positive indicator."
        else:
            analysis["whois_analysis"] = "Domain age information not available."

        # DNS Analysis
        dns_data = scan_data.get("threat_intelligence", {}).get("dns", {})
        a_records = dns_data.get("a_records", [])

        if len(a_records) > 0:
            analysis["dns_analysis"] = f"Domain resolves to {len(a_records)} IP address(es). DNS records present."
        else:
            analysis["dns_analysis"] = "No DNS records found. Domain may not be active or properly configured. SUSPICIOUS."

        # Risk Score Summary
        risk_score = scan_data.get("risk_score", 0)

        if risk_score >= 75:
            analysis["risk_summary"] = f"CRITICAL RISK ({risk_score}/100). Strong indicators of phishing. BLOCK IMMEDIATELY."
        elif risk_score >= 50:
            analysis["risk_summary"] = f"HIGH RISK ({risk_score}/100). Multiple suspicious indicators detected. Exercise caution."
        elif risk_score >= 25:
            analysis["risk_summary"] = f"MEDIUM RISK ({risk_score}/100). Some suspicious indicators present. Proceed with caution."
        else:
            analysis["risk_summary"] = f"LOW RISK ({risk_score}/100). URL appears legitimate based on available data."

        return analysis

    def calculate_risk_score(
        self,
        ml_score: float,
        virustotal_data: Dict,
        urlhaus_data: Dict,
        whois_data: Dict,
        dns_data: Dict
    ) -> int:
        """
        Calculate composite risk score (0-100)
        Combines ML predictions with threat intelligence
        """
        risk_score = 0

        # ML Score (40 points max)
        risk_score += int(ml_score * 40)

        # VirusTotal (25 points max)
        vt_malicious = virustotal_data.get("malicious", 0)
        if vt_malicious > 0:
            risk_score += min(25, vt_malicious * 2)

        # URLhaus (20 points max)
        if urlhaus_data.get("found"):
            risk_score += 20

        # Domain Age (10 points max)
        domain_age_days = whois_data.get("domain_age_days")
        if domain_age_days is not None:
            if domain_age_days < 7:
                risk_score += 10
            elif domain_age_days < 30:
                risk_score += 7
            elif domain_age_days < 90:
                risk_score += 4

        # DNS (5 points max)
        a_records = dns_data.get("a_records", [])
        if len(a_records) == 0:
            risk_score += 5

        # Cap at 100
        risk_score = min(100, risk_score)

        return risk_score


# Singleton instance
_report_service_instance = None


def get_report_service() -> ReportService:
    """Get singleton report service instance"""
    global _report_service_instance
    if _report_service_instance is None:
        _report_service_instance = ReportService()
    return _report_service_instance
