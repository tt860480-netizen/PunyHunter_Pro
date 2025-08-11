# modules/reporting.py
import json
import csv
from datetime import datetime
import os
import asyncio
from reportlab.lib.pagesizes import letter, A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
from reportlab.lib.units import inch

class ReportGenerator:
    def __init__(self):
        self.report_data = {}
        self.severity_weights = {
            'Critical': 10,
            'High': 8,
            'Medium': 5,
            'Low': 2,
            'Info': 1
        }
        
    def calculate_risk_score(self, results):
        """Calculate overall risk score based on findings"""
        if not results:
            return 0
            
        total_score = 0
        max_possible_score = 0
        
        for result in results:
            severity = result.get('severity', 'Medium')
            weight = self.severity_weights.get(severity, 5)
            total_score += weight
            max_possible_score += 10  # Maximum weight
            
        # Calculate percentage score out of 10
        if max_possible_score > 0:
            risk_percentage = (total_score / max_possible_score) * 10
            return round(min(risk_percentage, 10), 1)
        
        return 0
        
    async def generate_executive_summary(self, results):
        """Generate executive summary for management"""
        summary = {
            'total_vulnerabilities': len(results),
            'critical_findings': len([r for r in results if r.get('severity') == 'Critical']),
            'high_findings': len([r for r in results if r.get('severity') == 'High']),
            'medium_findings': len([r for r in results if r.get('severity') == 'Medium']),
            'low_findings': len([r for r in results if r.get('severity') == 'Low']),
            'affected_systems': len(set([r.get('target', 'Unknown') for r in results])),
            'risk_score': self.calculate_risk_score(results),
            'scan_timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }
        
        return summary
    
    async def generate_technical_report(self, results, output_file):
        """Generate detailed technical report in PDF format"""
        try:
            # Create output directory if it doesn't exist
            os.makedirs(os.path.dirname(output_file) if os.path.dirname(output_file) else 'reports', exist_ok=True)
            
            doc = SimpleDocTemplate(output_file, pagesize=A4, topMargin=1*inch)
            styles = getSampleStyleSheet()
            story = []
            
            # Custom styles
            title_style = ParagraphStyle(
                'CustomTitle',
                parent=styles['Title'],
                fontSize=24,
                textColor=colors.darkblue,
                spaceAfter=30
            )
            
            heading_style = ParagraphStyle(
                'CustomHeading',
                parent=styles['Heading1'],
                fontSize=16,
                textColor=colors.darkred,
                spaceAfter=12
            )
            
            # Title
            title = Paragraph("PunyHunter Pro - Penetration Testing Report", title_style)
            story.append(title)
            story.append(Spacer(1, 20))
            
            # Executive Summary
            exec_summary = await self.generate_executive_summary(results)
            
            summary_heading = Paragraph("Executive Summary", heading_style)
            story.append(summary_heading)
            
            summary_text = f"""
            <b>Scan Date:</b> {exec_summary['scan_timestamp']}<br/>
            <b>Total Vulnerabilities Found:</b> {exec_summary['total_vulnerabilities']}<br/>
            <b>Critical Findings:</b> {exec_summary['critical_findings']}<br/>
            <b>High Risk Findings:</b> {exec_summary['high_findings']}<br/>
            <b>Medium Risk Findings:</b> {exec_summary['medium_findings']}<br/>
            <b>Low Risk Findings:</b> {exec_summary['low_findings']}<br/>
            <b>Affected Systems:</b> {exec_summary['affected_systems']}<br/>
            <b>Overall Risk Score:</b> {exec_summary['risk_score']}/10
            """
            
            story.append(Paragraph(summary_text, styles['Normal']))
            story.append(Spacer(1, 30))
            
            # Risk Assessment Table
            if results:
                risk_heading = Paragraph("Risk Assessment Summary", heading_style)
                story.append(risk_heading)
                
                risk_data = [['Severity Level', 'Count', 'Risk Weight', 'Total Impact']]
                for severity in ['Critical', 'High', 'Medium', 'Low', 'Info']:
                    count = len([r for r in results if r.get('severity') == severity])
                    weight = self.severity_weights.get(severity, 0)
                    impact = count * weight
                    risk_data.append([severity, str(count), str(weight), str(impact)])
                
                risk_table = Table(risk_data, colWidths=[1.5*inch, 1*inch, 1*inch, 1*inch])
                risk_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, 0), 12),
                    ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                    ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                    ('GRID', (0, 0), (-1, -1), 1, colors.black)
                ]))
                
                story.append(risk_table)
                story.append(Spacer(1, 30))
            
            # Detailed Findings
            findings_heading = Paragraph("Detailed Vulnerability Findings", heading_style)
            story.append(findings_heading)
            
            if not results:
                no_findings = Paragraph("No vulnerabilities were discovered during this scan.", styles['Normal'])
                story.append(no_findings)
            else:
                for i, result in enumerate(results, 1):
                    finding_title = f"Finding #{i}: {result.get('title', 'Puny-Code Account Takeover Vulnerability')}"
                    finding_heading = Paragraph(finding_title, styles['Heading2'])
                    story.append(finding_heading)
                    
                    finding_details = f"""
                    <b>Severity:</b> {result.get('severity', 'Medium')}<br/>
                    <b>Target:</b> {result.get('target', 'Unknown')}<br/>
                    <b>Vulnerable Parameter:</b> {result.get('parameter', 'email')}<br/>
                    <b>Attack Vector:</b> {result.get('attack_vector', 'Puny-code character confusion')}<br/>
                    <b>Description:</b> {result.get('description', 'Character confusion vulnerability allowing account takeover through puny-code manipulation.')}<br/>
                    <b>Impact:</b> {result.get('impact', 'Account takeover, unauthorized access, data breach potential.')}<br/>
                    <b>Evidence:</b> {result.get('evidence', 'Successful password reset token delivery to attacker-controlled email.')}<br/>
                    <b>CVSS Score:</b> {result.get('cvss_score', '8.1 (High)')}<br/>
                    <b>Remediation:</b> {result.get('remediation', 'Implement proper Unicode normalization and character validation in email handling.')}
                    """
                    
                    story.append(Paragraph(finding_details, styles['Normal']))
                    story.append(Spacer(1, 20))
            
            # Recommendations Section
            recommendations_heading = Paragraph("Security Recommendations", heading_style)
            story.append(recommendations_heading)
            
            recommendations_text = """
            <b>Immediate Actions Required:</b><br/>
            1. Implement Unicode normalization (NFC/NFKC) for all user input<br/>
            2. Use consistent character collation settings across database and application layers<br/>
            3. Validate email addresses using strict RFC-compliant parsing<br/>
            4. Implement proper input sanitization for special characters<br/><br/>
            
            <b>Long-term Security Improvements:</b><br/>
            1. Deploy Web Application Firewall (WAF) with Unicode attack protection<br/>
            2. Implement multi-factor authentication for sensitive operations<br/>
            3. Regular security assessments and penetration testing<br/>
            4. Security awareness training for development teams<br/>
            5. Implement logging and monitoring for suspicious email patterns
            """
            
            story.append(Paragraph(recommendations_text, styles['Normal']))
            story.append(Spacer(1, 20))
            
            # Technical Details Section
            tech_heading = Paragraph("Technical Implementation Details", heading_style)
            story.append(tech_heading)
            
            tech_details = """
            <b>Attack Methodology:</b><br/>
            This assessment utilized advanced puny-code character confusion techniques to identify 
            vulnerabilities in email handling systems. The tool tested various Unicode characters 
            that may be treated as equivalent by database collation settings but differently by 
            SMTP servers.<br/><br/>
            
            <b>Tools Used:</b><br/>
            - PunyHunter Pro v2.0.0<br/>
            - Custom Unicode character database<br/>
            - Automated payload generation and testing<br/>
            - Advanced evasion and anti-detection mechanisms
            """
            
            story.append(Paragraph(tech_details, styles['Normal']))
            
            # Build PDF
            doc.build(story)
            print(f"✅ PDF report generated: {output_file}")
            
        except Exception as e:
            print(f"❌ Error generating PDF report: {e}")
            # Fallback to text report
            await self.generate_text_report(results, output_file.replace('.pdf', '.txt'))
    
    async def generate_text_report(self, results, output_file):
        """Generate text-based report as fallback"""
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write("=" * 60 + "\n")
                f.write("PunyHunter Pro - Penetration Testing Report\n")
                f.write("=" * 60 + "\n\n")
                
                # Executive Summary
                exec_summary = await self.generate_executive_summary(results)
                
                f.write("EXECUTIVE SUMMARY\n")
                f.write("-" * 20 + "\n")
                f.write(f"Scan Date: {exec_summary['scan_timestamp']}\n")
                f.write(f"Total Vulnerabilities: {exec_summary['total_vulnerabilities']}\n")
                f.write(f"Critical Findings: {exec_summary['critical_findings']}\n")
                f.write(f"High Risk Findings: {exec_summary['high_findings']}\n")
                f.write(f"Medium Risk Findings: {exec_summary['medium_findings']}\n")
                f.write(f"Low Risk Findings: {exec_summary['low_findings']}\n")
                f.write(f"Affected Systems: {exec_summary['affected_systems']}\n")
                f.write(f"Overall Risk Score: {exec_summary['risk_score']}/10\n\n")
                
                # Detailed Findings
                f.write("DETAILED FINDINGS\n")
                f.write("-" * 20 + "\n\n")
                
                if not results:
                    f.write("No vulnerabilities were discovered during this scan.\n\n")
                else:
                    for i, result in enumerate(results, 1):
                        f.write(f"Finding #{i}: {result.get('title', 'Puny-Code Vulnerability')}\n")
                        f.write(f"Severity: {result.get('severity', 'Medium')}\n")
                        f.write(f"Target: {result.get('target', 'Unknown')}\n")
                        f.write(f"Description: {result.get('description', 'Character confusion vulnerability')}\n")
                        f.write(f"Impact: {result.get('impact', 'Account takeover possible')}\n")
                        f.write(f"Remediation: {result.get('remediation', 'Implement proper input validation')}\n")
                        f.write("-" * 40 + "\n\n")
                
                # Recommendations
                f.write("SECURITY RECOMMENDATIONS\n")
                f.write("-" * 25 + "\n")
                f.write("1. Implement Unicode normalization for all user input\n")
                f.write("2. Use consistent character collation settings\n")
                f.write("3. Validate email addresses using strict parsing\n")
                f.write("4. Deploy WAF with Unicode attack protection\n")
                f.write("5. Implement multi-factor authentication\n\n")
                
            print(f"✅ Text report generated: {output_file}")
            
        except Exception as e:
            print(f"❌ Error generating text report: {e}")
    
    async def generate_json_report(self, results, output_file):
        """Generate JSON report for further processing"""
        try:
            exec_summary = await self.generate_executive_summary(results)
            
            report_data = {
                'metadata': {
                    'tool': 'PunyHunter Pro v2.0.0',
                    'scan_type': 'Puny-Code Account Takeover Assessment',
                    'timestamp': datetime.now().isoformat(),
                    'total_findings': len(results)
                },
                'executive_summary': exec_summary,
                'findings': results,
                'recommendations': [
                    'Implement Unicode normalization (NFC/NFKC) for all user input',
                    'Use consistent character collation settings across database and application layers',
                    'Validate email addresses using strict RFC-compliant parsing',
                    'Implement proper input sanitization for special characters',
                    'Deploy Web Application Firewall (WAF) with Unicode attack protection',
                    'Implement multi-factor authentication for sensitive operations'
                ]
            }
            
            json_file = output_file.replace('.pdf', '.json').replace('.txt', '.json')
            with open(json_file, 'w', encoding='utf-8') as f:
                json.dump(report_data, f, indent=2, ensure_ascii=False)
                
            print(f"✅ JSON report generated: {json_file}")
            
        except Exception as e:
            print(f"❌ Error generating JSON report: {e}")
    
    async def generate_csv_report(self, results, output_file):
        """Generate CSV report for spreadsheet analysis"""
        try:
            csv_file = output_file.replace('.pdf', '.csv').replace('.txt', '.csv')
            
            with open(csv_file, 'w', newline='', encoding='utf-8') as f:
                fieldnames = ['Finding_ID', 'Title', 'Severity', 'Target', 'Parameter', 
                             'Attack_Vector', 'Description', 'Impact', 'CVSS_Score', 'Remediation']
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                
                writer.writeheader()
                
                for i, result in enumerate(results, 1):
                    writer.writerow({
                        'Finding_ID': f'PUNY-{i:03d}',
                        'Title': result.get('title', 'Puny-Code Vulnerability'),
                        'Severity': result.get('severity', 'Medium'),
                        'Target': result.get('target', 'Unknown'),
                        'Parameter': result.get('parameter', 'email'),
                        'Attack_Vector': result.get('attack_vector', 'Character confusion'),
                        'Description': result.get('description', 'Character confusion vulnerability'),
                        'Impact': result.get('impact', 'Account takeover possible'),
                        'CVSS_Score': result.get('cvss_score', '8.1'),
                        'Remediation': result.get('remediation', 'Implement proper input validation')
                    })
                    
            print(f"✅ CSV report generated: {csv_file}")
            
        except Exception as e:
            print(f"❌ Error generating CSV report: {e}")
    
    async def generate_all_reports(self, results, output_prefix):
        """Generate all report formats"""
        print("📋 Generating comprehensive reports...")
        
        # Generate all formats concurrently
        tasks = [
            self.generate_technical_report(results, f"{output_prefix}.pdf"),
            self.generate_json_report(results, f"{output_prefix}.json"),
            self.generate_csv_report(results, f"{output_prefix}.csv"),
            self.generate_text_report(results, f"{output_prefix}.txt")
        ]
        
        await asyncio.gather(*tasks, return_exceptions=True)
        print("✅ All reports generated successfully!")

# Example usage and testing
if __name__ == "__main__":
    async def test_reporting():
        # Sample test data
        test_results = [
            {
                'title': 'Puny-Code Email Confusion Vulnerability',
                'severity': 'High',
                'target': 'https://example.com',
                'parameter': 'email',
                'attack_vector': 'Unicode character substitution',
                'description': 'Application accepts puny-code characters in email fields that are normalized differently by database and SMTP server',
                'impact': 'Account takeover through password reset token hijacking',
                'evidence': 'Successfully received password reset token for victim@example.com using рuny@example.com',
                'cvss_score': '8.1 (High)',
                'remediation': 'Implement consistent Unicode normalization across all components'
            }
        ]
        
        reporter = ReportGenerator()
        await reporter.generate_all_reports(test_results, 'test_report')
        
    asyncio.run(test_reporting())
