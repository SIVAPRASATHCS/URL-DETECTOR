"""
Enhanced Feature Extraction for Phishing URL Detection
Includes advanced features, real-time threat intelligence, and async processing
"""

import asyncio
import aiohttp
import ssl
import socket
from urllib.parse import urlparse, parse_qs
import re
import ipaddress
from datetime import datetime, timedelta
import hashlib
import base64
from typing import Dict, List, Optional, Tuple
import logging
import whois
from bs4 import BeautifulSoup
import dns.resolver
import json

logger = logging.getLogger(__name__)

class EnhancedFeatureExtraction:
    """Enhanced feature extraction with modern techniques and real-time intelligence"""
    
    def __init__(self, url: str, check_real_time: bool = True):
        self.url = url
        self.check_real_time = check_real_time
        self.domain = ""
        self.parsed_url = None
        self.response_content = ""
        self.soup = None
        self.ssl_info = {}
        self.whois_info = {}
        self.dns_info = {}
        
        # Feature names for model compatibility
        self.feature_names = [
            'using_ip', 'long_url', 'short_url', 'symbol', 'redirecting',
            'prefix_suffix', 'sub_domains', 'https', 'domain_reg_len', 'favicon',
            'non_std_port', 'https_domain_url', 'request_url', 'anchor_url',
            'links_in_script_tags', 'server_form_handler', 'info_email',
            'abnormal_url', 'website_forwarding', 'status_bar_cust',
            'disable_right_click', 'using_popup_window', 'iframe_redirection',
            'age_of_domain', 'dns_recording', 'website_traffic', 'page_rank',
            'google_index', 'links_pointing_to_page', 'stats_report'
        ]
        
        try:
            self.parsed_url = urlparse(url)
            self.domain = self.parsed_url.netloc
        except Exception as e:
            logger.error(f"Failed to parse URL {url}: {e}")
    
    async def extract_all_features(self) -> List[float]:
        """Extract all features asynchronously"""
        try:
            # Fetch web content and gather information
            await self._fetch_web_content()
            await self._gather_domain_info()
            
            # Extract traditional features
            features = [
                self._using_ip(),
                self._long_url(),
                self._short_url(),
                self._symbol(),
                self._redirecting(),
                self._prefix_suffix(),
                self._sub_domains(),
                self._https(),
                self._domain_reg_len(),
                self._favicon(),
                self._non_std_port(),
                self._https_domain_url(),
                self._request_url(),
                self._anchor_url(),
                self._links_in_script_tags(),
                self._server_form_handler(),
                self._info_email(),
                self._abnormal_url(),
                self._website_forwarding(),
                self._status_bar_cust(),
                self._disable_right_click(),
                self._using_popup_window(),
                self._iframe_redirection(),
                self._age_of_domain(),
                self._dns_recording(),
                self._website_traffic(),
                self._page_rank(),
                self._google_index(),
                self._links_pointing_to_page(),
                self._stats_report()
            ]
            
            return features
            
        except Exception as e:
            logger.error(f"Error extracting features for {self.url}: {e}")
            # Return default safe values if extraction fails
            return [1] * 30
    
    async def _fetch_web_content(self):
        """Fetch web content and SSL information"""
        try:
            timeout = aiohttp.ClientTimeout(total=10)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get(self.url, allow_redirects=True) as response:
                    self.response_content = await response.text()
                    self.soup = BeautifulSoup(self.response_content, 'html.parser')
        except Exception as e:
            logger.warning(f"Failed to fetch content for {self.url}: {e}")
    
    async def _gather_domain_info(self):
        """Gather domain information (WHOIS, DNS, SSL)"""
        tasks = []
        
        if self.check_real_time:
            tasks.extend([
                self._get_whois_info(),
                self._get_dns_info(),
                self._get_ssl_info()
            ])
        
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
    
    async def _get_whois_info(self):
        """Get WHOIS information"""
        try:
            loop = asyncio.get_event_loop()
            self.whois_info = await loop.run_in_executor(None, whois.whois, self.domain)
        except Exception as e:
            logger.warning(f"WHOIS lookup failed for {self.domain}: {e}")
    
    async def _get_dns_info(self):
        """Get DNS information"""
        try:
            loop = asyncio.get_event_loop()
            resolver = dns.resolver.Resolver()
            resolver.timeout = 5
            
            # Get A records
            try:
                answers = await loop.run_in_executor(None, resolver.resolve, self.domain, 'A')
                self.dns_info['a_records'] = [str(rdata) for rdata in answers]
            except:
                pass
            
            # Get MX records
            try:
                answers = await loop.run_in_executor(None, resolver.resolve, self.domain, 'MX')
                self.dns_info['mx_records'] = [str(rdata) for rdata in answers]
            except:
                pass
                
        except Exception as e:
            logger.warning(f"DNS lookup failed for {self.domain}: {e}")
    
    async def _get_ssl_info(self):
        """Get SSL certificate information"""
        if not self.url.startswith('https://'):
            return
        
        try:
            context = ssl.create_default_context()
            with socket.create_connection((self.domain, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=self.domain) as ssock:
                    cert = ssock.getpeercert()
                    self.ssl_info = {
                        'subject': dict(x[0] for x in cert.get('subject', [])),
                        'issuer': dict(x[0] for x in cert.get('issuer', [])),
                        'version': cert.get('version'),
                        'not_before': cert.get('notBefore'),
                        'not_after': cert.get('notAfter'),
                        'serial_number': cert.get('serialNumber')
                    }
        except Exception as e:
            logger.warning(f"SSL info gathering failed for {self.domain}: {e}")
    
    async def get_threat_intelligence(self) -> Dict:
        """Get real-time threat intelligence"""
        if not self.check_real_time:
            return {}
        
        threat_intel = {}
        
        try:
            # Check against known malicious patterns
            threat_intel['suspicious_patterns'] = self._check_suspicious_patterns()
            
            # Domain reputation score
            threat_intel['domain_reputation'] = self._calculate_domain_reputation()
            
            # SSL certificate analysis
            threat_intel['ssl_analysis'] = self._analyze_ssl_certificate()
            
            return threat_intel
            
        except Exception as e:
            logger.error(f"Threat intelligence gathering failed: {e}")
            return {}
    
    # Traditional feature extraction methods (enhanced versions)
    
    def _using_ip(self) -> int:
        """Check if URL uses IP address instead of domain"""
        try:
            ipaddress.ip_address(self.domain)
            return -1
        except:
            return 1
    
    def _long_url(self) -> int:
        """Check URL length"""
        length = len(self.url)
        if length < 54:
            return 1
        elif 54 <= length <= 75:
            return 0
        else:
            return -1
    
    def _short_url(self) -> int:
        """Check for URL shortening services"""
        shortening_services = [
            'bit.ly', 'goo.gl', 'shorte.st', 'go2l.ink', 'x.co', 'ow.ly',
            't.co', 'tinyurl', 'tr.im', 'is.gd', 'cli.gs', 'yfrog.com',
            'migre.me', 'ff.im', 'tiny.cc', 'url4.eu', 'twit.ac', 'su.pr',
            'twurl.nl', 'snipurl.com', 'short.to', 'budurl.com', 'ping.fm',
            'post.ly', 'just.as', 'bkite.com', 'snipr.com', 'fic.kr',
            'loopt.us', 'doiop.com', 'short.ie', 'kl.am', 'wp.me',
            'rubyurl.com', 'om.ly', 'to.ly', 'bit.do', 'lnkd.in',
            'db.tt', 'qr.ae', 'adf.ly', 'bitly.com', 'cur.lv',
            'tinyurl.com', 'ity.im', 'q.gs', 'po.st', 'bc.vc',
            'twitthis.com', 'u.to', 'j.mp', 'buzurl.com', 'cutt.us',
            'u.bb', 'yourls.org', 'prettylinkpro.com', 'scrnch.me',
            'filoops.info', 'vzturl.com', 'qr.net', '1url.com',
            'tweez.me', 'v.gd', '7ax.link'
        ]
        
        for service in shortening_services:
            if service in self.domain:
                return -1
        return 1
    
    def _symbol(self) -> int:
        """Check for @ symbol in URL"""
        return -1 if '@' in self.url else 1
    
    def _redirecting(self) -> int:
        """Check for redirecting using //"""
        return -1 if self.url.rfind('//') > 6 else 1
    
    def _prefix_suffix(self) -> int:
        """Check for - in domain name"""
        return -1 if '-' in self.domain else 1
    
    def _sub_domains(self) -> int:
        """Count subdomains"""
        dots = self.domain.count('.')
        if dots == 1:
            return 1
        elif dots == 2:
            return 0
        else:
            return -1
    
    def _https(self) -> int:
        """Check HTTPS usage"""
        return 1 if self.url.startswith('https://') else -1
    
    def _domain_reg_len(self) -> int:
        """Check domain registration length"""
        try:
            if self.whois_info and 'expiration_date' in self.whois_info:
                expiry = self.whois_info['expiration_date']
                if isinstance(expiry, list):
                    expiry = expiry[0]
                if isinstance(expiry, datetime):
                    days_until_expiry = (expiry - datetime.now()).days
                    return 1 if days_until_expiry > 365 else -1
        except:
            pass
        return -1
    
    def _favicon(self) -> int:
        """Check favicon"""
        if self.soup:
            favicon_links = self.soup.find_all('link', rel='icon') or self.soup.find_all('link', rel='shortcut icon')
            if favicon_links:
                favicon_url = favicon_links[0].get('href', '')
                if favicon_url.startswith('http') and self.domain not in favicon_url:
                    return -1
            return 1
        return 0
    
    def _non_std_port(self) -> int:
        """Check for non-standard ports"""
        port = self.parsed_url.port
        if port and port not in [80, 443]:
            return -1
        return 1
    
    def _https_domain_url(self) -> int:
        """Check HTTPS in domain part of URL"""
        return -1 if 'https' in self.domain else 1
    
    def _request_url(self) -> int:
        """Check percentage of request URL"""
        if not self.soup:
            return 1
        
        try:
            total_urls = 0
            external_urls = 0
            
            # Check img, audio, embed, iframe tags
            for tag in self.soup.find_all(['img', 'audio', 'embed', 'iframe']):
                src = tag.get('src', '')
                if src:
                    total_urls += 1
                    if src.startswith('http') and self.domain not in src:
                        external_urls += 1
            
            if total_urls == 0:
                return 1
            
            percentage = (external_urls / total_urls) * 100
            if percentage < 22:
                return 1
            elif 22 <= percentage < 61:
                return 0
            else:
                return -1
        except:
            return 1
    
    def _anchor_url(self) -> int:
        """Check anchor URL percentage"""
        if not self.soup:
            return 1
        
        try:
            anchors = self.soup.find_all('a', href=True)
            if not anchors:
                return 1
            
            unsafe_anchors = 0
            for anchor in anchors:
                href = anchor['href']
                if href in ['#', '#content', '#skip', 'JavaScript::void(0)'] or href.startswith('mailto:'):
                    unsafe_anchors += 1
                elif href.startswith('http') and self.domain not in href:
                    unsafe_anchors += 1
            
            percentage = (unsafe_anchors / len(anchors)) * 100
            if percentage < 31:
                return 1
            elif 31 <= percentage < 67:
                return 0
            else:
                return -1
        except:
            return 1
    
    def _links_in_script_tags(self) -> int:
        """Check links in script tags"""
        if not self.soup:
            return 1
        
        try:
            scripts = self.soup.find_all('script')
            external_scripts = 0
            
            for script in scripts:
                src = script.get('src', '')
                if src and src.startswith('http') and self.domain not in src:
                    external_scripts += 1
            
            percentage = (external_scripts / len(scripts) * 100) if scripts else 0
            if percentage < 17:
                return 1
            elif 17 <= percentage < 81:
                return 0
            else:
                return -1
        except:
            return 1
    
    def _server_form_handler(self) -> int:
        """Check server form handler"""
        if not self.soup:
            return 1
        
        try:
            forms = self.soup.find_all('form')
            for form in forms:
                action = form.get('action', '')
                if action == '' or action == 'about:blank':
                    return -1
                elif action.startswith('http') and self.domain not in action:
                    return -1
            return 1
        except:
            return 1
    
    def _info_email(self) -> int:
        """Check for info email"""
        if not self.response_content:
            return 1
        
        emails = re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', self.response_content)
        for email in emails:
            domain_part = email.split('@')[1]
            if domain_part != self.domain:
                return -1
        return 1
    
    def _abnormal_url(self) -> int:
        """Check abnormal URL"""
        if self.whois_info:
            try:
                hostname = self.whois_info.get('domain_name', '')
                if isinstance(hostname, list):
                    hostname = hostname[0]
                if isinstance(hostname, str) and hostname.lower() in self.url.lower():
                    return 1
            except:
                pass
        return -1
    
    def _website_forwarding(self) -> int:
        """Check website forwarding"""
        # This would require checking redirect chains
        # For now, return neutral
        return 0
    
    def _status_bar_cust(self) -> int:
        """Check status bar customization"""
        if not self.response_content:
            return 1
        
        status_bar_patterns = [
            'onMouseOver="window.status',
            'onClick="window.status',
        ]
        
        for pattern in status_bar_patterns:
            if pattern in self.response_content:
                return -1
        return 1
    
    def _disable_right_click(self) -> int:
        """Check if right click is disabled"""
        if not self.response_content:
            return 1
        
        right_click_patterns = [
            'event.button==2',
            'event.button==3',
            'contextmenu',
            'onselectstart',
            'ondragstart'
        ]
        
        for pattern in right_click_patterns:
            if pattern in self.response_content:
                return -1
        return 1
    
    def _using_popup_window(self) -> int:
        """Check for popup windows"""
        if not self.response_content:
            return 1
        
        popup_patterns = [
            'window.open(',
            'popup',
            'alert('
        ]
        
        for pattern in popup_patterns:
            if pattern in self.response_content:
                return -1
        return 1
    
    def _iframe_redirection(self) -> int:
        """Check iframe redirection"""
        if not self.soup:
            return 1
        
        iframes = self.soup.find_all('iframe')
        if iframes:
            for iframe in iframes:
                if iframe.get('frameborder') == '0' or iframe.get('border') == '0':
                    return -1
        return 1
    
    def _age_of_domain(self) -> int:
        """Check age of domain"""
        try:
            if self.whois_info and 'creation_date' in self.whois_info:
                creation_date = self.whois_info['creation_date']
                if isinstance(creation_date, list):
                    creation_date = creation_date[0]
                if isinstance(creation_date, datetime):
                    age_days = (datetime.now() - creation_date).days
                    return 1 if age_days > 180 else -1
        except:
            pass
        return -1
    
    def _dns_recording(self) -> int:
        """Check DNS recording"""
        return 1 if self.dns_info else -1
    
    def _website_traffic(self) -> int:
        """Check website traffic (simplified)"""
        # This would require external API calls to traffic analysis services
        return 0
    
    def _page_rank(self) -> int:
        """Check page rank (simplified)"""
        # This would require external API calls
        return 0
    
    def _google_index(self) -> int:
        """Check Google indexing (simplified)"""
        # This would require Google Search API
        return 0
    
    def _links_pointing_to_page(self) -> int:
        """Check links pointing to page"""
        if not self.soup:
            return 1
        
        links = self.soup.find_all('a', href=True)
        return 1 if len(links) > 0 else -1
    
    def _stats_report(self) -> int:
        """Check stats report"""
        # Check for suspicious hosting providers and IPs
        suspicious_hosts = [
            'at.ua', 'usa.cc', 'baltazarpresentes.com.br', 'pe.hu',
            'esy.es', 'hol.es', 'sweddy.com', 'myjino.ru', '96.lt'
        ]
        
        for host in suspicious_hosts:
            if host in self.domain:
                return -1
        return 1
    
    # Enhanced analysis methods
    
    def _check_suspicious_patterns(self) -> Dict:
        """Check for suspicious patterns"""
        patterns = {
            'suspicious_keywords': 0,
            'unicode_chars': 0,
            'excessive_subdomains': 0,
            'suspicious_tld': 0
        }
        
        # Check for suspicious keywords
        suspicious_keywords = [
            'secure', 'account', 'update', 'confirm', 'login', 'signin',
            'bank', 'paypal', 'amazon', 'microsoft', 'apple', 'google',
            'verify', 'suspended', 'limited', 'unlock'
        ]
        
        for keyword in suspicious_keywords:
            if keyword in self.url.lower():
                patterns['suspicious_keywords'] += 1
        
        # Check for unicode/punycode
        if 'xn--' in self.domain:
            patterns['unicode_chars'] = 1
        
        # Check subdomain count
        if self.domain.count('.') > 3:
            patterns['excessive_subdomains'] = 1
        
        # Check for suspicious TLDs
        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.pw', '.cc', '.ws']
        for tld in suspicious_tlds:
            if self.domain.endswith(tld):
                patterns['suspicious_tld'] = 1
        
        return patterns
    
    def _calculate_domain_reputation(self) -> Dict:
        """Calculate domain reputation score"""
        reputation = {
            'score': 0.5,  # Neutral score
            'factors': []
        }
        
        # Age factor
        if self.whois_info and 'creation_date' in self.whois_info:
            try:
                creation_date = self.whois_info['creation_date']
                if isinstance(creation_date, list):
                    creation_date = creation_date[0]
                if isinstance(creation_date, datetime):
                    age_days = (datetime.now() - creation_date).days
                    if age_days > 365:
                        reputation['score'] += 0.2
                        reputation['factors'].append('old_domain')
                    elif age_days < 30:
                        reputation['score'] -= 0.3
                        reputation['factors'].append('new_domain')
            except:
                pass
        
        # SSL factor
        if self.ssl_info:
            reputation['score'] += 0.1
            reputation['factors'].append('has_ssl')
        
        # WHOIS privacy
        if self.whois_info and 'registrar' in self.whois_info:
            reputation['score'] += 0.1
            reputation['factors'].append('whois_available')
        
        reputation['score'] = max(0.0, min(1.0, reputation['score']))
        return reputation
    
    def _analyze_ssl_certificate(self) -> Dict:
        """Analyze SSL certificate"""
        analysis = {
            'valid': False,
            'issuer': None,
            'expires_soon': False,
            'self_signed': False
        }
        
        if self.ssl_info:
            analysis['valid'] = True
            analysis['issuer'] = self.ssl_info.get('issuer', {}).get('organizationName')
            
            # Check expiration
            try:
                not_after = self.ssl_info.get('not_after')
                if not_after:
                    # Parse SSL date format
                    expiry = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                    days_until_expiry = (expiry - datetime.now()).days
                    analysis['expires_soon'] = days_until_expiry < 30
            except:
                pass
            
            # Check if self-signed
            subject = self.ssl_info.get('subject', {})
            issuer = self.ssl_info.get('issuer', {})
            if subject == issuer:
                analysis['self_signed'] = True
        
        return analysis