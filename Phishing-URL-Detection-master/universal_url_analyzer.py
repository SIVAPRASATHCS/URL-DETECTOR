"""
Universal URL Analyzer - Enhanced to handle all types of URLs
Supports HTTP, HTTPS, FTP, File, Data URLs, and more
"""

import re
import urllib.parse
from typing import Dict, List, Optional, Tuple, Any
import logging
import asyncio
import aiohttp
import ftplib
import base64
import mimetypes
from pathlib import Path
import hashlib
import ipaddress
from datetime import datetime

logger = logging.getLogger(__name__)

class UniversalURLAnalyzer:
    """Analyze any type of URL for security risks"""
    
    # Supported URL schemes and their risk levels
    URL_SCHEMES = {
        # Web protocols
        'http': {'risk_level': 'medium', 'category': 'web'},
        'https': {'risk_level': 'low', 'category': 'web'},
        
        # File transfer protocols
        'ftp': {'risk_level': 'high', 'category': 'file_transfer'},
        'ftps': {'risk_level': 'medium', 'category': 'file_transfer'},
        'sftp': {'risk_level': 'low', 'category': 'file_transfer'},
        
        # File and data protocols
        'file': {'risk_level': 'high', 'category': 'local_file'},
        'data': {'risk_level': 'medium', 'category': 'data_url'},
        
        # Email protocols
        'mailto': {'risk_level': 'medium', 'category': 'email'},
        
        # Network protocols
        'ldap': {'risk_level': 'high', 'category': 'directory'},
        'ldaps': {'risk_level': 'medium', 'category': 'directory'},
        
        # Remote access protocols
        'ssh': {'risk_level': 'high', 'category': 'remote_access'},
        'telnet': {'risk_level': 'high', 'category': 'remote_access'},
        'rdp': {'risk_level': 'high', 'category': 'remote_access'},
        'vnc': {'risk_level': 'high', 'category': 'remote_access'},
        
        # Database protocols
        'jdbc': {'risk_level': 'high', 'category': 'database'},
        'mysql': {'risk_level': 'high', 'category': 'database'},
        'postgresql': {'risk_level': 'high', 'category': 'database'},
        
        # Messaging protocols
        'irc': {'risk_level': 'medium', 'category': 'messaging'},
        'xmpp': {'risk_level': 'medium', 'category': 'messaging'},
        
        # Custom and application protocols
        'magnet': {'risk_level': 'high', 'category': 'p2p'},
        'torrent': {'risk_level': 'high', 'category': 'p2p'},
        'bitcoin': {'risk_level': 'medium', 'category': 'cryptocurrency'},
        'ethereum': {'risk_level': 'medium', 'category': 'cryptocurrency'},
        
        # Mobile and app protocols
        'sms': {'risk_level': 'medium', 'category': 'mobile'},
        'tel': {'risk_level': 'low', 'category': 'mobile'},
        'app': {'risk_level': 'medium', 'category': 'mobile'},
        
        # Unknown/Other
        'unknown': {'risk_level': 'high', 'category': 'unknown'}
    }
    
    # Suspicious URL patterns
    SUSPICIOUS_PATTERNS = [
        r'[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+',  # IP addresses
        r'[a-zA-Z0-9]+\.tk|\.ml|\.ga|\.cf',  # Suspicious TLDs
        r'bit\.ly|tinyurl|short',  # URL shorteners
        r'phish|scam|hack|malware',  # Suspicious keywords
        r'[0-9]{5,}',  # Long numbers
        r'login|signin|verify|account|secure|update',  # Phishing keywords
        r'\-{2,}|\_{3,}',  # Multiple dashes/underscores
        r'[a-zA-Z0-9]{20,}',  # Very long strings
    ]
    
    def __init__(self, url: str):
        self.original_url = url
        self.parsed_url = None
        self.scheme = None
        self.analysis_result = {}
        
        try:
            self.parsed_url = urllib.parse.urlparse(url)
            self.scheme = self.parsed_url.scheme.lower() if self.parsed_url.scheme else 'unknown'
        except Exception as e:
            logger.error(f"Failed to parse URL {url}: {e}")
            self.scheme = 'unknown'
    
    async def analyze_url(self) -> Dict[str, Any]:
        """Comprehensive URL analysis for all URL types"""
        
        # Basic URL structure analysis
        basic_analysis = self._analyze_basic_structure()
        
        # Scheme-specific analysis
        scheme_analysis = await self._analyze_by_scheme()
        
        # Security risk assessment
        security_analysis = self._analyze_security_risks()
        
        # Pattern matching for suspicious content
        pattern_analysis = self._analyze_patterns()
        
        # Combine all analyses
        self.analysis_result = {
            'url': self.original_url,
            'scheme': self.scheme,
            'basic_analysis': basic_analysis,
            'scheme_analysis': scheme_analysis,
            'security_analysis': security_analysis,
            'pattern_analysis': pattern_analysis,
            'overall_risk_score': self._calculate_risk_score(),
            'recommendations': self._generate_recommendations(),
            'timestamp': datetime.now().isoformat()
        }
        
        return self.analysis_result
    
    def _analyze_basic_structure(self) -> Dict[str, Any]:
        """Analyze basic URL structure"""
        if not self.parsed_url:
            return {'valid': False, 'error': 'Invalid URL structure'}
        
        return {
            'valid': True,
            'scheme': self.scheme,
            'netloc': self.parsed_url.netloc,
            'path': self.parsed_url.path,
            'params': self.parsed_url.params,
            'query': self.parsed_url.query,
            'fragment': self.parsed_url.fragment,
            'length': len(self.original_url),
            'has_subdomain': len(self.parsed_url.netloc.split('.')) > 2 if self.parsed_url.netloc else False,
            'has_port': ':' in self.parsed_url.netloc if self.parsed_url.netloc else False,
            'path_depth': len([p for p in self.parsed_url.path.split('/') if p]) if self.parsed_url.path else 0
        }
    
    async def _analyze_by_scheme(self) -> Dict[str, Any]:
        """Perform scheme-specific analysis"""
        
        scheme_info = self.URL_SCHEMES.get(self.scheme, self.URL_SCHEMES['unknown'])
        analysis = {
            'scheme': self.scheme,
            'category': scheme_info['category'],
            'base_risk_level': scheme_info['risk_level'],
        }
        
        try:
            if self.scheme in ['http', 'https']:
                analysis.update(await self._analyze_web_url())
            elif self.scheme in ['ftp', 'ftps']:
                analysis.update(await self._analyze_ftp_url())
            elif self.scheme == 'file':
                analysis.update(self._analyze_file_url())
            elif self.scheme == 'data':
                analysis.update(self._analyze_data_url())
            elif self.scheme == 'mailto':
                analysis.update(self._analyze_email_url())
            elif self.scheme in ['ssh', 'telnet', 'rdp', 'vnc']:
                analysis.update(self._analyze_remote_access_url())
            elif self.scheme in ['magnet', 'torrent']:
                analysis.update(self._analyze_p2p_url())
            elif self.scheme in ['bitcoin', 'ethereum']:
                analysis.update(self._analyze_crypto_url())
            else:
                analysis.update(self._analyze_unknown_url())
                
        except Exception as e:
            logger.error(f"Scheme analysis failed for {self.scheme}: {e}")
            analysis['error'] = str(e)
        
        return analysis
    
    async def _analyze_web_url(self) -> Dict[str, Any]:
        """Analyze HTTP/HTTPS URLs"""
        analysis = {}
        
        try:
            timeout = aiohttp.ClientTimeout(total=10)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.head(self.original_url, allow_redirects=True) as response:
                    analysis.update({
                        'status_code': response.status,
                        'content_type': response.headers.get('content-type', ''),
                        'server': response.headers.get('server', ''),
                        'redirect_count': len(response.history),
                        'final_url': str(response.url),
                        'ssl_enabled': self.scheme == 'https',
                        'response_headers': dict(response.headers)
                    })
        except Exception as e:
            analysis['connection_error'] = str(e)
            analysis['accessible'] = False
        
        return analysis
    
    async def _analyze_ftp_url(self) -> Dict[str, Any]:
        """Analyze FTP URLs"""
        analysis = {'protocol': 'FTP'}
        
        if self.parsed_url.netloc:
            try:
                # Basic FTP connection test (non-blocking)
                analysis['host'] = self.parsed_url.hostname or self.parsed_url.netloc
                analysis['port'] = self.parsed_url.port or 21
                analysis['path'] = self.parsed_url.path
                analysis['username'] = self.parsed_url.username or 'anonymous'
                analysis['encrypted'] = self.scheme == 'ftps'
                
                # FTP is generally considered risky for downloads
                analysis['risk_factors'] = ['unencrypted_transfer', 'potential_malware_source']
            except Exception as e:
                analysis['error'] = str(e)
        
        return analysis
    
    def _analyze_file_url(self) -> Dict[str, Any]:
        """Analyze file:// URLs"""
        analysis = {'protocol': 'Local File'}
        
        if self.parsed_url.path:
            file_path = self.parsed_url.path
            analysis.update({
                'file_path': file_path,
                'file_extension': Path(file_path).suffix.lower(),
                'is_executable': Path(file_path).suffix.lower() in ['.exe', '.bat', '.cmd', '.scr', '.com', '.pif'],
                'risk_factors': ['local_file_access', 'potential_malware']
            })
            
            # Check for suspicious file types
            dangerous_extensions = ['.exe', '.bat', '.cmd', '.scr', '.com', '.pif', '.vbs', '.js']
            if any(file_path.lower().endswith(ext) for ext in dangerous_extensions):
                analysis['high_risk_file_type'] = True
        
        return analysis
    
    def _analyze_data_url(self) -> Dict[str, Any]:
        """Analyze data: URLs"""
        analysis = {'protocol': 'Data URL'}
        
        try:
            # Parse data URL format: data:[<mediatype>][;base64],<data>
            data_part = self.original_url[5:]  # Remove 'data:'
            
            if ';base64,' in data_part:
                media_type, encoded_data = data_part.split(';base64,', 1)
                analysis.update({
                    'media_type': media_type or 'text/plain',
                    'encoding': 'base64',
                    'data_size': len(encoded_data),
                    'is_executable': media_type.startswith('application/'),
                })
                
                # Decode and analyze content
                try:
                    decoded_data = base64.b64decode(encoded_data)
                    analysis['decoded_size'] = len(decoded_data)
                    analysis['data_hash'] = hashlib.md5(decoded_data).hexdigest()
                except Exception:
                    analysis['decode_error'] = True
                    
            else:
                if ',' in data_part:
                    media_type, raw_data = data_part.split(',', 1)
                    analysis.update({
                        'media_type': media_type or 'text/plain',
                        'encoding': 'url-encoded',
                        'data_size': len(raw_data),
                    })
                    
        except Exception as e:
            analysis['parse_error'] = str(e)
        
        return analysis
    
    def _analyze_email_url(self) -> Dict[str, Any]:
        """Analyze mailto: URLs"""
        analysis = {'protocol': 'Email'}
        
        if self.parsed_url.path:
            email = self.parsed_url.path
            analysis.update({
                'email_address': email,
                'domain': email.split('@')[1] if '@' in email else None,
                'has_subject': 'subject=' in self.parsed_url.query,
                'has_body': 'body=' in self.parsed_url.query,
                'query_params': urllib.parse.parse_qs(self.parsed_url.query)
            })
            
            # Check for suspicious email patterns
            suspicious_domains = ['tempmail', 'guerrillamail', '10minutemail']
            if analysis['domain'] and any(susp in analysis['domain'] for susp in suspicious_domains):
                analysis['suspicious_email_provider'] = True
        
        return analysis
    
    def _analyze_remote_access_url(self) -> Dict[str, Any]:
        """Analyze remote access URLs (SSH, Telnet, RDP, VNC)"""
        analysis = {'protocol': f'Remote Access ({self.scheme.upper()})'}
        
        if self.parsed_url.netloc:
            analysis.update({
                'host': self.parsed_url.hostname or self.parsed_url.netloc,
                'port': self.parsed_url.port,
                'username': self.parsed_url.username,
                'encrypted': self.scheme in ['ssh'],
                'risk_factors': ['remote_access', 'credential_exposure']
            })
            
            # Check if it's targeting default ports
            default_ports = {'ssh': 22, 'telnet': 23, 'rdp': 3389, 'vnc': 5900}
            if self.parsed_url.port == default_ports.get(self.scheme):
                analysis['uses_default_port'] = True
        
        return analysis
    
    def _analyze_p2p_url(self) -> Dict[str, Any]:
        """Analyze P2P URLs (magnet, torrent)"""
        analysis = {'protocol': f'P2P ({self.scheme.upper()})'}
        
        if self.scheme == 'magnet':
            # Parse magnet link
            query_params = urllib.parse.parse_qs(self.parsed_url.query)
            analysis.update({
                'hash': query_params.get('xt', [None])[0],
                'display_name': query_params.get('dn', [None])[0],
                'trackers': query_params.get('tr', []),
                'risk_factors': ['p2p_download', 'potential_malware', 'copyright_infringement']
            })
        
        return analysis
    
    def _analyze_crypto_url(self) -> Dict[str, Any]:
        """Analyze cryptocurrency URLs"""
        analysis = {'protocol': f'Cryptocurrency ({self.scheme.upper()})'}
        
        if self.parsed_url.path:
            address = self.parsed_url.path
            analysis.update({
                'wallet_address': address,
                'address_length': len(address),
                'currency': self.scheme,
                'risk_factors': ['financial_transaction', 'potential_scam']
            })
            
            # Basic validation for Bitcoin addresses
            if self.scheme == 'bitcoin' and not (26 <= len(address) <= 62):
                analysis['invalid_address_format'] = True
        
        return analysis
    
    def _analyze_unknown_url(self) -> Dict[str, Any]:
        """Analyze unknown or custom scheme URLs"""
        return {
            'protocol': 'Unknown/Custom',
            'risk_factors': ['unknown_protocol', 'potential_malware', 'custom_handler'],
            'requires_manual_review': True
        }
    
    def _analyze_security_risks(self) -> Dict[str, Any]:
        """Analyze general security risks"""
        risks = []
        risk_score = 0
        
        # Check for IP addresses instead of domains
        if self.parsed_url and self.parsed_url.netloc:
            try:
                ipaddress.ip_address(self.parsed_url.netloc.split(':')[0])
                risks.append('uses_ip_address')
                risk_score += 30
            except ValueError:
                pass
        
        # Check URL length
        if len(self.original_url) > 200:
            risks.append('very_long_url')
            risk_score += 20
        elif len(self.original_url) > 100:
            risks.append('long_url')
            risk_score += 10
        
        # Check for suspicious schemes
        if self.scheme in ['file', 'ftp', 'telnet']:
            risks.append('high_risk_scheme')
            risk_score += 40
        
        # Check for non-standard ports
        if self.parsed_url and self.parsed_url.port:
            if self.parsed_url.port not in [80, 443, 21, 22, 25, 110, 143, 993, 995]:
                risks.append('non_standard_port')
                risk_score += 15
        
        return {
            'risks': risks,
            'risk_score': min(risk_score, 100),
            'risk_level': 'high' if risk_score > 60 else 'medium' if risk_score > 30 else 'low'
        }
    
    def _analyze_patterns(self) -> Dict[str, Any]:
        """Analyze URL for suspicious patterns"""
        pattern_matches = []
        
        for pattern in self.SUSPICIOUS_PATTERNS:
            if re.search(pattern, self.original_url, re.IGNORECASE):
                pattern_matches.append(pattern)
        
        return {
            'suspicious_patterns': pattern_matches,
            'pattern_count': len(pattern_matches),
            'high_risk_patterns': len(pattern_matches) > 2
        }
    
    def _calculate_risk_score(self) -> int:
        """Calculate overall risk score (0-100)"""
        base_score = 0
        
        # Scheme-based scoring
        scheme_risks = {
            'high': 40,
            'medium': 20,
            'low': 5
        }
        
        scheme_info = self.URL_SCHEMES.get(self.scheme, self.URL_SCHEMES['unknown'])
        base_score += scheme_risks.get(scheme_info['risk_level'], 50)
        
        # Add security analysis score
        if 'security_analysis' in self.analysis_result:
            base_score += self.analysis_result['security_analysis'].get('risk_score', 0)
        
        # Add pattern analysis score
        if 'pattern_analysis' in self.analysis_result:
            base_score += self.analysis_result['pattern_analysis']['pattern_count'] * 10
        
        return min(base_score, 100)
    
    def _generate_recommendations(self) -> List[str]:
        """Generate security recommendations based on analysis"""
        recommendations = []
        
        if self.scheme == 'http':
            recommendations.append("Consider using HTTPS instead of HTTP for better security")
        
        if self.scheme in ['ftp', 'telnet']:
            recommendations.append("This protocol is unencrypted and potentially unsafe")
        
        if self.scheme == 'file':
            recommendations.append("Be cautious when opening local files from unknown sources")
        
        if 'uses_ip_address' in self.analysis_result.get('security_analysis', {}).get('risks', []):
            recommendations.append("URL uses IP address instead of domain name - verify legitimacy")
        
        if len(self.original_url) > 200:
            recommendations.append("Very long URL - check for URL manipulation or obfuscation")
        
        if self.scheme == 'unknown':
            recommendations.append("Unknown protocol - verify with security team before accessing")
        
        if not recommendations:
            recommendations.append("URL appears to follow standard patterns - still verify source")
        
        return recommendations

def is_valid_url(url_string: str) -> bool:
    """Enhanced URL validation for all URL types"""
    if not url_string or not isinstance(url_string, str):
        return False
    
    if len(url_string) > 2000:  # Reasonable length limit
        return False
    
    try:
        parsed = urllib.parse.urlparse(url_string)
        
        # Must have a scheme
        if not parsed.scheme:
            return False
        
        # For most schemes, we need some kind of location/path
        if not any([parsed.netloc, parsed.path, parsed.query]):
            return False
        
        return True
        
    except Exception:
        return False

# URL scheme detection patterns
URL_SCHEME_PATTERNS = {
    'web': re.compile(r'^https?://', re.IGNORECASE),
    'ftp': re.compile(r'^ftps?://', re.IGNORECASE),
    'file': re.compile(r'^file://', re.IGNORECASE),
    'data': re.compile(r'^data:', re.IGNORECASE),
    'mailto': re.compile(r'^mailto:', re.IGNORECASE),
    'remote': re.compile(r'^(ssh|telnet|rdp|vnc)://', re.IGNORECASE),
    'p2p': re.compile(r'^(magnet|torrent):', re.IGNORECASE),
    'crypto': re.compile(r'^(bitcoin|ethereum):', re.IGNORECASE),
}

def detect_url_category(url: str) -> str:
    """Detect the general category of a URL"""
    for category, pattern in URL_SCHEME_PATTERNS.items():
        if pattern.match(url):
            return category
    return 'unknown'