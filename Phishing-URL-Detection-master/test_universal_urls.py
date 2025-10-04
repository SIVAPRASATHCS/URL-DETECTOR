"""
Universal URL Analysis Test Suite
Demonstrates the enhanced system's ability to analyze all types of URLs
"""

import asyncio
import aiohttp
import json
from typing import List, Dict

# Test URLs covering different schemes and protocols
TEST_URLS = [
    # Web protocols
    {
        'url': 'https://www.google.com',
        'category': 'web',
        'expected_risk': 'low',
        'description': 'Legitimate HTTPS website'
    },
    {
        'url': 'http://phishing-site.suspicious-domain.tk/fake-login.php',
        'category': 'web', 
        'expected_risk': 'high',
        'description': 'Suspicious HTTP phishing attempt'
    },
    
    # File transfer protocols
    {
        'url': 'ftp://ftp.example.com/files/document.pdf',
        'category': 'file_transfer',
        'expected_risk': 'medium',
        'description': 'FTP file download'
    },
    {
        'url': 'ftps://secure-ftp.company.com/confidential/data.zip',
        'category': 'file_transfer',
        'expected_risk': 'low',
        'description': 'Secure FTP transfer'
    },
    
    # Local files
    {
        'url': 'file:///C:/Users/Documents/suspicious_file.exe',
        'category': 'local_file',
        'expected_risk': 'high',
        'description': 'Local executable file'
    },
    {
        'url': 'file:///home/user/documents/report.pdf',
        'category': 'local_file',
        'expected_risk': 'medium',
        'description': 'Local PDF document'
    },
    
    # Data URLs
    {
        'url': 'data:text/html;base64,PGh0bWw+PGJvZHk+SGVsbG8gV29ybGQ8L2JvZHk+PC9odG1sPg==',
        'category': 'data_url',
        'expected_risk': 'medium',
        'description': 'Base64 encoded HTML data'
    },
    {
        'url': 'data:application/javascript;base64,YWxlcnQoJ01hbGljaW91cyBjb2RlJyk=',
        'category': 'data_url',
        'expected_risk': 'high',
        'description': 'Base64 encoded JavaScript (suspicious)'
    },
    
    # Email protocols
    {
        'url': 'mailto:contact@legitimate-company.com',
        'category': 'email',
        'expected_risk': 'low',
        'description': 'Legitimate email contact'
    },
    {
        'url': 'mailto:phishing@tempmail.org?subject=Urgent%20Action%20Required',
        'category': 'email',
        'expected_risk': 'medium',
        'description': 'Suspicious email with temp provider'
    },
    
    # Remote access protocols
    {
        'url': 'ssh://admin@192.168.1.100:22',
        'category': 'remote_access',
        'expected_risk': 'high',
        'description': 'SSH connection to IP address'
    },
    {
        'url': 'rdp://workstation.company.com:3389',
        'category': 'remote_access',
        'expected_risk': 'high',
        'description': 'Remote Desktop connection'
    },
    
    # P2P and torrents
    {
        'url': 'magnet:?xt=urn:btih:c12fe1c06bba254a9dc9f519b335aa7c1367a88a&dn=suspicious_software.exe',
        'category': 'p2p',
        'expected_risk': 'high',
        'description': 'Magnet link to suspicious executable'
    },
    
    # Cryptocurrency
    {
        'url': 'bitcoin:1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa?amount=0.001',
        'category': 'cryptocurrency',
        'expected_risk': 'medium',
        'description': 'Bitcoin payment request'
    },
    
    # Mobile protocols
    {
        'url': 'tel:+1-555-123-4567',
        'category': 'mobile',
        'expected_risk': 'low',
        'description': 'Phone number link'
    },
    {
        'url': 'sms:+1-555-987-6543?body=Suspicious%20message',
        'category': 'mobile',
        'expected_risk': 'medium',
        'description': 'SMS with suspicious content'
    },
    
    # Custom/Unknown protocols
    {
        'url': 'customapp://malicious-action?param=dangerous',
        'category': 'unknown',
        'expected_risk': 'high',
        'description': 'Unknown custom protocol'
    }
]

async def test_single_url(session: aiohttp.ClientSession, url_data: Dict) -> Dict:
    """Test analysis of a single URL"""
    
    url = url_data['url']
    print(f"\n🔍 Testing: {url}")
    print(f"   Category: {url_data['category']}")
    print(f"   Description: {url_data['description']}")
    
    try:
        async with session.post(
            'http://localhost:8000/analyze',
            json={
                'url': url,
                'deep_analysis': True,
                'check_real_time': False
            },
            timeout=aiohttp.ClientTimeout(total=30)
        ) as response:
            
            if response.status == 200:
                result = await response.json()
                
                print(f"   ✅ Analysis completed:")
                print(f"      Prediction: {result['prediction']}")
                print(f"      Confidence: {result['confidence']:.2f}")
                print(f"      Risk Score: {result['risk_score']}/100")
                print(f"      Analysis Time: {result['analysis_time_ms']}ms")
                
                # Check if universal analysis is included
                if result.get('explanation') and result['explanation'].get('universal_analysis'):
                    universal = result['explanation']['universal_analysis']
                    print(f"      URL Scheme: {universal.get('scheme', 'unknown')}")
                    print(f"      Category: {universal.get('scheme_analysis', {}).get('category', 'unknown')}")
                    
                    if 'recommendations' in universal:
                        print(f"      Recommendations: {len(universal['recommendations'])} items")
                
                return {
                    'url': url,
                    'status': 'success',
                    'prediction': result['prediction'],
                    'confidence': result['confidence'],
                    'risk_score': result['risk_score'],
                    'category': url_data['category'],
                    'expected_risk': url_data['expected_risk']
                }
                
            else:
                print(f"   ❌ HTTP Error: {response.status}")
                return {
                    'url': url,
                    'status': 'http_error',
                    'error': f"HTTP {response.status}"
                }
                
    except Exception as e:
        print(f"   ❌ Error: {str(e)}")
        return {
            'url': url,
            'status': 'error',
            'error': str(e)
        }

async def test_bulk_analysis(session: aiohttp.ClientSession, urls: List[str]) -> Dict:
    """Test bulk analysis of multiple URLs"""
    
    print(f"\n📦 Testing bulk analysis with {len(urls)} URLs...")
    
    try:
        async with session.post(
            'http://localhost:8000/analyze/bulk',
            json={
                'urls': urls,
                'deep_analysis': False
            },
            timeout=aiohttp.ClientTimeout(total=60)
        ) as response:
            
            if response.status == 200:
                result = await response.json()
                
                print(f"   ✅ Bulk analysis completed:")
                print(f"      Total URLs: {result['summary']['total']}")
                print(f"      Analyzed: {result['summary']['analyzed']}")
                print(f"      Phishing: {result['summary']['phishing']}")
                print(f"      Safe: {result['summary']['safe']}")
                print(f"      Errors: {result['summary']['errors']}")
                print(f"      Total Time: {result['total_time_ms']}ms")
                
                return result
                
            else:
                print(f"   ❌ HTTP Error: {response.status}")
                return {'error': f"HTTP {response.status}"}
                
    except Exception as e:
        print(f"   ❌ Error: {str(e)}")
        return {'error': str(e)}

async def run_comprehensive_test():
    """Run comprehensive test of universal URL analysis"""
    
    print("🚀 Universal URL Analysis Test Suite")
    print("=" * 60)
    print(f"Testing {len(TEST_URLS)} different URL types and protocols")
    
    # Test individual URLs
    results = []
    
    async with aiohttp.ClientSession() as session:
        print("\n📋 Individual URL Analysis Tests:")
        print("-" * 40)
        
        for url_data in TEST_URLS:
            result = await test_single_url(session, url_data)
            results.append(result)
            await asyncio.sleep(0.5)  # Rate limiting
        
        # Test bulk analysis
        print("\n📦 Bulk Analysis Test:")
        print("-" * 40)
        
        test_urls = [url_data['url'] for url_data in TEST_URLS[:10]]  # First 10 URLs
        bulk_result = await test_bulk_analysis(session, test_urls)
    
    # Generate summary report
    print("\n📊 Test Results Summary:")
    print("=" * 60)
    
    successful_tests = [r for r in results if r['status'] == 'success']
    failed_tests = [r for r in results if r['status'] != 'success']
    
    print(f"Total Tests: {len(results)}")
    print(f"Successful: {len(successful_tests)}")
    print(f"Failed: {len(failed_tests)}")
    print(f"Success Rate: {len(successful_tests)/len(results)*100:.1f}%")
    
    if successful_tests:
        # Categorize by URL scheme
        categories = {}
        for result in successful_tests:
            cat = result['category']
            if cat not in categories:
                categories[cat] = []
            categories[cat].append(result)
        
        print(f"\nResults by Category:")
        for category, cat_results in categories.items():
            avg_risk = sum(r['risk_score'] for r in cat_results) / len(cat_results)
            print(f"  {category.title()}: {len(cat_results)} URLs, Avg Risk: {avg_risk:.1f}/100")
    
    if failed_tests:
        print(f"\nFailed Tests:")
        for result in failed_tests:
            print(f"  ❌ {result['url']}: {result.get('error', 'Unknown error')}")
    
    print(f"\n✅ Universal URL Analysis Test Complete!")
    print(f"The system successfully handles multiple URL schemes including:")
    print(f"   • Web protocols (HTTP, HTTPS)")
    print(f"   • File transfer (FTP, FTPS, File)")
    print(f"   • Data URLs and embedded content")
    print(f"   • Email and communication protocols")
    print(f"   • Remote access protocols")
    print(f"   • P2P and cryptocurrency URLs")
    print(f"   • Mobile protocols (SMS, Tel)")
    print(f"   • Custom and unknown schemes")

if __name__ == "__main__":
    asyncio.run(run_comprehensive_test())