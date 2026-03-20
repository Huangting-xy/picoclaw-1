#!/usr/bin/env python3
"""
CVE Database Module for Picoclaw
Integrates with NVD API and caches CVEs locally in SQLite
"""

import sqlite3
import json
import os
import time
from datetime import datetime
from typing import Optional, List, Dict, Any
import urllib.request
import urllib.parse
import urllib.error

# Database path for CVE cache
CVE_DB_PATH = os.environ.get('CVE_DB', '/home/cogniwatch/data/cve_cache.db')
NVD_API_BASE = 'https://services.nvd.nist.gov/rest/json/cves/2.0'

# Rate limiting - NVD allows 5 requests per 30 seconds
last_request_time = 0
request_interval = 6  # seconds between requests


def init_cve_db():
    """Initialize the CVE cache database"""
    os.makedirs(os.path.dirname(CVE_DB_PATH), exist_ok=True)
    conn = sqlite3.connect(CVE_DB_PATH)
    c = conn.cursor()
    
    # CVE cache table
    c.execute('''CREATE TABLE IF NOT EXISTS cve_cache (
        cve_id TEXT PRIMARY KEY,
        source_identifier TEXT,
        published TEXT,
        modified TEXT,
        vuln_status TEXT,
        description TEXT,
        cvss_v3_score REAL,
        cvss_v3_vector TEXT,
        cvss_v3_severity TEXT,
        references_json TEXT,
        configurations_json TEXT,
        cached_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')
    
    # Search index table
    c.execute('''CREATE TABLE IF NOT EXISTS cve_search_index (
        cve_id TEXT,
        keyword TEXT,
        PRIMARY KEY (cve_id, keyword)
    )''')
    
    # Create indexes
    c.execute('CREATE INDEX IF NOT EXISTS idx_cve_published ON cve_cache(published)')
    c.execute('CREATE INDEX IF NOT EXISTS idx_cve_cvss_score ON cve_cache(cvss_v3_score)')
    c.execute('CREATE INDEX IF NOT EXISTS idx_search_keyword ON cve_search_index(keyword)')
    
    conn.commit()
    conn.close()


def rate_limit():
    """Implement rate limiting for NVD API"""
    global last_request_time
    elapsed = time.time() - last_request_time
    if elapsed < request_interval:
        time.sleep(request_interval - elapsed)
    last_request_time = time.time()


def fetch_from_nvd(cve_id: str = None, keyword: str = None) -> Optional[Dict]:
    """Fetch CVE data from NVD API with rate limiting"""
    rate_limit()
    
    try:
        if cve_id:
            url = f"{NVD_API_BASE}?cveId={cve_id}"
        elif keyword:
            url = f"{NVD_API_BASE}?keywordSearch={urllib.parse.quote(keyword)}"
        else:
            return None
        
        req = urllib.request.Request(url, headers={
            'User-Agent': 'Picoclaw/1.0 CVE Scanner',
            'Accept': 'application/json'
        })
        
        with urllib.request.urlopen(req, timeout=30) as response:
            data = json.loads(response.read().decode())
            return data
    except urllib.error.HTTPError as e:
        if e.code == 403:
            # Rate limited - wait and retry
            time.sleep(10)
            return fetch_from_nvd(cve_id=cve_id, keyword=keyword)
        print(f"NVD API HTTP error: {e.code}")
        return None
    except Exception as e:
        print(f"Error fetching from NVD: {e}")
        return None


def parse_cve_data(cve_item: Dict) -> Dict[str, Any]:
    """Parse CVE item from NVD response"""
    cve = cve_item.get('cve', {})
    cve_id = cve.get('id', '')
    
    # Get description
    descriptions = cve.get('descriptions', [])
    description = ''
    for desc in descriptions:
        if desc.get('lang') == 'en':
            description = desc.get('value', '')
            break
    
    # Get CVSS v3 metrics
    metrics = cve.get('metrics', {})
    cvss_v3 = {}
    cvss_v3_score = None
    cvss_v3_vector = ''
    cvss_v3_severity = ''
    
    # Try cvssMetricV31 first, then V30
    for metric_type in ['cvssMetricV31', 'cvssMetricV30']:
        if metric_type in metrics and metrics[metric_type]:
            cvss_data = metrics[metric_type][0].get('cvssData', {})
            cvss_v3_score = cvss_data.get('baseScore')
            cvss_v3_vector = cvss_data.get('vectorString', '')
            cvss_v3_severity = cvss_data.get('baseSeverity', '')
            break
    
    # Get references
    references = cve.get('references', [])
    ref_urls = [ref.get('url') for ref in references if ref.get('url')]
    
    # Get configurations (affected products)
    configurations = cve.get('configurations', [])
    
    return {
        'cve_id': cve_id,
        'source_identifier': cve.get('sourceIdentifier', ''),
        'published': cve.get('published', ''),
        'modified': cve.get('lastModified', ''),
        'vuln_status': cve.get('vulnStatus', ''),
        'description': description,
        'cvss_v3_score': cvss_v3_score,
        'cvss_v3_vector': cvss_v3_vector,
        'cvss_v3_severity': cvss_v3_severity,
        'references': ref_urls,
        'configurations': configurations
    }


def cache_cve(cve_data: Dict):
    """Cache CVE data in SQLite"""
    conn = sqlite3.connect(CVE_DB_PATH)
    c = conn.cursor()
    
    c.execute('''INSERT OR REPLACE INTO cve_cache 
                 (cve_id, source_identifier, published, modified, vuln_status,
                  description, cvss_v3_score, cvss_v3_vector, cvss_v3_severity,
                  references_json, configurations_json)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
              (cve_data['cve_id'],
               cve_data['source_identifier'],
               cve_data['published'],
               cve_data['modified'],
               cve_data['vuln_status'],
               cve_data['description'],
               cve_data['cvss_v3_score'],
               cve_data['cvss_v3_vector'],
               cve_data['cvss_v3_severity'],
               json.dumps(cve_data['references']),
               json.dumps(cve_data['configurations'])))
    
    # Update search index
    c.execute('DELETE FROM cve_search_index WHERE cve_id = ?', (cve_data['cve_id'],))
    
    # Index keywords from description
    description = cve_data['description'].lower()
    keywords = set()
    import re
    # Extract significant words
    words = re.findall(r'\b[a-z]{4,}\b', description)
    keywords.update(words)
    
    # Add CVE ID itself
    keywords.add(cve_data['cve_id'].lower())
    
    for keyword in keywords:
        c.execute('INSERT OR IGNORE INTO cve_search_index (cve_id, keyword) VALUES (?, ?)',
                  (cve_data['cve_id'], keyword.lower()))
    
    conn.commit()
    conn.close()


def get_cve(cve_id: str) -> Optional[Dict[str, Any]]:
    """
    Get CVE details by ID.
    First checks cache, then fetches from NVD if not found.
    
    Args:
        cve_id: CVE ID (e.g., 'CVE-2026-25253')
    
    Returns:
        Dictionary with CVE details or None if not found
    """
    # Check cache first
    conn = sqlite3.connect(CVE_DB_PATH)
    c = conn.cursor()
    c.execute('SELECT * FROM cve_cache WHERE cve_id = ?', (cve_id.upper(),))
    row = c.fetchone()
    conn.close()
    
    if row:
        return {
            'cve_id': row[0],
            'source_identifier': row[1],
            'published': row[2],
            'modified': row[3],
            'vuln_status': row[4],
            'description': row[5],
            'cvss_v3_score': row[6],
            'cvss_v3_vector': row[7],
            'cvss_v3_severity': row[8],
            'references': json.loads(row[9]) if row[9] else [],
            'configurations': json.loads(row[10]) if row[10] else [],
            'cached': True
        }
    
    # Fetch from NVD
    response = fetch_from_nvd(cve_id=cve_id)
    if response and response.get('vulnerabilities'):
        cve_item = response['vulnerabilities'][0]
        cve_data = parse_cve_data(cve_item)
        cache_cve(cve_data)
        cve_data['cached'] = False
        return cve_data
    
    return None


def search_cves(keyword: str, limit: int = 20) -> List[Dict[str, Any]]:
    """
    Search CVEs by keyword.
    Searches local cache first, then queries NVD API.
    
    Args:
        keyword: Search keyword
        limit: Maximum number of results
    
    Returns:
        List of CVE dictionaries
    """
    results = []
    
    # Search local cache
    conn = sqlite3.connect(CVE_DB_PATH)
    c = conn.cursor()
    c.execute('''SELECT cve_id FROM cve_search_index 
                  WHERE keyword LIKE ? 
                  GROUP BY cve_id 
                  LIMIT ?''', 
              (f'%{keyword.lower()}%', limit))
    
    cached_ids = [row[0] for row in c.fetchall()]
    for cve_id in cached_ids:
        c.execute('SELECT * FROM cve_cache WHERE cve_id = ?', (cve_id,))
        row = c.fetchone()
        if row:
            results.append({
                'cve_id': row[0],
                'description': row[5],
                'cvss_v3_score': row[6],
                'cvss_v3_severity': row[8],
                'cached': True
            })
    conn.close()
    
    # If not enough results, query NVD
    if len(results) < limit:
        response = fetch_from_nvd(keyword=keyword)
        if response and response.get('vulnerabilities'):
            for vuln in response['vulnerabilities']:
                cve_data = parse_cve_data(vuln)
                cache_cve(cve_data)
                results.append({
                    'cve_id': cve_data['cve_id'],
                    'description': cve_data['description'],
                    'cvss_v3_score': cve_data['cvss_v3_score'],
                    'cvss_v3_severity': cve_data['cvss_v3_severity'],
                    'cached': False
                })
                if len(results) >= limit:
                    break
    
    return results


def get_openclaw_cves() -> List[Dict[str, Any]]:
    """
    Get all CVEs related to OpenClaw.
    Searches for OpenClaw-related vulnerabilities.
    
    Returns:
        List of OpenClaw-related CVE dictionaries
    """
    keywords = ['openclaw', 'openclaw gateway', 'browser relay', 'websocket']
    results = []
    seen_cve_ids = set()
    
    for keyword in keywords:
        cves = search_cves(keyword, limit=10)
        for cve in cves:
            if cve['cve_id'] not in seen_cve_ids:
                seen_cve_ids.add(cve['cve_id'])
                results.append(cve)
    
    return results


def get_cve_statistics() -> Dict[str, Any]:
    """Get statistics about the CVE cache"""
    conn = sqlite3.connect(CVE_DB_PATH)
    c = conn.cursor()
    
    c.execute('SELECT COUNT(*) FROM cve_cache')
    total_cached = c.fetchone()[0]
    
    c.execute('SELECT COUNT(DISTINCT keyword) FROM cve_search_index')
    total_keywords = c.fetchone()[0]
    
    c.execute('SELECT AVG(cvss_v3_score) FROM cve_cache WHERE cvss_v3_score IS NOT NULL')
    avg_score = c.fetchone()[0] or 0
    
    c.execute('''SELECT cvss_v3_severity, COUNT(*) 
                  FROM cve_cache 
                  WHERE cvss_v3_severity IS NOT NULL 
                  GROUP BY cvss_v3_severity''')
    severity_counts = dict(c.fetchall())
    
    conn.close()
    
    return {
        'total_cached': total_cached,
        'total_keywords': total_keywords,
        'average_cvss_score': round(avg_score, 2) if avg_score else 0,
        'severity_distribution': severity_counts
    }


# Initialize database on module load
try:
    init_cve_db()
except Exception as e:
    print(f"Warning: Could not initialize CVE database: {e}")


if __name__ == '__main__':
    # Test the module
    print("Testing CVE Database Module...")
    
    # Test getting a CVE
    print("\nFetching CVE-2023-44487 (HTTP/2 DoS):")
    cve = get_cve('CVE-2023-44487')
    if cve:
        print(f"  ID: {cve['cve_id']}")
        print(f"  Score: {cve['cvss_v3_score']} ({cve['cvss_v3_severity']})")
        print(f"  Description: {cve['description'][:100]}...")
    
    print("\nCVE Database module ready.")
