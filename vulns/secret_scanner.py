#!/usr/bin/env python3
"""
Secret Scanner Module for Picoclaw
Scans for exposed API keys, tokens, passwords in common locations.
"""

import os
import re
import json
from typing import Dict, Any, List, Optional
from pathlib import Path


# Patterns for detecting secrets
SECRET_PATTERNS = {
    'api_key': {
        'patterns': [
            r'api[_-]?key[\s]*[=:][\s]*[\'"]?([a-zA-Z0-9_\-]{20,})[\'"]?',
            r'apikey[\s]*[=:][\s]*[\'"]?([a-zA-Z0-9_\-]{20,})[\'"]?',
        ],
        'description': 'API Key detected',
        'severity': 'high'
    },
    'aws_access_key': {
        'patterns': [
            r'AKIA[0-9A-Z]{16}',
            r'(?:aws_access_key|aws_access_key_id)[\s]*[=:][\s]*[\'"]?([A-Z0-9]{20})[\'"]?',
        ],
        'description': 'AWS Access Key detected',
        'severity': 'critical'
    },
    'aws_secret_key': {
        'patterns': [
            r'(?:aws_secret_access_key|aws_secret_key)[\s]*[=:][\s]*[\'"]?([a-zA-Z0-9/+=]{40})[\'"]?',
        ],
        'description': 'AWS Secret Key detected',
        'severity': 'critical'
    },
    'github_token': {
        'patterns': [
            r'ghp_[a-zA-Z0-9]{36}',
            r'gho_[a-zA-Z0-9]{36}',
            r'ghu_[a-zA-Z0-9]{36}',
            r'ghs_[a-zA-Z0-9]{36}',
            r'ghr_[a-zA-Z0-9]{36}',
            r'(?:github|gh)[_-]?(?:token|pat)[\s]*[=:][\s]*[\'"]?([a-zA-Z0-9_\-]+)[\'"]?',
        ],
        'description': 'GitHub token detected',
        'severity': 'critical'
    },
    'generic_token': {
        'patterns': [
            r'(?:token|auth_token|bearer_token)[\s]*[=:][\s]*[\'"]?([a-zA-Z0-9_\-\.=]{20,})[\'"]?',
            r'Bearer[\s]+([a-zA-Z0-9_\-\.=]{20,})',
        ],
        'description': 'Generic authentication token detected',
        'severity': 'high'
    },
    'private_key': {
        'patterns': [
            r'-----BEGIN[\s]+(?:RSA[\s]+)?PRIVATE[\s]+KEY-----',
            r'-----BEGIN[\s]+OPENSSH[\s]+PRIVATE[\s]+KEY-----',
        ],
        'description': 'Private key detected',
        'severity': 'critical'
    },
    'password': {
        'patterns': [
            r'(?:password|passwd|pwd)[\s]*[=:][\s]*[\'"]?([^\s\'"]{8,})[\'"]?',
        ],
        'description': 'Password in plaintext detected',
        'severity': 'high'
    },
    'discord_token': {
        'patterns': [
            r'[MN][a-zA-Z\d]{23}\.[a-zA-Z\d]{6}\.[a-zA-Z\d-_]{27}',
            r'(?:discord)[_-]?token[\s]*[=:][\s]*[\'"]?([a-zA-Z0-9_\-\.=]+)[\'"]?',
        ],
        'description': 'Discord token detected',
        'severity': 'critical'
    },
    'slack_token': {
        'patterns': [
            r'xox[abopr]-[\d-]+-[\d-]+-[\d-]+-[a-zA-Z\d]+',
            r'(?:slack)[_-]?token[\s]*[=:][\s]*[\'"]?([a-zA-Z0-9_\-]+)[\'"]?',
        ],
        'description': 'Slack token detected',
        'severity': 'critical'
    },
    'jwt_secret': {
        'patterns': [
            r'(?:jwt|jsonwebtoken)[_-]?(?:secret|key)[\s]*[=:][\s]*[\'"]?([a-zA-Z0-9_\-]{20,})[\'"]?',
        ],
        'description': 'JWT secret detected',
        'severity': 'critical'
    },
    'database_url': {
        'patterns': [
            r'(?:postgres|mysql|mongodb|redis)://[^:]+:[^@]+@[\w\.-]+',
            r'(?:DATABASE_URL|DB_URL)[\s]*[=:][\s]*[\'"]?([a-zA-Z0-9_\-\./:]+)[\'"]?',
        ],
        'description': 'Database URL with credentials detected',
        'severity': 'critical'
    },
    'openclaw_token': {
        'patterns': [
            r'(?:openclaw)[_-]?(?:token|key|secret)[\s]*[=:][\s]*[\'"]?([a-zA-Z0-9_\-]{20,})[\'"]?',
            r'openclaw_[a-zA-Z0-9]{32}',
        ],
        'description': 'OpenClaw token detected',
        'severity': 'critical'
    }
}

# Location patterns to search
SCAN_LOCATIONS = {
    'openclaw_config': {
        'path': '~/.openclaw/',
        'description': 'OpenClaw configuration directory',
        'priority': 'critical'
    },
    'env_files': {
        'path': '.env',
        'description': 'Environment files',
        'priority': 'high'
    },
    'config_files': {
        'patterns': ['*.json', '*.yaml', '*.yml', '*.toml', '*.ini', '*.conf'],
        'description': 'Configuration files',
        'priority': 'medium'
    },
    'ssh_files': {
        'path': '~/.ssh/',
        'description': 'SSH directory',
        'priority': 'critical'
    },
    'bash_history': {
        'path': '~/.bash_history',
        'description': 'Bash command history',
        'priority': 'medium'
    },
    'home_files': {
        'path': '~/',
        'patterns': ['*.key', '*.pem', 'id_rsa*', 'id_ed25519*', '*credentials*'],
        'description': 'Home directory sensitive files',
        'priority': 'critical'
    }
}


def expand_path(path: str) -> str:
    """Expand ~ and environment variables in path"""
    return os.path.expanduser(os.path.expandvars(path))


def scan_file(filepath: str) -> List[Dict[str, Any]]:
    """
    Scan a single file for secrets.
    
    Args:
        filepath: Path to the file to scan
    
    Returns:
        List of detected secrets
    """
    findings = []
    
    try:
        # Skip binary files
        with open(filepath, 'rb') as f:
            chunk = f.read(1024)
            if b'\x00' in chunk:
                return findings
        
        # Read file content
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
            lines = content.split('\n')
        
        # Check each pattern
        for secret_type, config in SECRET_PATTERNS.items():
            for pattern in config['patterns']:
                matches = re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE)
                for match in matches:
                    # Find line number
                    line_num = content[:match.start()].count('\n') + 1
                    line_content = lines[line_num - 1] if line_num <= len(lines) else ''
                    
                    # Mask the actual secret value
                    masked_value = '***REDACTED***'
                    if match.groups():
                        masked_value = '***REDACTED***'
                    
                    findings.append({
                        'file': filepath,
                        'line': line_num,
                        'type': secret_type,
                        'severity': config['severity'],
                        'description': config['description'],
                        'pattern_matched': pattern[:50] + '...' if len(pattern) > 50 else pattern,
                        'masked_value': masked_value,
                        'context': line_content.strip()[:100] if line_content else ''
                    })
    
    except Exception as e:
        # Skip files that can't be read
        pass
    
    return findings


def scan_directory(directory: str, max_depth: int = 5) -> List[Dict[str, Any]]:
    """
    Recursively scan a directory for secrets.
    
    Args:
        directory: Directory to scan
        max_depth: Maximum recursion depth
    
    Returns:
        List of detected secrets
    """
    findings = []
    directory = expand_path(directory)
    
    if not os.path.isdir(directory):
        return findings
    
    try:
        for root, dirs, files in os.walk(directory):
            # Check depth
            depth = root[len(directory):].count(os.sep)
            if depth > max_depth:
                dirs[:] = []
                continue
            
            # Skip hidden and common ignore directories
            dirs[:] = [d for d in dirs if not d.startswith('.') and d not in 
                      ['node_modules', '__pycache__', 'venv', '.git', '.svn']]
            
            for filename in files:
                filepath = os.path.join(root, filename)
                
                # Skip binary files by extension
                if filename.endswith(('.pyc', '.so', '.dll', '.dylib', '.exe', '.bin', '.dat')):
                    continue
                
                file_findings = scan_file(filepath)
                findings.extend(file_findings)
    
    except Exception as e:
        pass
    
    return findings


def scan_openclaw_directory() -> List[Dict[str, Any]]:
    """
    Scan ~/.openclaw/ directory for exposed secrets.
    
    Returns:
        List of detected secrets
    """
    findings = []
    openclaw_dir = expand_path('~/.openclaw/')
    
    if not os.path.isdir(openclaw_dir):
        return findings
    
    # Check for common OpenClaw config files
    config_files = [
        'config.json',
        'credentials.json',
        'api_keys.json',
        'tokens.json',
        'secrets.json',
        '.env',
        'settings.json',
        'gateway_config.json',
        'auth.json'
    ]
    
    for config_file in config_files:
        filepath = os.path.join(openclaw_dir, config_file)
        if os.path.exists(filepath):
            file_findings = scan_file(filepath)
            for finding in file_findings:
                finding['location'] = 'openclaw_config'
                findings.append(finding)
    
    # Scan entire directory
    dir_findings = scan_directory(openclaw_dir)
    for finding in dir_findings:
        finding['location'] = 'openclaw_config'
        if finding not in findings:
            findings.append(finding)
    
    return findings


def scan_env_files() -> List[Dict[str, Any]]:
    """
    Scan for .env files in common locations.
    
    Returns:
        List of detected secrets in .env files
    """
    findings = []
    
    # Common locations for .env files
    env_locations = [
        '~/.env',
        '~/.openclaw/.env',
        '/home/cogniwatch/picoclaw/.env',
        '/home/cogniwatch/.env',
        './.env'
    ]
    
    for loc in env_locations:
        filepath = expand_path(loc)
        if os.path.exists(filepath):
            file_findings = scan_file(filepath)
            for finding in file_findings:
                finding['location'] = 'env_file'
                findings.append(finding)
    
    return findings


def scan_ssh_directory() -> List[Dict[str, Any]]:
    """
    Scan ~/.ssh/ for exposed private keys.
    
    Returns:
        List of detected SSH-related secrets
    """
    findings = []
    ssh_dir = expand_path('~/.ssh/')
    
    if not os.path.isdir(ssh_dir):
        return findings
    
    # Check for private keys
    for filename in os.listdir(ssh_dir):
        filepath = os.path.join(ssh_dir, filename)
        
        if os.path.isfile(filepath):
            # Check file permissions
            try:
                mode = os.stat(filepath).st_mode & 0o777
            except:
                mode = 0o600
            
            # Scan for private keys
            file_findings = scan_file(filepath)
            for finding in file_findings:
                finding['location'] = 'ssh_directory'
                finding['file_permissions'] = oct(mode)
                # Add severity boost for weak permissions
                if mode > 0o600:
                    finding['severity'] = 'critical'
                    finding['description'] += ' (weak file permissions detected)'
                findings.append(finding)
    
    return findings


def check_plaintext_secrets_in_config() -> List[Dict[str, Any]]:
    """
    Check for plaintext secrets in OpenClaw config files.
    Specifically checks for unencrypted tokens/keys.
    
    Returns:
        List of plaintext secrets found
    """
    findings = []
    openclaw_dir = expand_path('~/.openclaw/')
    
    if not os.path.isdir(openclaw_dir):
        return findings
    
    # Check config.json for plaintext secrets
    config_path = os.path.join(openclaw_dir, 'config.json')
    if os.path.exists(config_path):
        try:
            with open(config_path, 'r') as f:
                config = json.load(f)
            
            # Check for plaintext tokens
            sensitive_keys = ['token', 'api_key', 'secret', 'password', 'credential', 'key']
            
            def check_dict(d, path=''):
                if isinstance(d, dict):
                    for k, v in d.items():
                        current_path = f"{path}.{k}" if path else k
                        if any(key in k.lower() for key in sensitive_keys):
                            if isinstance(v, str) and not v.startswith('enc:'):
                                findings.append({
                                    'file': config_path,
                                    'location': 'openclaw_config',
                                    'type': 'plaintext_config_value',
                                    'severity': 'critical',
                                    'description': f'Plaintext value for sensitive key: {current_path}',
                                    'key': current_path,
                                    'masked_value': '***REDACTED***'
                                })
                        check_dict(v, current_path)
                elif isinstance(d, list):
                    for i, item in enumerate(d):
                        check_dict(item, f"{path}[{i}]")
            
            check_dict(config)
        
        except Exception as e:
            pass
    
    return findings


def run_full_scan(target_path: str = None) -> Dict[str, Any]:
    """
    Run a comprehensive secret scan.
    
    Args:
        target_path: Optional specific path to scan (defaults to home directory)
    
    Returns:
        Dictionary with scan results:
        - found: int - Number of secrets found
        - locations: list - List of detected secrets with locations
    """
    all_findings = []
    
    # Scan OpenClaw config directory
    openclaw_findings = scan_openclaw_directory()
    all_findings.extend(openclaw_findings)
    
    # Scan .env files
    env_findings = scan_env_files()
    all_findings.extend(env_findings)
    
    # Scan SSH directory
    ssh_findings = scan_ssh_directory()
    all_findings.extend(ssh_findings)
    
    # Check for plaintext secrets in config
    config_findings = check_plaintext_secrets_in_config()
    all_findings.extend(config_findings)
    
    # Scan target path if specified
    if target_path:
        target_findings = scan_directory(target_path)
        for finding in target_findings:
            finding['location'] = 'target_path'
        all_findings.extend(target_findings)
    
    # Deduplicate findings
    unique_findings = []
    seen = set()
    for finding in all_findings:
        key = (finding.get('file', ''), finding.get('type', ''), finding.get('line', 0))
        if key not in seen:
            seen.add(key)
            unique_findings.append(finding)
    
    # Group by severity
    severity_counts = {
        'critical': 0,
        'high': 0,
        'medium': 0,
        'low': 0
    }
    for finding in unique_findings:
        sev = finding.get('severity', 'low')
        if sev in severity_counts:
            severity_counts[sev] += 1
    
    return {
        'found': len(unique_findings),
        'locations': unique_findings,
        'severity_summary': severity_counts,
        'scan_summary': {
            'openclaw_config': len([f for f in unique_findings if f.get('location') == 'openclaw_config']),
            'env_files': len([f for f in unique_findings if f.get('location') == 'env_file']),
            'ssh_directory': len([f for f in unique_findings if f.get('location') == 'ssh_directory']),
            'target_path': len([f for f in unique_findings if f.get('location') == 'target_path'])
        }
    }


def quick_scan() -> Dict[str, Any]:
    """
    Quick scan of most critical locations only.
    
    Returns:
        Dictionary with scan results
    """
    findings = []
    
    # Quick check of OpenClaw config
    openclaw_dir = expand_path('~/.openclaw/')
    if os.path.isdir(openclaw_dir):
        # Check most critical files only
        critical_files = ['config.json', 'credentials.json', 'tokens.json', '.env']
        for filename in critical_files:
            filepath = os.path.join(openclaw_dir, filename)
            if os.path.exists(filepath):
                file_findings = scan_file(filepath)
                for finding in file_findings:
                    finding['location'] = 'openclaw_config'
                findings.extend(file_findings)
    
    # Quick check of .env
    env_path = expand_path('~/.env')
    if os.path.exists(env_path):
        file_findings = scan_file(env_path)
        for finding in file_findings:
            finding['location'] = 'env_file'
        findings.extend(file_findings)
    
    return {
        'found': len(findings),
        'locations': findings
    }


if __name__ == '__main__':
    import sys
    
    print("Running Secret Scanner...")
    print()
    
    if len(sys.argv) > 1:
        target = sys.argv[1]
        print(f"Scanning target path: {target}")
        result = run_full_scan(target)
    else:
        print("Running quick scan of critical locations...")
        result = quick_scan()
    
    print(f"Secrets found: {result['found']}")
    print()
    
    if result['found'] > 0:
        print("Locations:")
        for loc in result['locations']:
            print(f"  [{loc['severity'].upper()}] {loc['type']}: {loc['description']}")
            print(f"    File: {loc['file']}")
            if loc.get('line'):
                print(f"    Line: {loc['line']}")
            print()
        
        if 'severity_summary' in result:
            print("Severity Summary:")
            for sev, count in result['severity_summary'].items():
                if count > 0:
                    print(f"  {sev.upper()}: {count}")
    else:
        print("No secrets found.")
