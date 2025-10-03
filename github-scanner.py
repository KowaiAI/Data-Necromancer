“””
GitHub/GitLab Scanner 
Version: 2.0.0 
Find Leaked Secrets & URLs

Review, check functions & test

“””

import requests
import re
import time
import logging
import sys
from typing import List, Dict, Optional
from datetime import datetime
import base64
import json

# Configure logging

logging.basicConfig(
level=logging.INFO,
format=’%(asctime)s - %(name)s - %(levelname)s - %(message)s’,
handlers=[
logging.FileHandler(‘github_scanner.log’),
logging.StreamHandler(sys.stdout)
]
)
logger = logging.getLogger(**name**)

class GitHubScannerError(Exception):
“”“Custom exception for GitHub scanner errors”””
pass

class GitHubScanner:
“””
Production-ready GitHub scanner for exposed secrets and URLs
“””

```
def __init__(self, github_token: Optional[str] = None):
    """
    Initialize GitHub Scanner
    
    Args:
        github_token: GitHub personal access token (optional but recommended)
    """
    self.github_token = github_token
    self.session = requests.Session()
    
    if github_token:
        self.session.headers.update({
            'Authorization': f'token {github_token}',
            'Accept': 'application/vnd.github.v3+json'
        })
        logger.info("GitHub scanner initialized with authentication")
    else:
        logger.warning("GitHub scanner initialized without token - rate limits apply (60 requests/hour)")
    
    # Secret detection patterns
    self.secret_patterns = {
        'aws_key': r'AKIA[0-9A-Z]{16}',
        'slack_token': r'xox[baprs]-[0-9a-zA-Z]{10,48}',
        'slack_webhook': r'https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+',
        'github_token': r'ghp_[0-9a-zA-Z]{36}',
        'github_oauth': r'gho_[0-9a-zA-Z]{36}',
        'stripe_key': r'sk_live_[0-9a-zA-Z]{24,}',
        'google_api': r'AIza[0-9A-Za-z\-_]{35}',
        'private_key': r'-----BEGIN (RSA|DSA|EC|OPENSSH) PRIVATE KEY-----',
        'jwt_token': r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}',
        'api_key': r'api[_-]?key["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-]{20,})["\']',
        'password': r'password["\']?\s*[:=]\s*["\']([^"\']{8,})["\']',
        'database_url': r'(mysql|postgres|mongodb|redis)://[^\s]+',
        'internal_url': r'https?://[a-zA-Z0-9\-]+\.(local|internal|corp|dev|staging)[^\s]*',
        'aws_secret': r'aws_secret_access_key[\s]*=[\s]*["\']([A-Za-z0-9/+=]{40})["\']',
        'azure_key': r'DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=([A-Za-z0-9+/=]{88});',
        'sendgrid_key': r'SG\.[a-zA-Z0-9_\-]{22}\.[a-zA-Z0-9_\-]{43}',
        'twilio_key': r'SK[a-z0-9]{32}',
        'mailgun_key': r'key-[0-9a-zA-Z]{32}',
    }
    
    logger.info(f"Loaded {len(self.secret_patterns)} secret detection patterns")

def comprehensive_scan(self, target_domain: str, target_org: Optional[str] = None, max_results: int = 100) -> Dict:
    """
    Perform comprehensive scan across GitHub and GitLab
    
    Args:
        target_domain: Domain to search for (e.g., 'example.com')
        target_org: Optional GitHub organization to focus on
        max_results: Maximum results per search type
        
    Returns:
        Dictionary with all scan results
    """
    logger.info(f"Starting comprehensive scan for: {target_domain}")
    
    results = {
        'target': target_domain,
        'scan_time': datetime.now().isoformat(),
        'github_results': {
            'code': [],
            'commits': [],
            'issues': []
        },
        'summary': {
            'total_leaks': 0,
            'critical_findings': 0,
            'repositories_affected': set()
        }
    }
    
    try:
        # GitHub Code Search
        logger.info("Searching GitHub code...")
        code_results = self.search_code(target_domain, target_org, max_results)
        results['github_results']['code'] = code_results
        
        for result in code_results:
            if result.get('secrets_found'):
                results['summary']['total_leaks'] += len(result['secrets_found'])
                results['summary']['repositories_affected'].add(result['repository'])
        
        time.sleep(2)  # Rate limiting
        
        # GitHub Commits
        logger.info("Searching GitHub commits...")
        commit_results = self.search_commits(target_domain, target_org)
        results['github_results']['commits'] = commit_results
        
        time.sleep(2)
        
        # GitHub Issues
        logger.info("Searching GitHub issues...")
        issue_results = self.search_issues(target_domain, target_org)
        results['github_results']['issues'] = issue_results
        
        for result in issue_results:
            if result.get('secrets_found'):
                results['summary']['total_leaks'] += len(result['secrets_found'])
        
        # Calculate critical findings
        critical_types = ['aws_key', 'aws_secret', 'private_key', 'password', 'database_url']
        for code_result in results['github_results']['code']:
            for secret in code_result.get('secrets_found', []):
                if secret['type'] in critical_types:
                    results['summary']['critical_findings'] += 1
        
        results['summary']['repositories_affected'] = list(results['summary']['repositories_affected'])
        
        logger.info(f"Scan complete: {results['summary']['total_leaks']} total leaks, "
                   f"{results['summary']['critical_findings']} critical")
        
    except Exception as e:
        logger.error(f"Error during comprehensive scan: {str(e)}", exc_info=True)
    
    return results

def search_code(self, query: str, target_org: Optional[str] = None, max_results: int = 100) -> List[Dict]:
    """
    Search GitHub code for specific patterns
    
    Args:
        query: Search query
        target_org: Optional organization to limit search
        max_results: Maximum results to return
        
    Returns:
        List of code search results with secrets
    """
    results = []
    
    try:
        # Build search query
        search_query = query
        if target_org:
            search_query += f" org:{target_org}"
        
        # GitHub Code Search API
        url = "https://api.github.com/search/code"
        params = {
            'q': search_query,
            'per_page': min(100, max_results),
            'sort': 'indexed',
            'order': 'desc'
        }
        
        logger.debug(f"Searching GitHub code with query: {search_query}")
        response = self.session.get(url, params=params, timeout=15)
        
        if response.status_code == 403:
            logger.error("GitHub rate limit exceeded. Use a GitHub token for higher limits.")
            return results
        
        if response.status_code != 200:
            logger.error(f"GitHub API error: {response.status_code}")
            return results
        
        data = response.json()
        logger.info(f"Found {data.get('total_count', 0)} code results")
        
        for item in data.get('items', [])[:max_results]:
            try:
                # Get file content
                content_url = item.get('url')
                content = self._get_file_content(content_url)
                
                if content:
                    # Scan content for secrets
                    secrets_found = self._scan_content_for_secrets(content)
                    
                    if secrets_found:
                        results.append({
                            'type': 'github_code',
                            'repository': item.get('repository', {}).get('full_name'),
                            'file_path': item.get('path'),
                            'html_url': item.get('html_url'),
                            'secrets_found': secrets_found,
                            'content_preview': content[:500],
                            'last_modified': item.get('repository', {}).get('updated_at'),
                            'size': item.get('repository', {}).get('size'),
                            'stars': item.get('repository', {}).get('stargazers_count'),
                            'discovered_at': datetime.now().isoformat()
                        })
                        logger.warning(f"Found {len(secrets_found)} secrets in {item.get('path')}")
                
                time.sleep(1)  # Rate limiting between file fetches
                
            except Exception as e:
                logger.error(f"Error processing code item: {str(e)}")
        
    except Exception as e:
        logger.error(f"Error searching GitHub code: {str(e)}", exc_info=True)
    
    return results

def search_commits(self, query: str, target_org: Optional[str] = None) -> List[Dict]:
    """
    Search GitHub commits for exposed secrets
    
    Args:
        query: Search query
        target_org: Optional organization to limit search
        
    Returns:
        List of commit search results
    """
    results = []
    
    try:
        search_query = query
        if target_org:
            search_query += f" org:{target_org}"
        
        url = "https://api.github.com/search/commits"
        params = {
            'q': search_query,
            'per_page': 30,
            'sort': 'committer-date'
        }
        
        # Commits search requires special preview header
        headers = {'Accept': 'application/vnd.github.cloak-preview+json'}
        
        logger.debug(f"Searching GitHub commits with query: {search_query}")
        response = self.session.get(url, params=params, headers=headers, timeout=15)
        
        if response.status_code == 403:
            logger.error("GitHub rate limit exceeded")
            return results
        
        if response.status_code != 200:
            logger.error(f"GitHub commits API error: {response.status_code}")
            return results
        
        data = response.json()
        logger.info(f"Found {data.get('total_count', 0)} commit results")
        
        for item in data.get('items', []):
            commit_message = item.get('commit', {}).get('message', '')
            
            # Scan commit message for secrets
            secrets_in_message = self._scan_content_for_secrets(commit_message)
            
            results.append({
                'type': 'github_commit',
                'repository': item.get('repository', {}).get('full_name'),
                'commit_sha': item.get('sha'),
                'html_url': item.get('html_url'),
                'message': commit_message,
                'author': item.get('commit', {}).get('author', {}).get('name'),
                'date': item.get('commit', {}).get('author', {}).get('date'),
                'secrets_found': secrets_in_message,
                'discovered_at': datetime.now().isoformat()
            })
            
            time.sleep(1)
    
    except Exception as e:
        logger.error(f"Error searching commits: {str(e)}", exc_info=True)
    
    return results

def search_issues(self, query: str, target_org: Optional[str] = None) -> List[Dict]:
    """
    Search GitHub issues for exposed information
    
    Args:
        query: Search query
        target_org: Optional organization to limit search
        
    Returns:
        List of issue search results
    """
    results = []
    
    try:
        search_query = query
        if target_org:
            search_query += f" org:{target_org}"
        
        url = "https://api.github.com/search/issues"
        params = {
            'q': search_query,
            'per_page': 50,
            'sort': 'created'
        }
        
        logger.debug(f"Searching GitHub issues with query: {search_query}")
        response = self.session.get(url, params=params, timeout=15)
        
        if response.status_code == 403:
            logger.error("GitHub rate limit exceeded")
            return results
        
        if response.status_code != 200:
            logger.error(f"GitHub issues API error: {response.status_code}")
            return results
        
        data = response.json()
        logger.info(f"Found {data.get('total_count', 0)} issue results")
        
        for item in data.get('items', []):
            body = item.get('body', '') or ''
            title = item.get('title', '') or ''
            combined_text = f"{title}\n{body}"
            
            secrets_found = self._scan_content_for_secrets(combined_text)
            
            if secrets_found:
                results.append({
                    'type': 'github_issue',
                    'title': title,
                    'html_url': item.get('html_url'),
                    'state': item.get('state'),
                    'secrets_found': secrets_found,
                    'created_at': item.get('created_at'),
                    'user': item.get('user', {}).get('login'),
                    'discovered_at': datetime.now().isoformat()
                })
                logger.warning(f"Found {len(secrets_found)} secrets in issue: {title}")
    
    except Exception as e:
        logger.error(f"Error searching issues: {str(e)}", exc_info=True)
    
    return results

def _get_file_content(self, content_url: str) -> Optional[str]:
    """
    Fetch file content from GitHub API
    
    Args:
        content_url: GitHub API URL for file content
        
    Returns:
        File content as string or None if error
    """
    try:
        response = self.session.get(content_url, timeout=10)
        
        if response.status_code != 200:
            logger.warning(f"Failed to fetch content: {response.status_code}")
            return None
        
        data = response.json()
        
        # Content is base64 encoded
        if 'content' in data:
            try:
                content = base64.b64decode(data['content']).decode('utf-8', errors='ignore')
                return content
            except Exception as e:
                logger.error(f"Error decoding content: {str(e)}")
                return None
    
    except Exception as e:
        logger.error(f"Error fetching file content: {str(e)}")
        return None
    
    return None

def _scan_content_for_secrets(self, content: str) -> List[Dict]:
    """
    Scan text content for secret patterns
    
    Args:
        content: Text content to scan
        
    Returns:
        List of found secrets with metadata
    """
    found_secrets = []
    
    if not content:
        return found_secrets
    
    for secret_type, pattern in self.secret_patterns.items():
        try:
            matches = re.findall(pattern, content, re.IGNORECASE | re.MULTILINE)
            
            if matches:
                for match in matches:
                    # Get context around the match
                    match_str = match if isinstance(match, str) else (match[0] if isinstance(match, tuple) else str(match))
                    context = self._get_context(content, match_str)
                    
                    # Truncate long secrets for display
                    display_value = match_str[:50] + '...' if len(match_str) > 50 else match_str
                    
                    found_secrets.append({
                        'type': secret_type,
                        'value': display_value,
                        'context': context,
                        'full_match': match_str,
                        'severity': self._determine_severity(secret_type)
                    })
                    
                    logger.debug(f"Found {secret_type}: {display_value}")
        
        except Exception as e:
            logger.error(f"Error scanning for {secret_type}: {str(e)}")
    
    return found_secrets

def _get_context(self, content: str, match: str, context_chars: int = 100) -> str:
    """
    Get text context around a match
    
    Args:
        content: Full content
        match: Matched string
        context_chars: Characters to include before/after
        
    Returns:
        Context string
    """
    try:
        index = content.find(match)
        if index != -1:
            start = max(0, index - context_chars)
            end = min(len(content), index + len(match) + context_chars)
            context = content[start:end]
            # Clean up context
            return context.replace('\n', ' ').strip()
    except Exception as e:
        logger.error(f"Error getting context: {str(e)}")
    
    return ""

def _determine_severity(self, secret_type: str) -> str:
    """
    Determine severity level of secret type
    
    Args:
        secret_type: Type of secret
        
    Returns:
        Severity level (critical, high, medium, low)
    """
    critical_types = ['aws_key', 'aws_secret', 'private_key', 'database_url', 'azure_key']
    high_types = ['github_token', 'github_oauth', 'stripe_key', 'password']
    medium_types = ['slack_token', 'google_api', 'sendgrid_key', 'twilio_key']
    
    if secret_type in critical_types:
        return 'critical'
    elif secret_type in high_types:
        return 'high'
    elif secret_type in medium_types:
        return 'medium'
    else:
        return 'low'

def export_results(self, results: Dict, filename: str = 'github_scan_results.json'):
    """
    Export scan results to JSON file
    
    Args:
        results: Scan results dictionary
        filename: Output filename
    """
    try:
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, ensure_ascii=False, default=str)
        
        logger.info(f"Results exported to {filename}")
    except Exception as e:
        logger.error(f"Failed to export results: {str(e)}")
```

# Example usage

if **name** == “**main**”:
import os

```
print("=" * 70)
print("GitHub/GitLab Scanner - Production Version 2.0.0")
print("=" * 70)

# Get GitHub token from environment
github_token = os.getenv('GITHUB_TOKEN')

if not github_token:
    print("\n⚠️  WARNING: No GitHub token found.")
    print("Set GITHUB_TOKEN environment variable for higher rate limits.")
    print("Without token: 60 requests/hour")
    print("With token: 5000 requests/hour\n")

# Initialize scanner
scanner = GitHubScanner(github_token=github_token)

# Example scan
target_domain = "example.com"
target_org = "example-org"  # Optional

print(f"\nTarget Domain: {target_domain}")
if target_org:
    print(f"Target Organization: {target_org}")

print("\nStarting comprehensive scan...\n")

try:
    results = scanner.comprehensive_scan(
        target_domain=target_domain,
        target_org=target_org,
        max_results=50
    )
    
    print("\n" + "=" * 70)
    print("SCAN RESULTS")
    print("=" * 70)
    print(f"\nTotal Leaks Found: {results['summary']['total_leaks']}")
    print(f"Critical Findings: {results['summary']['critical_findings']}")
    print(f"Repositories Affected: {len(results['summary']['repositories_affected'])}")
    
    print("\nBreakdown:")
    print(f"  Code Results: {len(results['github_results']['code'])}")
    print(f"  Commit Results: {len(results['github_results']['commits'])}")
    print(f"  Issue Results: {len(results['github_results']['issues'])}")
    
    # Show sample findings
    if results['github_results']['code']:
        print("\n" + "-" * 70)
        print("SAMPLE CODE FINDINGS (first 3):")
        print("-" * 70)
        for item in results['github_results']['code'][:3]:
            print(f"\nRepository: {item['repository']}")
            print(f"File: {item['file_path']}")
            print(f"URL: {item['html_url']}")
            print(f"Secrets Found: {len(item['secrets_found'])}")
            for secret in item['secrets_found'][:3]:
                print(f"  - [{secret['severity'].upper()}] {secret['type']}: {secret['value']}")
    
    # Export results
    scanner.export_results(results)
    print(f"\n✓ Full results exported to github_scan_results.json")
    print("=" * 70)
    
except GitHubScannerError as e:
    logger.error(f"Scanner error: {str(e)}")
    sys.exit(1)
except KeyboardInterrupt:
    print("\n\nScan interrupted by user")
    sys.exit(0)
except Exception as e:
    logger.critical(f"Critical error: {str(e)}", exc_info=True)
    sys.exit(1)
```