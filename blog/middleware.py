import requests
from django.conf import settings
import re


EXCLUDED_PATHS = [
    '/admin/',
    '/static/',
    '/media/',
    '/favicon/',
    '/robots.txt',
    '/sitemap',
]

EXCLUDED_IPS = getattr(settings, 'ANALYTICS_EXCLUDED_IPS', [])

# Comprehensive bot user-agent patterns
BOT_USER_AGENTS = [
    # Search engines
    'googlebot', 'bingbot', 'slurp', 'duckduckbot', 'baiduspider',
    'yandexbot', 'applebot', 'naver', 'sogou', 'exabot',
    
    # Social media & messaging
    'facebookexternalhit', 'twitterbot', 'linkedinbot', 'whatsapp',
    'telegrambot', 'pinterest', 'instagram', 'slackbot', 'viber',
    'discord', 'skype', 'snapchat',
    
    # Monitoring & uptime services
    'pingdom', 'uptime', 'monitoring', 'statuscake', 'newrelic',
    'datadog', 'synthetic', 'http-client', 'healthchecker', 'statuspage',
    'icinga', 'nagios', 'zabbix', 'pagerduty', 'opsgenie',
    
    # Scrapers & HTTP clients
    'curl', 'wget', 'python', 'scrapy', 'requests', 'httpx',
    'aiohttp', 'perl', 'java', 'ruby', 'php', 'golang', 'node',
    'libcurl', 'urllib', 'httpclient', 'okhttp',
    
    # SEO & analysis tools
    'ahrefs', 'semrush', 'screaming frog', 'mj12bot', 'dotbot',
    'majestic', 'rogerbot', 'grapeshot', 'sistrix', 'seobility',
    'semrush', 'growthbot', 'contently',
    
    # Headless browsers & testing frameworks
    'headlesschrome', 'phantom', 'selenium', 'puppeteer', 'playwright',
    'chrome-lighthouse', 'wkhtmltoimage', 'geckodriver', 'appium',
    'watir', 'testcafe', 'nightwatch', 'cypress',
    
    # CDN & prefetch services
    'cdnbot', 'mediapartners', 'googlepreview', 'bingpreview',
    'bingbot', 'slurp', 'googlebot', 'linkedincrawler',
    
    # Generic bot patterns (catch-all)
    'bot', 'crawler', 'spider', 'scraper', 'fetcher',
    'validator', 'scanner', 'replicant', 'agent'
]

def is_bot_request(user_agent):
    """
    Detect if request is from a bot or crawler.
    
    Args:
        user_agent (str): User-Agent string from request
        
    Returns:
        bool: True if bot detected, False otherwise
    """
    if not user_agent:
        return False
    
    user_agent_lower = user_agent.lower()
    
    # Check against known bot patterns
    for bot_pattern in BOT_USER_AGENTS:
        if bot_pattern in user_agent_lower:
            return True
    
    # Additional heuristic checks for patterns like "curl/7.68.0"
    suspicious_patterns = [
        r'curl/[\d.]+',                    # curl
        r'wget/[\d.]+',                    # wget
        r'python-[\w]+/[\d.]+',           # python libraries
        r'java/[\d.]+',                    # Java
        r'ruby/[\d.]+',                    # Ruby
        r'perl/[\d.]+',                    # Perl
        r'go-http-client/[\d.]+',         # Go
        r'libcurl/[\d.]+',                 # libcurl
        r'requests/[\d.]+',                # Python requests
        r'aiohttp/[\d.]+',                 # Python aiohttp
        r'httpx/[\d.]+',                   # Python httpx
        r'mechanize/[\d.]+',               # mechanize
        r'scrapy/[\d.]+',                  # scrapy
        r'nutch/[\d.]+',                   # Nutch crawler
        r'urlopen',                        # urllib
    ]
    
    for pattern in suspicious_patterns:
        if re.search(pattern, user_agent, re.IGNORECASE):
            return True
    
    return False


def is_suspicious_request(request):
    """
    Detect suspicious or bot-like request patterns.
    Checks for missing headers that legitimate browsers always send.
    
    Args:
        request: Django request object
        
    Returns:
        bool: True if request looks suspicious, False otherwise
    """
    missing_headers = 0
    
    # Modern browsers always send these headers
    headers_to_check = [
        'HTTP_ACCEPT_LANGUAGE',
        'HTTP_ACCEPT_ENCODING',
        'HTTP_ACCEPT',
    ]
    
    for header in headers_to_check:
        if not request.META.get(header):
            missing_headers += 1
    
    # If too many common headers are missing, it's likely a bot
    if missing_headers >= 2:
        return True
    
    # Check for suspiciously short User-Agent
    user_agent = request.META.get('HTTP_USER_AGENT', '')
    if user_agent and len(user_agent) < 10:
        return True
    
    return False


def get_client_ip(request):
    """
    Extract client IP address from request.
    Handles proxy headers (X-Forwarded-For) and direct requests.
    
    Args:
        request: Django request object
        
    Returns:
        str: Client IP address
    """
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        # Take the first IP in case of multiple proxies
        return x_forwarded_for.split(',')[0].strip()
    return request.META.get('REMOTE_ADDR', '')


def get_location(ip):
    """
    Get geographic location (country, city) from IP address.
    Uses ip-api.com service.
    
    Args:
        ip (str): IP address to look up
        
    Returns:
        tuple: (country, city) - empty strings if lookup fails
    """
    try:
        response = requests.get(
            f'http://ip-api.com/json/{ip}?fields=country,city',
            timeout=2
        )
        if response.status_code == 200:
            data = response.json()
            return data.get('country', ''), data.get('city', '')
    except Exception:
        # Silently fail - don't disrupt tracking if geo lookup fails
        pass
    return '', ''


class VisitorTrackingMiddleware:
    """
    Django middleware for tracking visitor analytics.
    
    Tracks:
    - Page views
    - IP addresses
    - Geographic location
    - Referrer
    - User agent
    
    Excludes:
    - Staff/superuser accounts
    - Bot requests
    - Admin, static, media paths
    - Configured IPs
    - Suspicious/non-browser requests
    """
    
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)

        # Only track GET requests (not POST, DELETE, etc.)
        if request.method != 'GET':
            return response
        
        path = request.path

        # Exclude static paths that shouldn't be tracked
        if any(path.startswith(p) for p in EXCLUDED_PATHS):
            return response
        
        # Extract client IP
        ip = get_client_ip(request)

        # Exclude configured IPs (office, monitoring services, etc.)
        if ip in EXCLUDED_IPS:
            return response
        
        # Exclude staff and superuser activity
        if request.user.is_authenticated and (request.user.is_staff or request.user.is_superuser):
            return response
        
        # Check User-Agent for bot patterns
        user_agent = request.META.get('HTTP_USER_AGENT', '')
        if is_bot_request(user_agent):
            return response
        
        # Check for suspicious request patterns (missing headers, etc.)
        if is_suspicious_request(request):
            return response
        
        # All checks passed - record the visitor
        try:
            from .models import Visitor
            
            referrer = request.META.get('HTTP_REFERER', '')
            country, city = get_location(ip)

            Visitor.objects.create(
                ip_address=ip,
                path=path,
                referrer=referrer[:500] if referrer else '',
                country=country,
                city=city,
                user_agent=user_agent[:500],
                is_authenticated=request.user.is_authenticated,
            )
        except Exception:
            # Silently fail - don't disrupt the page load if tracking fails
            pass

        return response