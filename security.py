import os
import hashlib
import hmac
import secrets
from functools import wraps
from datetime import datetime, timedelta
from flask import request, jsonify, current_app
from collections import defaultdict
import time
import ipaddress

class RateLimiter:
    """Simple in-memory rate limiter"""
    def __init__(self):
        self.requests = defaultdict(list)
        self.blocked_ips = {}
    
    def is_allowed(self, identifier, max_requests=60, window=60):
        """Check if request is allowed within rate limit"""
        now = time.time()
        
        # Check if IP is temporarily blocked
        if identifier in self.blocked_ips:
            if now < self.blocked_ips[identifier]:
                return False, "IP temporarily blocked due to rate limit violations"
            else:
                del self.blocked_ips[identifier]
        
        # Clean old requests
        self.requests[identifier] = [
            req_time for req_time in self.requests[identifier] 
            if req_time > now - window
        ]
        
        # Check rate limit
        if len(self.requests[identifier]) >= max_requests:
            # Block IP for 5 minutes after violation
            self.blocked_ips[identifier] = now + 300
            return False, f"Rate limit exceeded: {max_requests} requests per {window} seconds"
        
        # Add current request
        self.requests[identifier].append(now)
        return True, None

class APIKeyManager:
    """Manage API keys securely"""
    def __init__(self):
        self.keys_file = 'api_keys.txt'
        self.valid_keys = self._load_keys()
    
    def _load_keys(self):
        """Load hashed API keys from file"""
        keys = {}
        if os.path.exists(self.keys_file):
            with open(self.keys_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and '|' in line:
                        key_hash, description = line.split('|', 1)
                        keys[key_hash] = description
        return keys
    
    def generate_key(self, description=""):
        """Generate a new API key"""
        key = secrets.token_urlsafe(32)
        key_hash = hashlib.sha256(key.encode()).hexdigest()
        
        # Save to file
        with open(self.keys_file, 'a') as f:
            f.write(f"{key_hash}|{description}\n")
        
        self.valid_keys[key_hash] = description
        return key
    
    def validate_key(self, api_key):
        """Validate an API key"""
        if not api_key:
            return False
        
        key_hash = hashlib.sha256(api_key.encode()).hexdigest()
        return key_hash in self.valid_keys
    
    def revoke_key(self, api_key):
        """Revoke an API key"""
        key_hash = hashlib.sha256(api_key.encode()).hexdigest()
        if key_hash in self.valid_keys:
            del self.valid_keys[key_hash]
            
            # Rewrite file without revoked key
            with open(self.keys_file, 'w') as f:
                for k_hash, desc in self.valid_keys.items():
                    f.write(f"{k_hash}|{desc}\n")
            return True
        return False

class IPAllowlist:
    """Manage IP allowlist"""
    def __init__(self):
        self.allowed_ips = set()
        self.allowed_networks = []
        self._load_config()
    
    def _load_config(self):
        """Load IP configuration from environment or file"""
        # Allow localhost by default
        self.allowed_ips.add('127.0.0.1')
        self.allowed_ips.add('::1')
        
        # Allow private networks for internal access
        self.allowed_networks.extend([
            ipaddress.ip_network('10.0.0.0/8'),
            ipaddress.ip_network('172.16.0.0/12'),
            ipaddress.ip_network('192.168.0.0/16'),
            ipaddress.ip_network('fc00::/7'),  # IPv6 private
        ])
        
        # Load additional IPs from environment
        additional_ips = os.environ.get('ALLOWED_IPS', '').split(',')
        for ip in additional_ips:
            ip = ip.strip()
            if ip:
                try:
                    # Check if it's a network
                    if '/' in ip:
                        self.allowed_networks.append(ipaddress.ip_network(ip))
                    else:
                        self.allowed_ips.add(ip)
                except ValueError:
                    pass
    
    def is_allowed(self, ip_address):
        """Check if IP is allowed"""
        # Always allow localhost
        if ip_address in self.allowed_ips:
            return True
        
        try:
            ip_obj = ipaddress.ip_address(ip_address)
            
            # Check if IP is in allowed networks
            for network in self.allowed_networks:
                if ip_obj in network:
                    return True
        except ValueError:
            pass
        
        return False

# Initialize security components
rate_limiter = RateLimiter()
api_key_manager = APIKeyManager()
ip_allowlist = IPAllowlist()

def get_client_ip():
    """Get client IP address.

    Forwarded headers are client-controlled, so they are only honoured when
    TRUST_PROXY=1 says a reverse proxy we control sets them. Otherwise anyone
    could send "X-Forwarded-For: 127.0.0.1" and pass the IP allowlist.
    """
    remote_addr = request.environ.get('REMOTE_ADDR', '')
    if os.environ.get('TRUST_PROXY') == '1':
        forwarded = request.environ.get('HTTP_X_FORWARDED_FOR')
        if forwarded:
            # The right-most entry is the one appended by our own proxy.
            return forwarded.split(',')[-1].strip()
        real_ip = request.environ.get('HTTP_X_REAL_IP')
        if real_ip:
            return real_ip.strip()
    return remote_addr

def require_api_key(f):
    """Decorator to require API key for endpoints"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Get API key from header or query param
        api_key = request.headers.get('X-API-Key') or request.args.get('api_key')
        
        if not api_key:
            return jsonify({'error': 'API key required'}), 401
        
        if not api_key_manager.validate_key(api_key):
            return jsonify({'error': 'Invalid API key'}), 401
        
        return f(*args, **kwargs)
    
    return decorated_function

def require_admin_token(f):
    """Gate an admin endpoint on a shared secret instead of on where the request came from.

    Network position is not proof of identity: behind a reverse proxy on the same host, every
    visitor's socket address is 127.0.0.1, so a "localhost only" check lets everyone in. The
    endpoint is therefore disabled unless ADMIN_TOKEN is set, and when it is set the caller must
    send the same value in the X-Admin-Token header.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        expected = os.environ.get('ADMIN_TOKEN', '')
        if not expected:
            # Not configured: behave as if the endpoint does not exist.
            return jsonify({'error': 'Not found'}), 404
        supplied = request.headers.get('X-Admin-Token', '')
        if not hmac.compare_digest(supplied.encode(), expected.encode()):
            return jsonify({'error': 'Access denied'}), 403
        return f(*args, **kwargs)

    return decorated_function

def rate_limit(max_requests=60, window=60):
    """Decorator to apply rate limiting"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            client_ip = get_client_ip()
            
            # Use API key for rate limiting if provided
            api_key = request.headers.get('X-API-Key') or request.args.get('api_key')
            identifier = f"key:{api_key}" if api_key else f"ip:{client_ip}"
            
            allowed, message = rate_limiter.is_allowed(identifier, max_requests, window)
            
            if not allowed:
                return jsonify({'error': message}), 429
            
            return f(*args, **kwargs)
        
        return decorated_function
    return decorator

def ip_restrict(f):
    """Decorator to restrict access by IP"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        client_ip = get_client_ip()
        
        # Skip IP check if valid API key is provided
        api_key = request.headers.get('X-API-Key') or request.args.get('api_key')
        if api_key and api_key_manager.validate_key(api_key):
            return f(*args, **kwargs)
        
        # Otherwise check IP allowlist
        if not ip_allowlist.is_allowed(client_ip):
            return jsonify({'error': 'Access denied'}), 403
        
        return f(*args, **kwargs)
    
    return decorated_function

def ip_restrict_strict(f):
    """Restrict access by IP with no exception for API-key holders.

    ip_restrict lets any valid client API key skip the allowlist, which is right for data
    endpoints and wrong for admin ones: a client key must not widen who can reach them.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not ip_allowlist.is_allowed(get_client_ip()):
            return jsonify({'error': 'Access denied'}), 403
        return f(*args, **kwargs)

    return decorated_function

def secure_headers(response):
    """Add security headers to response"""
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    
    # More permissive CSP for web dashboard functionality
    # Allow Chart.js CDN, inline styles for charts, and inline scripts for dashboard
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://unpkg.com; "
        "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://unpkg.com; "
        "img-src 'self' data: https:; "
        "font-src 'self' data:; "
        "connect-src 'self'; "
        "child-src 'none'; "
        "frame-ancestors 'none'; "
        "object-src 'none'"
    )
    return response