"""
ClatScope Web - Flask Backend
A web interface for the ClatScope OSINT tool.
"""

import os
import sys
import json
import re
import ssl
import socket
import http.client
import urllib.parse
import threading
import time
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from email.parser import Parser
from queue import Queue, Empty
from enum import Enum
from typing import Any, Dict

from flask import Flask, request, jsonify, render_template, send_from_directory
from flask_cors import CORS

# Add parent directory to path to access passwords.txt
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

app = Flask(__name__)
CORS(app)

CONFIG_FILE = os.path.join(os.path.dirname(__file__), 'config.json')
LOG_FILE = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'clatscope_log.txt')
PASSWORDS_FILE = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'passwords.txt')

def load_config():
    try:
        with open(CONFIG_FILE, 'r') as f:
            return json.load(f)
    except:
        return {}

def save_config(config):
    with open(CONFIG_FILE, 'w') as f:
        json.dump(config, f, indent=2)

def get_api_key(key_name):
    config = load_config()
    return config.get(key_name, '')

def log_result(text):
    stamp = datetime.now().strftime("[%Y-%m-%d %H:%M:%S] ")
    with open(LOG_FILE, 'a', encoding='utf-8') as f:
        f.write(f"{stamp}{text}\n\n")

# ─── IMPORTS ──────────────────────────────────────────────────────────────────
try:
    import requests as req_lib
    import dns.resolver
    from dns import reversename
    import phonenumbers
    from phonenumbers import geocoder, carrier
    from email_validator import validate_email, EmailNotValidError
    import whois
    from bs4 import BeautifulSoup
    import magic
    from PIL import Image
    from PIL.ExifTags import TAGS, GPSTAGS
    import PyPDF2
    import openpyxl
    import docx
    from pptx import Presentation
    from mutagen.easyid3 import EasyID3
    from mutagen.mp3 import MP3
    from mutagen.mp4 import MP4
    from mutagen.id3 import ID3
    from mutagen.flac import FLAC
    import wave
    from mutagen.oggvorbis import OggVorbis
    from tinytag import TinyTag
    import stat
    DEPS_OK = True
except ImportError as e:
    DEPS_OK = False
    DEPS_ERROR = str(e)

# ─── ROUTES ───────────────────────────────────────────────────────────────────

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/config', methods=['GET'])
def get_config():
    config = load_config()
    # Mask keys for display
    masked = {}
    for k, v in config.items():
        if v and len(v) > 8:
            masked[k] = v[:4] + '*' * (len(v) - 8) + v[-4:]
        elif v:
            masked[k] = '*' * len(v)
        else:
            masked[k] = ''
    return jsonify({'config': masked, 'keys': list(config.keys())})

@app.route('/api/config', methods=['POST'])
def update_config():
    data = request.json
    config = load_config()
    for k, v in data.items():
        if v and not all(c == '*' for c in v):  # Don't save masked values
            config[k] = v
    save_config(config)
    return jsonify({'success': True, 'message': 'Configuration saved successfully'})

@app.route('/api/log', methods=['GET'])
def get_log():
    try:
        with open(LOG_FILE, 'r', encoding='utf-8') as f:
            content = f.read()
        return jsonify({'log': content})
    except:
        return jsonify({'log': 'No log entries yet.'})

@app.route('/api/log/clear', methods=['POST'])
def clear_log():
    with open(LOG_FILE, 'w', encoding='utf-8') as f:
        f.write('')
    return jsonify({'success': True})

# ─── 1. IP ADDRESS SEARCH ─────────────────────────────────────────────────────
@app.route('/api/ip', methods=['POST'])
def ip_search():
    data = request.json
    ip = data.get('ip', '').strip()
    if not ip:
        return jsonify({'error': 'IP address is required'}), 400
    try:
        resp = req_lib.get(f"https://ipinfo.io/{ip}/json", timeout=15)
        resp.raise_for_status()
        d = resp.json()
        loc = d.get('loc', '')
        maps_link = f"https://www.google.com/maps?q={loc}" if loc else ''
        result = {
            'ip': d.get('ip', ''),
            'city': d.get('city', ''),
            'region': d.get('region', ''),
            'country': d.get('country', ''),
            'postal': d.get('postal', ''),
            'org': d.get('org', ''),
            'coordinates': loc,
            'timezone': d.get('timezone', ''),
            'maps_link': maps_link
        }
        log_result(f"IP Search: {ip}\n{json.dumps(result, indent=2)}")
        return jsonify({'result': result})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ─── 2. DEEP ACCOUNT SEARCH ───────────────────────────────────────────────────
@app.route('/api/deep-account', methods=['POST'])
def deep_account_search():
    data = request.json
    username = data.get('username', '').strip()
    if not username:
        return jsonify({'error': 'Username is required'}), 400

    sites = [
        "https://youtube.com/@{target}", "https://facebook.com/{target}",
        "https://instagram.com/{target}", "https://reddit.com/user/{target}",
        "https://medium.com/@{target}", "https://x.com/{target}",
        "https://tiktok.com/@{target}", "https://twitch.tv/{target}",
        "https://vk.com/{target}", "https://pinterest.com/{target}",
        "https://github.com/{target}", "https://soundcloud.com/{target}",
        "https://stackoverflow.com/users/{target}", "https://pastebin.com/u/{target}",
        "https://producthunt.com/@{target}", "https://pypi.org/user/{target}",
        "https://strava.com/athletes/{target}", "https://t.me/{target}",
        "https://tryhackme.com/p/{target}", "https://trakt.tv/users/{target}",
        "https://scratch.mit.edu/users/{target}", "https://hub.docker.com/u/{target}",
        "https://www.chess.com/member/{target}", "https://bitbucket.org/{target}",
        "https://deviantart.com/{target}", "https://www.behance.net/{target}",
        "https://vimeo.com/{target}", "https://www.scribd.com/{target}",
        "https://myspace.com/{target}", "https://genius.com/{target}",
        "https://www.flickr.com/people/{target}", "https://about.me/{target}",
        "https://giphy.com/{target}", "https://onlyfans.com/{target}",
        "https://www.codecademy.com/profiles/{target}",
        "https://connect.garmin.com/modern/profile/{target}",
        "https://roblox.com/users/{target}/profile",
        "https://ebay.com/usr/{target}", "https://steamcommunity.com/user/{target}",
        "https://www.buymeacoffee.com/{target}", "https://keybase.io/{target}",
        "http://en.gravatar.com/{target}", "https://profiles.wordpress.org/{target}",
        "https://hackaday.io/{target}", "https://freesound.org/people/{target}",
        "https://disqus.com/{target}", "https://last.fm/user/{target}",
        "https://tryhackme.com/p/{target}", "https://replit.com/@{target}",
    ]

    urls = [s.format(target=username) for s in sites]
    found = []
    not_found = []
    errors = []

    def check_url(url):
        try:
            r = req_lib.get(url, timeout=8)
            if r.status_code == 200:
                return ('found', url)
            elif r.status_code == 404:
                return ('not_found', url)
            else:
                return ('error', f"{url} (HTTP {r.status_code})")
        except Exception as e:
            return ('error', f"{url} (Error)")

    with ThreadPoolExecutor(max_workers=20) as executor:
        futures = {executor.submit(check_url, url): url for url in urls}
        for future in as_completed(futures):
            status, url = future.result()
            if status == 'found':
                found.append(url)
            elif status == 'not_found':
                not_found.append(url)
            else:
                errors.append(url)

    result = {
        'username': username,
        'found': found,
        'not_found': not_found,
        'errors': errors,
        'total_checked': len(urls),
        'total_found': len(found)
    }
    log_result(f"Deep Account Search: {username}\nFound on {len(found)} sites")
    return jsonify({'result': result})

# ─── 3. PHONE SEARCH ──────────────────────────────────────────────────────────
@app.route('/api/phone', methods=['POST'])
def phone_search():
    data = request.json
    phone_number = data.get('phone', '').strip()
    if not phone_number:
        return jsonify({'error': 'Phone number is required'}), 400
    try:
        parsed = phonenumbers.parse(phone_number)
        country = geocoder.country_name_for_number(parsed, "en")
        region = geocoder.description_for_number(parsed, "en")
        op = carrier.name_for_number(parsed, "en")
        valid = phonenumbers.is_valid_number(parsed)
        result = {
            'number': phone_number,
            'country': country,
            'region': region,
            'operator': op,
            'valid': valid
        }
        log_result(f"Phone Search: {phone_number}\n{json.dumps(result, indent=2)}")
        return jsonify({'result': result})
    except phonenumbers.phonenumberutil.NumberParseException:
        return jsonify({'error': 'Invalid phone number format (use international format e.g. +1-000-000-0000)'}), 400
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ─── 4. DNS RECORD SEARCH ─────────────────────────────────────────────────────
@app.route('/api/dns', methods=['POST'])
def dns_search():
    data = request.json
    domain = data.get('domain', '').strip()
    if not domain:
        return jsonify({'error': 'Domain is required'}), 400
    record_types = ['A', 'CNAME', 'MX', 'NS']
    results = {}
    for rtype in record_types:
        try:
            answers = dns.resolver.resolve(domain, rtype)
            if rtype == 'MX':
                results[rtype] = [f"{ans.preference} {ans.exchange}" for ans in answers]
            else:
                results[rtype] = [str(ans) for ans in answers]
        except dns.resolver.NoAnswer:
            results[rtype] = []
        except dns.resolver.NXDOMAIN:
            results[rtype] = ['Domain does not exist']
        except Exception as e:
            results[rtype] = [f'Error: {str(e)}']
    log_result(f"DNS Search: {domain}\n{json.dumps(results, indent=2)}")
    return jsonify({'result': {'domain': domain, 'records': results}})

# ─── 5. EMAIL MX SEARCH ───────────────────────────────────────────────────────
@app.route('/api/email-mx', methods=['POST'])
def email_mx_search():
    data = request.json
    email_address = data.get('email', '').strip()
    if not email_address:
        return jsonify({'error': 'Email address is required'}), 400
    try:
        v = validate_email(email_address)
        email_domain = v.domain
    except EmailNotValidError as e:
        return jsonify({'error': f'Invalid email: {str(e)}'}), 400
    mx_records = []
    try:
        answers = dns.resolver.resolve(email_domain, 'MX')
        for rdata in answers:
            mx_records.append(str(rdata.exchange))
    except:
        mx_records = []
    validity = "MX Found (Might be valid)" if mx_records else "No MX found (Might be invalid)"
    result = {
        'email': email_address,
        'domain': email_domain,
        'mx_records': mx_records,
        'validity': validity
    }
    log_result(f"Email MX Search: {email_address}\n{json.dumps(result, indent=2)}")
    return jsonify({'result': result})

# ─── 6. PERSON NAME SEARCH (Perplexity) ───────────────────────────────────────
@app.route('/api/person', methods=['POST'])
def person_search():
    data = request.json
    first_name = data.get('first_name', '').strip()
    last_name = data.get('last_name', '').strip()
    city = data.get('city', '').strip()
    if not first_name or not last_name:
        return jsonify({'error': 'First and last name are required'}), 400

    api_key = get_api_key('PERPLEXITY_API_KEY')
    if not api_key:
        return jsonify({'error': 'Perplexity API key not configured. Please add it in Settings.'}), 400

    query = f"{first_name} {last_name} {city}".strip()
    payload = {
        "model": "sonar-reasoning-pro",
        "messages": [
            {"role": "system", "content": "Create a well-sourced profile of the target individual. Include: Full name and known aliases, Date/place of birth (or death) and current residence, Education and career timeline, Public offices, major events, controversies, Close family relations, Publicly available contact details only. Cite each fact with [Source #] and supply a Chicago-style bibliography."},
            {"role": "user", "content": f"Provide the profile for: {query}"}
        ],
        "max_tokens": 8000,
        "temperature": 0.7,
        "stream": False
    }
    try:
        resp = req_lib.post(
            "https://api.perplexity.ai/chat/completions",
            headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
            json=payload, timeout=60
        )
        resp.raise_for_status()
        result_text = resp.json()['choices'][0]['message']['content']
        log_result(f"Person Search: {query}\n{result_text}")
        return jsonify({'result': {'query': query, 'content': result_text}})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ─── 7. REVERSE DNS SEARCH ────────────────────────────────────────────────────
@app.route('/api/reverse-dns', methods=['POST'])
def reverse_dns_search():
    data = request.json
    ip = data.get('ip', '').strip()
    if not ip:
        return jsonify({'error': 'IP address is required'}), 400
    try:
        rev_name = reversename.from_address(ip)
        answers = dns.resolver.resolve(rev_name, "PTR")
        ptr_record = str(answers[0]).strip('.')
    except:
        ptr_record = "No PTR record found"
    result = {'ip': ip, 'ptr_record': ptr_record}
    log_result(f"Reverse DNS: {ip} -> {ptr_record}")
    return jsonify({'result': result})

# ─── 8. EMAIL HEADER SEARCH ───────────────────────────────────────────────────
@app.route('/api/email-header', methods=['POST'])
def email_header_search():
    data = request.json
    raw_headers = data.get('headers', '').strip()
    if not raw_headers:
        return jsonify({'error': 'Email headers are required'}), 400

    parser = Parser()
    msg = parser.parsestr(raw_headers)
    from_ = msg.get("From", "")
    to_ = msg.get("To", "")
    subject_ = msg.get("Subject", "")
    date_ = msg.get("Date", "")
    received_lines = msg.get_all("Received", [])
    found_ips = []
    if received_lines:
        for line in received_lines:
            potential_ips = re.findall(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', line)
            for ip in potential_ips:
                if ip not in found_ips:
                    found_ips.append(ip)

    spf_result, dkim_result, dmarc_result = None, None, None
    auth_results = msg.get_all("Authentication-Results", [])
    if auth_results:
        for entry in auth_results:
            spf_match = re.search(r'spf=(pass|fail|softfail|neutral)', entry, re.IGNORECASE)
            if spf_match:
                spf_result = spf_match.group(1)
            dkim_match = re.search(r'dkim=(pass|fail|none|neutral)', entry, re.IGNORECASE)
            if dkim_match:
                dkim_result = dkim_match.group(1)
            dmarc_match = re.search(r'dmarc=(pass|fail|none)', entry, re.IGNORECASE)
            if dmarc_match:
                dmarc_result = dmarc_match.group(1)

    result = {
        'from': from_, 'to': to_, 'subject': subject_, 'date': date_,
        'found_ips': found_ips,
        'spf': spf_result or 'Not found',
        'dkim': dkim_result or 'Not found',
        'dmarc': dmarc_result or 'Not found'
    }
    log_result(f"Email Header Analysis\n{json.dumps(result, indent=2)}")
    return jsonify({'result': result})

# ─── 9. EMAIL BREACH SEARCH (HIBP) ────────────────────────────────────────────
@app.route('/api/breach', methods=['POST'])
def breach_search():
    data = request.json
    email = data.get('email', '').strip()
    if not email:
        return jsonify({'error': 'Email address is required'}), 400

    api_key = get_api_key('HIBP_API_KEY')
    if not api_key:
        return jsonify({'error': 'Have I Been Pwned API key not configured. Please add it in Settings.'}), 400

    headers = {
        "hibp-api-key": api_key,
        "User-Agent": "ClatScope-Web/1.0"
    }
    url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}?truncateResponse=false"
    try:
        resp = req_lib.get(url, headers=headers, timeout=30)
        if resp.status_code == 200:
            breaches = resp.json()
            result = {
                'email': email,
                'found': True,
                'breach_count': len(breaches),
                'breaches': [{
                    'name': b.get('Name', ''),
                    'domain': b.get('Domain', ''),
                    'breach_date': b.get('BreachDate', ''),
                    'pwn_count': b.get('PwnCount', 0),
                    'data_classes': b.get('DataClasses', [])
                } for b in breaches]
            }
        elif resp.status_code == 404:
            result = {'email': email, 'found': False, 'breach_count': 0, 'breaches': []}
        else:
            return jsonify({'error': f'API error: HTTP {resp.status_code}'}), 500
        log_result(f"Breach Search: {email} - {result['breach_count']} breaches found")
        return jsonify({'result': result})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ─── 10. WHOIS SEARCH ─────────────────────────────────────────────────────────
@app.route('/api/whois', methods=['POST'])
def whois_search():
    data = request.json
    domain = data.get('domain', '').strip()
    if not domain:
        return jsonify({'error': 'Domain is required'}), 400

    def _safe(value):
        if isinstance(value, list):
            value = ", ".join({str(v) for v in value if v}) or "N/A"
        elif isinstance(value, datetime):
            value = value.strftime("%Y-%m-%d %H:%M:%S")
        return str(value) if value else "N/A"

    try:
        w = whois.whois(domain)
        result = {
            'domain': domain,
            'domain_name': _safe(w.domain_name),
            'registrar': _safe(w.registrar),
            'creation_date': _safe(w.creation_date),
            'expiration_date': _safe(w.expiration_date),
            'updated_date': _safe(w.updated_date),
            'name_servers': _safe(w.name_servers),
            'status': _safe(w.status)
        }
        log_result(f"WHOIS: {domain}\n{json.dumps(result, indent=2)}")
        return jsonify({'result': result})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ─── 11. PASSWORD ANALYZER ────────────────────────────────────────────────────
@app.route('/api/password', methods=['POST'])
def password_analyzer():
    data = request.json
    password = data.get('password', '')
    if not password:
        return jsonify({'error': 'Password is required'}), 400

    # Check against common passwords
    if os.path.isfile(PASSWORDS_FILE):
        try:
            with open(PASSWORDS_FILE, 'r', encoding='utf-8') as f:
                common_words = [line.strip() for line in f if line.strip()]
            for word in common_words:
                if word and word.lower() in password.lower():
                    return jsonify({'result': {
                        'password': '***',
                        'strength': 'Weak',
                        'message': 'Contains or overlaps with a common word/phrase/sequence. DO NOT use this password.',
                        'score': 0
                    }})
        except:
            pass

    score = 0
    criteria = []
    if len(password) >= 8:
        score += 1
        criteria.append({'name': 'At least 8 characters', 'met': True})
    else:
        criteria.append({'name': 'At least 8 characters', 'met': False})
    if len(password) >= 12:
        score += 1
        criteria.append({'name': 'At least 12 characters', 'met': True})
    else:
        criteria.append({'name': 'At least 12 characters', 'met': False})
    if re.search(r'[A-Z]', password):
        score += 1
        criteria.append({'name': 'Uppercase letters', 'met': True})
    else:
        criteria.append({'name': 'Uppercase letters', 'met': False})
    if re.search(r'[a-z]', password):
        score += 1
        criteria.append({'name': 'Lowercase letters', 'met': True})
    else:
        criteria.append({'name': 'Lowercase letters', 'met': False})
    if re.search(r'\d', password):
        score += 1
        criteria.append({'name': 'Numbers', 'met': True})
    else:
        criteria.append({'name': 'Numbers', 'met': False})
    if re.search(r'[^a-zA-Z0-9]', password):
        score += 1
        criteria.append({'name': 'Special characters', 'met': True})
    else:
        criteria.append({'name': 'Special characters', 'met': False})

    if score <= 2:
        strength = 'Weak'
        message = 'Too short or lacks variety. DO NOT use this password.'
    elif 3 <= score <= 4:
        strength = 'Moderate'
        message = 'Room for improvement.'
    else:
        strength = 'Strong'
        message = 'Suitable for high security apps/credentials.'

    return jsonify({'result': {'password': '***', 'strength': strength, 'message': message, 'score': score, 'criteria': criteria}})

# ─── 12. USERNAME SEARCH (WhatsMyName) ────────────────────────────────────────
@app.route('/api/username', methods=['POST'])
def username_search():
    data = request.json
    username = data.get('username', '').strip()
    if not username:
        return jsonify({'error': 'Username is required'}), 400

    try:
        resp = req_lib.get("https://raw.githubusercontent.com/WebBreacher/WhatsMyName/main/wmn-data.json", timeout=30)
        resp.raise_for_status()
        wmn_data = resp.json()
    except Exception as e:
        return jsonify({'error': f'Failed to fetch WhatsMyName data: {str(e)}'}), 500

    headers = {
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    }
    sites = wmn_data["sites"]
    found_sites = []

    def check_site(site):
        uri_check = site["uri_check"].format(account=username)
        try:
            r = req_lib.get(uri_check, headers=headers, timeout=10)
            estring_pos = site["e_string"] in r.text
            estring_neg = site["m_string"] in r.text
            if r.status_code == site["e_code"] and estring_pos and not estring_neg:
                return {'site': site["name"], 'url': uri_check}
        except:
            pass
        return None

    with ThreadPoolExecutor(max_workers=20) as executor:
        futures = [executor.submit(check_site, site) for site in sites[:200]]  # Limit for web
        for future in as_completed(futures):
            result = future.result()
            if result:
                found_sites.append(result)

    log_result(f"Username Search: {username} - Found on {len(found_sites)} sites")
    return jsonify({'result': {'username': username, 'found': found_sites, 'total_found': len(found_sites)}})

# ─── 13. REVERSE PHONE SEARCH (Perplexity) ────────────────────────────────────
@app.route('/api/reverse-phone', methods=['POST'])
def reverse_phone_search():
    data = request.json
    phone = data.get('phone', '').strip()
    if not phone:
        return jsonify({'error': 'Phone number is required'}), 400

    api_key = get_api_key('PERPLEXITY_API_KEY')
    if not api_key:
        return jsonify({'error': 'Perplexity API key not configured. Please add it in Settings.'}), 400

    payload = {
        "model": "sonar-reasoning-pro",
        "messages": [
            {"role": "system", "content": "You are a reverse-phone-lookup analyst. Identify the person or business most often linked to a given number. Return only publicly sourced facts. Flag uncertainties and rate confidence."},
            {"role": "user", "content": f"Perform a reverse lookup for: {phone}"}
        ],
        "max_tokens": 8000,
        "temperature": 0.7,
        "stream": False
    }
    try:
        resp = req_lib.post(
            "https://api.perplexity.ai/chat/completions",
            headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
            json=payload, timeout=60
        )
        resp.raise_for_status()
        result_text = resp.json()['choices'][0]['message']['content']
        log_result(f"Reverse Phone Search: {phone}\n{result_text}")
        return jsonify({'result': {'phone': phone, 'content': result_text}})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ─── 14. SSL SEARCH ───────────────────────────────────────────────────────────
@app.route('/api/ssl', methods=['POST'])
def ssl_search():
    data = request.json
    domain = data.get('domain', '').strip()
    if not domain:
        return jsonify({'error': 'Domain is required'}), 400
    # Strip protocol if present
    domain = re.sub(r'^https?://', '', domain).split('/')[0]
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=15) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
        subject = dict(x[0] for x in cert['subject'])
        issuer = dict(x[0] for x in cert['issuer'])
        not_before = cert['notBefore']
        not_after = cert['notAfter']
        not_before_dt = datetime.strptime(not_before, "%b %d %H:%M:%S %Y %Z")
        not_after_dt = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
        result = {
            'domain': domain,
            'issued_to': subject.get('commonName', 'N/A'),
            'issued_by': issuer.get('commonName', 'N/A'),
            'valid_from': str(not_before_dt),
            'valid_until': str(not_after_dt)
        }
        log_result(f"SSL Search: {domain}\n{json.dumps(result, indent=2)}")
        return jsonify({'result': result})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ─── 15. WEB CRAWLER SEARCH ───────────────────────────────────────────────────
@app.route('/api/crawler', methods=['POST'])
def web_crawler():
    data = request.json
    domain = data.get('domain', '').strip()
    if not domain:
        return jsonify({'error': 'Domain is required'}), 400
    domain = re.sub(r'^https?://', '', domain).split('/')[0]
    results = {}
    for resource in ['robots.txt', 'sitemap.xml']:
        url = f"https://{domain}/{resource}"
        try:
            resp = req_lib.get(url, timeout=15)
            if resp.status_code == 200:
                lines = resp.text.split('\n')
                results[resource] = {
                    'status': 200,
                    'content': '\n'.join(lines[:20]),
                    'truncated': len(lines) > 20
                }
            else:
                results[resource] = {'status': resp.status_code, 'content': None}
        except Exception as e:
            results[resource] = {'status': 'error', 'content': str(e)}
    log_result(f"Web Crawler: {domain}")
    return jsonify({'result': {'domain': domain, 'resources': results}})

# ─── 16. DNSBL SEARCH ─────────────────────────────────────────────────────────
@app.route('/api/dnsbl', methods=['POST'])
def dnsbl_search():
    data = request.json
    ip_address = data.get('ip', '').strip()
    if not ip_address:
        return jsonify({'error': 'IP address is required'}), 400
    dnsbl_list = ["zen.spamhaus.org", "bl.spamcop.net", "dnsbl.sorbs.net", "b.barracudacentral.org"]
    reversed_ip = ".".join(ip_address.split(".")[::-1])
    results = []
    for dnsbl in dnsbl_list:
        query_domain = f"{reversed_ip}.{dnsbl}"
        try:
            answers = dns.resolver.resolve(query_domain, 'A')
            for ans in answers:
                results.append({'dnsbl': dnsbl, 'answer': str(ans), 'listed': True})
        except dns.resolver.NXDOMAIN:
            results.append({'dnsbl': dnsbl, 'answer': 'Not listed', 'listed': False})
        except Exception as e:
            results.append({'dnsbl': dnsbl, 'answer': f'Error: {str(e)}', 'listed': False})
    log_result(f"DNSBL Check: {ip_address}")
    return jsonify({'result': {'ip': ip_address, 'checks': results}})

# ─── 17. WEB METADATA SEARCH ──────────────────────────────────────────────────
@app.route('/api/metadata', methods=['POST'])
def web_metadata():
    data = request.json
    url = data.get('url', '').strip()
    if not url:
        return jsonify({'error': 'URL is required'}), 400
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
    try:
        resp = req_lib.get(url, headers=headers, timeout=15)
        resp.raise_for_status()
        soup = BeautifulSoup(resp.text, "html.parser")
        title_tag = soup.find("title")
        meta_desc = soup.find("meta", attrs={"name": "description"})
        meta_keyw = soup.find("meta", attrs={"name": "keywords"})
        meta_author = soup.find("meta", attrs={"name": "author"})
        og_title = soup.find("meta", attrs={"property": "og:title"})
        og_desc = soup.find("meta", attrs={"property": "og:description"})
        result = {
            'url': url,
            'title': title_tag.get_text(strip=True) if title_tag else 'N/A',
            'description': meta_desc["content"] if meta_desc and "content" in meta_desc.attrs else 'N/A',
            'keywords': meta_keyw["content"] if meta_keyw and "content" in meta_keyw.attrs else 'N/A',
            'author': meta_author["content"] if meta_author and "content" in meta_author.attrs else 'N/A',
            'og_title': og_title["content"] if og_title and "content" in og_title.attrs else 'N/A',
            'og_description': og_desc["content"] if og_desc and "content" in og_desc.attrs else 'N/A',
        }
        log_result(f"Web Metadata: {url}\n{json.dumps(result, indent=2)}")
        return jsonify({'result': result})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ─── 18. TRAVEL RISK SEARCH (Perplexity) ──────────────────────────────────────
@app.route('/api/travel', methods=['POST'])
def travel_risk():
    data = request.json
    location = data.get('location', '').strip()
    if not location:
        return jsonify({'error': 'Location is required'}), 400

    api_key = get_api_key('PERPLEXITY_API_KEY')
    if not api_key:
        return jsonify({'error': 'Perplexity API key not configured. Please add it in Settings.'}), 400

    payload = {
        "model": "sonar-reasoning-pro",
        "messages": [
            {"role": "system", "content": "You are a travel risk analysis assistant. Provide comprehensive, detailed, and practical risk assessments for travel destinations covering political stability, crime rates, natural disasters, health risks, local laws, infrastructure, and other relevant factors."},
            {"role": "user", "content": f"Provide a comprehensive travel risk analysis for: {location}"}
        ],
        "max_tokens": 8000,
        "temperature": 0.7,
        "stream": False
    }
    try:
        resp = req_lib.post(
            "https://api.perplexity.ai/chat/completions",
            headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
            json=payload, timeout=60
        )
        resp.raise_for_status()
        result_text = resp.json()['choices'][0]['message']['content']
        log_result(f"Travel Risk: {location}\n{result_text}")
        return jsonify({'result': {'location': location, 'content': result_text}})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ─── 19. BOTOMETER SEARCH (RapidAPI) ──────────────────────────────────────────
@app.route('/api/botometer', methods=['POST'])
def botometer_search():
    data = request.json
    username = data.get('username', '').strip()
    if not username:
        return jsonify({'error': 'Username is required'}), 400
    if not username.startswith("@"):
        username = "@" + username

    api_key = get_api_key('RAPIDAPI_KEY')
    if not api_key:
        return jsonify({'error': 'RapidAPI key not configured. Please add it in Settings.'}), 400

    try:
        url = "https://botometer-pro.p.rapidapi.com/botometer-x/get_botscores_in_batch"
        payload = {"user_ids": [], "usernames": [username]}
        headers = {"x-rapidapi-key": api_key, "x-rapidapi-host": "botometer-pro.p.rapidapi.com", "Content-Type": "application/json"}
        resp = req_lib.post(url, json=payload, headers=headers, timeout=30)
        result = resp.json()
        log_result(f"Botometer: {username}\n{json.dumps(result, indent=2)}")
        return jsonify({'result': result})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ─── 20. BUSINESS SEARCH (Perplexity) ─────────────────────────────────────────
@app.route('/api/business', methods=['POST'])
def business_search():
    data = request.json
    business_name = data.get('business_name', '').strip()
    if not business_name:
        return jsonify({'error': 'Business name is required'}), 400

    api_key = get_api_key('PERPLEXITY_API_KEY')
    if not api_key:
        return jsonify({'error': 'Perplexity API key not configured. Please add it in Settings.'}), 400

    payload = {
        "model": "sonar-reasoning-pro",
        "messages": [
            {"role": "system", "content": "You are a business-intelligence assistant. Compile a structured, source-cited dossier on the named organisation. Include: legal name, locations, leadership, financials, contacts, market position, and risks."},
            {"role": "user", "content": f"Provide general information about {business_name}."}
        ],
        "max_tokens": 8000,
        "temperature": 0.7,
        "stream": False
    }
    try:
        resp = req_lib.post(
            "https://api.perplexity.ai/chat/completions",
            headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
            json=payload, timeout=60
        )
        resp.raise_for_status()
        result_text = resp.json()['choices'][0]['message']['content']
        log_result(f"Business Search: {business_name}\n{result_text}")
        return jsonify({'result': {'business_name': business_name, 'content': result_text}})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ─── 21-24. HUDSON ROCK SEARCHES ──────────────────────────────────────────────
@app.route('/api/hudson-rock', methods=['POST'])
def hudson_rock_search():
    data = request.json
    search_type = data.get('type', '').strip()
    query = data.get('query', '').strip()
    if not query or not search_type:
        return jsonify({'error': 'Type and query are required'}), 400

    endpoints = {
        'email': f"https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-email?email={query}",
        'username': f"https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-username?username={query}",
        'domain': f"https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-domain?domain={query}",
        'ip': f"https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-ip?ip_address={query}"
    }

    if search_type not in endpoints:
        return jsonify({'error': 'Invalid search type'}), 400

    try:
        resp = req_lib.get(endpoints[search_type], timeout=30)
        resp.raise_for_status()
        result = resp.json()
        log_result(f"Hudson Rock {search_type}: {query}\n{json.dumps(result, indent=2)}")
        return jsonify({'result': result})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ─── 25. FACT CHECK SEARCH (Perplexity) ───────────────────────────────────────
@app.route('/api/fact-check', methods=['POST'])
def fact_check():
    data = request.json
    text = data.get('text', '').strip()
    if not text:
        return jsonify({'error': 'Text is required'}), 400

    api_key = get_api_key('PERPLEXITY_API_KEY')
    if not api_key:
        return jsonify({'error': 'Perplexity API key not configured. Please add it in Settings.'}), 400

    payload = {
        "model": "sonar-reasoning-pro",
        "messages": [
            {"role": "system", "content": "You are a fact-check analyst. Evaluate the accuracy of the supplied passage. For each distinct claim: State whether it is True, False, Partly True, or Unclear. Provide a one-sentence justification. Note any missing context or bias. Cite sources using Chicago style."},
            {"role": "user", "content": f"Fact-check the following text:\n\n{text}"}
        ],
        "max_tokens": 8000,
        "temperature": 0.7,
        "stream": False
    }
    try:
        resp = req_lib.post(
            "https://api.perplexity.ai/chat/completions",
            headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
            json=payload, timeout=60
        )
        resp.raise_for_status()
        result_text = resp.json()['choices'][0]['message']['content']
        log_result(f"Fact Check\n{result_text}")
        return jsonify({'result': {'text': text[:100] + '...', 'content': result_text}})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ─── 26. RELATIONSHIP SEARCH (Perplexity) ─────────────────────────────────────
@app.route('/api/relationship', methods=['POST'])
def relationship_search():
    data = request.json
    query = data.get('query', '').strip()
    if not query:
        return jsonify({'error': 'Query is required'}), 400

    api_key = get_api_key('PERPLEXITY_API_KEY')
    if not api_key:
        return jsonify({'error': 'Perplexity API key not configured. Please add it in Settings.'}), 400

    payload = {
        "model": "sonar-reasoning-pro",
        "messages": [
            {"role": "system", "content": "You are a relationship-mapping analyst. Create a fully sourced dossier on the entities in the query, covering: Brief subject overview, Categorised links, Timeline of key interactions, Evidence-based assessment, Network map summary."},
            {"role": "user", "content": query}
        ],
        "max_tokens": 8000,
        "temperature": 0.7,
        "stream": False
    }
    try:
        resp = req_lib.post(
            "https://api.perplexity.ai/chat/completions",
            headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
            json=payload, timeout=60
        )
        resp.raise_for_status()
        result_text = resp.json()['choices'][0]['message']['content']
        log_result(f"Relationship Search: {query}\n{result_text}")
        return jsonify({'result': {'query': query, 'content': result_text}})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ─── 27. FILE METADATA SEARCH ─────────────────────────────────────────────────
@app.route('/api/file-metadata', methods=['POST'])
def file_metadata():
    if 'file' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400

    import tempfile
    with tempfile.NamedTemporaryFile(delete=False, suffix=os.path.splitext(file.filename)[1]) as tmp:
        file.save(tmp.name)
        tmp_path = tmp.name

    try:
        file_stat = os.stat(tmp_path)
        file_size = f"{file_stat.st_size / 1024:.2f} KB"
        mime = magic.Magic(mime=True)
        file_type = mime.from_file(tmp_path)

        result = {
            'filename': file.filename,
            'size': file_size,
            'type': file_type,
            'created': str(datetime.fromtimestamp(file_stat.st_ctime).date()),
            'modified': str(datetime.fromtimestamp(file_stat.st_mtime).date()),
            'accessed': str(datetime.fromtimestamp(file_stat.st_atime).date()),
            'extra': {}
        }

        if file_type.startswith("image"):
            try:
                with Image.open(tmp_path) as img:
                    result['extra']['width'] = img.width
                    result['extra']['height'] = img.height
                    result['extra']['format'] = img.format
                    result['extra']['mode'] = img.mode
                    exif_data = img._getexif()
                    if exif_data:
                        exif = {}
                        for tag_id, val in exif_data.items():
                            tag = TAGS.get(tag_id, tag_id)
                            if isinstance(val, bytes):
                                val = val.decode('utf-8', errors='ignore')
                            exif[str(tag)] = str(val)[:100]
                        result['extra']['exif'] = exif
            except:
                pass
        elif file_type == "application/pdf":
            try:
                with open(tmp_path, "rb") as pdf_file:
                    pdf_reader = PyPDF2.PdfReader(pdf_file)
                    pdf_data = pdf_reader.metadata
                    if pdf_data:
                        result['extra']['pdf_metadata'] = {k: str(v) for k, v in pdf_data.items()}
                    result['extra']['pages'] = len(pdf_reader.pages)
            except:
                pass

        log_result(f"File Metadata: {file.filename}\n{json.dumps(result, indent=2)}")
        return jsonify({'result': result})
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        os.unlink(tmp_path)

# ─── 28. SUBDOMAIN SEARCH ─────────────────────────────────────────────────────
@app.route('/api/subdomain', methods=['POST'])
def subdomain_search():
    data = request.json
    domain = data.get('domain', '').strip()
    if not domain:
        return jsonify({'error': 'Domain is required'}), 400
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    try:
        resp = req_lib.get(url, timeout=30)
        resp.raise_for_status()
        crt_data = resp.json()
        found_subs = set()
        for entry in crt_data:
            if 'name_value' in entry:
                for subd in entry['name_value'].split('\n'):
                    subd_strip = subd.strip()
                    if subd_strip and subd_strip != domain:
                        found_subs.add(subd_strip)
        result = {'domain': domain, 'subdomains': sorted(list(found_subs)), 'count': len(found_subs)}
        log_result(f"Subdomain Search: {domain} - {len(found_subs)} found")
        return jsonify({'result': result})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ─── 29-34. HUNTER.IO SEARCHES ────────────────────────────────────────────────
@app.route('/api/hunter', methods=['POST'])
def hunter_search():
    data = request.json
    search_type = data.get('type', '').strip()
    api_key = get_api_key('HUNTER_API_KEY')
    if not api_key:
        return jsonify({'error': 'Hunter.io API key not configured. Please add it in Settings.'}), 400

    try:
        if search_type == 'domain':
            domain = data.get('domain', '').strip()
            url = f"https://api.hunter.io/v2/domain-search?domain={domain}&api_key={api_key}"
        elif search_type == 'email_finder':
            domain = data.get('domain', '').strip()
            first_name = data.get('first_name', '').strip()
            last_name = data.get('last_name', '').strip()
            url = f"https://api.hunter.io/v2/email-finder?domain={domain}&first_name={first_name}&last_name={last_name}&api_key={api_key}"
        elif search_type == 'email_verify':
            email = data.get('email', '').strip()
            url = f"https://api.hunter.io/v2/email-verifier?email={email}&api_key={api_key}"
        elif search_type == 'company':
            domain = data.get('domain', '').strip()
            url = f"https://api.hunter.io/v2/companies/find?domain={domain}&api_key={api_key}"
        elif search_type == 'person':
            email = data.get('email', '').strip()
            url = f"https://api.hunter.io/v2/people/find?email={email}&api_key={api_key}"
        elif search_type == 'combined':
            email = data.get('email', '').strip()
            url = f"https://api.hunter.io/v2/combined/find?email={email}&api_key={api_key}"
        else:
            return jsonify({'error': 'Invalid Hunter.io search type'}), 400

        resp = req_lib.get(url, timeout=30)
        resp.raise_for_status()
        result = resp.json()
        log_result(f"Hunter.io {search_type}\n{json.dumps(result, indent=2)}")
        return jsonify({'result': result})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ─── 35. CASTRICK EMAIL SEARCH ────────────────────────────────────────────────
@app.route('/api/castrick', methods=['POST'])
def castrick_search():
    data = request.json
    email = data.get('email', '').strip()
    if not email:
        return jsonify({'error': 'Email is required'}), 400

    api_key = get_api_key('CASTRICK_API_KEY')
    if not api_key:
        return jsonify({'error': 'Castrick API key not configured. Please add it in Settings.'}), 400

    try:
        headers = {"api-key": api_key}
        url = f"https://api.castrickclues.com/api/v1/search?query={email}&type=email"
        resp = req_lib.get(url, headers=headers, timeout=30)
        resp.raise_for_status()
        result = resp.json()
        log_result(f"Castrick Email Search: {email}\n{json.dumps(result, indent=2)}")
        return jsonify({'result': result})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ─── 36. VIRUSTOTAL SEARCH ────────────────────────────────────────────────────
@app.route('/api/virustotal', methods=['POST'])
def virustotal_search():
    data = request.json
    domain = data.get('domain', '').strip()
    if not domain:
        return jsonify({'error': 'Domain is required'}), 400

    api_key = get_api_key('VIRUSTOTAL_API_KEY')
    if not api_key:
        return jsonify({'error': 'VirusTotal API key not configured. Please add it in Settings.'}), 400

    try:
        url = f"https://www.virustotal.com/api/v3/domains/{domain}"
        headers = {"accept": "application/json", "x-apikey": api_key}
        resp = req_lib.get(url, headers=headers, timeout=30)
        resp.raise_for_status()
        result = resp.json()
        log_result(f"VirusTotal: {domain}\n{json.dumps(result, indent=2)}")
        return jsonify({'result': result})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ─── 37. MALICE SEARCH (Perplexity) ───────────────────────────────────────────
@app.route('/api/malice', methods=['POST'])
def malice_search():
    data = request.json
    text = data.get('text', '').strip()
    if not text:
        return jsonify({'error': 'Text is required'}), 400

    api_key = get_api_key('PERPLEXITY_API_KEY')
    if not api_key:
        return jsonify({'error': 'Perplexity API key not configured. Please add it in Settings.'}), 400

    payload = {
        "model": "sonar-reasoning-pro",
        "messages": [
            {"role": "system", "content": "You are a malicious-content analyst. Inspect the supplied text for phishing, scams, or social-engineering cues. Output: Risk level (Low/Medium/High), bullet-listed red flags with rationale, and recommendation."},
            {"role": "user", "content": f"Analyze the following text for potential malicious intent:\n\n{text}"}
        ],
        "max_tokens": 8000,
        "temperature": 0.7,
        "stream": False
    }
    try:
        resp = req_lib.post(
            "https://api.perplexity.ai/chat/completions",
            headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
            json=payload, timeout=60
        )
        resp.raise_for_status()
        result_text = resp.json()['choices'][0]['message']['content']
        log_result(f"Malice Search\n{result_text}")
        return jsonify({'result': {'text': text[:100] + '...', 'content': result_text}})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ─── 38. SUPPLY/VENDOR SEARCH (Perplexity) ────────────────────────────────────
@app.route('/api/supply-vendor', methods=['POST'])
def supply_vendor_search():
    data = request.json
    company_name = data.get('company_name', '').strip()
    start_date = data.get('start_date', '').strip()
    if not company_name or not start_date:
        return jsonify({'error': 'Company name and start date are required'}), 400

    api_key = get_api_key('PERPLEXITY_API_KEY')
    if not api_key:
        return jsonify({'error': 'Perplexity API key not configured. Please add it in Settings.'}), 400

    payload = {
        "model": "sonar-reasoning-pro",
        "messages": [
            {"role": "system", "content": f"Provide a comprehensive risk assessment for {company_name} covering the period from {start_date} to present. Include documented incidents, regulatory violations, compliance issues, legal proceedings, and public controversies. Cite all sources in Chicago format."},
            {"role": "user", "content": f"Supply/Vendor Risk Assessment for {company_name} from {start_date} to present."}
        ],
        "max_tokens": 8000,
        "temperature": 0.7,
        "stream": False
    }
    try:
        resp = req_lib.post(
            "https://api.perplexity.ai/chat/completions",
            headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
            json=payload, timeout=60
        )
        resp.raise_for_status()
        result_text = resp.json()['choices'][0]['message']['content']
        log_result(f"Supply/Vendor Search: {company_name}\n{result_text}")
        return jsonify({'result': {'company_name': company_name, 'start_date': start_date, 'content': result_text}})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ─── 39. BUSINESS REP SEARCH (Perplexity) ─────────────────────────────────────
@app.route('/api/business-rep', methods=['POST'])
def business_rep_search():
    data = request.json
    company_name = data.get('company_name', '').strip()
    if not company_name:
        return jsonify({'error': 'Company name is required'}), 400

    api_key = get_api_key('PERPLEXITY_API_KEY')
    if not api_key:
        return jsonify({'error': 'Perplexity API key not configured. Please add it in Settings.'}), 400

    payload = {
        "model": "sonar-reasoning-pro",
        "messages": [
            {"role": "system", "content": "Conduct a comprehensive business reputation analysis. Include documented incidents, regulatory violations, compliance issues, legal proceedings, and public controversies. Cite all sources in Chicago format."},
            {"role": "user", "content": f"Conduct a comprehensive business reputation analysis for {company_name}."}
        ],
        "max_tokens": 8000,
        "temperature": 0.7,
        "stream": False
    }
    try:
        resp = req_lib.post(
            "https://api.perplexity.ai/chat/completions",
            headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
            json=payload, timeout=60
        )
        resp.raise_for_status()
        result_text = resp.json()['choices'][0]['message']['content']
        log_result(f"Business Rep Search: {company_name}\n{result_text}")
        return jsonify({'result': {'company_name': company_name, 'content': result_text}})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ─── 40. WAYBACK SEARCH ───────────────────────────────────────────────────────
@app.route('/api/wayback', methods=['POST'])
def wayback_search():
    data = request.json
    domain = data.get('domain', '').strip()
    if not domain:
        return jsonify({'error': 'Domain is required'}), 400
    base_url = "http://web.archive.org/cdx/search/cdx"
    params = {"url": domain, "output": "json", "fl": "original,timestamp", "collapse": "digest", "filter": "statuscode:200", "limit": 20}
    try:
        resp = req_lib.get(base_url, params=params, timeout=30)
        resp.raise_for_status()
        data_list = resp.json()
        if len(data_list) <= 1:
            return jsonify({'result': {'domain': domain, 'snapshots': [], 'count': 0}})
        snapshots = []
        for snap in data_list[1:]:
            original_url, timestamp = snap
            archive_url = f"https://web.archive.org/web/{timestamp}/{original_url}"
            snapshots.append({'timestamp': timestamp, 'original_url': original_url, 'archive_url': archive_url})
        log_result(f"Wayback Search: {domain} - {len(snapshots)} snapshots")
        return jsonify({'result': {'domain': domain, 'snapshots': snapshots, 'count': len(snapshots)}})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ─── 41. PORT SCAN SEARCH ─────────────────────────────────────────────────────
@app.route('/api/port-scan', methods=['POST'])
def port_scan():
    data = request.json
    target = data.get('target', '').strip()
    if not target:
        return jsonify({'error': 'Target is required'}), 400
    ports = [20, 21, 22, 23, 25, 53, 67, 68, 69, 80, 88, 110, 123, 137, 138, 139, 143, 162, 389, 443, 445, 465, 500, 636, 993, 995, 1433, 3306, 5060, 8080]
    results = []
    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1.0)
        try:
            result = sock.connect_ex((target, port))
            results.append({'port': port, 'status': 'OPEN' if result == 0 else 'closed'})
        except Exception as e:
            results.append({'port': port, 'status': f'error: {str(e)}'})
        finally:
            sock.close()
    open_ports = [r for r in results if r['status'] == 'OPEN']
    log_result(f"Port Scan: {target} - {len(open_ports)} open ports")
    return jsonify({'result': {'target': target, 'ports': results, 'open_count': len(open_ports)}})

# ─── 43. PHONE LEAK SEARCH (RapidAPI) ─────────────────────────────────────────
@app.route('/api/phone-leak', methods=['POST'])
def phone_leak_search():
    data = request.json
    phone = data.get('phone', '').strip()
    if not phone:
        return jsonify({'error': 'Phone number is required'}), 400

    api_key = get_api_key('RAPIDAPI_KEY')
    if not api_key:
        return jsonify({'error': 'RapidAPI key not configured. Please add it in Settings.'}), 400

    try:
        conn = http.client.HTTPSConnection("phone-leak-search.p.rapidapi.com")
        headers = {'x-rapidapi-key': api_key, 'x-rapidapi-host': "phone-leak-search.p.rapidapi.com"}
        conn.request("GET", f"/api/search?phone={phone}", headers=headers)
        res = conn.getresponse()
        data_raw = res.read().decode("utf-8")
        try:
            result = json.loads(data_raw)
        except:
            result = {'raw': data_raw}
        log_result(f"Phone Leak Search: {phone}")
        return jsonify({'result': result})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ─── 44-45. AES ENCRYPTION/DECRYPTION (RapidAPI) ──────────────────────────────
@app.route('/api/aes', methods=['POST'])
def aes_operation():
    data = request.json
    operation = data.get('operation', '').strip()
    api_key = get_api_key('RAPIDAPI_KEY')
    if not api_key:
        return jsonify({'error': 'RapidAPI key not configured. Please add it in Settings.'}), 400

    try:
        conn = http.client.HTTPSConnection("encryption-api2.p.rapidapi.com")
        headers = {
            'x-rapidapi-key': api_key,
            'x-rapidapi-host': "encryption-api2.p.rapidapi.com",
            'Content-Type': "application/json"
        }
        if operation == 'encrypt':
            plaintext = data.get('plaintext', '').strip()
            key = data.get('key', '').strip()
            payload = json.dumps({"text": plaintext, "encryption_key": key})
            conn.request("POST", "/enc.php", payload, headers)
        elif operation == 'decrypt':
            ciphertext = data.get('ciphertext', '').strip()
            key = data.get('key', '').strip()
            iv = data.get('iv', '').strip()
            payload = json.dumps({"ciphertext": ciphertext, "encryption_key": key, "iv": iv})
            conn.request("POST", "/dec.php", payload, headers)
        else:
            return jsonify({'error': 'Invalid operation'}), 400

        res = conn.getresponse()
        result = json.loads(res.read().decode("utf-8"))
        log_result(f"AES {operation}\n{json.dumps(result, indent=2)}")
        return jsonify({'result': result})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ─── 46. EMAIL INTEL SEARCH (RapidAPI) ────────────────────────────────────────
@app.route('/api/email-intel', methods=['POST'])
def email_intel_search():
    data = request.json
    email = data.get('email', '').strip()
    if not email:
        return jsonify({'error': 'Email is required'}), 400

    api_key = get_api_key('RAPIDAPI_KEY')
    if not api_key:
        return jsonify({'error': 'RapidAPI key not configured. Please add it in Settings.'}), 400

    try:
        encoded_email = urllib.parse.quote(email)
        conn = http.client.HTTPSConnection("email-intelligence-api.p.rapidapi.com")
        headers = {"x-rapidapi-key": api_key, "x-rapidapi-host": "email-intelligence-api.p.rapidapi.com"}
        conn.request("GET", f"/v1/check?email={encoded_email}", headers=headers)
        res = conn.getresponse()
        result = json.loads(res.read().decode("utf-8"))
        log_result(f"Email Intel: {email}\n{json.dumps(result, indent=2)}")
        return jsonify({'result': result})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ─── 47. TIKTOK USER SEARCH (RapidAPI) ────────────────────────────────────────
@app.route('/api/tiktok', methods=['POST'])
def tiktok_search():
    data = request.json
    username = data.get('username', '').strip()
    if not username:
        return jsonify({'error': 'Username is required'}), 400

    api_key = get_api_key('RAPIDAPI_KEY')
    if not api_key:
        return jsonify({'error': 'RapidAPI key not configured. Please add it in Settings.'}), 400

    try:
        conn = http.client.HTTPSConnection("tiktok-private1.p.rapidapi.com")
        headers = {'x-rapidapi-key': api_key, 'x-rapidapi-host': "tiktok-private1.p.rapidapi.com"}
        conn.request("GET", f"/user?username={username}", headers=headers)
        res = conn.getresponse()
        result = json.loads(res.read().decode("utf-8"))
        log_result(f"TikTok Search: {username}\n{json.dumps(result, indent=2)}")
        return jsonify({'result': result})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ─── 48-49. SKIP TRACE SEARCH (RapidAPI) ──────────────────────────────────────
@app.route('/api/skip-trace', methods=['POST'])
def skip_trace_search():
    data = request.json
    search_type = data.get('type', 'name').strip()
    api_key = get_api_key('RAPIDAPI_KEY')
    if not api_key:
        return jsonify({'error': 'RapidAPI key not configured. Please add it in Settings.'}), 400

    try:
        conn = http.client.HTTPSConnection("skip-tracing-working-api.p.rapidapi.com")
        headers = {'x-rapidapi-key': api_key, 'x-rapidapi-host': "skip-tracing-working-api.p.rapidapi.com"}
        if search_type == 'name':
            name = data.get('name', '').strip()
            encoded_name = urllib.parse.quote(name)
            conn.request("GET", f"/search/byname?name={encoded_name}&page=1", headers=headers)
        elif search_type == 'id':
            id_val = data.get('id', '').strip()
            conn.request("GET", f"/search/byid?id={id_val}&page=1", headers=headers)
        else:
            return jsonify({'error': 'Invalid search type'}), 400

        res = conn.getresponse()
        result = json.loads(res.read().decode("utf-8"))
        log_result(f"Skip Trace ({search_type})\n{json.dumps(result, indent=2)}")
        return jsonify({'result': result})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ─── 50-53. SHIP & AIRCRAFT SEARCH ────────────────────────────────────────────
@app.route('/api/ship', methods=['POST'])
def ship_search():
    data = request.json
    search_type = data.get('type', '').strip()
    try:
        if search_type == 'mmsi':
            mmsi = data.get('mmsi', '').strip()
            url = f"https://api.facha.dev/v1/ship/{mmsi}"
        elif search_type == 'radius':
            lat = data.get('latitude', '').strip()
            lon = data.get('longitude', '').strip()
            radius = data.get('radius', '').strip()
            url = f"https://api.facha.dev/v1/ship/radius/{lat}/{lon}/{radius}"
        else:
            return jsonify({'error': 'Invalid search type'}), 400

        resp = req_lib.get(url, timeout=30)
        resp.raise_for_status()
        result = resp.json()
        log_result(f"Ship Search ({search_type})\n{json.dumps(result, indent=2)}")
        return jsonify({'result': result})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/aircraft', methods=['POST'])
def aircraft_search():
    data = request.json
    search_type = data.get('type', '').strip()
    try:
        if search_type == 'location':
            lat = data.get('latitude', '').strip()
            lon = data.get('longitude', '').strip()
            range_val = data.get('range', '').strip()
            url = f"https://api.facha.dev/v1/aircraft/live/range/{lat}/{lon}/{range_val}"
        elif search_type == 'callsign':
            callsign = data.get('callsign', '').strip()
            url = f"https://api.facha.dev/v1/aircraft/live/callsign/{callsign}"
        else:
            return jsonify({'error': 'Invalid search type'}), 400

        resp = req_lib.get(url, timeout=30)
        resp.raise_for_status()
        result = resp.json()
        log_result(f"Aircraft Search ({search_type})\n{json.dumps(result, indent=2)}")
        return jsonify({'result': result})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ─── 54. PREDICTA SEARCH ──────────────────────────────────────────────────────
@app.route('/api/predicta', methods=['POST'])
def predicta_search():
    data = request.json
    query = data.get('query', '').strip()
    query_type = data.get('query_type', '').strip()
    if not query or not query_type:
        return jsonify({'error': 'Query and query type are required'}), 400

    api_key = get_api_key('PREDICTA_API_KEY')
    if not api_key:
        return jsonify({'error': 'Predicta API key not configured. Please add it in Settings.'}), 400

    try:
        url = "https://dev.predictasearch.com/api/search"
        headers = {'x-api-key': api_key, 'Content-Type': 'application/json'}
        payload = {"query": query, "query_type": query_type, "networks": ["all"]}
        resp = req_lib.post(url, headers=headers, json=payload, timeout=30)
        resp.raise_for_status()
        result = resp.json()
        log_result(f"Predicta Search: {query}\n{json.dumps(result, indent=2)}")
        return jsonify({'result': result})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ─── 55. IDENTITY GENERATOR (RapidAPI) ────────────────────────────────────────
@app.route('/api/identity', methods=['POST'])
def identity_generator():
    api_key = get_api_key('RAPIDAPI_KEY')
    if not api_key:
        return jsonify({'error': 'RapidAPI key not configured. Please add it in Settings.'}), 400

    try:
        conn = http.client.HTTPSConnection("identity-generator.p.rapidapi.com")
        headers = {'x-rapidapi-key': api_key, 'x-rapidapi-host': "identity-generator.p.rapidapi.com"}
        conn.request("GET", "/identitygenerator/api/", headers=headers)
        res = conn.getresponse()
        result = json.loads(res.read().decode("utf-8"))
        log_result(f"Identity Generator\n{json.dumps(result, indent=2)}")
        return jsonify({'result': result})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ─── 56. VIRTUAL PHONE SEARCH (RapidAPI) ──────────────────────────────────────
@app.route('/api/virtual-phone', methods=['POST'])
def virtual_phone_search():
    data = request.json
    phone = data.get('phone', '').strip()
    if not phone:
        return jsonify({'error': 'Phone number is required'}), 400

    api_key = get_api_key('RAPIDAPI_KEY')
    if not api_key:
        return jsonify({'error': 'RapidAPI key not configured. Please add it in Settings.'}), 400

    try:
        conn = http.client.HTTPSConnection("virtual-phone-numbers-detector.p.rapidapi.com")
        payload = json.dumps({"phone": phone})
        headers = {
            'x-rapidapi-key': api_key,
            'x-rapidapi-host': "virtual-phone-numbers-detector.p.rapidapi.com",
            'Content-Type': "application/json"
        }
        conn.request("POST", "/check-number", payload, headers)
        res = conn.getresponse()
        result = json.loads(res.read().decode("utf-8"))
        log_result(f"Virtual Phone Search: {phone}\n{json.dumps(result, indent=2)}")
        return jsonify({'result': result})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ─── 57. MAC ADDRESS SEARCH (RapidAPI) ────────────────────────────────────────
@app.route('/api/mac', methods=['POST'])
def mac_search():
    data = request.json
    mac = data.get('mac', '').strip()
    if not mac:
        return jsonify({'error': 'MAC address is required'}), 400

    api_key = get_api_key('RAPIDAPI_KEY')
    if not api_key:
        return jsonify({'error': 'RapidAPI key not configured. Please add it in Settings.'}), 400

    try:
        encoded_mac = urllib.parse.quote(mac)
        conn = http.client.HTTPSConnection("mac-address-lookup-api-apiverve.p.rapidapi.com")
        headers = {
            "x-rapidapi-key": api_key,
            "x-rapidapi-host": "mac-address-lookup-api-apiverve.p.rapidapi.com",
            "Accept": "application/json"
        }
        conn.request("GET", f"/v1/macaddresslookup?mac={encoded_mac}", headers=headers)
        res = conn.getresponse()
        result = json.loads(res.read().decode("utf-8"))
        log_result(f"MAC Address Search: {mac}\n{json.dumps(result, indent=2)}")
        return jsonify({'result': result})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ─── 58. AUTOSCAN SEARCH ──────────────────────────────────────────────────────
@app.route('/api/autoscan', methods=['POST'])
def autoscan_search():
    data = request.json
    full_name = data.get('full_name', '').strip()
    city = data.get('city', '').strip()
    phone = data.get('phone', '').strip()
    ip = data.get('ip', '').strip()
    email = data.get('email', '').strip()
    domain = data.get('domain', '').strip()
    username = data.get('username', '').strip()

    api_key = get_api_key('PERPLEXITY_API_KEY')
    output_log = {}

    if ip:
        try:
            resp = req_lib.get(f"https://ipinfo.io/{ip}/json", timeout=10)
            d = resp.json()
            output_log['ip_info'] = d
        except Exception as e:
            output_log['ip_info'] = {'error': str(e)}

    if phone:
        try:
            parsed = phonenumbers.parse(phone)
            output_log['phone_info'] = {
                'number': phone,
                'country': geocoder.country_name_for_number(parsed, "en"),
                'region': geocoder.description_for_number(parsed, "en"),
                'operator': carrier.name_for_number(parsed, "en"),
                'valid': phonenumbers.is_valid_number(parsed)
            }
        except Exception as e:
            output_log['phone_info'] = {'error': str(e)}

    if email:
        try:
            v = validate_email(email)
            email_domain = v.domain
            mx_records = []
            try:
                answers = dns.resolver.resolve(email_domain, 'MX')
                mx_records = [str(r.exchange) for r in answers]
            except:
                pass
            output_log['email_info'] = {'email': email, 'domain': email_domain, 'mx_records': mx_records}
        except Exception as e:
            output_log['email_info'] = {'error': str(e)}

    if domain:
        try:
            w = whois.whois(domain)
            output_log['whois'] = {
                'domain': domain,
                'registrar': str(w.registrar) if w.registrar else 'N/A',
                'creation_date': str(w.creation_date) if w.creation_date else 'N/A',
                'expiration_date': str(w.expiration_date) if w.expiration_date else 'N/A'
            }
        except Exception as e:
            output_log['whois'] = {'error': str(e)}

    if full_name and api_key:
        try:
            query = f"{full_name} {city}".strip()
            payload = {
                "model": "sonar-reasoning-pro",
                "messages": [
                    {"role": "system", "content": "You are a people-profile analyst. Build a source-cited dossier on the target individual."},
                    {"role": "user", "content": f"Provide detailed background for: {query}"}
                ],
                "max_tokens": 4000,
                "temperature": 0.5,
                "stream": False
            }
            resp = req_lib.post(
                "https://api.perplexity.ai/chat/completions",
                headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
                json=payload, timeout=60
            )
            resp.raise_for_status()
            output_log['person_search'] = resp.json()['choices'][0]['message']['content']
        except Exception as e:
            output_log['person_search'] = {'error': str(e)}

    log_result(f"AutoScan: {full_name or 'N/A'}\n{json.dumps(output_log, indent=2)}")
    return jsonify({'result': output_log})

# ─── 59. CONFLICT SEARCH (Perplexity) ─────────────────────────────────────────
@app.route('/api/conflict', methods=['POST'])
def conflict_search():
    data = request.json
    entity1 = data.get('entity1', '').strip()
    entity2 = data.get('entity2', '').strip()
    if not entity1 or not entity2:
        return jsonify({'error': 'Both entities are required'}), 400

    api_key = get_api_key('PERPLEXITY_API_KEY')
    if not api_key:
        return jsonify({'error': 'Perplexity API key not configured. Please add it in Settings.'}), 400

    payload = {
        "model": "sonar-reasoning-pro",
        "messages": [
            {"role": "system", "content": "You are a conflict-of-interest analyst. Assess potential bias between two named entities. Evaluate: Financial ties, Personal ties, Professional ties, Power imbalance, Institutional links, Transparency lapses."},
            {"role": "user", "content": f"Analyze potential conflicts of interest between '{entity1}' and '{entity2}'."}
        ],
        "max_tokens": 8000,
        "temperature": 0.7,
        "stream": False
    }
    try:
        resp = req_lib.post(
            "https://api.perplexity.ai/chat/completions",
            headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
            json=payload, timeout=60
        )
        resp.raise_for_status()
        result_text = resp.json()['choices'][0]['message']['content']
        log_result(f"Conflict Search: {entity1} vs {entity2}\n{result_text}")
        return jsonify({'result': {'entity1': entity1, 'entity2': entity2, 'content': result_text}})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ─── 60. DETAILED IP SEARCH (IPStack) ─────────────────────────────────────────
@app.route('/api/ip-detailed', methods=['POST'])
def ip_detailed_search():
    data = request.json
    ip = data.get('ip', '').strip()
    if not ip:
        return jsonify({'error': 'IP address is required'}), 400

    api_key = get_api_key('IPSTACK_API_KEY')
    if not api_key:
        return jsonify({'error': 'IPStack API key not configured. Please add it in Settings.'}), 400

    try:
        conn = http.client.HTTPSConnection("api.ipstack.com")
        conn.request("GET", f"/{ip}?access_key={api_key}")
        res = conn.getresponse()
        result = json.loads(res.read().decode("utf-8"))
        log_result(f"Detailed IP Search: {ip}\n{json.dumps(result, indent=2)}")
        return jsonify({'result': result})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ─── 61. VERIPHONE SEARCH ─────────────────────────────────────────────────────
@app.route('/api/veriphone', methods=['POST'])
def veriphone_search():
    data = request.json
    phone = data.get('phone', '').strip()
    if not phone:
        return jsonify({'error': 'Phone number is required'}), 400

    api_key = get_api_key('VERIPHONE_API_KEY')
    if not api_key:
        return jsonify({'error': 'Veriphone API key not configured. Please add it in Settings.'}), 400

    try:
        conn = http.client.HTTPSConnection("api.veriphone.io")
        conn.request("GET", f"/v2/verify?phone={phone}&key={api_key}")
        res = conn.getresponse()
        result = json.loads(res.read().decode("utf-8"))
        log_result(f"Veriphone Search: {phone}\n{json.dumps(result, indent=2)}")
        return jsonify({'result': result})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ─── 62. NUMVERIFY SEARCH ─────────────────────────────────────────────────────
@app.route('/api/numverify', methods=['POST'])
def numverify_search():
    data = request.json
    phone = data.get('phone', '').strip()
    if not phone:
        return jsonify({'error': 'Phone number is required'}), 400

    api_key = get_api_key('NUMVERIFY_API_KEY')
    if not api_key:
        return jsonify({'error': 'NumVerify API key not configured. Please add it in Settings.'}), 400

    try:
        conn = http.client.HTTPConnection("apilayer.net")
        conn.request("GET", f"/api/validate?access_key={api_key}&number={phone}")
        res = conn.getresponse()
        result = json.loads(res.read().decode("utf-8"))
        log_result(f"NumVerify Search: {phone}\n{json.dumps(result, indent=2)}")
        return jsonify({'result': result})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ─── 63. GENERAL OSINT SEARCH (RapidAPI) ──────────────────────────────────────
@app.route('/api/osint', methods=['POST'])
def osint_search():
    data = request.json
    query = data.get('query', '').strip()
    if not query:
        return jsonify({'error': 'Query is required'}), 400

    api_key = get_api_key('RAPIDAPI_KEY')
    if not api_key:
        return jsonify({'error': 'RapidAPI key not configured. Please add it in Settings.'}), 400

    try:
        encoded_query = urllib.parse.quote(query)
        conn = http.client.HTTPSConnection("osint-tool-investigation.p.rapidapi.com")
        headers = {"x-rapidapi-key": api_key, "x-rapidapi-host": "osint-tool-investigation.p.rapidapi.com"}
        conn.request("GET", f"/api/search?request={encoded_query}", headers=headers)
        res = conn.getresponse()
        data_raw = res.read().decode("utf-8")
        try:
            result = json.loads(data_raw)
        except:
            result = {'raw': data_raw}
        log_result(f"OSINT Search: {query}\n{json.dumps(result, indent=2)}")
        return jsonify({'result': result})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ─── 64. CONTACT INFO SEARCH (Perplexity) ─────────────────────────────────────
@app.route('/api/contact-info', methods=['POST'])
def contact_info_search():
    data = request.json
    first_name = data.get('first_name', '').strip()
    last_name = data.get('last_name', '').strip()
    city = data.get('city', '').strip()
    if not first_name or not last_name:
        return jsonify({'error': 'First and last name are required'}), 400

    api_key = get_api_key('PERPLEXITY_API_KEY')
    if not api_key:
        return jsonify({'error': 'Perplexity API key not configured. Please add it in Settings.'}), 400

    target = f"{first_name} {last_name}" if not city else f"{first_name} {last_name}, {city}"
    payload = {
        "model": "sonar-reasoning-pro",
        "messages": [
            {"role": "system", "content": "You are a contact-intelligence analyst. Gather verifiable, up-to-date contact details for the named person. Required fields: Primary email(s), Direct phone(s), Physical address or HQ, Social-media profiles, Current employer & role. Output only contact-relevant data."},
            {"role": "user", "content": f"Provide comprehensive contact information for: {target}"}
        ],
        "max_tokens": 4096,
        "temperature": 0.5,
        "stream": False
    }
    try:
        resp = req_lib.post(
            "https://api.perplexity.ai/chat/completions",
            headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
            json=payload, timeout=60
        )
        resp.raise_for_status()
        result_text = resp.json()['choices'][0]['message']['content']
        log_result(f"Contact Info Search: {target}\n{result_text}")
        return jsonify({'result': {'target': target, 'content': result_text}})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ─── 65. INSTAGRAM SEARCH (RapidAPI) ──────────────────────────────────────────
@app.route('/api/instagram', methods=['POST'])
def instagram_search():
    data = request.json
    email = data.get('email', '').strip()
    if not email:
        return jsonify({'error': 'Email is required'}), 400

    api_key = get_api_key('RAPIDAPI_KEY')
    if not api_key:
        return jsonify({'error': 'RapidAPI key not configured. Please add it in Settings.'}), 400

    try:
        conn = http.client.HTTPSConnection("instagram-checker.p.rapidapi.com")
        payload = json.dumps({"input": email})
        headers = {
            'x-rapidapi-key': api_key,
            'x-rapidapi-host': "instagram-checker.p.rapidapi.com",
            'Content-Type': "application/json"
        }
        conn.request("POST", "/check", payload, headers)
        res = conn.getresponse()
        result = json.loads(res.read().decode("utf-8"))
        log_result(f"Instagram Search: {email}\n{json.dumps(result, indent=2)}")
        return jsonify({'result': result})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ─── 66. SIMILAR FACE SEARCH (RapidAPI) ───────────────────────────────────────
@app.route('/api/face-similarity', methods=['POST'])
def face_similarity():
    data = request.json
    url1 = data.get('url1', '').strip()
    url2 = data.get('url2', '').strip()
    if not url1 or not url2:
        return jsonify({'error': 'Both image URLs are required'}), 400

    api_key = get_api_key('RAPIDAPI_KEY')
    if not api_key:
        return jsonify({'error': 'RapidAPI key not configured. Please add it in Settings.'}), 400

    try:
        encoded_url1 = urllib.parse.quote(url1, safe='')
        encoded_url2 = urllib.parse.quote(url2, safe='')
        conn = http.client.HTTPSConnection("face-similarity-api.p.rapidapi.com")
        headers = {'x-rapidapi-key': api_key, 'x-rapidapi-host': "face-similarity-api.p.rapidapi.com"}
        endpoint = f"/5547/compare?hide_analysis=false&url1={encoded_url1}&url2={encoded_url2}"
        conn.request("GET", endpoint, headers=headers)
        res = conn.getresponse()
        result = json.loads(res.read().decode("utf-8"))
        log_result(f"Face Similarity\n{json.dumps(result, indent=2)}")
        return jsonify({'result': result})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ─── 67. REVERSE IMAGE SEARCH (RapidAPI) ──────────────────────────────────────
@app.route('/api/reverse-image', methods=['POST'])
def reverse_image_search():
    data = request.json
    image_url = data.get('url', '').strip()
    if not image_url:
        return jsonify({'error': 'Image URL is required'}), 400

    api_key = get_api_key('RAPIDAPI_KEY')
    if not api_key:
        return jsonify({'error': 'RapidAPI key not configured. Please add it in Settings.'}), 400

    try:
        encoded_url = urllib.parse.quote(image_url, safe='')
        conn = http.client.HTTPSConnection("reverse-image-search1.p.rapidapi.com")
        headers = {'x-rapidapi-key': api_key, 'x-rapidapi-host': "reverse-image-search1.p.rapidapi.com"}
        conn.request("GET", f"/reverse-image-search?url={encoded_url}&limit=10&safe_search=off", headers=headers)
        res = conn.getresponse()
        result = json.loads(res.read().decode("utf-8"))
        log_result(f"Reverse Image Search\n{json.dumps(result, indent=2)}")
        return jsonify({'result': result})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ─── 68. X/TWITTER SEARCH (RapidAPI) ──────────────────────────────────────────
@app.route('/api/twitter', methods=['POST'])
def twitter_search():
    data = request.json
    email = data.get('email', '').strip()
    if not email:
        return jsonify({'error': 'Email is required'}), 400

    api_key = get_api_key('RAPIDAPI_KEY')
    if not api_key:
        return jsonify({'error': 'RapidAPI key not configured. Please add it in Settings.'}), 400

    try:
        payload = json.dumps({"input": email})
        conn = http.client.HTTPSConnection("x-checker.p.rapidapi.com")
        headers = {
            'x-rapidapi-key': api_key,
            'x-rapidapi-host': "x-checker.p.rapidapi.com",
            'Content-Type': "application/json"
        }
        conn.request("POST", "/check", payload, headers)
        res = conn.getresponse()
        result = json.loads(res.read().decode("utf-8"))
        log_result(f"Twitter Search: {email}\n{json.dumps(result, indent=2)}")
        return jsonify({'result': result})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ─── 69. SHERLOCK USERNAME SEARCH ─────────────────────────────────────────────
@app.route('/api/sherlock', methods=['POST'])
def sherlock_search():
    data = request.json
    username = data.get('username', '').strip()
    if not username:
        return jsonify({'error': 'Username is required'}), 400

    DATA_URL = "https://raw.githubusercontent.com/sherlock-project/sherlock/master/sherlock_project/resources/data.json"
    HEADERS = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
    MAX_WORKERS = 50
    REQUEST_TIMEOUT = 15

    WAF_FINGERPRINTS = [
        ".loading-spinner{visibility:hidden}body.no-js",
        '<span id="challenge-error-text">',
        "AwsWafIntegration.forceRefreshToken",
        "perimeterxIdentifiers",
    ]

    class QueryStatus(Enum):
        CLAIMED = "claimed"
        AVAILABLE = "available"
        ERROR = "error"
        WAF = "waf"

    try:
        raw = req_lib.get(DATA_URL, timeout=30).json()
        raw.pop("$schema", None)
    except Exception as e:
        return jsonify({'error': f'Failed to fetch Sherlock data: {str(e)}'}), 500

    found = []
    sess = req_lib.Session()

    def probe(name, site_data):
        url_fmt = site_data.get("url", "")
        error_type = site_data.get("errorType", "")
        error_msg = site_data.get("errorMsg")
        error_code = site_data.get("errorCode")
        url_user = url_fmt.replace("{}", username)

        try:
            r = sess.get(url_user, headers=HEADERS, timeout=REQUEST_TIMEOUT, allow_redirects=(error_type != "response_url"))
            page = r.text or ""

            if any(fp in page for fp in WAF_FINGERPRINTS):
                return None

            if error_type == "message":
                msgs = error_msg
                if isinstance(msgs, str):
                    found_flag = msgs not in page
                else:
                    found_flag = not any(m in page for m in (msgs or []))
                if found_flag:
                    return {'site': name, 'url': url_user, 'status': r.status_code}
            elif error_type == "status_code":
                codes = error_code
                if isinstance(codes, int): codes = [codes]
                if codes and r.status_code not in codes and 200 <= r.status_code < 300:
                    return {'site': name, 'url': url_user, 'status': r.status_code}
            elif error_type == "response_url":
                if 200 <= r.status_code < 300:
                    return {'site': name, 'url': url_user, 'status': r.status_code}
        except:
            pass
        return None

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {executor.submit(probe, name, data): name for name, data in list(raw.items())[:300]}
        for future in as_completed(futures):
            result = future.result()
            if result:
                found.append(result)

    log_result(f"Sherlock Search: {username} - Found on {len(found)} sites")
    return jsonify({'result': {'username': username, 'found': found, 'total_found': len(found)}})

# ─── 70. COMPLETE IP DETAILS ──────────────────────────────────────────────────
@app.route('/api/ip-complete', methods=['POST'])
def ip_complete():
    data = request.json
    ip = data.get('ip', '').strip() or None

    PROVIDERS = [
        f"https://ipapi.co/{ip or ''}/json/",
        f"https://ipinfo.io/{ip or ''}/json",
    ]

    meta = {}
    for url in PROVIDERS:
        try:
            r = req_lib.get(url, timeout=8)
            r.raise_for_status()
            d = r.json()
            for k, v in d.items():
                if v and k not in meta:
                    meta[k] = v
            if len(meta) > 10:
                break
        except:
            continue

    log_result(f"Complete IP Details: {ip or 'self'}\n{json.dumps(meta, indent=2)}")
    return jsonify({'result': meta})

# ─── 71. SPAM CHECK SEARCH (APILayer) ─────────────────────────────────────────
@app.route('/api/spam-check', methods=['POST'])
def spam_check():
    data = request.json
    text = data.get('text', '').strip()
    if not text:
        return jsonify({'error': 'Text is required'}), 400

    api_key = get_api_key('SPAM_API_KEY')
    if not api_key:
        return jsonify({'error': 'Spam Checker API key not configured. Please add it in Settings.'}), 400

    try:
        url = f"https://api.apilayer.com/spamchecker?threshold=5"
        headers = {"apikey": api_key}
        resp = req_lib.post(url, headers=headers, data=text.encode("utf-8"), timeout=30)
        resp.raise_for_status()
        result = resp.json()
        log_result(f"Spam Check\n{json.dumps(result, indent=2)}")
        return jsonify({'result': result})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ─── 72. INFO SCRAPE (Website Contact Scraper) ────────────────────────────────
@app.route('/api/info-scrape', methods=['POST'])
def info_scrape():
    data = request.json
    url = data.get('url', '').strip()
    if not url:
        return jsonify({'error': 'URL is required'}), 400
    if not url.lower().startswith(("http://", "https://")):
        url = "http://" + url

    EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
    PHONE_RE = re.compile(r"(?:\+?\d{1,3}[\s\-.])?(?:\(?\d{3}\)?[\s\-.])?\d{3}[\s\-.]\d{4}")
    SOCIAL_RE = re.compile(
        r"https?://(?:www\.)?(facebook|twitter|linkedin|instagram|youtube|t\.me|telegram|pinterest|threads)\.[^\s\"'<>]+",
        re.I
    )

    try:
        resp = req_lib.get(url, headers={"User-Agent": "Mozilla/5.0"}, timeout=15)
        resp.raise_for_status()
        html = resp.text
        emails = list(set(EMAIL_RE.findall(html)))[:20]
        phones = list(set(PHONE_RE.findall(html)))[:20]
        socials = list(set(SOCIAL_RE.findall(html)))[:20]
        result = {'url': url, 'emails': emails, 'phones': phones, 'social_platforms': socials}
        log_result(f"Info Scrape: {url}\n{json.dumps(result, indent=2)}")
        return jsonify({'result': result})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ─── 73. EMAIL VALIDATION ─────────────────────────────────────────────────────
@app.route('/api/email-validate', methods=['POST'])
def email_validate():
    data = request.json
    email = data.get('email', '').strip()
    if not email:
        return jsonify({'error': 'Email is required'}), 400

    api_key = get_api_key('EMAIL_VALIDATOR_API_KEY')
    if not api_key:
        return jsonify({'error': 'Email Validator API key not configured. Please add it in Settings.'}), 400

    try:
        payload = {"EmailAddress": email, "APIKey": api_key}
        resp = req_lib.post("https://api.email-validator.net/api/verify", data=payload, timeout=15)
        result = resp.json()
        log_result(f"Email Validation: {email}\n{json.dumps(result, indent=2)}")
        return jsonify({'result': result})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ─── 74-75. SHERLOCKEYE SEARCHES ──────────────────────────────────────────────
@app.route('/api/sherlockeye', methods=['POST'])
def sherlockeye_search():
    data = request.json
    search_type = data.get('type', '').strip()
    api_key = get_api_key('SHERLOCKEYE_API_KEY')
    if not api_key:
        return jsonify({'error': 'SherlockEye API key not configured. Please add it in Settings.'}), 400

    try:
        headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
        if search_type == 'username':
            username = data.get('username', '').strip()
            payload = {"username": username}
            resp = req_lib.post("https://api.sherlockeye.io/search", headers=headers, json=payload, timeout=30)
            result = resp.json()
        elif search_type == 'get_result':
            search_id = data.get('search_id', '').strip()
            resp = req_lib.get(f"https://api.sherlockeye.io/get/{search_id}", headers=headers, timeout=30)
            result = resp.json()
        else:
            return jsonify({'error': 'Invalid search type'}), 400

        log_result(f"SherlockEye {search_type}\n{json.dumps(result, indent=2)}")
        return jsonify({'result': result})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ─── TRUECALLER SEARCH (RapidAPI) ─────────────────────────────────────────────
@app.route('/api/truecaller', methods=['POST'])
def truecaller_search():
    data = request.json
    phone = data.get('phone', '').strip()
    if not phone:
        return jsonify({'error': 'Phone number is required'}), 400

    api_key = get_api_key('RAPIDAPI_KEY')
    if not api_key:
        return jsonify({'error': 'RapidAPI key not configured. Please add it in Settings.'}), 400

    try:
        conn = http.client.HTTPSConnection("truecaller-lookup.p.rapidapi.com")
        headers = {'x-rapidapi-key': api_key, 'x-rapidapi-host': "truecaller-lookup.p.rapidapi.com"}
        conn.request("GET", f"/v1/search?phone={urllib.parse.quote(phone)}", headers=headers)
        res = conn.getresponse()
        result = json.loads(res.read().decode("utf-8"))
        log_result(f"Truecaller Search: {phone}\n{json.dumps(result, indent=2)}")
        return jsonify({'result': result})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ─── REDDIT USER SEARCH ───────────────────────────────────────────────────────
@app.route('/api/reddit', methods=['POST'])
def reddit_search():
    data = request.json
    username = data.get('username', '').strip()
    if not username:
        return jsonify({'error': 'Username is required'}), 400
    try:
        headers = {"User-Agent": "ClatScope-Web/1.0"}
        resp = req_lib.get(f"https://www.reddit.com/user/{username}/about.json", headers=headers, timeout=15)
        if resp.status_code == 200:
            result = resp.json()
        elif resp.status_code == 404:
            result = {'error': 'User not found', 'username': username}
        else:
            result = {'error': f'HTTP {resp.status_code}', 'username': username}
        log_result(f"Reddit Search: {username}")
        return jsonify({'result': result})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    print("\n" + "="*60)
    print("  ClatScope Web - OSINT Tool")
    print("  Running at: http://localhost:5000")
    print("="*60 + "\n")
    app.run(host='0.0.0.0', port=5000, debug=False)
