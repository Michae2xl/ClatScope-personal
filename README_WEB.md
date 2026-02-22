# ClatScope Web — Personal Edition

Interface web moderna para o ClatScope OSINT Tool, com todas as 75+ funcionalidades originais.

## 🚀 Como Iniciar

```bash
cd ClatScope-personal
./start.sh
```

Depois acesse: **http://localhost:5000**

## 📦 Dependências

```bash
sudo pip3 install flask flask-cors dnspython phonenumbers email-validator python-whois beautifulsoup4 python-magic PyPDF2 python-docx python-pptx mutagen tinytag Pillow requests
```

## ⚙️ Configuração de API Keys

Acesse **Settings** no app e configure suas chaves. Elas são salvas em `webapp/config.json`.

| API Key | Ferramentas |
|---|---|
| Perplexity AI | Person Search, Business, Travel Risk, Fact Check, Malice, Relationship, Conflict |
| RapidAPI | Botometer, TikTok, AES, Skip Trace, Phone Leak, MAC, OSINT, Instagram, Twitter, Face, Image |
| Have I Been Pwned | Breach Check |
| Hunter.io | Domain/Email/Person Search |
| Castrick | Email Search |
| VirusTotal | Domain Scan |
| IPStack | Detailed IP Lookup |
| Veriphone | Phone Validation |
| NumVerify | Phone Validation |
| Spam Checker (APILayer) | Spam Check |
| Email Validator | Email Validation |
| Predicta | Email/Phone Search |
| SherlockEye | Username Search |

## 🛠 Ferramentas Gratuitas (sem API key)

- IP Address Search
- Reverse DNS
- DNS Records
- SSL Certificate
- DNSBL Blacklist Check
- Port Scanner
- Complete IP Details
- WHOIS Lookup
- Subdomain Finder
- Web Crawler
- Web Metadata
- Wayback Machine
- Info Scraper
- Email MX Check
- Email Header Analyzer
- Phone Info
- Password Analyzer
- Username Check (WhatsMyName)
- Deep Account Search
- Sherlock Username Search
- Hudson Rock (Cavalier DB)
- Reddit User Search
- Ship Tracker
- Aircraft Tracker
- File Metadata

## 📋 Log

Todas as pesquisas são salvas em `clatscope_log.txt` na raiz do projeto.
