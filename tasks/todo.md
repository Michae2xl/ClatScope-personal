# OrbisInt — Task Tracker

## Projeto
Fork privado do ClatScope transformado em app web pessoal com interface Cyber Verde.
Repositório: `Michae2xl/ClatScope-personal` (privado)
App local: `http://localhost:5000`

---

## ✅ Concluído

### Infraestrutura
- [x] Fork privado do repositório `Clats97/ClatScope` criado no GitHub
- [x] Repositório clonado localmente em `/home/ubuntu/ClatScope-personal`
- [x] Backend Flask criado em `webapp/app.py`
- [x] Template HTML principal criado em `webapp/templates/index.html`
- [x] Script de inicialização `start.sh` criado
- [x] Dependências Python instaladas (flask, flask-cors, dnspython, phonenumbers, etc.)
- [x] `config.json` e `api_credentials.md` adicionados ao `.gitignore` (segurança)

### APIs Configuradas
- [x] **IPStack** — Detailed IP Geolocation (100 req/mês grátis)
- [x] **NumVerify** — Phone Number Validation (100 req/mês grátis)
- [x] **Veriphone** — Phone Validate (1.000 req/mês grátis, e-mail confirmado)
- [x] **VirusTotal** — Domain/URL/IP Scan (500 req/dia grátis)
- [x] **Perplexity AI** — 13 ferramentas de IA (pré-pago, ~$0.002/consulta)

### Visual / UX
- [x] Rebrand completo: ClatScope → **OrbisInt**
- [x] Tema **Cyber Verde** aplicado (fundo preto + verde neon #00ff41)
- [x] Tipografia: Orbitron + Share Tech Mono + Rajdhani
- [x] Badge `✓ Active` (verde pulsante) para APIs configuradas
- [x] Badge `API` (roxo) para APIs não configuradas
- [x] Badge `Free` (verde claro) para ferramentas gratuitas
- [x] LED pulsante "SYSTEM ONLINE" no header
- [x] Textos do menu em branco bold com glow verde
- [x] Headers de categoria em Orbitron branco com glow
- [x] Settings com indicadores LED verde (active) e vermelho (missing)

---

## 🔄 Em Progresso

- [ ] Aguardando ativação/configuração de APIs adicionais

---

## 📋 Backlog — APIs Pendentes

| Serviço | Ferramentas | Como obter |
|---|---|---|
| **Hunter.io** | Email finder, domain search | Requer SMS único — cadastrar com número pessoal |
| **APILayer** | Spam Check | [apilayer.com/signup](https://apilayer.com/signup) |
| **HIBP** | Breach Check | [haveibeenpwned.com/API/Key](https://haveibeenpwned.com/API/Key) — $4.50/mês |
| **RapidAPI** | Botometer, TikTok, AES, Skip Trace, MAC, Face, Image | [rapidapi.com](https://rapidapi.com) — varia por API |

---

## 📋 Backlog — Melhorias de UX

- [ ] Adicionar modo escuro/claro (toggle)
- [ ] Histórico de buscas persistente (localStorage)
- [ ] Exportar resultados como PDF ou JSON
- [ ] Atalhos de teclado para ferramentas favoritas
- [ ] Favoritos — fixar ferramentas mais usadas no topo
- [ ] Modo "AutoScan" com relatório consolidado
- [ ] Notificações toast mais detalhadas com tempo de resposta da API

---

## 📋 Backlog — Técnico

- [ ] Adicionar rate limiting no backend para evitar abuso acidental
- [ ] Implementar cache de resultados (Redis ou simples dict em memória)
- [ ] Adicionar logging estruturado com rotação de arquivos
- [ ] Criar Dockerfile para containerização
- [ ] Testes automatizados para os endpoints principais

---

## 🔍 Revisão de Qualidade

- [x] Backend Flask inicia sem erros
- [x] Todas as 30 ferramentas gratuitas testadas e funcionando
- [x] IPStack testado: retorna geolocalização correta
- [x] NumVerify testado: retorna operadora e tipo de número
- [x] Veriphone testado: retorna região e operadora
- [x] VirusTotal testado: retorna análise de 90+ engines
- [x] Perplexity testado: retorna resultados com citações
- [x] Settings: LEDs verde/vermelho funcionando corretamente
- [x] Menu: badges Free/API/Active visíveis e corretos
