# Narmol -- TODO

## Checklist del scan

### FASE 1 -- Identificar superficie

- [ ] Definir activos in-scope / out-of-scope
- [ ] Subdomains
  - [ ] Pasivo (recursive)
    - [ ] Certificados (subfinder ya usa crtsh como fuente)
    - [ ] Dorking (no hay tool Go adecuada, considerar wrapper de SerpAPI o implementacion custom)
  - [ ] Activo (recursive)
    - [ ] dnsx + wordlist + permutated wordlist (alterx)
    - [ ] Logica de recursion: output subfinder -> alterx -> dnsx -> volver como input

### FASE 2 -- Depurar superficie

- [ ] DNS takeover: nuclei -t http/takeovers/
- [ ] URLs historicas: gau (incluye wayback, commoncrawl, otx, urlscan)
- [x] httpx (comprobar servicio web activo) -- implementado
- [ ] Identificar tecnologias
  - [x] wappalyzergo + httpx TechDetect -- implementado
  - [ ] whatweb: redundante, httpx TechDetect lo cubre
- [ ] .git exposure: nuclei -t http/exposures/configs/git-config.yaml + checker custom en Go

### FASE 3 -- Fuzzing (segundo plano)

- [ ] Crawling (robots, sitemap, etc): katana (registrada)
  - [ ] JavaScript endpoints: katana extrae de JS automaticamente
  - [ ] JavaScript parameters: custom Go (regex sobre output de katana) o x8 (Rust)
  - [ ] Source maps: custom Go, HTTP GET {js_url}.map
  - [ ] Spidering: katana / gospider como alternativa
- [ ] API Endpoints: ffuf para fuzzing de API paths
  - [ ] 403/401 bypass: custom Go (headers: X-Forwarded-For, X-Original-URL, path traversal)
  - [ ] GraphQL introspeccion: custom Go, query {__schema{types{name}}} + nuclei templates
  - [ ] OpenAPI/Swagger/Postman: custom Go, GET /swagger.json, /openapi.json, /v2/api-docs + nuclei templates
- [ ] Directorios y archivos: ffuf / gobuster
  - [ ] 403/401 bypass: mismo checker custom

### FASE 4 -- Vulnerabilidades

- [ ] Information Disclosure
  - [ ] Dorking (Dorksearch, Big bounty recon) -- futuro: AI review
  - [ ] Passwords, API tokens en codigo: trufflehog (Go) + nuclei exposure templates
- [ ] Vuln Assessment
  - [ ] WAF detection: wafw00f (Python, no hay equivalente Go). httpx detecta CDN pero no WAF rules
  - [ ] IP whois: asnmap
  - [x] nuclei -- registrada
  - [ ] Configurations
    - [ ] Test TLS/SSL: tlsx (TLS version, cipher, certs, misconfigs, JARM)
    - [ ] CORS misconfig: custom Go, enviar Origin: evil.com, analizar Access-Control-Allow-Origin
    - [ ] Cookies (HttpOnly, Secure, SameSite): custom Go, parsear Set-Cookie headers
    - [ ] Missing headers: custom Go, comprobar X-Frame-Options, CSP, HSTS, etc.
    - [ ] HTTP Request Smuggling: custom Go, CL/TE desync detection
    - [ ] Security headers checker: custom Go (alternativa local a securityheaders.com)

---

## Implementado

| Componente | Detalle |
|---|---|
| Scope system (scope/) | Wildcards, exclusiones, filtrado |
| Workflow system (workflows/) | Interfaz modular + registro |
| Active workflow (workflows/active/) | subfinder->httpx FIFO pipeline con OnResult streaming |
| Arquitectura modular | cli/, runner/, updater/, scope/, workflows/ |
| Tools registradas | nuclei, httpx, katana, dnsx, subfinder, gau, wappalyzergo |
| Tests | 11/11 passing (scope + active) |

---

## Tools por integrar

### Go -- Integrables como libreria (parcheo main->Main)

| Prioridad | Tool | Funcion | Checklist |
|---|---|---|---|
| 1 | naabu | Port scanning | Servicios no-web |
| 2 | ffuf | Web fuzzer | Dirs, API endpoints, params, vhosts |
| 3 | trufflehog | Secret scanner | Passwords, API tokens, keys en codigo |
| 4 | gobuster | Dir/DNS/VHost brute | Dirs, files, S3 buckets |
| 5 | gowitness | Screenshots | Analisis visual de superficie |
| 6 | gospider | Web spider | JS endpoints, links, S3, subdominios |

### ProjectDiscovery -- Compatibles con sistema de parcheo

| Prioridad | Tool | Funcion | Checklist |
|---|---|---|---|
| 1 | tlsx | TLS analysis | TLS/SSL, certs, SANs, misconfigs |
| 2 | alterx | Subdomain permutations | Wordlists mutadas para dnsx |
| 3 | uncover | Shodan/Censys/FOFA | Superficie pasiva extra |
| 4 | asnmap | ASN -> CIDRs | IP whois, org mapping |
| 5 | notify | Notificaciones | Slack/Discord/Telegram |

### Custom Go -- Implementar en narmol

| Prioridad | Checker | Complejidad | Funcion |
|---|---|---|---|
| 1 | headers-checker | Baja | Valida security headers (CSP, HSTS, X-Frame, etc.) |
| 2 | cookie-checker | Baja | Valida HttpOnly, Secure, SameSite |
| 3 | cors-checker | Media | Envia Origin: evil.com, analiza ACAO header |
| 4 | git-exposure | Baja | GET /.git/HEAD, /.git/config |
| 5 | sourcemap-finder | Baja | GET {js_url}.map sobre URLs de JS |
| 6 | swagger-finder | Baja | GET /swagger.json, /openapi.json, /api-docs |
| 7 | 403-bypass | Media | Prueba bypass headers/paths en URLs con 403 |
| 8 | smuggling-checker | Alta | CL/TE desync detection |
| 9 | graphql-introspection | Baja | Query {__schema{types{name}}} |

### Descartadas

| Tool | Razon |
|---|---|
| wafw00f | Python, no integrable como lib Go |
| feroxbuster | Rust, no integrable como lib Go |
| whatweb | Ruby, redundante con httpx TechDetect |
| waybackurls | Redundante, gau incluye wayback y mas fuentes |
| assetfinder | Redundante, subfinder es superior |
| hakrawler | Redundante, katana y gospider son mejores |
| dnsprobe | Discontinuado, redirige a dnsx |
| shuffledns | Requiere massdns (binario C externo) |

---

## Workflows

| # | Nombre | Pipeline | Cobertura |
|---|---|---|---|
| 1 | recon | subfinder -> alterx -> dnsx -> dedup | Subdomain discovery completo |
| 2 | active | subfinder -> httpx | Implementado |
| 3 | ports | recon output -> naabu -> httpx | Servicios en todos los puertos |
| 4 | tech | httpx results -> wappalyzergo -> classify | Fingerprinting |
| 5 | fuzz | httpx results -> ffuf/gobuster + katana + gau | Fuzzing de superficie depurada |
| 6 | secrets | katana/gau output -> trufflehog + nuclei exposures | Leaks, tokens, passwords |
| 7 | vuln | httpx results -> nuclei + custom checkers | CORS, headers, cookies, smuggling, git |
| 8 | takeover | dnsx results -> nuclei takeover templates | DNS takeover |
| 9 | tls | httpx results -> tlsx | TLS/SSL misconfigs, certs, JARM |
| 10 | visual | httpx results -> gowitness | Screenshots |

### Pipeline completo

```
asnmap (org -> CIDRs)
  |
subfinder + uncover + tlsx (subdomain discovery pasivo)
  |
alterx + dnsx (permutaciones + resolucion)
  |
naabu (port scanning)
  |
httpx (HTTP probing + tech detect)
  |
katana + gau (crawling + URLs historicos)
  |
ffuf + gobuster (fuzzing dirigido)
  |
trufflehog + custom checkers (secrets + misconfigs)
  |
gowitness (screenshots)
  |
nuclei (vulnerability scanning)
```

---

## Infraestructura pendiente

- [ ] Fix sonic: actualizar bytedance/sonic para compatibilidad con Go 1.26
- [ ] Result store: sistema para guardar y reutilizar resultados entre workflows
- [ ] Dedup engine: deduplicacion de resultados entre runs
- [ ] Notify integration: alertas en tiempo real a Slack/Discord/Telegram
