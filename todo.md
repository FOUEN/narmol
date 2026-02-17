# Narmol — TODO

## Tools por añadir

### Tier 1 — Imprescindibles
- [ ] **naabu** — Escaneo de puertos (`projectdiscovery/naabu`)
- [ ] **notify** — Notificaciones Slack/Discord/Telegram (`projectdiscovery/notify`)
- [ ] **uncover** — Reconocimiento pasivo via Shodan/Censys/FOFA (`projectdiscovery/uncover`)

### Tier 2 — Muy útiles
- [ ] **tlsx** — Análisis TLS/SSL y extracción de SANs (`projectdiscovery/tlsx`)
- [ ] **alterx** — Generación de subdominios por mutación (`projectdiscovery/alterx`)
- [ ] **cdncheck** — Detección de CDN/WAF (`projectdiscovery/cdncheck`)

### Tier 3 — Especializadas
- [ ] **interactsh** — OOB testing standalone (`projectdiscovery/interactsh`)
- [ ] **asnmap** — Mapeo ASN → rangos IP (`projectdiscovery/asnmap`)

---

## Workflows por añadir

- [ ] **recon** — Reconocimiento completo: `asnmap → subfinder → alterx → dnsx → httpx → nuclei (info/low)`
- [ ] **vuln** — Scan de vulnerabilidades: `httpx → nuclei (critical+high)`
- [ ] **urls** — Descubrimiento de endpoints: `subfinder → httpx → katana + gau → dedup`
- [ ] **ports** — Descubrimiento de servicios: `subfinder → naabu → httpx (puertos descubiertos)`
- [ ] **monitor** — Monitorización continua: `subfinder → diff con previos → httpx (nuevos) → notify`
- [ ] **tech** — Fingerprinting: `httpx (-td) → filtrar por tech → nuclei (templates específicos)`

---

## Infraestructura

- [x] **Workflow system** — Interfaz modular + registro (`workflows/`)
- [x] **active workflow** — Subdominios activos (`workflows/active/`)
- [ ] **Scope middleware** — Definición obligatoria de scope con wildcards y exclusiones (`scope/`)
- [ ] **Fix sonic** — Actualizar `bytedance/sonic` para compatibilidad con Go 1.26
