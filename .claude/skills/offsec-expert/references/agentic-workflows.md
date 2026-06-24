# Agentic AI Pentest Workflows Reference

## The 2026 AI-Assisted Pentest Model

Architecture: **AI for breadth → Human for depth + exploitation**

AI handles:
- Asset discovery and enumeration (subdomain, cloud, API surface)
- Vulnerability scanning and triage
- Attack path generation from graph data (BloodHound, CloudFox)
- Report drafting (finding descriptions, CVSS v4.0 scoring, business impact)
- Real-time intelligence correlation (KEV, EPSS, AttackerKB)

Human operator handles:
- Novel exploit development and chaining
- Business logic testing
- Social engineering and phishing
- EDR evasion and implant customization
- Client-facing communication
- Final report sign-off

This is the only architecture that passes full red team exercises AND scales to continuous PTaaS.

---

## AI Recon Pipeline

### Phase 1: Passive Recon (No Target Interaction)
```bash
# Subdomain enumeration
subfinder -d target.com -all -recursive -o subs.txt
amass enum -passive -d target.com -o amass.txt
cat subs.txt amass.txt | sort -u > all_subs.txt

# Historical DNS + certificate transparency
curl "https://crt.sh/?q=%.target.com&output=json" | jq '.[].name_value' | sort -u

# GitHub recon (leaked keys, internal endpoints)
github-search: "target.com" + ("apikey" OR "secret" OR "password")
trufflehog github --org=targetorg
```

### Phase 2: Active Recon (Footprinting)
```bash
# HTTP probing + tech stack
cat all_subs.txt | httpx -silent -tech-detect -status-code -title -o live.txt

# Port scan (top 1000 + common services)
nmap -iL live.txt --top-ports 1000 -sV --open -oG nmap.gnmap

# Nuclei — CVE + misconfiguration sweep
nuclei -l live.txt -t cves/ -t exposures/ -t misconfigurations/ \
  -severity critical,high,medium -o nuclei_findings.txt
```

### Phase 3: AI Triage
Feed scan output to LLM agent:
- Deduplicate and cluster findings
- Correlate CVE IDs against live KEV/EPSS API
- Rank by exploitability + business context
- Generate attack path hypotheses for human validation

---

## AI-Assisted AD Attack Path Generation

```bash
# Collect BloodHound data
SharpHound.exe -c All --zipfilename bh_data.zip

# Ingest into Neo4j
bloodhound-cli ingest bh_data.zip

# AI-assisted Cypher queries (generate and run against Neo4j)
# "Find all paths from owned computers to Domain Admins with < 5 hops"
MATCH p=shortestPath((c:Computer {owned:true})-[*1..5]->(g:Group {name:"DOMAIN ADMINS@DOMAIN.LOCAL"})) RETURN p

# Attack path summary → human operator picks chain to execute
```

---

## Human-in-Loop Exploitation Gates

Define mandatory human approval gates before AI can proceed:

| Gate | Condition | Reason |
|------|-----------|--------|
| Pre-exploitation | Before any exploit attempt | Verify target is in scope, ROE check |
| Destructive action | File deletion, service stop, data modification | Irreversible — require explicit approval |
| Lateral movement | Before moving to new host | Scope boundary check |
| Exfiltration simulation | Before any data collection | Data handling compliance |
| Privilege escalation | Before DA/root-level access | Blast radius confirmation |

Implementation: agent pauses and sends approval request to operator dashboard before crossing gate.

---

## AI Report Generation Pipeline

1. **Finding ingestion**: Agent parses raw tool output (nuclei JSON, Burp XML, nmap, BloodHound paths)
2. **CVE enrichment**: Auto-fetch CVSS v4.0 score, EPSS, KEV status for each finding
3. **Deduplication**: Cluster related findings (e.g., SQLi on 3 endpoints → one finding with 3 instances)
4. **Draft generation**: LLM generates description, attack narrative, business impact, remediation
5. **Human review**: Operator edits, confirms accuracy, signs off
6. **Final assembly**: Report template populated with findings, exec summary, appendices

Quality bar for AI-generated findings (human checklist):
- [ ] Attack narrative reflects actual observed behavior (not hallucinated)
- [ ] Commands/evidence are from real testing session
- [ ] Business impact is relevant to this client's industry
- [ ] CVSS vector string is correct for the specific finding instance
- [ ] Remediation is specific (version/config/code), not generic

---

## 2026 Agentic Pentest Tools Landscape

| Tool | Role | Notes |
|------|------|-------|
| **PentestGPT** | AI-guided methodology assistant | Open source, good for junior guidance |
| **ReconAI / ReconFTW** | Automated recon orchestration | Chains subfinder/amass/httpx/nuclei |
| **AutoRecon** | Multi-threaded enumeration | CTF-focused but useful for scoped assessments |
| **HackBot** | LLM-powered pentest chat | Research stage |
| **Fabric** (Daniel Miessler) | Pattern-based AI pipelines | Useful for report generation patterns |
| **Our platform** | Full-stack AI+human | Covers all phases with human gates |

---

## MCP Integration for Pentest Tooling

Pentest-specific MCP servers (emerging ecosystem):
- **nuclei-mcp**: Run nuclei scans via agent tool calls
- **nmap-mcp**: Network discovery from agent
- **shodan-mcp**: Shodan search from agent
- **bloodhound-mcp**: Neo4j Cypher queries from agent

Security requirements for pentest MCP servers:
- Authenticate each tool call (operator session token)
- Log all parameters with timestamp and operator ID
- Rate-limit to prevent runaway scan loops
- Restrict egress to defined target IP ranges (enforce scope at server level)
- Require human gate confirmation before destructive/exploiting actions

---

## OPSEC for AI-Assisted Operations

- AI-generated scan traffic has distinct timing patterns — randomize delays
- LLM API calls to OpenAI/Anthropic from pentest infrastructure create external log trail — use self-hosted models for sensitive engagements
- Agent memory (conversation history) may persist sensitive target data — clear between engagements
- Prompt injection from target systems (web pages, documents) can hijack agent actions — sandbox retrieval steps
