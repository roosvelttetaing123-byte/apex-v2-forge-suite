# Competitive Intelligence Reference

## Market Overview (2026)

### Market Segments

| Segment | Leaders | Our Position |
|---------|---------|--------------|
| Vulnerability Management | Tenable, Qualys, Rapid7 | Adjacent — we prove exploitability they can't |
| DAST / Web Scanning | Invicti (Acunetix), Burp Enterprise, Checkmarx | Adjacent — we go beyond web layer |
| Pentest Platforms / PTaaS | Cobalt, Synack, HackerOne, Pentera, NodeZero | Direct competition |
| BAS (Breach & Attack Simulation) | SafeBreach, AttackIQ, Cymulate | Adjacent — we produce real exploitation evidence |
| Red Team / Adversary Sim | Cobalt Strike, Brute Ratel, Nighthawk, Sliver | C2 layer only — we're the full platform |
| CTEM | Tenable One, XM Cyber | Adjacent — continuous is our PTaaS offering |

---

## Head-to-Head Comparisons

### vs. Tenable One / Nessus

**Their pitch**: Comprehensive vulnerability visibility across the entire attack surface.

**Their limits**:
- Scanners find exposed vulnerabilities; they cannot prove exploitation
- No AD/Kerberos/ADCS attack path analysis
- No lateral movement simulation
- CVSS-only prioritization without EPSS/KEV context in base product
- No AI/LLM/MCP assessment capability

**Our counter**:
"Tenable tells you CVE-2024-XXXX exists on server X. We tell you that CVE-2024-XXXX on server X, chained with a misconfigured ADCS template and a Kerberoastable service account, lets an attacker own your domain in 4 hours. That's the difference between a vulnerability list and a risk."

---

### vs. Invicti (Acunetix) / Burp Suite Enterprise

**Their pitch**: Best-in-class web application security scanning with low false positives.

**Their limits**:
- Web layer only — no cloud IAM, no AD, no mobile, no AI
- Cannot test business logic, IDOR requiring multi-session context, race conditions
- No human exploitation — automated only
- No C2 or post-exploitation capability
- No red team narrative for executive reporting

**Our counter**:
"Burp finds the SQLi. We exploit the SQLi, use it to enumerate the internal network, pivot to the AD environment, and demonstrate what a real attacker would do with it. Those are two very different conversations to have with a CISO."

---

### vs. Cobalt Strike

**Their pitch**: The industry-standard C2 framework for red team operators.

**Their limits**:
- A C2 framework, not a pentest platform — no scanning, reporting, scoping tools
- Default beacon is heavily fingerprinted by all Tier 1 EDRs without significant customization
- Requires highly skilled operator to customize for modern EDR evasion
- No AI/LLM/cloud assessment modules
- No automated AI-assisted recon layer
- Expensive licenses + significant operator time investment

**Our counter**:
"Cobalt Strike is a hammer. We're a full workshop. Our implant is production-hardened for 2026 EDRs by default — sleep masking, direct syscalls, Cloudflare relay — without the operator needing to customize the profile. And we wrap it in AI-assisted recon, reporting, and the full engagement workflow."

---

### vs. Core Impact

**Their pitch**: Validated exploits, professional-grade penetration testing platform.

**Their limits**:
- Legacy architecture — GUI-first, Windows-centric
- Exploit library lags behind current CVE/KEV pace
- No modern EDR evasion built in
- No cloud/AI/LLM coverage
- No agentic AI automation layer
- Smaller community → slower TTP updates

**Our counter**:
"Core Impact was built in the 2000s for a 2000s threat landscape. We track CISA KEV and Rapid7 AttackerKB in near-real-time and cover attack surfaces — AI workloads, cloud IAM, MCP servers — that didn't exist when Core Impact shipped its architecture."

---

### vs. Pentera

**Their pitch**: Autonomous penetration testing — continuous, automatic, no human needed.

**Their limits**:
- Cannot exploit business logic vulnerabilities requiring human judgment
- Cannot chain multi-step attacks requiring context accumulation across sessions
- Cannot operate in low-and-slow red team mode (generates consistent noise)
- No human operator for novel CVE exploitation
- No AI/LLM/MCP assessment
- Clients report high false positive rates on complex attack chains

**Our counter**:
"Automation finds what automation can find. Pentera will never social-engineer your CFO, chain a logic flaw in your ERP with a misconfigured cloud storage bucket, or silently dwell for six weeks. Our model is AI for breadth, human for depth — the only model that replicates real APT behavior."

---

### vs. NodeZero / Horizon3.ai

**Their pitch**: AI-powered autonomous pentesting, find-fix-verify cycle.

**Their limits**:
- Same as Pentera — fully automated, limited to what machine reasoning can achieve
- Strong marketing on "AI" but automation is rule-based attack graph traversal
- No red team / adversary simulation capability
- No mobile/AI-workload coverage
- Human operators cannot be inserted into NodeZero workflows

**Our counter**:
"NodeZero's AI is really a sophisticated attack graph traversal engine — valuable for coverage, not for adversary simulation. For board-level red team exercises, ransomware simulations, or proving that an advanced persistent threat can reach your Crown Jewels, you need human operators. We give you both in one platform."

---

## CTEM Positioning

Continuous Threat Exposure Management (Gartner 2022 framework):
1. Scoping
2. Discovery
3. Prioritization
4. Validation
5. Mobilization

Our PTaaS offering maps to all five phases. Competitors:
- **Tenable One / XM Cyber**: Strong at 1-3, weak at 4 (no real exploitation)
- **Pentera/NodeZero**: Strong at 4 (automated validation), weak at 2-3 for complex surfaces
- **Our platform**: Full CTEM cycle with human-in-loop for validation on complex findings

---

## Win Themes by Buyer

| Buyer | Top Concern | Our Angle |
|-------|-------------|-----------|
| CISO | Board-level risk narrative | We produce the "attacker got to Crown Jewels" story, not a CVE list |
| Security Director | Coverage + efficiency | AI-assisted recon gives breadth; humans give depth without 10x headcount |
| Compliance Officer | Audit evidence | CVSS v4.0 + KEV + compliance mapping in every finding |
| DevSecOps Lead | Shift-left + CI/CD coverage | Supply chain + API + AI workload coverage competitors miss |
| Red Team Lead | EDR evasion + tradecraft | Production-hardened implant, not CS default profile |
