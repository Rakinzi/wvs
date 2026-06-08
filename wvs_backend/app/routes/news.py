from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Request

from app import db
from app.auth import current_user, require_admin
from app.models import NewsArticle, User
from app.utils.time_utils import utc_now

router = APIRouter()

CISA_KEV_URL = 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog'

CURATED_ARTICLES = [
    {
        'id': 'curated-miasma-redhat-npm-supply-chain-2026-06-01',
        'title': 'Miasma: TeamPCP compromises 32 Red Hat npm packages — credential-stealing worm hooks Claude, Codex, Copilot, and Gemini',
        'slug': 'miasma-redhat-npm-supply-chain-teampcp-2026-06-01',
        'summary': 'On June 1, 2026, Wiz Research discovered "Miasma" — a supply chain attack by TeamPCP that injected a credential-stealing worm into 32 @redhat-cloud-services npm packages (~80,000 weekly downloads). The malware steals cloud credentials, injects hooks into AI coding tools including Claude, Codex, Copilot, Gemini, and Kiro, and wipes the victim\'s home directory if a stolen token is revoked.',
        'body': (
            'On June 1, 2026, Wiz Research published a report on "Miasma: The Spreading Blight," a '
            'supply chain compromise affecting at least 32 package releases under the '
            '`@redhat-cloud-services` npm namespace. The attack is attributed to TeamPCP — the same '
            'group behind the May 11 TanStack attack and the May 18 Nx Console poisoning that led to '
            'the GitHub internal repository breach.\n\n'
            '**How the attack worked**\n\n'
            'Evidence points to a specific Red Hat employee\'s GitHub account being compromised and '
            'used to inject malicious code directly into the packages\' source repositories before '
            'publishing. The attack bypassed standard CI/CD controls because the commits came from '
            'a trusted, authenticated account.\n\n'
            'The malicious packages execute a 4.2 MB obfuscated payload automatically during every '
            '`npm install`, before any application code runs. The payload is a new variant of the '
            'Mini Shai-Hulud malware family, upgraded with several new capabilities.\n\n'
            '**What the malware steals**\n\n'
            '- GitHub personal access tokens and OAuth tokens\n'
            '- SSH private keys\n'
            '- AWS credentials (`~/.aws/credentials`)\n'
            '- GCP service account tokens and all GCP identities accessible from the machine\n'
            '- Azure credentials and all Azure identities accessible from the machine\n'
            '- npm publish tokens (`~/.npmrc`)\n'
            '- Docker and Kubernetes config files\n\n'
            '**AI tool hook injection**\n\n'
            'A new and particularly dangerous capability: the malware injects persistent hooks into '
            'AI developer tools running on the infected machine, specifically:\n\n'
            '- Anthropic Claude Code\n'
            '- OpenAI Codex\n'
            '- GitHub Copilot\n'
            '- Google Gemini CLI\n'
            '- Microsoft Kiro\n'
            '- opencode\n\n'
            'These hooks allow the malware to intercept prompts, responses, and any credentials or '
            'secrets that pass through these tools during a session — a novel exfiltration vector '
            'that exploits the privileged access AI coding assistants have to local filesystems and '
            'environment variables.\n\n'
            '**Destructive kill-switch**\n\n'
            'If a stolen token is revoked before the malware\'s persistence is removed, the payload '
            'executes a destructive command that wipes the victim\'s home directory. This is a '
            'deliberate deterrent against token rotation without full remediation — a tactic designed '
            'to coerce victims into negotiating rather than simply rotating credentials.\n\n'
            '**Scale of exposure**\n\n'
            'The 32 compromised packages collectively average ~80,000 weekly downloads. Red Hat '
            'published security advisory RHSB-2026-006 on June 1 and removed the malicious versions '
            'from npm. Any developer or CI system that ran `npm install` with these packages before '
            'the takedown should treat their entire credential store as compromised.\n\n'
            '**Affected packages (examples)**\n\n'
            '- `@redhat-cloud-services/frontend-components`\n'
            '- `@redhat-cloud-services/frontend-components-utilities`\n'
            '- `@redhat-cloud-services/frontend-components-notifications`\n'
            '- 29 additional `@redhat-cloud-services/*` packages\n\n'
            '**Operational checklist**\n\n'
            '1. Run `npm ls @redhat-cloud-services` across all projects and CI environments.\n'
            '2. Check `package-lock.json` / `yarn.lock` for any `@redhat-cloud-services` version '
            'published on June 1, 2026 before 18:00 UTC.\n'
            '3. Rotate ALL credentials on any machine that ran `npm install` with these packages: '
            'GitHub tokens, AWS keys, GCP tokens, Azure credentials, SSH keys, npm tokens.\n'
            '4. Audit AI developer tool configurations (Claude Code, Copilot, Codex, Gemini) for '
            'unexpected hook files or modified configuration.\n'
            '5. Check for the persistence service installed by the malware: look for new systemd '
            'units, launchd plists, or cron jobs added on June 1.\n'
            '6. Do NOT simply rotate tokens without first removing the malware — the kill-switch '
            'will wipe your home directory if a token is revoked while the malware is still running.'
        ),
        'category': 'Breach',
        'tags': ['npm', 'supply-chain', 'redhat', 'teampcp', 'ai-tools', 'credential-theft'],
        'severity': 'Critical',
        'cve_ids': [],
        'source_url': 'https://www.wiz.io/blog/miasma-supply-chain-attack-targeting-redhat-npm-packages',
        'image_url': 'https://images.unsplash.com/photo-1516321318423-f06f85e504b3?auto=format&fit=crop&w=1200&q=80',
        'image_alt': 'Dark terminal with npm package installation and malicious code concept',
        'published': True,
        'published_at': '2026-06-01T20:00:00+00:00',
        'created_at': '2026-06-01T20:00:00+00:00',
        'updated_at': '2026-06-01T20:00:00+00:00',
        'author': 'LaunchGuard Security Team',
    },
    {
        'id': 'curated-charter-shinyhunters-breach-2026-05-29',
        'title': 'ShinyHunters breaches Charter Communications via vishing — 42M records claimed, 13M confirmed published after ransom refusal',
        'slug': 'charter-communications-shinyhunters-breach-2026-05-29',
        'summary': 'ShinyHunters breached Charter Communications on April 1, 2026 via a voice phishing attack that compromised an employee\'s Microsoft Entra account, then exfiltrated millions of Salesforce customer records. After Charter refused to negotiate, ShinyHunters published at least 13 million records on May 29. Have I Been Pwned confirmed 4.9 million unique email addresses.',
        'body': (
            'On May 23, 2026, the cybercriminal extortion group ShinyHunters claimed responsibility '
            'for a data breach at Charter Communications, the US telecommunications company behind '
            'the Spectrum brand. ShinyHunters listed Charter on its dark web leak site, claiming to '
            'hold between 40 and 42 million records containing PII for residential and business '
            'customers — which, if true, would exceed Charter\'s entire reported customer base of '
            '32 million.\n\n'
            '**How the breach happened**\n\n'
            'ShinyHunters told BleepingComputer that the initial access came on April 1, 2026 via a '
            'voice phishing (vishing) attack targeting a Charter employee. The attacker impersonated '
            'IT support and tricked the employee into providing credentials and approving an MFA push, '
            'compromising their Microsoft Entra (formerly Azure AD) account.\n\n'
            'Once inside Charter\'s environment, the attacker used the compromised Entra account to '
            'access Charter\'s Salesforce CRM instance and bulk-export customer records. The vishing '
            'technique bypasses technical controls entirely — it is the same social engineering vector '
            'used in the 2022 Uber, Rockstar Games, and Twilio breaches.\n\n'
            '**What was exposed**\n\n'
            'Based on the published sample analyzed by SOCRadar and others:\n'
            '- Full names\n'
            '- Email addresses\n'
            '- Phone numbers\n'
            '- Physical service addresses\n'
            '- Account numbers and service plan details\n'
            '- In some records: date of birth and last four digits of SSN\n\n'
            'Charter stated that "no sensitive personal information or CPNI data was exfiltrated," '
            'which contradicts the sample data published by ShinyHunters. Have I Been Pwned confirmed '
            '4.9 million unique email addresses in the exposed dataset.\n\n'
            '**Timeline**\n\n'
            '- April 1, 2026 — Breach via vishing / Entra account compromise\n'
            '- May 23, 2026 — ShinyHunters lists Charter on leak site, demands ransom\n'
            '- May 27, 2026 — ShinyHunters\' ransom deadline passes; Charter did not negotiate\n'
            '- May 29, 2026 — ShinyHunters publishes ~13 million records publicly\n'
            '- June 2026 — Have I Been Pwned ingests 4.9M unique email addresses\n\n'
            '**Context: ShinyHunters\' recent activity**\n\n'
            'ShinyHunters is one of the most prolific data extortion groups active in 2025–2026. '
            'Previous targets include Ticketmaster (560M records, 2024), Santander, and numerous '
            'SaaS platforms. The group consistently uses social engineering as the initial access '
            'vector, targeting helpdesk and IT support staff.\n\n'
            '**Operational checklist for organizations**\n\n'
            '1. Enroll all Microsoft Entra accounts in phishing-resistant MFA (FIDO2 hardware keys '
            'or passkeys) — SMS and push-based MFA are vulnerable to real-time vishing attacks.\n'
            '2. Implement Entra Conditional Access policies that block bulk data exports from CRM '
            'systems unless performed from managed, compliant devices.\n'
            '3. Configure Salesforce Data Export Shield or equivalent DLP controls to alert on '
            'large record exports.\n'
            '4. Train helpdesk staff on vishing playbooks — verify caller identity through a '
            'callback to a known number, never the number provided by the caller.\n'
            '5. If you are a Charter/Spectrum customer: monitor for phishing emails, change account '
            'passwords, and check Have I Been Pwned for your email address.'
        ),
        'category': 'Breach',
        'tags': ['data-breach', 'vishing', 'social-engineering', 'telecom', 'shinyhunters', 'salesforce'],
        'severity': 'High',
        'cve_ids': [],
        'source_url': 'https://cyberinsider.com/charter-communications-confirms-data-breach-as-hackers-threaten-leak-of-42-million-records/',
        'image_url': 'https://images.unsplash.com/photo-1504639725590-34d0984388bd?auto=format&fit=crop&w=1200&q=80',
        'image_alt': 'Data breach concept with exposed records and security lock',
        'published': True,
        'published_at': '2026-05-29T14:00:00+00:00',
        'created_at': '2026-05-29T14:00:00+00:00',
        'updated_at': '2026-05-29T14:00:00+00:00',
        'author': 'LaunchGuard Security Team',
    },
    {
        'id': 'curated-oracle-weblogic-cve-2024-21182-kev-2026-06-01',
        'title': 'Oracle WebLogic CVE-2024-21182 added to CISA KEV — unpatched servers under active attack',
        'slug': 'oracle-weblogic-cve-2024-21182-cisa-kev-2026-06-01',
        'summary': 'CISA added CVE-2024-21182, an unspecified Oracle WebLogic Server vulnerability, to the Known Exploited Vulnerabilities catalog on June 1, 2026 after confirmed active exploitation. WebLogic remains one of the most persistently targeted enterprise Java platforms.',
        'body': (
            'On June 1, 2026, CISA added CVE-2024-21182 — an unspecified vulnerability in Oracle '
            'WebLogic Server — to the Known Exploited Vulnerabilities catalog after confirming active '
            'exploitation in the wild.\n\n'
            'Oracle WebLogic Server is a frequent and high-value target for threat actors. Its '
            'deployment profile — enterprise Java applications, often handling financial transactions, '
            'ERP systems, and critical internal services — makes a successful exploit high-impact. '
            'WebLogic CVEs have appeared repeatedly in CISA KEV over the past several years, and '
            'nation-state groups as well as ransomware operators routinely scan for unpatched instances.\n\n'
            '**Affected product**\n\n'
            'Oracle WebLogic Server — specific affected versions are documented in Oracle\'s Critical '
            'Patch Update (CPU) advisory. Organizations running WebLogic should cross-reference their '
            'installed version against Oracle\'s published patch matrix.\n\n'
            '**What to do**\n\n'
            'Oracle releases security patches through its quarterly Critical Patch Update cycle. '
            'CVE-2024-21182 was originally patched in a prior CPU; organizations that have not '
            'applied Oracle CPU patches since early 2024 are likely exposed.\n\n'
            '**Operational checklist**\n\n'
            '1. Inventory all Oracle WebLogic Server instances in your environment.\n'
            '2. Apply the latest Oracle Critical Patch Update immediately.\n'
            '3. If patching is blocked, restrict network access to WebLogic admin ports '
            '(7001, 7002, 9002) to known management networks only.\n'
            '4. Review WebLogic access logs for unexpected admin console access or T3/IIOP '
            'protocol traffic from unfamiliar sources.\n'
            '5. Federal agencies must remediate by the CISA-specified deadline per BOD 22-01.'
        ),
        'category': 'Vulnerability',
        'tags': ['oracle', 'weblogic', 'java', 'cisa-kev', 'enterprise'],
        'severity': 'High',
        'cve_ids': ['CVE-2024-21182'],
        'source_url': 'https://www.cisa.gov/news-events/alerts/2026/06/01/cisa-adds-one-known-exploited-vulnerability-catalog',
        'image_url': 'https://images.unsplash.com/photo-1558494949-ef010cbdcc31?auto=format&fit=crop&w=1200&q=80',
        'image_alt': 'Enterprise server room with Java application server infrastructure',
        'published': True,
        'published_at': '2026-06-01T16:00:00+00:00',
        'created_at': '2026-06-01T16:00:00+00:00',
        'updated_at': '2026-06-01T16:00:00+00:00',
        'author': 'LaunchGuard Security Team',
    },
    {
        'id': 'curated-github-breach-teampcp-nx-console-2026-05-20',
        'title': 'GitHub\'s internal repos breached: TeamPCP poisoned the Nx Console VS Code extension to steal 3,800 private repositories',
        'slug': 'github-internal-breach-nx-console-teampcp-2026-05-20',
        'summary': 'Threat actor TeamPCP published a malicious version of the Nx Console VS Code extension (CVE-2026-48027, CVSS 9.3) on May 18, 2026. The 18-minute window was enough — a GitHub employee installed it, leading to the exfiltration of ~3,800 GitHub internal private repositories. CISA issued an alert on May 28.',
        'body': (
            'On May 18, 2026, the threat actor group TeamPCP (also tracked as DeadCatx3 / UNC6780) '
            'published a poisoned release of the Nx Console VS Code extension (nrwl.angular-console) '
            'to the Visual Studio Marketplace. Version 18.95.0 — downloaded by an extension with '
            '2.2 million installs — was live for just 18 minutes on the VS Code Marketplace '
            '(12:30–12:48 UTC) and 36 minutes on OpenVSX before being removed. That window was '
            'enough.\n\n'
            '**How the attack worked**\n\n'
            'The malicious extension fetched a 498 KB obfuscated payload hidden in a dangling '
            'orphan commit inside the official nrwl/nx GitHub repository — not published to npm '
            'or any registry, making it invisible to standard software composition analysis. The '
            'payload executed silently in the VS Code extension host process and performed a '
            'systematic sweep of developer credentials:\n\n'
            '- GitHub personal access tokens and OAuth tokens\n'
            '- 1Password vault entries\n'
            '- SSH private keys\n'
            '- AWS credentials files (`~/.aws/credentials`)\n'
            '- npm publish tokens (`~/.npmrc`)\n'
            '- Anthropic Claude Code configuration and API keys\n\n'
            '**GitHub internal breach**\n\n'
            'A GitHub employee installed the extension during the exposure window. By May 19–20, '
            'GitHub disclosed that the stolen token was used to clone approximately **3,800 internal '
            'private GitHub repositories**, containing proprietary source code, deployment scripts, '
            'and internal configuration material. The stolen data was reportedly listed for sale on '
            'criminal forums for over $50,000 USD. Grafana Labs confirmed it was affected by the '
            'same attack chain.\n\n'
            '**CISA response and attribution**\n\n'
            'CISA issued a joint alert on May 28, 2026 covering both the Nx Console compromise and '
            'the downstream GitHub breach. CVE-2026-48027 was assigned a CVSS 4.0 score of 9.3 '
            '(Critical). CISA added it to the Known Exploited Vulnerabilities catalog with a federal '
            'remediation deadline of June 10, 2026.\n\n'
            'TeamPCP\'s May 2026 campaign is part of a sustained developer toolchain targeting '
            'operation that also included the TanStack npm supply chain attack on May 11 and the '
            'Megalodon GitHub repository mass-poisoning campaign on May 18 (the same day). The group '
            'is linked to the Vect ransomware-as-a-service operation, meaning credential harvesting '
            'is a precursor to ransomware deployments.\n\n'
            '**Operational checklist**\n\n'
            '1. Verify Nx Console is updated to version 18.100.0 or later on all developer machines.\n'
            '2. Audit developer workstations and CI runner images that had Nx Console installed during '
            'May 18, 12:30–13:09 UTC.\n'
            '3. Rotate all credentials potentially accessible from affected developer workstations: '
            'GitHub tokens, AWS keys, npm tokens, SSH keys, 1Password entries.\n'
            '4. Search GitHub audit logs for unexpected API activity or repository cloning from '
            'unfamiliar IP addresses around May 18–20.\n'
            '5. Remove or quarantine the `dangling-orphan` commit from your nx monorepo forks if '
            'present.\n'
            '6. Consider blocking VS Code extension auto-updates in enterprise environments pending '
            'review of Marketplace security controls.'
        ),
        'category': 'Breach',
        'tags': ['github', 'supply-chain', 'vscode', 'credential-theft', 'cisa-kev', 'teampcp'],
        'severity': 'Critical',
        'cve_ids': ['CVE-2026-48027'],
        'source_url': 'https://www.cisa.gov/news-events/alerts/2026/05/28/supply-chain-compromises-impact-nx-console-and-github-repositories',
        'image_url': 'https://images.unsplash.com/photo-1614064641938-3bbee52942c7?auto=format&fit=crop&w=1200&q=80',
        'image_alt': 'Dark terminal screen with source code repositories and git commands',
        'published': True,
        'published_at': '2026-05-20T16:00:00+00:00',
        'created_at': '2026-05-20T16:00:00+00:00',
        'updated_at': '2026-05-20T16:00:00+00:00',
        'author': 'LaunchGuard Security Team',
    },
    {
        'id': 'curated-github-enterprise-rce-cve-2026-3854',
        'title': 'GitHub Enterprise Server RCE via git push (CVE-2026-3854, CVSS 8.7): 88% of self-hosted instances remain unpatched',
        'slug': 'github-enterprise-server-rce-cve-2026-3854',
        'summary': 'Wiz Research discovered a command injection in GitHub Enterprise Server\'s git proxy (babeld) that lets any authenticated user execute arbitrary commands on the backend. GitHub.com was patched immediately; as of late April 2026, 88% of self-hosted GHES instances were still vulnerable.',
        'body': (
            'On April 29, 2026, GitHub disclosed CVE-2026-3854, a command injection vulnerability '
            'in `babeld`, GitHub\'s internal git proxy service. Wiz Research discovered the flaw '
            'on March 4, 2026; GitHub patched GitHub.com on the same day. Public disclosure came '
            '56 days later, after a coordinated disclosure period.\n\n'
            '**Technical root cause**\n\n'
            'The `babeld` service processes `git push` requests and passes push option values from '
            'the client into an internal header called `X-Stat`, using semicolons as field delimiters. '
            'User-supplied push option values were copied verbatim into this header without sanitizing '
            'the semicolon character. An attacker could craft a single `git push` command with a '
            'malicious `--push-option` value containing a semicolon followed by arbitrary shell syntax:\n\n'
            '```\ngit push origin main --push-option="a; <payload>"\n```\n\n'
            'When `babeld` forwarded this to backend processing, the injected command executed with '
            'the privileges of the `git` service account.\n\n'
            '**Impact on GitHub.com**\n\n'
            'On GitHub.com, successful exploitation placed an attacker on a shared storage node '
            'with read access to any repository hosted on that node, regardless of ownership or '
            'visibility. The blast radius for a single exploit was thousands of repositories. GitHub '
            'states there is no evidence this was exploited on GitHub.com prior to patching.\n\n'
            '**Self-hosted GHES exposure**\n\n'
            'GitHub Enterprise Server (GHES) versions prior to 3.19.3 are all vulnerable. Shodan '
            'data analyzed by Wiz in late April 2026 found that **88% of internet-accessible GHES '
            'instances** had not yet applied the patch. Many GHES deployments are on annual or '
            'quarterly upgrade cycles, which dramatically slows remediation for critical flaws.\n\n'
            '**Fixed version**\n\n'
            'GHES 3.19.3 contains the fix. The patch sanitizes push option values before '
            'constructing the `X-Stat` header, rejecting any value containing semicolons or other '
            'shell metacharacters.\n\n'
            '**Note on timing**\n\n'
            'This vulnerability was disclosed in the same week as the Nx Console compromise and '
            'subsequent GitHub internal breach — making April/May 2026 a historically damaging '
            'period for GitHub\'s security posture.\n\n'
            '**Operational checklist**\n\n'
            '1. Upgrade GHES to 3.19.3 immediately.\n'
            '2. If upgrading is blocked, restrict who can push to GHES instances at the network '
            'layer as a temporary mitigation.\n'
            '3. Review GHES audit logs for unusual `git push` activity with `--push-option` values.\n'
            '4. For GitHub.com users: no action required; GitHub.com was patched on March 4, 2026.'
        ),
        'category': 'Vulnerability',
        'tags': ['github', 'rce', 'git', 'enterprise', 'command-injection'],
        'severity': 'High',
        'cve_ids': ['CVE-2026-3854'],
        'source_url': 'https://github.blog/security/securing-the-git-push-pipeline-responding-to-a-critical-remote-code-execution-vulnerability/',
        'image_url': 'https://images.unsplash.com/photo-1556075798-4825dfaaf498?auto=format&fit=crop&w=1200&q=80',
        'image_alt': 'Git version control terminal commands on a developer screen',
        'published': True,
        'published_at': '2026-04-29T14:00:00+00:00',
        'created_at': '2026-04-29T14:00:00+00:00',
        'updated_at': '2026-04-29T14:00:00+00:00',
        'author': 'LaunchGuard Security Team',
    },
    {
        'id': 'curated-megalodon-github-actions-2026-05-18',
        'title': 'Megalodon: 5,561 GitHub repositories backdoored in 6-hour CI/CD secret-theft campaign',
        'slug': 'megalodon-github-actions-supply-chain-2026-05-18',
        'summary': 'On May 18, 2026, attackers used stolen GitHub credentials to inject malicious GitHub Actions workflows into 5,561 public repositories in a 6-hour window, exfiltrating CI/CD secrets including AWS, GCP, Azure, and Docker credentials. CISA issued a joint alert on May 28.',
        'body': (
            'On May 18, 2026 — the same day as the Nx Console VS Code extension poisoning — a '
            'separate attack campaign dubbed "Megalodon" by StepSecurity silently backdoored '
            '5,561 public GitHub repositories across a 6-hour window (11:36–17:48 UTC).\n\n'
            '**How it worked**\n\n'
            'Attackers, using GitHub personal access tokens (PATs) sourced from infostealer '
            'credential markets, made automated commits injecting malicious GitHub Actions workflow '
            'files into the `.github/workflows/` directory of targeted repositories. Two distinct '
            'payload variants were observed:\n\n'
            '**SysDiag variant** — Adds a new workflow triggered on `push` and `pull_request` '
            'events. Every subsequent CI run immediately exfiltrates all environment variables, '
            'secrets, and cloud credentials available in the runner environment to a hardcoded '
            'C2 server (216.126.225.129:8443).\n\n'
            '**Optimize-Build variant** — More stealthy: replaces existing legitimate workflows '
            'with a `workflow_dispatch`-only trigger, creating dormant backdoors. These can be '
            'activated silently later via the GitHub API without pushing any new code, making '
            'detection significantly harder.\n\n'
            '**What was exfiltrated**\n\n'
            'From affected CI runs, the payload swept:\n'
            '- AWS access keys and secret keys (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`)\n'
            '- GCP service account tokens (`GOOGLE_CREDENTIALS`)\n'
            '- Azure service principal credentials (`AZURE_CLIENT_SECRET`)\n'
            '- Docker Hub and container registry passwords\n'
            '- Kubernetes `kubeconfig` files and service account tokens\n'
            '- Database connection strings\n'
            '- GitHub and GitLab personal access tokens\n'
            '- Any custom `*_TOKEN`, `*_KEY`, `*_SECRET` environment variables\n\n'
            '**Attribution and context**\n\n'
            'Megalodon is distinct from the TeamPCP campaign running on the same day. While TeamPCP '
            'compromised the Nx Console extension through a sophisticated multi-stage attack on the '
            'developer toolchain, Megalodon relied on infostealer-sourced PATs to make brute-force '
            'commits at scale — an opportunistic operation rather than a targeted one.\n\n'
            'CISA issued a joint alert on May 28, 2026 covering both the Nx Console/GitHub breach '
            'and Megalodon, calling it one of the most significant coordinated attacks on the open '
            'source CI/CD ecosystem.\n\n'
            '**Operational checklist**\n\n'
            '1. Audit `.github/workflows/` for unexpected files or recent commits from unfamiliar '
            'contributors — especially files added on May 18, 2026.\n'
            '2. Check GitHub repository audit logs for commits made between 11:36–17:48 UTC May 18.\n'
            '3. Rotate any cloud credentials (AWS, GCP, Azure) exposed in CI environments during '
            'the affected window — assume they are compromised.\n'
            '4. Remove dormant `workflow_dispatch`-only workflows that were not added by your team.\n'
            '5. Enable GitHub Actions secret scanning and set `ACTIONS_RUNNER_DEBUG` to catch '
            'unexpected variable access.\n'
            '6. Restrict GitHub PAT scopes and enforce short expiry periods across your organization.'
        ),
        'category': 'Breach',
        'tags': ['github', 'ci-cd', 'supply-chain', 'github-actions', 'credential-theft'],
        'severity': 'Critical',
        'cve_ids': [],
        'source_url': 'https://www.stepsecurity.io/blog/megalodon-mass-github-actions-secret-exfiltration-across-5-500-public-repositories',
        'image_url': 'https://images.unsplash.com/photo-1510511459019-5dda7724fd87?auto=format&fit=crop&w=1200&q=80',
        'image_alt': 'CI/CD pipeline automation visualization with interconnected nodes',
        'published': True,
        'published_at': '2026-05-18T22:00:00+00:00',
        'created_at': '2026-05-18T22:00:00+00:00',
        'updated_at': '2026-05-18T22:00:00+00:00',
        'author': 'LaunchGuard Security Team',
    },
    {
        'id': 'curated-tanstack-npm-supply-chain-2026-05-11',
        'title': 'TanStack "Mini Shai-Hulud": 42 npm packages poisoned in 6 minutes, spreading to 170+ packages across npm and PyPI',
        'slug': 'tanstack-npm-supply-chain-mini-shai-hulud-2026-05-11',
        'summary': 'On May 11, 2026, TeamPCP chained three GitHub Actions vulnerabilities to hijack TanStack\'s own release pipeline and publish 84 malicious versions across 42 @tanstack/* packages (CVE-2026-45321, CVSS 9.6). The attack worm spread to 170+ packages from Mistral AI, UiPath, OpenSearch, and others within hours.',
        'body': (
            'On May 11, 2026, the threat actor group TeamPCP executed a supply chain attack on the '
            'TanStack ecosystem — one of the most widely used React/TypeScript library suites with '
            'packages like `@tanstack/react-query` and `@tanstack/react-router` downloaded tens of '
            'millions of times per week.\n\n'
            'The attack, codenamed "Mini Shai-Hulud" by the security community, exploited three '
            'GitHub Actions vulnerabilities chained together to publish malicious package versions '
            'using TanStack\'s own legitimate release pipeline and trusted OIDC identity — meaning '
            'the malicious packages were signed and appeared fully authentic.\n\n'
            '**The three-vulnerability chain**\n\n'
            '**1. `pull_request_target` Pwn Request** — A fork-based pull request triggered a '
            'workflow that runs in the context of the base repository with access to its secrets. '
            'This is a known dangerous pattern in GitHub Actions.\n\n'
            '**2. GitHub Actions cache poisoning across fork trust boundary** — The attacker '
            'poisoned the GitHub Actions build cache from the fork, injecting malicious binaries '
            'that were consumed by the privileged base-repo workflow.\n\n'
            '**3. Runtime OIDC token extraction** — The injected code scraped GitHub\'s OIDC '
            'token from runner memory mid-workflow, obtaining the token needed to publish packages '
            'to npm with TanStack\'s verified identity.\n\n'
            'The entire attack window lasted just 6 minutes (19:20–19:26 UTC). During that time, '
            '84 malicious versions of 42 `@tanstack/*` packages were published to npm.\n\n'
            '**Malicious payload behavior**\n\n'
            'The payload was engineered for stealth and breadth:\n'
            '- Spawned a fully detached child process (parent exits cleanly so CI appears to succeed)\n'
            '- Checked `process.env.__DAEMONIZED` before acting (anti-sandbox detection)\n'
            '- Deliberately skipped tokens named `github_token` to evade GitHub secret scanning\n'
            '- Systematically harvested: AWS credentials, GCP tokens, Azure credentials, SSH '
            'private keys, Docker/Kubernetes configs, database connection strings, GitHub/GitLab '
            'tokens, and any environment variable matching `*_TOKEN`, `*_KEY`, `*_SECRET`\n'
            '- Exfiltrated everything to a hardcoded C2 server\n\n'
            '**Affected packages (42 total, examples)**\n\n'
            '- `@tanstack/react-router` (12.7M+ weekly downloads)\n'
            '- `@tanstack/react-query`\n'
            '- `@tanstack/react-form`\n'
            '- `@tanstack/start-server-core`\n'
            '- 38 additional `@tanstack/*` packages\n\n'
            '**Worm propagation to 170+ packages**\n\n'
            'Within hours, the malicious dependency spread to 170+ downstream packages across npm '
            'and PyPI, including packages from Mistral AI, UiPath, OpenSearch, and Guardrails AI — '
            'any project that used a `@tanstack` package as a direct or transitive dependency and '
            'ran a build or install during the 6-minute window received the poisoned code.\n\n'
            '**Detection and response**\n\n'
            'External researcher @ashishkurmi (StepSecurity) publicly detected the compromise '
            'within 20–26 minutes. TanStack published a full postmortem and rotated all npm '
            'publish credentials. The malicious versions were unpublished from npm the same day.\n\n'
            '**Connection to GitHub breach**\n\n'
            'CVE-2026-45321 (CVSS 9.6) was added to CISA KEV on May 27, 2026. The same threat '
            'actor group (TeamPCP) went on to execute the Nx Console extension poisoning on '
            'May 18, which led to the GitHub internal repository breach — making TanStack the '
            'first major strike in what became a month-long campaign against the developer toolchain.\n\n'
            '**Operational checklist**\n\n'
            '1. Check `package-lock.json` or `yarn.lock` for any `@tanstack/*` versions published '
            'between 19:20–19:26 UTC on May 11, 2026.\n'
            '2. Rotate all credentials available in CI environments that ran `npm install` or '
            '`npm ci` during that window.\n'
            '3. Audit all downstream packages for transitive `@tanstack` dependencies.\n'
            '4. Harden GitHub Actions: pin all third-party actions to commit SHAs, restrict '
            'fork PR workflows from accessing secrets, and audit `pull_request_target` usage.\n'
            '5. Enable GitHub Actions cache integrity verification (OIDC pinning where available).'
        ),
        'category': 'Breach',
        'tags': ['npm', 'supply-chain', 'tanstack', 'cisa-kev', 'teampcp', 'github-actions'],
        'severity': 'Critical',
        'cve_ids': ['CVE-2026-45321'],
        'source_url': 'https://tanstack.com/blog/npm-supply-chain-compromise-postmortem',
        'image_url': 'https://images.unsplash.com/photo-1516321318423-f06f85e504b3?auto=format&fit=crop&w=1200&q=80',
        'image_alt': 'Developer laptop with npm package dependencies and code',
        'published': True,
        'published_at': '2026-05-11T22:00:00+00:00',
        'created_at': '2026-05-11T22:00:00+00:00',
        'updated_at': '2026-05-11T22:00:00+00:00',
        'author': 'LaunchGuard Security Team',
    },
    {
        'id': 'curated-nextjs-websocket-ssrf-cve-2026-44578',
        'title': 'Next.js WebSocket SSRF (CVE-2026-44578, CVSS 8.6): unauthenticated access to cloud metadata services and internal APIs',
        'slug': 'nextjs-websocket-ssrf-cve-2026-44578',
        'summary': 'A server-side request forgery flaw in Next.js\'s WebSocket upgrade handler (CVE-2026-44578) lets unauthenticated attackers probe any host reachable from the server — including AWS IMDSv1 at 169.254.169.254. Patched in Next.js 15.5.16 and 16.2.5 on May 11, 2026.',
        'body': (
            'On May 11, 2026, Vercel shipped a coordinated security release for Next.js addressing '
            '13 separate advisories. The most impactful is CVE-2026-44578, an unauthenticated '
            'Server-Side Request Forgery (SSRF) in the WebSocket upgrade handler.\n\n'
            '**Technical details**\n\n'
            'Next.js proxies WebSocket upgrade requests to the appropriate application route. The '
            'upgrade handler constructs the upstream URL from the `Host` header and the request '
            'path without validating that the resulting hostname is within the expected scope. An '
            'attacker who sends a crafted HTTP upgrade request can force the Next.js process to '
            'issue an internal HTTP GET to any IPv4 address reachable from the server on port 80, '
            'and read back the response body.\n\n'
            'The most critical target is the AWS instance metadata service (IMDSv1) at '
            '`169.254.169.254`. On EC2 instances running Next.js without IMDSv2 enforcement, '
            'a single unauthenticated request can retrieve the full IAM role credentials:\n\n'
            '```\nGET /?__nextws=1&host=169.254.169.254&path=/latest/meta-data/iam/security-credentials/\n```\n\n'
            'The response returns the role name; a second request to '
            '`/latest/meta-data/iam/security-credentials/<role-name>` returns `AccessKeyId`, '
            '`SecretAccessKey`, and `Token` — giving the attacker temporary AWS credentials with '
            'the permissions of the EC2 instance role.\n\n'
            '**Affected versions and fix**\n\n'
            'All self-hosted Next.js from 13.4.13 onward are affected. Vercel-hosted and Netlify-hosted '
            'apps are not affected as the platform handles WebSocket routing separately. Fixed in:\n'
            '- Next.js 15.5.16\n'
            '- Next.js 16.2.5\n\n'
            'No fix for Next.js 13.x or 14.x branches — operators on those branches must upgrade '
            'to 15.x or enforce IMDSv2 at the cloud provider level.\n\n'
            '**Part of a recurring pattern**\n\n'
            'This is part of a 13-advisory batch released May 11, 2026 — continuing a pattern of '
            'significant monthly Next.js security releases throughout 2025–2026. The same release '
            'also addressed a DoS (CVE-2026-23869) and several middleware/proxy bypass issues. '
            'The March 2025 middleware authorization bypass (CVE-2025-29927, CVSS 9.1) — where '
            'the `x-middleware-subrequest` header could bypass all authentication middleware — '
            'remains in the background as an example of how critical these monthly releases can be.\n\n'
            '**Operational checklist**\n\n'
            '1. Upgrade to Next.js 15.5.16 or 16.2.5.\n'
            '2. Enforce IMDSv2 on all EC2 instances (`HttpTokens: required`) as a defense-in-depth '
            'measure regardless of this specific CVE.\n'
            '3. Block outbound requests from the Next.js process to 169.254.0.0/16 at the '
            'network or security group level.\n'
            '4. Search access logs for WebSocket upgrade requests with unusual `host` parameters.\n'
            '5. Review all 13 advisories in the May 11 Vercel security release — not all are '
            'equally severe, but several DoS and proxy bypass issues may affect your deployment.'
        ),
        'category': 'Vulnerability',
        'tags': ['nextjs', 'ssrf', 'react', 'aws', 'cloud-metadata', 'web-framework'],
        'severity': 'High',
        'cve_ids': ['CVE-2026-44578', 'CVE-2026-23869'],
        'source_url': 'https://vercel.com/changelog/next-js-may-2026-security-release',
        'image_url': 'https://images.unsplash.com/photo-1633356122544-f134324a6cee?auto=format&fit=crop&w=1200&q=80',
        'image_alt': 'React and Next.js framework code on a developer monitor',
        'published': True,
        'published_at': '2026-05-11T18:00:00+00:00',
        'created_at': '2026-05-11T18:00:00+00:00',
        'updated_at': '2026-05-11T18:00:00+00:00',
        'author': 'LaunchGuard Security Team',
    },
    {
        'id': 'curated-nextjs-middleware-bypass-cve-2025-29927',
        'title': 'Next.js middleware auth bypass CVE-2025-29927 (CVSS 9.1): one HTTP header unlocks every protected route',
        'slug': 'nextjs-middleware-authorization-bypass-cve-2025-29927',
        'summary': 'CVE-2025-29927 is a critical authorization bypass in Next.js: sending the internal header `x-middleware-subrequest` causes Next.js to skip all middleware logic, including authentication — exposing admin panels and private routes to any unauthenticated attacker. Affects Next.js 12.x–15.x on self-hosted deployments.',
        'body': (
            'Disclosed on March 21, 2025, CVE-2025-29927 is one of the most impactful Next.js '
            'vulnerabilities ever published. CVSS 9.1 (Critical). A single HTTP header bypasses '
            'every authentication and authorization check implemented in Next.js middleware.\n\n'
            '**How it works**\n\n'
            'Next.js uses an internal header `x-middleware-subrequest` to mark HTTP requests as '
            'internal middleware subrequests — used internally to prevent infinite middleware '
            'recursion. When this header is present, Next.js skips middleware execution entirely. '
            'The problem: the header was never validated as internal-only. Any external HTTP client '
            'can send it.\n\n'
            'A typical Next.js application protects routes like `/admin`, `/dashboard`, or `/api/private` '
            'with middleware (`middleware.ts`) that checks for a valid session token. With this '
            'vulnerability, an attacker bypasses that middleware entirely:\n\n'
            '```\ncurl https://target.com/admin -H "x-middleware-subrequest: middleware"\n```\n\n'
            'The request reaches the route handler directly, with no authentication check. On '
            'applications where the only authorization layer is middleware (a common pattern '
            'promoted in Next.js documentation), this grants full unauthenticated access.\n\n'
            '**Affected versions**\n\n'
            '- Next.js 12.x < 12.3.5\n'
            '- Next.js 13.x < 13.5.9\n'
            '- Next.js 14.x < 14.2.25\n'
            '- Next.js 15.x < 15.2.3\n\n'
            '**Important: Vercel and Netlify hosted apps are NOT affected.** The vulnerability '
            'only affects self-hosted deployments using `next start` with `output: standalone`. '
            'The hosting platforms strip external headers before they reach the Next.js runtime.\n\n'
            '**Exploitation in the wild**\n\n'
            'Mass scanning for vulnerable Next.js instances began within 24 hours of disclosure. '
            'ProjectDiscovery published a Nuclei template the same day. Zscaler ThreatLabz '
            'observed active exploitation across multiple industries within the following week.\n\n'
            '**Fixed versions**\n\n'
            'Apply the fix by upgrading to Next.js 15.2.3 (or the corresponding patch for your '
            'major version). The fix adds a cryptographic signature to `x-middleware-subrequest` '
            'using a server-side secret, so externally crafted headers are rejected.\n\n'
            '**Defense in depth**\n\n'
            'This vulnerability underscores a fundamental principle: never implement authorization '
            'exclusively in Next.js middleware. Middleware runs at the edge/proxy layer and can be '
            'bypassed if a flaw is discovered. Always enforce authorization again in route handlers '
            'or API handlers — the data layer is the last line of defense, not the proxy.\n\n'
            '**Operational checklist**\n\n'
            '1. Upgrade Next.js to the patched version for your major branch.\n'
            '2. Immediately, block the `x-middleware-subrequest` header at your reverse proxy, '
            'load balancer, or WAF as a temporary workaround if patching is delayed.\n'
            '3. Audit all routes that are protected only by middleware — assume they were '
            'accessible to unauthenticated users and review access logs.\n'
            '4. Add authorization checks at the route handler level as defense in depth.'
        ),
        'category': 'Vulnerability',
        'tags': ['nextjs', 'auth-bypass', 'middleware', 'react', 'web-framework'],
        'severity': 'Critical',
        'cve_ids': ['CVE-2025-29927'],
        'source_url': 'https://securitylabs.datadoghq.com/articles/nextjs-middleware-auth-bypass/',
        'image_url': 'https://images.unsplash.com/photo-1555066931-4365d14bab8c?auto=format&fit=crop&w=1200&q=80',
        'image_alt': 'Web application security code with authentication bypass concept',
        'published': True,
        'published_at': '2025-03-21T16:00:00+00:00',
        'created_at': '2025-03-21T16:00:00+00:00',
        'updated_at': '2025-03-21T16:00:00+00:00',
        'author': 'LaunchGuard Security Team',
    },
    {
        'id': 'curated-react2shell-cve-2025-55182',
        'title': 'React2Shell: CVSS 10.0 pre-auth RCE in React Server Components actively exploited by China-nexus groups (CVE-2025-55182)',
        'slug': 'react2shell-rce-react-server-components-cve-2025-55182',
        'summary': 'CVE-2025-55182 "React2Shell" is a maximum-severity (CVSS 10.0) pre-authenticated RCE via insecure deserialization in React Server Components. Active exploitation began within 48 hours of December 2025 disclosure; China-nexus threat groups Earth Lamia and Jackpot Panda were among the first observed attackers.',
        'body': (
            'On December 3, 2025, the React team disclosed CVE-2025-55182 — a pre-authenticated '
            'remote code execution vulnerability in React Server Components that earned the '
            'maximum possible CVSS score of 10.0. The community quickly named it "React2Shell" '
            'by analogy with Log4Shell, and for good reason: the exploit is nearly 100% reliable, '
            'requires no credentials, and affects default configurations of any Next.js application '
            'using App Router with React Server Components.\n\n'
            '**Technical root cause**\n\n'
            'React Server Functions (also called "server actions") accept serialized arguments from '
            'the client, transmitted in a custom React wire format. The deserialization of this '
            'format did not validate that the incoming data represented only the expected argument '
            'types. An attacker can craft a specially shaped payload that, when deserialized on the '
            'server, executes arbitrary code in the Node.js process hosting Next.js.\n\n'
            'Unlike many deserialization vulnerabilities that require the attacker to control '
            'the full serialized stream, React2Shell only requires control of the HTTP request body '
            'to the server action endpoint — which is publicly reachable by design.\n\n'
            '**Affected versions**\n\n'
            '- React Server Components: all versions prior to 19.0.3, 19.1.4, 19.2.3\n'
            '- Next.js 13.x/14.x: fix in 14.2.35\n'
            '- Next.js 15.x: fix in 15.0.5 through 15.5.7 (each minor branch received its own patch)\n'
            '- Next.js 16.x: fix in 16.0.7\n\n'
            '**Only applications using React Server Functions are affected.** Apps that use the '
            'Pages Router exclusively or do not use server actions are not vulnerable.\n\n'
            '**Exploitation timeline**\n\n'
            'December 3, 2025 — Disclosure.\n'
            'December 5, 2025 — First active exploitation detected (2 days post-disclosure).\n'
            'December 10–15 — China-nexus threat groups Earth Lamia and Jackpot Panda confirmed '
            'by AWS Threat Intelligence as early adopters. Google GTIG observed widespread '
            'exploitation across multiple clusters.\n\n'
            '**Observed payloads in the wild**\n\n'
            'Incident responders documented the following payloads across compromised Next.js deployments:\n'
            '- Cloud credential theft (AWS instance metadata, GCP service account tokens)\n'
            '- XMRig cryptominer deployment (Monero mining using server CPU)\n'
            '- MINOCAT tunneler — creates persistent reverse tunnel to C2\n'
            '- SNOWLIGHT downloader — stages secondary payloads\n'
            '- HISONIC backdoor — China-nexus persistent access tool\n'
            '- COMPOOD backdoor — attributed to Jackpot Panda\n\n'
            '**Urgency for the React ecosystem**\n\n'
            'The React/Next.js ecosystem runs a very large fraction of the web — Vercel-hosted '
            'apps, AWS Amplify deployments, self-hosted containers, and edge-deployed instances. '
            'The breadth of the attack surface rivals Log4Shell. Vercel-hosted apps received '
            'platform-level mitigations, but self-hosted deployments (which constitute the majority '
            'of enterprise Next.js usage) required manual patching.\n\n'
            '**Operational checklist**\n\n'
            '1. Upgrade React and Next.js to patched versions immediately.\n'
            '2. Search for React Server Functions in your codebase: any file with `"use server"` '
            'at the top is a potential entry point.\n'
            '3. Review web access logs for unusual POST requests to server action endpoints '
            '(paths ending in `.action`, or POST to page routes with `_rsc=1` parameter).\n'
            '4. Hunt for anomalous outbound connections, unexpected child processes, or new cron '
            'jobs on hosts running Next.js.\n'
            '5. Rotate cloud credentials accessible from the Next.js server process.\n'
            '6. If unable to patch immediately: disable server actions by removing `"use server"` '
            'directives — but verify this does not break application functionality.'
        ),
        'category': 'Vulnerability',
        'tags': ['react', 'nextjs', 'rce', 'deserialization', 'zero-day', 'china-nexus'],
        'severity': 'Critical',
        'cve_ids': ['CVE-2025-55182', 'CVE-2025-66478'],
        'source_url': 'https://react.dev/blog/2025/12/03/critical-security-vulnerability-in-react-server-components',
        'image_url': 'https://images.unsplash.com/photo-1633356122102-3fe601e05bd2?auto=format&fit=crop&w=1200&q=80',
        'image_alt': 'React JavaScript framework with critical security warning concept',
        'published': True,
        'published_at': '2025-12-03T20:00:00+00:00',
        'created_at': '2025-12-03T20:00:00+00:00',
        'updated_at': '2025-12-03T20:00:00+00:00',
        'author': 'LaunchGuard Security Team',
    },
    {
        'id': 'curated-cisa-litespeed-cpanel-2026-05-26',
        'title': 'LiteSpeed cPanel plugin privilege escalation added to CISA KEV',
        'slug': 'litespeed-cpanel-plugin-privilege-escalation-2026-05-26',
        'summary': 'CISA added CVE-2026-48172 on May 26, 2026. The cPanel plugin flaw can allow arbitrary scripts to execute with root privileges from a cPanel user account.',
        'body': (
            'CISA added CVE-2026-48172, the LiteSpeed cPanel Plugin Privilege Escalation '
            'Vulnerability, to KEV on May 26, 2026. The CISA description says the user-end cPanel '
            'plugin exposure can be abused by any cPanel user account to execute arbitrary scripts '
            'with root privileges.\n\n'
            'Operational priority: update the LiteSpeed cPanel plugin immediately on shared hosting '
            'systems, review cPanel account activity, and treat the May 29, 2026 federal due date as '
            'an urgent service-provider deadline.\n\n'
            'Sources checked: CISA KEV catalog and the LiteSpeed security update linked from the CISA entry.'
        ),
        'category': 'Vulnerability',
        'tags': ['cpanel', 'privilege-escalation', 'hosting', 'cisa-kev'],
        'severity': 'Critical',
        'cve_ids': ['CVE-2026-48172'],
        'source_url': CISA_KEV_URL,
        'image_url': 'https://images.unsplash.com/photo-1518770660439-4636190af475?auto=format&fit=crop&w=1200&q=80',
        'image_alt': 'Server hardware and circuit board close-up',
        'published': True,
        'published_at': '2026-05-26T12:00:00+00:00',
        'created_at': '2026-05-26T12:00:00+00:00',
        'updated_at': '2026-05-26T12:00:00+00:00',
        'author': 'LaunchGuard Security Team',
    },
    {
        'id': 'curated-cisa-drupal-core-2026-05-22',
        'title': 'Drupal Core SQL injection receives KEV deadline after active exploitation',
        'slug': 'drupal-core-sql-injection-cisa-kev-2026-05-22',
        'summary': 'CISA added CVE-2026-9082 on May 22, 2026, warning that Drupal Core SQL injection can lead to privilege escalation and remote code execution.',
        'body': (
            'CISA added CVE-2026-9082, Drupal Core SQL Injection Vulnerability, to KEV on '
            'May 22, 2026. The entry says crafted requests sent with the database abstraction API '
            'could allow privilege escalation and remote code execution.\n\n'
            'Operational priority: upgrade affected Drupal installations, review web logs for '
            'suspicious database abstraction API activity, and verify that internet-facing CMS '
            'instances are covered by emergency patching. CISA lists May 27, 2026 as the federal due date.\n\n'
            'Sources checked: CISA KEV catalog and Drupal SA-CORE-2026-004 linked from the CISA entry.'
        ),
        'category': 'Vulnerability',
        'tags': ['drupal', 'sql-injection', 'cms', 'rce'],
        'severity': 'Critical',
        'cve_ids': ['CVE-2026-9082'],
        'source_url': CISA_KEV_URL,
        'image_url': 'https://images.unsplash.com/photo-1563986768609-322da13575f3?auto=format&fit=crop&w=1200&q=80',
        'image_alt': 'Application security dashboard displayed on a laptop',
        'published': True,
        'published_at': '2026-05-22T12:00:00+00:00',
        'created_at': '2026-05-22T12:00:00+00:00',
        'updated_at': '2026-05-22T12:00:00+00:00',
        'author': 'LaunchGuard Security Team',
    },
    {
        'id': 'curated-cisa-langflow-2026-05-21',
        'title': 'Langflow CORS and token handling flaw added to exploited-vulnerability catalog',
        'slug': 'langflow-origin-validation-cisa-kev-2026-05-21',
        'summary': 'CISA added CVE-2025-34291 on May 21, 2026. The Langflow issue combines permissive CORS and credentialed refresh-token requests.',
        'body': (
            'CISA added CVE-2025-34291 for Langflow to KEV on May 21, 2026. The CISA entry '
            'describes an origin validation issue where permissive CORS and a SameSite=None refresh '
            'token cookie can let a malicious webpage make credentialed cross-origin requests, obtain '
            'tokens, and call authenticated endpoints.\n\n'
            'Operational priority: upgrade to a fixed Langflow release, review CORS and cookie settings, '
            'rotate tokens, and search for unexpected authenticated endpoint calls. CISA lists June 4, '
            '2026 as the federal due date.\n\n'
            'Sources checked: CISA KEV catalog and Langflow release/advisory links from the CISA entry.'
        ),
        'category': 'Advisory',
        'tags': ['ai-tools', 'cors', 'tokens', 'langflow'],
        'severity': 'High',
        'cve_ids': ['CVE-2025-34291'],
        'source_url': CISA_KEV_URL,
        'image_url': 'https://images.unsplash.com/photo-1555949963-aa79dcee981c?auto=format&fit=crop&w=1200&q=80',
        'image_alt': 'Source code on a dark monitor',
        'published': True,
        'published_at': '2026-05-21T12:00:00+00:00',
        'created_at': '2026-05-21T12:00:00+00:00',
        'updated_at': '2026-05-21T12:00:00+00:00',
        'author': 'LaunchGuard Security Team',
    },
    {
        'id': 'curated-cisa-trend-micro-apex-one-2026-05-21',
        'title': 'Trend Micro Apex One directory traversal is now in CISA KEV',
        'slug': 'trend-micro-apex-one-directory-traversal-2026-05-21',
        'summary': 'CISA added CVE-2026-34926 on May 21, 2026, covering an on-premise Apex One directory traversal path that can inject code deployed to agents.',
        'body': (
            'CISA added CVE-2026-34926, Trend Micro Apex One On-Premise Directory Traversal '
            'Vulnerability, to KEV on May 21, 2026. CISA says a pre-authenticated local attacker '
            'could modify a key table on the server to inject malicious code that deploys to agents.\n\n'
            'Operational priority: apply Trend Micro guidance on on-premise Apex One servers, inspect '
            'server-side table changes, and validate agent update integrity. CISA lists June 4, 2026 '
            'as the federal due date.\n\n'
            'Sources checked: CISA KEV catalog and Trend Micro guidance linked from the CISA entry.'
        ),
        'category': 'Vulnerability',
        'tags': ['endpoint-security', 'directory-traversal', 'trend-micro', 'cisa-kev'],
        'severity': 'High',
        'cve_ids': ['CVE-2026-34926'],
        'source_url': CISA_KEV_URL,
        'image_url': 'https://images.unsplash.com/photo-1510511459019-5dda7724fd87?auto=format&fit=crop&w=1200&q=80',
        'image_alt': 'Network security visualization on a dark display',
        'published': True,
        'published_at': '2026-05-21T11:30:00+00:00',
        'created_at': '2026-05-21T11:30:00+00:00',
        'updated_at': '2026-05-21T11:30:00+00:00',
        'author': 'LaunchGuard Security Team',
    },
    {
        'id': 'curated-nginx-heap-overflow-cve-2026-42945',
        'title': 'NGINX heap buffer overflow CVE-2026-42945 exploited in the wild — patch to 1.30.1 now',
        'slug': 'nginx-heap-overflow-cve-2026-42945',
        'summary': 'A CVSS 9.2 heap buffer overflow in NGINX\'s rewrite module (CVE-2026-42945) allows unauthenticated remote code execution on all versions from 0.6.27 through 1.30.0. Active exploitation confirmed May 16, 2026.',
        'body': (
            'On May 18, 2026, the NGINX project disclosed CVE-2026-42945, a heap buffer overflow in '
            'the ngx_http_rewrite_module. The vulnerability is present in every stable NGINX release '
            'from 0.6.27 through 1.30.0 — a range that covers the vast majority of internet-facing '
            'web servers.\n\n'
            '**Technical details**\n\n'
            'The flaw lives in the bytecode interpreter that evaluates compiled `rewrite` directives. '
            'When a rewrite rule is evaluated against a specially crafted URI, an integer used as an '
            'offset into the rewrite bytecode stack is not bounds-checked before the corresponding '
            'heap allocation. An attacker who controls the request URI can force the allocation to '
            'underflow, corrupt adjacent heap metadata, and ultimately achieve arbitrary code execution '
            'under the nginx worker process account. Because the vulnerable code runs before authentication '
            'middleware, no credentials are required.\n\n'
            'The CVSS v3.1 vector is AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H, scoring 9.2. Proof-of-concept '
            'code targeting Ubuntu 24.04 LTS with NGINX 1.28.0 was published on GitHub within 48 hours '
            'of the advisory.\n\n'
            '**Exploitation timeline**\n\n'
            'Threat intelligence teams at Cloudflare and Censys reported active scanning activity '
            'beginning May 16, 2026 — two days before the official advisory. By May 20, multiple '
            'intrusion-detection vendors reported confirmed exploitation attempts in production '
            'environments. CISA added CVE-2026-42945 to the Known Exploited Vulnerabilities catalog '
            'on May 22, 2026 with a federal remediation deadline of June 5, 2026.\n\n'
            '**Affected versions and fix**\n\n'
            'All NGINX stable branches 0.6.27–1.30.0 are affected. NGINX 1.30.1 (stable) and 1.31.0 '
            '(mainline) include the fix. The patch adds an explicit bounds check before every '
            'bytecode-stack offset dereference in ngx_http_script.c.\n\n'
            '**Workarounds if patching is not immediately possible**\n\n'
            'If upgrading is blocked, operators can mitigate exposure by removing or simplifying '
            'complex `rewrite` directives. There is no indication that NGINX instances without any '
            '`rewrite` directives are exploitable. However, this is not a complete mitigation — '
            'patching to 1.30.1 is the only fully supported remediation.\n\n'
            '**Operational checklist**\n\n'
            '1. Inventory all NGINX instances including those embedded in reverse-proxy containers.\n'
            '2. Upgrade to 1.30.1 or 1.31.0.\n'
            '3. Review access logs for requests with unusually long URIs or percent-encoded sequences '
            'in the rewrite path.\n'
            '4. Rotate secrets accessible to the nginx worker process account.\n'
            '5. Alert on anomalous worker process behavior (unexpected child spawning, outbound connections).'
        ),
        'category': 'Vulnerability',
        'tags': ['nginx', 'rce', 'heap-overflow', 'web-server', 'cisa-kev'],
        'severity': 'Critical',
        'cve_ids': ['CVE-2026-42945'],
        'source_url': 'https://nginx.org/en/security_advisories.html',
        'image_url': 'https://images.unsplash.com/photo-1558494949-ef010cbdcc31?auto=format&fit=crop&w=1200&q=80',
        'image_alt': 'Data center server room with rows of blinking network hardware',
        'published': True,
        'published_at': '2026-05-18T10:00:00+00:00',
        'created_at': '2026-05-18T10:00:00+00:00',
        'updated_at': '2026-05-18T10:00:00+00:00',
        'author': 'LaunchGuard Security Team',
    },
    {
        'id': 'curated-gitea-container-registry-cve-2026-27771',
        'title': 'Gitea CVE-2026-27771: unauthenticated pull of private container images exposes 31,000 self-hosted instances',
        'slug': 'gitea-container-registry-auth-bypass-cve-2026-27771',
        'summary': 'A missing authentication check in Gitea\'s built-in container registry (CVE-2026-27771, CVSS 8.2) allows any internet user to pull private OCI images. The bug went undetected for four years and affects every Gitea release from v1.19 through v1.26.1.',
        'body': (
            'On May 27, 2026, Gitea published a security advisory for CVE-2026-27771, a missing '
            'authentication check in the built-in OCI container registry that ships with Gitea v1.19 '
            'and later. The vulnerability allows any unauthenticated user who can reach the Gitea '
            'instance to pull images from private container repositories without credentials.\n\n'
            '**How the bug works**\n\n'
            'The Gitea OCI registry implements the distribution specification. The `/v2/<name>/manifests/<ref>` '
            'and `/v2/<name>/blobs/<digest>` endpoints are supposed to require registry-scope tokens. '
            'The authentication middleware correctly rejects unauthenticated requests for scope '
            '`repository:push` and `repository:delete`, but a conditional branch in the scope-validation '
            'logic silently falls through on `repository:pull` requests when the repository visibility '
            'is set to "private" (as opposed to "internal"). The result: any HTTP client can issue a '
            'Docker-compatible `GET` against a private image manifest and receive a 200 response with '
            'the full layer list.\n\n'
            '**Scope of exposure**\n\n'
            'Censys scans on May 27 found 31,750 internet-accessible Gitea instances. All of them that '
            'had not yet upgraded to v1.26.2 were affected. Gitea self-hosting is especially common in '
            'financial services, healthcare, and government sectors that prefer on-premises source '
            'control. The bug was introduced in the v1.19 container registry implementation in early '
            '2022 and went undetected for approximately four years.\n\n'
            '**What attackers can do with pulled images**\n\n'
            'Container images frequently embed secrets: hard-coded API keys, TLS certificates, database '
            'connection strings, and SSH private keys are all common. Pulling a private image with '
            'a layer-aware tool like `crane` or `skopeo` and extracting the filesystem takes under '
            'a minute. Attackers who harvest secrets from images can pivot directly into production '
            'environments.\n\n'
            '**Fixed version and workarounds**\n\n'
            'Gitea v1.26.2, released May 27, 2026, contains the fix. For operators who cannot upgrade '
            'immediately, placing the Gitea instance behind a network boundary that blocks anonymous '
            'internet access to port 3000 (or the custom HTTPS port) fully mitigates the pull exposure '
            'until patching is possible.\n\n'
            '**Operational checklist**\n\n'
            '1. Upgrade to Gitea v1.26.2.\n'
            '2. Audit all private container repositories for embedded secrets.\n'
            '3. Rotate any credentials that may have been stored in image layers.\n'
            '4. Review Gitea access logs for unauthenticated registry pull requests (HTTP 200 on '
            '`/v2/` paths without an Authorization header).\n'
            '5. Consider enabling the new `REQUIRE_SIGNIN_VIEW` setting for registry endpoints as '
            'a defense-in-depth layer.'
        ),
        'category': 'Vulnerability',
        'tags': ['gitea', 'container-registry', 'auth-bypass', 'devops', 'oci'],
        'severity': 'High',
        'cve_ids': ['CVE-2026-27771'],
        'source_url': 'https://github.com/go-gitea/gitea/security/advisories',
        'image_url': 'https://images.unsplash.com/photo-1618401471353-b98afee0b2eb?auto=format&fit=crop&w=1200&q=80',
        'image_alt': 'Open source code on a screen with git branch visualization',
        'published': True,
        'published_at': '2026-05-27T09:00:00+00:00',
        'created_at': '2026-05-27T09:00:00+00:00',
        'updated_at': '2026-05-27T09:00:00+00:00',
        'author': 'LaunchGuard Security Team',
    },
    {
        'id': 'curated-microsoft-defender-redsun-undefend-2026-05-21',
        'title': 'CISA mandates emergency patch for Microsoft Defender "RedSun" and "UnDefend" flaws by June 3',
        'slug': 'microsoft-defender-redsun-undefend-cisa-kev-2026-05-21',
        'summary': 'Two Microsoft Defender vulnerabilities — CVE-2026-41091 ("RedSun", local privilege escalation) and CVE-2026-45498 ("UnDefend", denial of service) — were added to CISA KEV on May 21 with a June 3, 2026 federal remediation deadline after confirmed in-the-wild exploitation.',
        'body': (
            'Microsoft patched two vulnerabilities in Microsoft Defender on May 19, 2026. Two days '
            'later, CISA added both to the Known Exploited Vulnerabilities catalog with an unusually '
            'short remediation window of 13 days, expiring June 3, 2026.\n\n'
            '**CVE-2026-41091 — "RedSun" (Local Privilege Escalation, CVSS 8.8)**\n\n'
            'RedSun is a local privilege escalation flaw in the Microsoft Defender Antivirus scan '
            'engine service (MsMpEng.exe). The service runs as SYSTEM and processes files submitted '
            'for scanning. A low-privileged local attacker can craft a malicious archive file whose '
            'extraction path, when processed by MsMpEng.exe\'s decompression routine, writes a DLL '
            'to a directory that is subsequently loaded by a high-privileged process. The technique '
            'is a classic DLL planting attack made possible by a TOCTOU race in the temp-file cleanup '
            'path.\n\n'
            'Ransomware operators have integrated RedSun into post-exploitation tool kits as a reliable '
            'SYSTEM escalation step, according to threat intelligence from CrowdStrike. This is the '
            'primary reason CISA moved quickly to add it to KEV.\n\n'
            '**CVE-2026-45498 — "UnDefend" (Denial of Service, CVSS 7.5)**\n\n'
            'UnDefend is a denial-of-service vulnerability in the same scan engine. A network-accessible '
            'malformed PE file sent to a Defender-protected endpoint triggers an unhandled exception '
            'that terminates the MsMpEng.exe process. On endpoints where Defender is the primary '
            'security control, this effectively disables real-time protection for the duration of the '
            'crash restart cycle (typically 2–5 minutes). Attackers use this window to load unsigned '
            'drivers or execute payloads that Defender would otherwise block.\n\n'
            'The combination of RedSun and UnDefend is particularly dangerous: UnDefend disables '
            'Defender\'s real-time scanning briefly while RedSun escalates privileges. Both bugs '
            'appear in the same threat actor playbook.\n\n'
            '**Patch and workaround**\n\n'
            'Both vulnerabilities are fixed in Microsoft Defender engine version 1.1.26050.2 or later, '
            'delivered via Windows Update. The engine update is separate from Windows OS updates and '
            'may need to be explicitly forced on endpoints with Windows Update deferred. Isolated '
            'environments that cannot receive automatic updates should use WSUS or SCCM to distribute '
            'the engine update.\n\n'
            '**Operational checklist**\n\n'
            '1. Verify Defender engine version is 1.1.26050.2 or later on all Windows endpoints.\n'
            '2. Check Defender update policy; confirm automatic engine updates are enabled.\n'
            '3. Review endpoint detection logs for MsMpEng.exe crashes and unexpected DLL loads '
            'in system32 or temp directories.\n'
            '4. Hunt for lateral movement following MsMpEng.exe crash events.\n'
            '5. Federal agencies must remediate by June 3, 2026 per CISA BOD 22-01.'
        ),
        'category': 'Advisory',
        'tags': ['microsoft', 'defender', 'privilege-escalation', 'windows', 'cisa-kev', 'ransomware'],
        'severity': 'Critical',
        'cve_ids': ['CVE-2026-41091', 'CVE-2026-45498'],
        'source_url': CISA_KEV_URL,
        'image_url': 'https://images.unsplash.com/photo-1614064641938-3bbee52942c7?auto=format&fit=crop&w=1200&q=80',
        'image_alt': 'Windows security shield concept with digital threat visualization',
        'published': True,
        'published_at': '2026-05-21T14:00:00+00:00',
        'created_at': '2026-05-21T14:00:00+00:00',
        'updated_at': '2026-05-21T14:00:00+00:00',
        'author': 'LaunchGuard Security Team',
    },
    {
        'id': 'curated-cpanel-auth-bypass-ransomware-2026-05-12',
        'title': 'cPanel CVE-2026-41940 (CVSS 9.8): 1.5 million hosting servers at risk as ransomware groups weaponize auth bypass',
        'slug': 'cpanel-auth-bypass-ransomware-cve-2026-41940',
        'summary': 'An authentication bypass in cPanel & WHM (CVE-2026-41940, CVSS 9.8) has been exploited since February 2026 by ransomware operators and Mirai botnet variants. Approximately 1.5 million cPanel servers remain unpatched as of early May 2026.',
        'body': (
            'CVE-2026-41940 is an authentication bypass in cPanel & WHM that affects all versions '
            'prior to 116.0.63. The vulnerability was first reported to cPanel\'s security team in '
            'late April 2026, but threat intelligence evidence suggests exploitation began as early '
            'as February 2026, meaning attackers had a roughly two-month head start.\n\n'
            '**Technical root cause**\n\n'
            'The flaw is in cPanel\'s session token validation routine. The WHM API endpoint '
            '`/json-api/cpanel` accepts a `cpanel_jsonapi_user` parameter that specifies which '
            'cPanel account\'s context the API call should run in. The session token validation '
            'checks that the token belongs to a valid WHM reseller account, but a logic error in '
            'the privilege-delegation check allows an attacker to pass a valid reseller token '
            'alongside an arbitrary `cpanel_jsonapi_user` value, including `root`. This lets an '
            'attacker with any valid WHM account (or a leaked token) execute API calls as any user '
            'on the server, including root.\n\n'
            '**Exploitation in the wild**\n\n'
            'At least three distinct threat actor groups have been observed exploiting CVE-2026-41940:\n\n'
            '- **LockFile-X**: A ransomware-as-a-service group that used the bypass to deploy a '
            'cPanel-aware ransomware variant that specifically targets files in `/home/*/public_html` '
            'directories, maximizing impact on hosted websites.\n\n'
            '- **MiraiPanel**: A variant of the Mirai botnet that abuses the bypass to install '
            'a persistent DDoS agent on the server and add the server\'s IP to its C2 infrastructure.\n\n'
            '- **SilentMine**: A cryptomining campaign that uses the bypass to install XMRig on '
            'affected servers, leveraging their CPU headroom for Monero mining.\n\n'
            'Shodan and Censys estimates in early May 2026 put the number of internet-accessible '
            'cPanel servers at approximately 2.1 million. Of those, roughly 1.5 million had not yet '
            'applied the cPanel security update as of May 12, 2026.\n\n'
            '**Fixed versions**\n\n'
            'cPanel & WHM 116.0.63 (released May 4, 2026) contains the fix. Operators on LTS '
            'branches should apply the corresponding hotfix available in the cPanel RELEASES file. '
            'Auto-update is enabled by default on most cPanel installations; servers that have '
            'disabled auto-update are the primary unpatched population.\n\n'
            '**Operational checklist**\n\n'
            '1. Run `/usr/local/cpanel/scripts/check_cpanel_rpms --fix` and verify version is '
            '≥116.0.63.\n'
            '2. Check WHM access logs (`/usr/local/cpanel/logs/access_log`) for API calls to '
            '`/json-api/cpanel` with mismatched `cpanel_jsonapi_user` values.\n'
            '3. Search for newly installed cron jobs under all hosted accounts.\n'
            '4. Check for XMRig, suspicious outbound DNS to known C2 domains, and '
            'encrypted file extensions in `/home/*/public_html`.\n'
            '5. Rotate all WHM and cPanel account passwords and API tokens.\n'
            '6. Consider enabling cPanel\'s IP-based login restriction for WHM API access as '
            'a defense-in-depth measure.'
        ),
        'category': 'Vulnerability',
        'tags': ['cpanel', 'auth-bypass', 'ransomware', 'hosting', 'botnet'],
        'severity': 'Critical',
        'cve_ids': ['CVE-2026-41940'],
        'source_url': 'https://docs.cpanel.net/security/security-advisories/',
        'image_url': 'https://images.unsplash.com/photo-1504639725590-34d0984388bd?auto=format&fit=crop&w=1200&q=80',
        'image_alt': 'Server racks in a data center with red warning lights',
        'published': True,
        'published_at': '2026-05-12T08:00:00+00:00',
        'created_at': '2026-05-12T08:00:00+00:00',
        'updated_at': '2026-05-12T08:00:00+00:00',
        'author': 'LaunchGuard Security Team',
    },
    {
        'id': 'curated-patch-tuesday-may-2026',
        'title': 'May 2026 Patch Tuesday: 118 CVEs, 16 critical — Windows MSHTML and Azure Service Bus lead the list',
        'slug': 'patch-tuesday-may-2026-118-cves',
        'summary': 'Microsoft\'s May 2026 Patch Tuesday addressed 118 CVEs across Windows, Azure, Office, and Edge. Sixteen are rated Critical. Three Windows MSHTML remote code execution flaws and an Azure Service Bus privilege escalation are highlighted as highest priority.',
        'body': (
            'Microsoft released its May 2026 security update on May 12, 2026, addressing 118 CVEs '
            'across Windows, Azure, Microsoft 365, Office, Edge (Chromium-based), Visual Studio, '
            'and .NET. Sixteen vulnerabilities are rated Critical; 95 are Important; 7 are Moderate.\n\n'
            '**Highlights by product area**\n\n'
            '**Windows MSHTML Platform (3 Critical RCEs)**\n\n'
            'CVE-2026-30118, CVE-2026-30119, and CVE-2026-30120 are remote code execution '
            'vulnerabilities in the MSHTML (Trident) rendering engine that remains present in Windows '
            'even though Internet Explorer has been retired. The attack vector for all three is '
            'a malicious Office document or MHT file: opening the document causes MSHTML to parse '
            'attacker-controlled markup, which triggers the memory corruption. CVE-2026-30118 has a '
            'CVSS of 8.8 and is marked as "Exploitation More Likely" by Microsoft. Threat actors '
            'regularly abuse MSHTML for document-based phishing campaigns.\n\n'
            '**Azure Service Bus (Critical PE, CVE-2026-30155)**\n\n'
            'CVE-2026-30155 is a privilege escalation in the Azure Service Bus AMQP connection '
            'handler. A low-privileged Azure user with `Microsoft.ServiceBus/namespaces/read` '
            'permission can construct a malformed AMQP frame that triggers a server-side deserialization '
            'path, elevating to namespace Owner-level access. Microsoft deployed a server-side fix '
            'and states no customer action is required, but advises auditing Service Bus access logs '
            'for anomalous namespace-level operations.\n\n'
            '**Windows Kernel (3 LPE zero-days, CVE-2026-30199, CVE-2026-30200, CVE-2026-30201)**\n\n'
            'Three Windows kernel local privilege escalation vulnerabilities are patched this cycle. '
            'All three are rated Important (CVSS 7.8). Microsoft confirms CVE-2026-30199 and '
            'CVE-2026-30200 were exploited in the wild prior to the patch. Both use a win32k '
            'use-after-free technique that was detailed in an academic paper published in March 2026, '
            'which appears to have accelerated weaponization.\n\n'
            '**Microsoft Edge (Chromium) — 11 CVEs**\n\n'
            'Eleven CVEs in Edge track upstream Chromium fixes, including three high-severity V8 '
            'issues and one WebGPU out-of-bounds read. Edge users on the stable channel should '
            'already have received automatic updates.\n\n'
            '**Office / Microsoft 365 — 9 CVEs**\n\n'
            'Nine Office CVEs span Excel (2 RCE), Word (1 RCE), Outlook (2 Information Disclosure), '
            'and SharePoint (4 including one Critical RCE via crafted document upload). The SharePoint '
            'RCE (CVE-2026-30175) is marked "Exploitation More Likely" and should be prioritized for '
            'on-premises SharePoint deployments.\n\n'
            '**Patching priorities**\n\n'
            '1. Apply May 2026 cumulative update to all Windows endpoints immediately.\n'
            '2. Prioritize CVE-2026-30199/30200 (already exploited in the wild) for endpoint '
            'patch verification.\n'
            '3. Test and deploy SharePoint Server patch for CVE-2026-30175 on on-premises farms.\n'
            '4. Audit Azure Service Bus namespace access logs for anomalous operations.\n'
            '5. Disable MSHTML previewing in Office Trust Center if immediate patching is blocked.\n'
            '6. Apply .NET and Visual Studio updates on developer workstations and build servers.'
        ),
        'category': 'Advisory',
        'tags': ['patch-tuesday', 'microsoft', 'windows', 'azure', 'rce', 'zero-day'],
        'severity': 'Critical',
        'cve_ids': ['CVE-2026-30118', 'CVE-2026-30119', 'CVE-2026-30120', 'CVE-2026-30155', 'CVE-2026-30199', 'CVE-2026-30200'],
        'source_url': 'https://msrc.microsoft.com/update-guide/releaseNote/2026-May',
        'image_url': 'https://images.unsplash.com/photo-1607799279861-4dd421887fb3?auto=format&fit=crop&w=1200&q=80',
        'image_alt': 'Microsoft Windows update and security patch concept on a laptop',
        'published': True,
        'published_at': '2026-05-12T18:00:00+00:00',
        'created_at': '2026-05-12T18:00:00+00:00',
        'updated_at': '2026-05-12T18:00:00+00:00',
        'author': 'LaunchGuard Security Team',
    },
]


def _slugify(text: str) -> str:
    text = text.lower().strip()
    text = re.sub(r'[^\w\s-]', '', text)
    text = re.sub(r'[\s_-]+', '-', text)
    text = re.sub(r'^-+|-+$', '', text)
    return text[:280]


def _unique_slug(base: str, exclude_id: int | None = None) -> str:
    slug = base
    n = 1
    while True:
        q = NewsArticle.query.filter_by(slug=slug)
        if exclude_id:
            q = q.filter(NewsArticle.id != exclude_id)
        if not q.first():
            return slug
        slug = f"{base}-{n}"
        n += 1


def _published_timestamp(article: dict) -> datetime:
    value = article.get('published_at') or article.get('created_at')
    if not value:
        return datetime.min.replace(tzinfo=timezone.utc)
    return datetime.fromisoformat(str(value).replace('Z', '+00:00'))


def _filtered_curated_articles(category: str | None, severity: str | None, tag: str | None):
    articles = CURATED_ARTICLES
    if category:
        articles = [a for a in articles if a['category'] == category]
    if severity:
        articles = [a for a in articles if a['severity'] == severity]
    if tag:
        articles = [a for a in articles if tag in (a.get('tags') or [])]
    return articles


def _available_categories():
    db_categories = {
        row[0]
        for row in db.session.query(NewsArticle.category)
        .filter(NewsArticle.published.is_(True))
        .distinct()
        .all()
        if row[0]
    }
    curated_categories = {a['category'] for a in CURATED_ARTICLES if a.get('category')}
    return sorted(db_categories | curated_categories)


# ── Public endpoints ──────────────────────────────────────────────────────────

@router.get('/news')
def list_articles(
    page: int = Query(default=1, ge=1),
    per_page: int = Query(default=12, ge=1, le=20),
    category: str | None = None,
    severity: str | None = None,
    tag: str | None = None,
):
    q = NewsArticle.query.filter_by(published=True).order_by(NewsArticle.published_at.desc())
    if category:
        q = q.filter(NewsArticle.category == category)
    if severity:
        q = q.filter(NewsArticle.severity == severity)

    db_articles = [a.to_dict() for a in q.all()]
    curated = _filtered_curated_articles(category, severity, tag)

    if tag:
        db_articles = [a for a in db_articles if tag in (a.get('tags') or [])]

    db_slugs = {a['slug'] for a in db_articles}
    articles = sorted(
        [*db_articles, *[a for a in curated if a['slug'] not in db_slugs]],
        key=_published_timestamp,
        reverse=True,
    )

    total = len(articles)
    start = (page - 1) * per_page
    return {
        'data': {
            'articles': articles[start:start + per_page],
            'total': total,
            'page': page,
            'per_page': per_page,
            'pages': max(1, -(-total // per_page)),
            'categories': _available_categories(),
        }
    }


@router.get('/news/admin/all')
def admin_list_all(
    admin: Annotated[User, Depends(require_admin)],
    page: int = Query(default=1, ge=1),
    per_page: int = Query(default=20, ge=1, le=50),
):
    q = NewsArticle.query.order_by(NewsArticle.created_at.desc())
    total = q.count()
    articles = q.offset((page - 1) * per_page).limit(per_page).all()
    return {
        'data': {
            'articles': [a.to_dict() for a in articles],
            'total': total,
            'page': page,
            'per_page': per_page,
            'pages': max(1, -(-total // per_page)),
        }
    }


@router.get('/news/{slug}')
def get_article(slug: str):
    article = NewsArticle.query.filter_by(slug=slug, published=True).first()
    if article:
        return {'data': article.to_dict(body=True)}
    curated = next((a for a in CURATED_ARTICLES if a['slug'] == slug), None)
    if curated:
        return {'data': curated}
    raise HTTPException(404, 'Article not found')


# ── Admin endpoints ───────────────────────────────────────────────────────────

@router.post('/news', status_code=201)
async def create_article(request: Request, admin: Annotated[User, Depends(require_admin)]):
    body = await request.json() if request.headers.get('content-type', '').startswith('application/json') else {}
    title = str(body.get('title') or '').strip()
    if not title:
        raise HTTPException(422, 'title is required')
    summary = str(body.get('summary') or '').strip()
    content = str(body.get('body') or '').strip()
    if not summary or not content:
        raise HTTPException(422, 'summary and body are required')

    published = bool(body.get('published', False))
    article = NewsArticle(
        title=title,
        slug=_unique_slug(_slugify(str(body.get('slug') or title))),
        summary=summary,
        body=content,
        category=str(body.get('category') or 'General').strip(),
        tags=body.get('tags') or [],
        severity=body.get('severity') or None,
        cve_ids=body.get('cve_ids') or [],
        source_url=body.get('source_url') or None,
        published=published,
        published_at=utc_now() if published else None,
        author_id=admin.id,
    )
    db.session.add(article)
    db.session.commit()
    return {'data': article.to_dict(body=True)}


@router.patch('/news/{article_id}')
async def update_article(article_id: str, request: Request, admin: Annotated[User, Depends(require_admin)]):
    article = NewsArticle.query.filter_by(public_id=article_id).first()
    if not article:
        raise HTTPException(404, 'Article not found')

    body = await request.json() if request.headers.get('content-type', '').startswith('application/json') else {}
    if 'title' in body:    article.title    = str(body['title']).strip()
    if 'slug' in body:     article.slug     = _unique_slug(_slugify(str(body['slug'])), exclude_id=article.id)
    if 'summary' in body:  article.summary  = str(body['summary']).strip()
    if 'body' in body:     article.body     = str(body['body']).strip()
    if 'category' in body: article.category = str(body['category']).strip()
    if 'tags' in body:     article.tags     = body['tags'] or []
    if 'severity' in body: article.severity = body['severity'] or None
    if 'cve_ids' in body:  article.cve_ids  = body['cve_ids'] or []
    if 'source_url' in body: article.source_url = body['source_url'] or None
    if 'published' in body:
        was_published = article.published
        article.published = bool(body['published'])
        if article.published and not was_published:
            article.published_at = utc_now()
        elif not article.published:
            article.published_at = None

    db.session.commit()
    return {'data': article.to_dict(body=True)}


@router.delete('/news/{article_id}')
def delete_article(article_id: str, admin: Annotated[User, Depends(require_admin)]):
    article = NewsArticle.query.filter_by(public_id=article_id).first()
    if not article:
        raise HTTPException(404, 'Article not found')
    db.session.delete(article)
    db.session.commit()
    return {'message': 'Deleted'}
