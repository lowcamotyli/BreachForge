# AppSec Platform Founder Memo

## Bottom line

The AppSec market is crowded, but it is not solved. The uncomfortable truth is that most tools are still selling one of three things: **raw findings, governance theatre, or compliance comfort**. Buyers want risk reduction, developers want fixable signal, and security teams want evidence they can trust. They rarely get all three from one product. citeturn22search2turn31view1turn20view0turn30view3

The biggest gap is not “more scanning.” It is **reliable, authenticated, business-logic-aware testing for modern APIs and apps, with proof, ownership, and remediation built in**. Traditional SAST tools still approximate reality; traditional DAST tools still struggle with login state, API shape, and workflow semantics; ASPM tools help consolidate data, but they can introduce a new trust problem when their normalized view does not match source tools. citeturn21search16turn27search0turn27search2turn31view3turn20view0turn23search4

If you want a realistic shot at $100M+ ARR, do **not** build another generic scanner or another dashboard layer. Build the **high-signal exploit validation and remediation layer for API-heavy software teams**. The winning wedge is: **replace flaky legacy DAST and a chunk of manual validation work for teams with modern auth, GraphQL, single-page apps, and multi-step business workflows**. citeturn25view2turn25view3turn32view1turn27search1turn33view0

## Competitor reality check

| Vendor | What it actually does well | Where it breaks in real usage | Who it is really for | Why customers leave |
|---|---|---|---|---|
| Snyk | Excellent developer adoption motion: CLI, IDE, PR workflows, strong SCA, and reachability-based prioritization for open source. citeturn25view0turn21search0 | Cost scales through contributing-developer pricing, separate product purchases, and monthly test caps; users still report false positives and weak custom rule flexibility. citeturn25view0turn16search2turn8search0turn16search4 | Dev-led cloud-native teams that want fast rollout more than deep central governance. citeturn25view0turn21search4 | They outgrow it when central security wants correlation, custom policy depth, and predictable pricing across many repos, containers, and teams. citeturn16search2turn8search0 |
| Burp Suite | Still the best toolkit for skilled manual web testers; Burp Suite DAST adds real enterprise automation and improving auth/API support. citeturn26search3turn26search1turn27search1turn27search9 | API scanning often depends on definitions or introspection, complex login handling still needs recorded sequences, and the learning curve remains real; users also call out UI/reporting friction. citeturn27search0turn27search2turn27search1turn9search0turn9search6 | Pentesters and AppSec engineers with actual testing expertise; not broad engineering orgs by default. citeturn26search3turn26search12 | Teams leave when they need lower-touch rollout across many apps, cleaner reporting, or less manual setup for auth, APIs, and scale. citeturn9search5turn9search8turn26search0 |
| Detectify | Strong hosted DAST plus external attack-surface coverage; easy to stand up; good for lean teams that want broad internet-facing visibility quickly. citeturn33view1turn33view0 | Multiple-site economics get painful, GraphQL/spidering visibility is weaker than teams want, and some users say false positives can resurface or coverage is hard to verify. citeturn33view0turn17search0 | IT/security managers who need easy hosted scanning and reporting, not deep developer-centric workflows. citeturn33view0turn17search1 | Customers churn when scale moves from “scan my sites” to “understand my APIs, auth, and developer ownership model.” Pricing complexity on subdomains/scan profiles also hurts. citeturn33view0turn17search2 |
| Invicti / Netsparker | Proof-based DAST is the real differentiator. It is one of the few products explicitly built around auto-verifying findings to reduce DAST false positives. citeturn18search0turn21search2turn18search7 | Scan duration is still a recurring complaint, licensing is often called costly, and it is still fundamentally strongest on classic web/API runtime vulns rather than deeper product logic. citeturn18search1turn18search2 | Security teams that already believe in DAST and want lower-noise runtime validation. citeturn18search0turn18search3 | They lose when buyers want faster scans, broader code-to-runtime context, or less-expensive scaling across portfolios. citeturn18search1turn18search2 |
| Rapid7 | InsightAppSec is genuinely usable, deploys quickly, and attack replay is valuable for validation and remediation handoff. It also makes more sense if you already live in the Rapid7 estate. citeturn31view0turn31view2 | Authentication setup remains a pain point, CI/CD integration and docs get criticized, and the product still depends on manual review states and replay for trust. citeturn31view3turn31view1 | Central security teams, especially those buying platform consistency across exposure management. citeturn31view0turn10search1 | They lose on friction: auth, integration depth, and teams wanting more than “good DAST with reporting.” citeturn31view3turn10search1 |
| Checkmarx | Broad enterprise surface area, huge packaging menu, strong fit for buyers who want one procurement event for SAST/SCA/API/ASPM/DAST. citeturn28view0 | Opaque packaging, scan/reporting speed complaints, ongoing false-positive triage, and surprisingly narrow API-security language support in the official docs. citeturn11search0turn28view1turn28view3 | Large enterprises and compliance-heavy organizations with AppSec programs, budget, and patience. citeturn28view0turn28view2 | Teams leave or stall because rollout becomes admin-heavy, developer feedback is too slow, and buyers discover they bought a platform before they bought a reliable developer experience. citeturn11search0turn11search2turn28view0 |
| Veracode | Mature, credible enterprise brand; strong binary analysis story; explicit exploitability scoring and a long-standing focus on reducing noise. citeturn29view0turn29view1 | Some reviewers still cite slow scans, cloud-only limitations, multiple senior resources for setup/review, and false positives on certain stacks or project structures. citeturn12search0turn14search0turn14search4 | Large enterprises, especially those comfortable with platform process and policy-driven governance. citeturn12search0turn29view0 | Customers get frustrated when “enterprise maturity” turns into slower CI, cloud-only deployment constraints, or heavy operational overhead for engineering teams. citeturn12search0turn14search0 |
| Qualys | Unified platform story is the appeal: web app scanning, API security, malware detection, and broader infrastructure context in one cloud console. citeturn30view0turn24view3 | It is not a beloved developer tool. Users call out UI complexity, reporting friction, licensing/concurrency issues, weak business-logic coverage, and limited SDLC integration. citeturn30view3 | Security/compliance owners who already use the broader platform and want AppSec as one more module. citeturn30view3turn30view0 | It loses when engineering wants developer-native workflows, deeper authenticated coverage, or faster iteration on modern API/app patterns. citeturn30view3 |
| Tenable | Fast onboarding, simple entry point, strong fit if the buyer already thinks in exposure-management terms. Public pricing helps more than many enterprise peers. citeturn30view2turn24view2 | Licensing is FQDN-based, add-on concurrency exists, overages can reduce functionality, and the product is explicitly DAST-only. That creates awkward economics for fast-growing API estates. citeturn30view1turn24view2 | Security ops and vulnerability-management buyers, not developer platform teams. citeturn30view2turn15search1 | They lose when AppSec buyers realize they need code context, ownership, and workflow-level evidence, not another exposure module. citeturn30view2turn30view1 |
| Escape | Clear modern wedge: API discovery, business-logic-aware DAST, GraphQL depth, developer-friendly remediation, and strong integration posture. citeturn25view2turn25view3turn32view0 | The obvious weakness is maturity. Review volume is still small, customers explicitly mention missing features and occasional upgrade/setup friction, and it is not yet the whole platform for every buyer. citeturn32view1turn32view0 | API-heavy teams who are unhappy with legacy DAST and want modern coverage first. citeturn25view2turn32view1 | They will lose if they broaden too early and become “another platform” before nailing signal and evidence on the modern API use cases that make them interesting. citeturn32view1turn25view3 |
| Cycode | Strong orchestration and context story across AST, ASPM, and software supply chain security; good fit for consolidating fragmented tool output. citeturn20view0turn19search2 | The sharp risk is trust: one recent review says ASPM numbers do not align with source tools because Cycode applies its own import logic. If correlation output is not trusted, the whole ASPM value proposition collapses. citeturn20view0 | Big enterprises already suffering from tool sprawl. citeturn20view0turn19search2 | They lose when the buyer wanted a painkiller for engineers but bought a meta-layer for security operations instead. citeturn20view0 |

The pattern across all of them is brutal but simple: **each tool is optimized around one axis** — developer adoption, manual depth, runtime verification, governance, or platform breadth. Almost none are exceptional at **all five**. That is why AppSec budgets keep expanding while trust in results stays weirdly fragile. citeturn16search2turn31view3turn20view0turn30view3

## What customers actually hate

### Developers

- They ignore security tools when feedback arrives too late for the coding moment. A build that drags to 30–50 minutes, or even “a few minutes” on a medium repo, is enough to turn security into pipeline tax. citeturn11search0turn16search7turn12search0
- They stop trusting tools when “fixed” or “false positive” issues come back, or when the tool cannot clearly prove what was tested. That shows up in Detectify feedback, in manual false-positive handling across Rapid7 and Checkmarx, and in recurring complaints about noisy output from Snyk. citeturn33view0turn31view1turn28view1turn16search2
- They do not want to leave their normal workflow to learn a security product. The guidance from security-culture best practice is still the same: tools must be embedded in developer-native environments and tuned for low false positives, or developers will ignore true positives too. citeturn22search2
- They especially hate “security without ownership”: a finding with no clear code owner, weak reproduction steps, and generic remediation text is not a task, it is just guilt. That is exactly why replay, reachability, proof, and better IDE guidance keep showing up as differentiators across vendors. citeturn31view2turn21search0turn18search0turn11search0

### CTO and engineering leaders

- They think they are buying “continuous application security coverage.” What they often get is **partial coverage plus a triage workflow**. Authenticated areas still require setup. APIs often require definitions or special handling. Business logic flaws are still hard for both static and dynamic analysis. citeturn27search0turn27search1turn23search4turn23search0
- They think a platform will reduce tool sprawl. Sometimes it does; sometimes it just centralizes the sprawl into one expensive contract with multiple add-ons and a big rollout burden. Checkmarx, Veracode, Qualys, and Cycode all illustrate versions of that trade-off. citeturn28view0turn12search0turn24view3turn20view0
- They think pricing will follow value. In reality, pricing often follows seats, FQDNs, scan quotas, modules, or opaque enterprise packaging. That penalizes broad rollout and makes “secure-by-default” harder to fund. citeturn25view0turn30view1turn24view3turn28view0

### Security teams

- They cannot fully trust completeness. If auth setup is fragile, spidering visibility is weak, or APIs are undiscovered, a clean report can mean “scan blind spots,” not “no risk.” citeturn31view3turn33view0turn27search2
- They cannot fully trust normalized posture layers if the data does not reconcile with source tools. That is a fatal flaw for any ASPM-led product. citeturn20view0
- They cannot fully trust automated tooling on business logic abuse. The current community taxonomy and recent research are very clear: those vulnerabilities are deeply contextual, mimic valid behavior, and are difficult for conventional static and dynamic analysis to catch. citeturn23search0turn23search4
- They also do not trust metrics that reward activity over risk reduction. Scan counts, dashboards, and findings volume are easy to sell upward, but they do not answer the real question: **what is exploitable, exposed, owned, and still unfixed?** citeturn29view1turn20view0turn31view1

## Signal versus noise

False positives are still a major AppSec problem because most tools still operate on **partial context**. Static tools reason about possible paths, sanitizers, and reachability without seeing runtime state. Even vendors that do reachability acknowledge that the output is still an approximation of reality. Dynamic tools see runtime behavior, but they only see what they can crawl, authenticate to, and understand; that breaks badly on modern APIs and workflow logic. citeturn21search16turn29view0turn27search0turn27search1turn23search4

Vendors attack the problem in four main ways:

- **Reachability and prioritization**: Snyk uses reachability analysis to reduce dependency noise. Veracode applies exploitability ratings and whole-program analysis. citeturn21search0turn29view1turn29view0
- **Runtime proof**: Invicti’s proof-based scanning is built around auto-verifying exploitable findings. citeturn18search0turn21search6
- **Replay and manual validation**: Rapid7 leans on attack replay and explicit review states. Checkmarx persists “Not Exploitable” triage decisions across scans. citeturn31view2turn31view1turn28view1
- **Correlation/orchestration**: Cycode and similar ASPM tools try to reduce duplicate noise by normalizing multiple tools into one view. citeturn20view0turn19search2

Why they still fail:

- **Static exploitability is not the same as deployed exploitability**. A path may be reachable in code but dead behind auth, config, or product design. citeturn21search16turn29view1
- **Runtime proof only works where safe exploitation is possible and coverage exists**. It does not magically solve business-logic abuse or missing authenticated coverage. citeturn21search6turn27search1turn23search4
- **Correlation can hide as much as it helps** if the meta-layer’s logic is opaque or irreconcilable. citeturn20view0
- **Tooling still underweights owner context and fix economics**. Developers care about “can I fix this now, in this repo, with evidence?” far more than “what colour is the risk tile on a dashboard?” citeturn22search2turn31view2turn11search0

My practical definition of **high-quality signal** in AppSec is this:

- the issue is tied to a **real exposed or deployable asset**;
- it includes **proof or strong evidence** of exploitability;
- it is mapped to a **specific owner, repo, branch, or service**;
- it explains **what was tested and what was not**;
- it is **deduped** across scanners and states;
- and it comes with a **credible fix path** that an engineer can act on immediately.

If one of those is missing, the finding is still useful for a security analyst. It is **not** high-quality signal for a product team.

## Pricing traps

Here is how pricing really works in practice:

- **Seat pricing kills broad developer rollout.** Snyk starts at $25 per month per contributing developer, products are purchased separately, and test limits vary by module and tier. Burp Suite Professional is $499 per user per year and is explicitly non-shareable. citeturn25view0turn26search5
- **Asset/FQDN/site pricing punishes modern architectures.** Tenable licenses by FQDN, counts scanned FQDNs over 90 days, sells extra concurrency, and can reduce functionality after prolonged overages. Detectify pricing varies by asset scope and scan tier, and users complain that multiple sites, subdomains, or scan-profile structure make the model feel awkward or uncompetitive. citeturn30view1turn24view2turn33view1turn33view0
- **Module pricing hides the real bill until the buyer is already committed.** Checkmarx packages are built around combinations of SAST, SCA, API, ASPM, DAST, container, IaC, secrets, and more. Veracode pricing is also module-and-usage-based. Qualys prices by app mix, IPs, and user licenses. citeturn28view0turn12search0turn24view3
- **“Simple platform” stories often still contain hidden scaling points.** Qualys users mention concurrency/licensing pain. Tenable separates concurrency as an add-on. Detectify users complain about cost once multiple sites or scan structures enter the picture. citeturn30view3turn30view1turn33view0

Why customers feel cheated:

- They buy for risk reduction, but the bill grows with **enablement**. More developers, more apps, more APIs, more subdomains, more environments — the exact behaviours you want in a secure program — often mean a bigger penalty. citeturn25view0turn30view1turn33view0
- They hear “platform consolidation,” but the contract expands as soon as they ask for the modules that make the platform actually useful. citeturn28view0turn12search0
- They deploy the tool broadly, then learn that operational scale is gated by concurrency, overage controls, or module gaps. citeturn30view1turn30view3

A radically simpler pricing model:

- **Bill by production service group**, not by user, FQDN, repo, or scan.
- Define a service group as: one customer-facing application/API plus its associated repos and environments.
- Include **unlimited developers, users, scans, PR checks, and findings**.
- Offer only two paid dimensions:
  - number of production service groups;
  - optional private execution runners for regulated/private environments.
- Add a **quarterly true-up**, not hard overage penalties.
- No seat tax. No scan caps. No “that subdomain is a separate billable object.”

That model aligns price with business value and removes the perverse incentive to limit usage.

## Opportunity zones

### Top opportunities

| Opportunity | Why it is open | Why incumbents are weak |
|---|---|---|
| Authenticated API and business-logic testing for modern SaaS | Modern apps rely on APIs, SPAs, GraphQL, SSO, MFA, and multi-step flows; business-logic flaws remain difficult for conventional tooling. citeturn27search1turn27search9turn23search4turn23search0 | Legacy DAST still depends on definitions, login recordings, and payload-style testing; broad enterprise suites are not built around workflow semantics first. citeturn27search0turn27search2turn31view3 |
| Evidence-first exploit validation | Security teams want proof, not suspicion; attack replay, proof-based scanning, and exploitability ratings all point in this direction. citeturn18search0turn31view2turn29view1 | Most tools solve only one part: static likelihood, runtime proof for some classes, or manual replay. Very few connect proof to owner and fix path cleanly. citeturn21search16turn21search6turn31view2 |
| Trusted code-to-runtime prioritization | Tool sprawl is real, but so is distrust in meta-layers when their numbers diverge from source systems. citeturn20view0turn22search6 | ASPM vendors often optimize for orchestration breadth before trust and reconciliation accuracy. citeturn20view0 |
| Mid-market AppSec platform with sane economics | Enterprises can tolerate platform friction. Mid-market SaaS teams cannot. Current pricing punishes broad rollout and architecture complexity. citeturn25view0turn30view1turn33view0 | Big vendors are too enterprise-shaped; startup tools are often too narrow or too early. citeturn28view0turn12search0turn32view1 |
| AI-code-era guardrails with very fast feedback | Developers are using AI daily and AI-assisted code volume is already material. That increases code velocity and raises the cost of slow, noisy scans. citeturn22search0turn22search8 | Incumbents are still retrofitting older engines and workflows into a much faster coding environment. User complaints about scan delays make that painfully obvious. citeturn11search0turn16search7turn12search0 |

### Underserved segment

The most underserved segment is **mid-market, API-heavy B2B SaaS companies with roughly 50–500 engineers and tiny AppSec teams**.

They are too complex for basic scanners, too modern for legacy web-only DAST, and too cost-sensitive for heavyweight enterprise platforms. They have real authentication complexity, real multi-tenant risk, real customer compliance pressure, and absolutely no appetite for a six-month rollout. That segment is large enough to build a serious business, and incumbents consistently underserve it on usability, pricing, and modern coverage. citeturn33view0turn30view1turn28view0turn25view2

### Overbuilt and underbuilt

**Overbuilt:**

- executive dashboards and posture theatre;
- packaging complexity and platform sprawl;
- compliance reporting layers that sit on top of weak evidence;
- orchestration that optimizes presentation before trust. citeturn20view0turn28view0turn30view3

**Underbuilt:**

- reliable authenticated testing for modern apps and APIs;
- business-logic and multi-tenant abuse detection;
- proof-rich developer remediation;
- ownership mapping from repo to deployed endpoint;
- pricing that encourages, rather than punishes, rollout. citeturn25view2turn23search4turn31view2turn30view1turn25view0

## The MVP that can win

### v1

Build **an authenticated API and app exploit-validation platform** for modern SaaS teams.

Minimal but powerful feature set:

- **Service inventory from code to endpoint**: ingest repos, API specs, gateways, and cloud metadata to map services and owners. citeturn25view2turn30view0
- **Robust authenticated scanning**: support recorded flows, session refresh, SSO, MFA/TOTP, and multi-user test scenarios. Burp’s recent improvements and the praise for Escape’s auth handling show this is both painful and valuable. citeturn27search1turn27search9turn32view1
- **Business-logic test packs** for the highest-value modern flaws: BOLA/IDOR, tenancy isolation, broken workflow sequencing, privilege misuse, rate-limit abuse, and sensitive data exposure. The key is not breadth; it is reliability on the cases incumbent DAST misses. citeturn23search4turn23search0turn25view2
- **Evidence-first findings**: each issue ships with replayable requests, screenshots or trace evidence, what credentials and paths were used, affected owner, and a concrete remediation action. citeturn31view2turn32view1
- **Developer delivery**: PR comments, Jira tickets, and service-owner routing by default. No separate triage universe unless needed. citeturn22search2turn31view0turn25view2
- **Flat service-based pricing**: unlimited developers, scans, and users. This needs to be part of the product, not just the contract. citeturn25view0turn30view1turn33view0

What must be exceptional:

- authentication reliability;
- signal quality;
- proof quality;
- ownership mapping;
- time to first trusted finding.

If any of those are mediocre, the product is dead on arrival.

### v2

Expand into the platform layer **after** v1 wins trust:

- runtime-aware prioritization from cloud, gateway, or WAF context;
- automated discovery of shadow and zombie APIs;
- broader web coverage for SPA-heavy front ends;
- compliance evidence packs generated from proof-backed tests;
- a thin ASPM layer that reconciles to source tools instead of replacing them. citeturn30view0turn18search13turn20view0

### What to ignore

Explicitly ignore these in the first 18–24 months:

- full broad-market SAST;
- full SCA;
- CNAPP / CSPM / VMDR ambitions;
- generic “single pane of glass” positioning;
- PTaaS and services-heavy delivery;
- executive dashboard vanity features;
- on-prem control plane complexity, beyond optional private runners.

Those are expansion paths, not a wedge. The market is already full of vendors trying to be everything. That is precisely why so many products feel diluted. citeturn28view0turn12search0turn20view0

## Winning strategy

**Positioning:** The fastest way for API-heavy software teams to find and prove the exploitable app risks that legacy AppSec tools miss.

**Wedge strategy:** Start with mid-market SaaS teams whose current pain is “our DAST does not handle our auth and APIs, manual validation is eating us alive, and our developers do not trust the output.” Replace a mix of legacy DAST, spreadsheet triage, and part of the manual verification workload. Land as a line-item inside the existing AppSec budget, not as a broad platform replacement. citeturn31view3turn33view0turn32view1

**Why we win:**

- incumbents are optimized for breadth, not this pain;
- the real differentiation is not more findings, but **trusted findings**;
- pricing can become a weapon if it removes adoption friction;
- if the product becomes the system of record for “is this exploitable and who owns it?”, expansion gets much easier. citeturn20view0turn25view0turn30view1turn18search0

**Biggest risk:** Business-logic-heavy testing is hard to productize without drifting into a services business or overpromising AI magic. The product has to be very disciplined: focus on a narrow set of repeatable, high-value exploit classes and prove value there first. The temptation to broaden too early will be enormous. citeturn23search4turn23search0turn32view1

## What exactly to build

Build a **proof-driven AppSec product for authenticated API and modern web testing** that does four things exceptionally well:

1. **discovers the real service and API surface with ownership attached;**
2. **authenticates reliably into modern apps and APIs;**
3. **finds a small number of replayable, business-relevant, exploitable issues;**
4. **delivers those issues directly to the team that can fix them, with proof and guidance.**

That beats existing AppSec tools because most of them force customers to choose between:

- developer friendliness and enterprise control;
- runtime proof and code context;
- modern API depth and broad platform breadth;
- adoption and predictable pricing.

You win by refusing that trade-off for one narrow, painful category first.

The product I would actually build is this:

**A business-logic-aware, authenticated API security platform for mid-market SaaS teams, sold as the high-signal exploit-validation layer that replaces noisy legacy DAST and manual AppSec verification.**

That is the wedge.  
That is differentiated.  
And honestly, that is one of the few AppSec products I can see earning real trust fast enough to matter.