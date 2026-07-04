# ADR 0001 — AWS SSO gateway credential as an external clawpatrol plugin

- **Status:** Accepted (design)
- **Date:** 2026-07-04
- **Deciders:** akefirad
- **Spec:** [`akefirad/clawpatrol-plugin-aws#1`](https://github.com/akefirad/clawpatrol-plugin-aws/issues/1)
  (the PRD this ADR backs)
- **Supersedes:** the in-tree implementation on the clawpatrol fork
  ([`akefirad/clawpatrol` PR #14, `gh-1-aws-sso-credentials`](https://github.com/akefirad/clawpatrol/pull/14))

## Context

We built AWS IAM Identity Center (SSO) support for the clawpatrol gateway as an
**in-tree** credential (`aws_sso_credential`) on our fork of clawpatrol. One SSO
device login fans out to many `(account, role)` mappings; the agent signs with a
placeholder access-key-id, the gateway maps it to a role, mints short-lived
credentials via `sso:GetRoleCredentials`, and re-signs the request. The agent
never holds real credentials.

Rather than keeping it in-tree on the gateway fork, we are building this
functionality as an **external plugin**. clawpatrol supports out-of-process,
Terraform-style plugins via its public `pluginsdk` (hashicorp/go-plugin over
gRPC), loaded declaratively with `plugin "..." { source = "..." }`.

This ADR records the design for reimplementing our SSO feature as a **fresh
external plugin** ([`akefirad/clawpatrol-plugin-aws`](https://github.com/akefirad/clawpatrol-plugin-aws), this repo), including how we
handle the one piece that cannot live in an external plugin today: the SSO
device-login flow.

### The sibling plugin, and why we are not it

[`denoland/clawpatrol-plugin-aws`](https://github.com/denoland/clawpatrol-plugin-aws) gates AWS APIs using a **long-lived base IAM
key** and **STS `AssumeRole`**, with the target account encoded in the AKID and a
single uniform role assumed across all accounts. AWS SSO is fundamentally
different: you authenticate **once** and gain access to whatever accounts/roles
your permission sets grant — there is no per-account base key. So our credential
model must be SSO, not account-key. We share a large amount of *mechanism* with
that plugin (SigV4 re-signing, action parsing, the `aws` facet, account-from-AKID
dispatch) but differ in the **minting** half (`GetRoleCredentials` vs
`AssumeRole`) and the **auth** model (device login vs pasted base key).

## Decisions

### D1 — Credential model is AWS SSO, not account-based

The credential type is `aws_sso`. One SSO authentication (`start_url` + SSO
`region` → one device login → one stored token) serves many accounts.

### D2 — The account is the sole per-request dispatch key; role is fixed config

A bot never *chooses* a role per request. Exposing a role choice would push a
decision onto an agent that has no basis to make it. The role is determined
ahead of time by config (per account); the only thing that varies per request is
**which account**. If a genuine two-roles-same-account need ever arises, model it
as a second credential, not a per-request switch.

### D3 — Credential schema: a per-account allowlist

```hcl
credential "aws_sso" "wp" {
  start_url = "https://<org>.awsapps.com/start"
  region    = "eu-central-1"                     # SSO / Identity Center region
  endpoints = [aws_api.aws, aws_api.s3]          # one session, many endpoints
  accounts  = ["111111111111", "222222222222"]   # the explicit allowlist (account ids)
}
```

- `accounts` — **required**, a flat `list(string)` of 12-digit account numbers:
  the explicit allowlist. Each id appears at most once.
- **Role** is not configured per account in this cut — it is **auto-discovered**
  via `sso:ListAccountRoles` and must resolve to a **single** role per account
  (else a clear error).
- **Placeholder** is always **derived** from the account id (see D5); dispatch
  placeholders are unique by construction.

> **Flat-schema constraint (discovered building Slice 1):** pluginsdk (v0.5.3,
> `ctyTypeFromString`) accepts only **flat attributes** — primitive or
> `list(primitive)` — with **no nested/repeated blocks**. So the earlier
> `account { id, role_name, placeholder }` block isn't expressible; the allowlist is
> a flat `accounts = list(string)`. Two things are deferred with it: the per-account
> `role_name` **guard** and the explicit `placeholder` **override**. If we later need
> them, the flat path is **option B** — encode per entry (e.g. `"<id>:<role>"`) and
> parse in the plugin (or add a credential-level uniform `role_name`). Multiple roles
> for the *same* account would then work via distinct (encoded) placeholders,
> shifting dispatch to placeholder-match and relaxing D2. For now: **one
> auto-discovered role per account, derived placeholders, account-id allowlist.**

### D4 — The account allowlist is explicit and required; the boundary is never auto-discovered

Guiding principle:

> Auto-discovery may only **narrow within** an explicit boundary (the singleton
> role inside a listed account). It must never **expand the boundary itself**
> (which accounts the bot can touch).

Auto-discovering the account set (`sso:ListAccounts`) is deliberately **not**
offered: the bot's blast radius would silently grow whenever the operator's own
SSO entitlements grow. The account allowlist is the primary blast-radius guard,
so it stays explicit and mandatory. Role auto-discovery is safe only because it
is already fenced by the account being on the allowlist **and** the
must-be-singleton rule.

### D5 — Dispatch by decoding the account from the AKID; placeholders derived

The gateway routes a connection to an endpoint by **host** (see D6), before TLS
termination. AWS accounts are indistinguishable by host, so account selection
happens **inside** the endpoint handler, after TLS termination, by decoding the
account from the SigV4 access-key-id the agent signed with:

- Default placeholder = `AKIA` + the 12-digit account id + padding
  (e.g. `AKIA5597323133910000`). The handler extracts the **first 12-consecutive-
  digit run** as the account (compatible with the sibling plugin's scheme).
- The agent's `~/.aws/credentials` profiles are therefore **mechanically
  derivable** from the account list — no coordination table between the gateway
  config and the agent file. A seed script can generate them directly.
- An explicit placeholder override is **not** expressible under the flat schema
  (D3); placeholders are always derived in this cut (custom AKIDs → option B).
- An AKID whose decoded account is **not on the allowlist** is denied.

### D6 — Topology: state on the credential, `hosts` on the endpoint

Endpoint selection is by **destination host** (`CompiledProfile.HostIndex` /
`HostPatterns`, longest-suffix wins), scoped to the connecting agent's profile,
**before** TLS termination. Consequences:

- Per-account **endpoints** are impossible (accounts share `*.amazonaws.com`; the
  account isn't visible until after the endpoint is chosen and TLS terminated).
- The **credential** holds everything shared: the SSO session, the account
  allowlist, and the roles. It binds to a **list** of endpoints (`endpoints = […]`
  is a framework-level list attribute on any credential).
- The **endpoint** carries only `hosts` — the routing key *and* the policy-scoping
  unit. No `role`, no `region`.

```hcl
endpoint "aws_api" "aws" { hosts = ["*.amazonaws.com"] }
endpoint "aws_api" "s3"  { hosts = ["*.s3.amazonaws.com", "s3.amazonaws.com"] }
```

The only axis you split endpoints on is **host/service** (e.g. S3 with its own
rules vs. general AWS). The sibling plugin puts `role` on the endpoint only
because *its* role is uniform-global; ours is per-account, so it lives on the
credential.

### D7 — Signing region comes from the request host, never from config

SigV4 bakes the region into the credential scope, and AWS validates against the
region of the endpoint that received the request. We derive it from the host
(`ec2.eu-central-1.amazonaws.com` → `eu-central-1`). Region-less **global**
services (IAM, Route53, CloudFront, Organizations, the legacy global
`s3`/`sts` endpoints) are signed as `us-east-1`, which AWS mandates regardless of
where your resources live. This `us-east-1` fallback therefore **never** touches
regional traffic. No signing region is configured anywhere. (The credential's
`region` is a *different* thing — the SSO/Identity-Center region.)

### D8 — Rules are gateway-owned CEL; we design only the `aws` facet

The `rule` block schema (`condition` [CEL], `verdict`, `approve`, `priority`,
`endpoint(s)`) is defined in gateway core. A plugin **cannot** add rule
attributes or CEL functions (the `match`/`action` shown in the sibling plugin's
README is a documentation error — those attributes do not exist in the gateway).
The only lever we own is the **facet fields** the CEL matches on.

The `aws` facet exposes: `service`, `action` (CloudTrail op name, the audit
verb, always present), `iam_action` (`s3:DeleteObject`; permission-shaped,
best-effort, absent when undeterminable), `account`, `account_name`, `region`,
`resource`, `method`. Result fields: `status`, `response_body`.

Matching guidance:
- **Allow rules (reads):** match on `iam_action` — a missing mapping just
  over-denies (fails closed = safe). IAM-style wildcards via
  `condition = "aws.iam_action.matches('^s3:(Get|List).*')"`.
- **Write/approval gates:** do **not** gate solely on `iam_action` — an unmapped
  mutating op has no `iam_action` and would slip the gate. Anchor on the
  always-present `method` (PUT/POST/DELETE) or `action`.
- The **IAM role is the primary permission boundary**; the facet/rules are a
  secondary layer for observability and HITL approval.

### D9 — Login architecture: Path A (interim) — flow in the fork, rest in the plugin

The SDK exposes `OAuthIntegration` **declaratively** only; there is no
gateway→plugin callback to run a custom device flow, and AWS SSO's ssooidc
(dynamic `RegisterClient` + JSON device) cannot be driven by the gateway's
generic RFC-8628 `device` flow. So an external plugin cannot execute the SSO
login today.

We keep the login flow in the **gateway fork** core (the `oauth_aws_sso.go`
device flow + the `Flow=="aws_sso"` dispatch, tracked in
[`akefirad/clawpatrol#24`](https://github.com/akefirad/clawpatrol/issues/24)),
and put everything else in this plugin:

- The plugin's credential declares
  `OAuthIntegration{Flow:"aws_sso", OAuth:{AuthURL:start_url, DeviceURL:region}}`.
  This makes the dashboard render a **Connect card** (trust: the operator
  visually verifies the device before authorizing — a Telegram link alone is not
  enough) and routes the login to the fork gateway's ssooidc handler.
- The gateway runs the device flow, persists the token, and delivers it to the
  plugin as `Conn.CredentialSecret` (the gateway secret store returns the OAuth
  bearer token as the secret bytes). The plugin **never** runs the device flow,
  persists tokens, single-flights logins, or refreshes.

**Cost accepted:** the plugin only works against our fork gateway (which has the
`aws_sso` flow) until Path B; the fork surface we carry is small and stable
(`oauth_aws_sso.go` + a 2-line dispatch — device-flow logic rarely churns).

**Path B (future):** move the login into the plugin using `pluginsdk` `StateStore`
plus a **generic plugin-driven OAuth/device-flow primitive** contributed
upstream (the gateway renders the card + proxies; the plugin executes
RegisterClient/StartDeviceAuth/CreateToken). This makes the plugin fork-free and
dissolves the refresh limitation (D10). "Needs the fork" and "no token refresh"
are the same limitation seen twice — both lift at Path B. Migrating A→B is a
one-time re-connect (token moves to `StateStore`); the sign/mint/facet code is
unchanged.

### D10 — Token refresh: deferred, then a fork-side packed-column fix

Not in the first cut: when the SSO token expires (Identity Center default ~8h)
the operator re-connects via the card. Graceful, not seamless. (This consciously
defers a PRD requirement — auto-refresh for the SSO session lifetime — to the
fast-follow below.)

Fast-follow (fork-side, no schema migration): persist the refresh token, and
**JSON-pack `client_id` + `client_secret` into the existing `client_id`
column** (the `credentials` table has no `client_secret` column; adding one is
rejected). Add an `awsSSORefreshSource` for `Flow=="aws_sso"` mirroring the
existing `anthropicRefreshSource`, calling ssooidc `CreateToken(grant_type=
refresh_token)`. Use JSON (self-describing) rather than a fixed offset (the
ssooidc `client_id`/`client_secret` are opaque, non-fixed-length) or a naive
delimiter (the secret is opaque and may contain it).

This is throwaway once Path B lands (StateStore supersedes it). Enabling it later
is seamless — the next natural re-auth at expiry populates the packed value; the
card is never deleted/recreated.

### D11 — Fresh MIT module, clean-room machinery

This repo (`akefirad/clawpatrol-plugin-aws`, MIT) is a **fresh module**, not a
fork of `denoland/clawpatrol-plugin-aws`. That repo currently ships **no LICENSE**
(all-rights-reserved) and its code is `package main` (not importable), so we
**clean-room reimplement** the shared machinery (action parsing, `iam_action`
table, S3 op reconstruction, aws-chunked decode, `signRequest`) rather than copy
or import it. We reference the sibling repo in docs as the base-key prior art.

### D12 — First cut is lean and read-first

Required for the first cut:
- `parseServiceRegion` + `signRequest` (SigV4 re-sign) — correctness floor.
- account-from-AKID dispatch + `sso:GetRoleCredentials` + per-role credential
  cache (+ `ListAccountRoles` role auto-discovery, cached).
- minimal `aws` facet: `service`, `account`, `region`, `resource`, `method`.

Deferred to follow-ups (driven by real need):
- rich `action` parsing + `iam_action` table + S3 operation reconstruction.
- `aws-chunked` decode + `Expect: 100-continue` (S3 uploads / write bodies).
- response `SetResult` (status + response-body tap).
- **cross-connection cache sharing (#10):** Slice 2 builds the minter +
  `aws.CredentialsCache` **per connection**, so single-flight/expiry apply within a
  keep-alive connection but separate connections re-mint. A shared
  per-credential-instance cache keyed by `(account, role)` (SSO token threaded
  per-mint) is deferred to #10.
- **redaction of minted creds:** pluginsdk v0.5.3 exposes no redaction hook to an
  endpoint plugin's `HandleConn` (only the built-in HTTPS inject/transform path has
  `Redactions`). Exposure is low — the plugin proxies the re-signed request itself
  via the brokered dial, and the gateway audits via the `aws` facet (no cred
  material), not the re-signed bytes. Deferred pending a pluginsdk hook.

### D13 — Re-authentication is surfaced actively (expired-token UX)

When the gateway cannot deliver a live SSO token — the session expired with no
valid refresh (D10) — the plugin receives an **empty/absent
`Conn.CredentialSecret`**. Because the plugin owns `HandleConn`, it controls the
response fully (unlike the in-tree design, where the gateway's fail-open forwarded
the request), and it surfaces the re-auth need on three channels instead of
failing opaquely:

1. **Agent (request response):** deny with a clear, *recognizable* error — e.g.
   `aws_sso: AWS SSO session expired; an operator must reconnect the
   "<credential>" credential in the clawpatrol dashboard` — so the calling agent
   gets an actionable signal, not a generic 403.
2. **Dashboard:** the Connect card already reflects the expired state via the
   gateway's OAuth credential status; the plugin additionally `Emit`s an audit
   event for the denied-for-reauth request so it shows in the activity stream.
   (Supplementary — the card, not the event, is the primary signal.)
3. **Human (agent-driven):** an agent instructed to do so forwards the error to
   the operator over Telegram/Slack. This is an **agent-side convention**, not
   plugin code — the plugin's responsibility ends at the structured error.

The surfaced target is the **dashboard** (where the operator clicks Connect and
the gateway runs the device flow), **not** a raw ssooidc verification URL: the
plugin can't mint one under Path A, and pointing at the dashboard is the right
trust posture — the operator re-authenticates on a surface they verify, never
from a link received over chat (a Telegram/Slack message alone must never be
sufficient to authorize a device). If the plugin is configured with the gateway's
dashboard URL it includes it; otherwise the message names the credential and says
"reconnect in the dashboard."

Why this matters beyond Path A: this surfacing lives entirely in the plugin (the
error + the emit), so it is **independent of where the login runs** — identical
under Path A (login in the fork) and Path B (login in the plugin). It reduces
reliance on the polished core card, de-risking a future decision to drop the
in-core AWS SSO flow.

## Request flow (Path A, per connection)

1. Gateway routes by host → this endpoint; terminates TLS; delivers the current
   SSO token as `Conn.CredentialSecret`.
2. Plugin reads the HTTP request; decodes the **account** from the AKID; **fails
   closed before any SSO call** if there is no parseable AKID or the account is not
   on the credential's allowlist.
3. Builds the `aws` facet and calls `conn.Evaluate` — **before** any SSO call or
   mint, so a denied request does no SSO work, and a request routed to a human
   approver **blocks synchronously** on `Evaluate` (which walks the `approve`
   chain) until the decision or the request timeout.
4. On allow: resolve the **role** (the singleton from `ListAccountRoles`, cached
   per account) → mint via `GetRoleCredentials` → SigV4 re-sign (region from host)
   → `conn.DialUpstream` to the AWS host.

Minting is **after** the verdict, so a request approved after a delay is signed
with freshly minted credentials. The per-role credential cache is
**expiry-window + single-flight** — a burst triggers at most one
`GetRoleCredentials` per role (per connection in the first cut; cross-connection
sharing → #10). Under Path A the SSO token is re-delivered as
`Conn.CredentialSecret` on every connection, so the in-memory caches repopulate
naturally after a plugin/gateway restart — no re-authentication.

## Capabilities

`Network = NetworkNone`, `Egress = ["*.amazonaws.com:443"]` (covers
`portal.sso.<region>` for GetRoleCredentials/ListAccountRoles and the service
hosts). All upstream connections go through the gateway's audited brokered dial.

## Security model (defense in depth)

- **Account allowlist** (D4) — the bot can only reach listed accounts, even if the
  operator's SSO can reach more.
- **Role guard** (D3) — an explicit `role_name` pins the permission set.
- **IAM role** — the primary permission boundary; the facet/rules are secondary.
- **Gateway CEL rules** (D8) — per-host-group policy + HITL approval.
- **No ambient identity** — no env pushdown / default profile; a request with no
  matching placeholder is denied. The SSO token and minted credentials are never
  written to the agent's environment (the token reaches the plugin only as
  `Conn.CredentialSecret`), so a compromised agent cannot read them.

## Consequences

- ✅ Solves clawpatrol **#15** (role/account invisible to policy): the `aws` facet
  exposes `account`/`iam_action`/… so CEL rules discriminate per account/action.
- ✅ Moves the churny sign/mint/facet/policy logic out of the gateway fork; only
  the small, stable login flow remains forked.
- ✅ Keeps the verifiable dashboard Connect card.
- ✅ Actively surfaces re-auth on expiry (D13) — plugin-owned, so it works under
  both Path A and Path B and de-risks dropping the in-core flow.
- ⚠️ Plugin is coupled to the fork gateway (needs `Flow:"aws_sso"`) until Path B.
- ⚠️ No silent token refresh until the D10 fast-follow (or Path B).
- ⚠️ Clean-room reimplementation of AWS machinery (cost of fresh-not-fork).

## References

- Spec (PRD): [`akefirad/clawpatrol-plugin-aws#1`](https://github.com/akefirad/clawpatrol-plugin-aws/issues/1).
- Core device-flow (Path A, in the gateway fork): [`akefirad/clawpatrol#24`](https://github.com/akefirad/clawpatrol/issues/24).
- Sibling plugin: [`denoland/clawpatrol-plugin-aws`](https://github.com/denoland/clawpatrol-plugin-aws) (base-key + STS AssumeRole).
- In-tree predecessor: [`akefirad/clawpatrol` PR #14](https://github.com/akefirad/clawpatrol/pull/14) (`gh-1-aws-sso-credentials`).
- clawpatrol issues: #6 (SSO token refresh / client_secret storage), #15 (role
  invisible to policy — solved here), #16 (gateway fail-closed on sign error),
  #18 (SigV4 parser dedup), #21 (body-content rules advisory on re-sign),
  #22 (redaction of minted creds).
- `pluginsdk`: `CredentialDef`, `EndpointDef`, `FacetDef`, `Conn` (Evaluate /
  DialUpstream / SetResult / CredentialSecret), `StateStore` (Path B).
