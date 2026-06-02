# AltNet — Legal documents

This folder holds the public legal terms for AltNet (Path A: a gatekept,
accountable host). They are written to match what the software actually does
(account-gated publishing, name review, 72h report handling, signed
revocation, three-strikes suspension, abuse.report@panmox.org).

| File | What it is |
|------|------------|
| `../LICENSE` | GNU GPL v3 — the software licence (canonical FSF text) |
| `PRIVACY.md` | Privacy Policy (GDPR) for the account service |
| `TERMS.md` | Terms of Service + Acceptable Use Policy |
| `TAKEDOWN.md` | Notice & takedown (EU DSA Art. 16 + US DMCA §512) |

---

## ⚠️ NOT legal advice

These are good-faith **drafts** written by an engineer, not a lawyer. They
get you most of the way, but you should have them reviewed by a qualified
lawyer (ideally Czech/EU, familiar with the DSA and GDPR) before you rely on
them — especially the liability, GDPR, and DSA sections.

## ✅ Placeholders — FILLED (31 May 2026)

The three public docs are now filled in:
- Operator: **Gabriel Wenzel (operating as PANMOX)**, Prague, Czech Republic
- Contact: **abuse.report@panmox.org** (single point of contact)
- Postal address: shown as **"available on request"** — swap in a real
  street address once you set up a **virtual mailbox** in Prague (~€5–15/mo)
  so your home address stays private. Update §1 of PRIVACY.md and the
  contact lines in TERMS.md / TAKEDOWN.md when you have it.
- Minimum age: **18**
- Effective date: **31 May 2026**

## ✅ Registrations / steps to actually be protected

1. **Publish these on panmox.org** at stable URLs (e.g.
   panmox.org/privacy, /terms, /takedown) and link them from the app and
   from sign-up. The in-app Terms screen should point here.
2. **DMCA designated agent (only if you want US §512 safe harbour):**
   register an agent with the U.S. Copyright Office DMCA Designated Agent
   Directory (online, ~$6, renew every 3 years). Without this, the DMCA
   safe harbour doesn't apply to you in the US.
3. **EU DSA point of contact:** abuse.report@panmox.org is set as your
   single point of contact (Art. 11–12). As a small/micro operator you are
   exempt from the heavier VLOP obligations, but the notice-and-action
   mechanism (TAKEDOWN.md) and statement-of-reasons are baseline duties —
   keep records of reports and actions (the abuse_reports table does this).
4. **GDPR controller details:** confirm the controller name/address in
   PRIVACY.md. You likely do **not** need a DPO at this scale. Keep the
   processor list (Zoho, Oracle, Cloudflare) current and have
   data-processing terms in place with each.
5. **Decide the minimum age** and enforce it at sign-up if needed.
6. **Keep the audit trail:** the backend already logs reports, decisions,
   and reporter emails — that record is what demonstrates you acted on
   notices. Don't disable it.

## Where the software backs this up

- Name review before go-live, in-app **Report a site**, 72h handling.
- **Signed revocation** (`dht_revoke`) purges chunks network-wide.
- **Content blocklist** so nodes refuse known-bad hashes.
- **Three-strikes** auto-suspension of repeat infringers.
- **Account deletion** (GDPR erasure) from the app.
- Abuse-report **audit trail** retained for accountability.
