# AltNet — Privacy Policy

**Effective date:** 31 May 2026
**Last updated:** 31 May 2026

> This policy explains what personal data AltNet's account service collects,
> why, and your rights under the EU General Data Protection Regulation (GDPR).
> It covers the **panmox.org account/registration service** (the "Service").
> The AltNet peer-to-peer network itself is account-less — see "The
> peer-to-peer network" below for how data behaves there.

---

## 1. Who is responsible (Data Controller)

The data controller for the Service is:

> **Gabriel Wenzel** (operating as PANMOX)
> Prague, Czech Republic
> Full postal address available on request via the contact email.
> Contact: **abuse.report@panmox.org** (also for privacy questions)

We are a small operator. We have not appointed a Data Protection Officer
because our processing does not require one under GDPR Art. 37; you can
reach a human at the address above.

## 2. What we collect and why

We only collect what the Service needs to work and to keep it safe from abuse.

| Data | Why we hold it | Lawful basis (GDPR Art. 6) |
|------|----------------|----------------------------|
| Email address | Account identity, login, verification, password reset, abuse correspondence | Contract (Art. 6(1)(b)) |
| Password (stored only as a **bcrypt hash**, never in plaintext) | Authentication | Contract |
| Email verification / password-reset codes (short-lived) | Confirm you control the email; anti-abuse | Legitimate interest (Art. 6(1)(f)) |
| Login sessions (random token + timestamps) | Keep you signed in | Contract |
| Domain requests (the `.alt` name, your description, status, timestamps) | Review and approve `.alt` registrations | Contract; legal obligation (Art. 6(1)(c)) |
| Abuse reports (the reported `.alt` name, the reason text, and the **reporter's email**) | Handle illegal-content notices; keep an audit trail | Legal obligation (EU DSA); legitimate interest |
| Account flags (verified, admin, suspended) | Operate and moderate the Service | Contract; legitimate interest |

We do **not** collect: real names, addresses, phone numbers, payment data
(the Service is free), advertising or tracking identifiers, or any special-
category data. We do not profile users or sell data. There are no
third-party analytics or advertising cookies — the only cookie/token is the
strictly-necessary login session.

## 3. The peer-to-peer network (important)

Running an AltNet node, and browsing `.alt` sites, happens on a
decentralised peer-to-peer network — **not** on our servers and **without an
account**:

- **IP addresses are visible to peers.** Like BitTorrent or any P2P system,
  the nodes you connect to can see your IP address. This is inherent to how
  peer-to-peer networking works; we cannot prevent it. Our always-on
  bootstrap node may log connecting IP addresses transiently for
  connectivity and abuse-prevention.
- **Content is content-addressed and chunked.** Node operators store and
  serve encrypted/addressed pieces of other people's content and **cannot
  read what files they are serving**.
- **We do not control what other nodes log or retain.** Once content is
  published to the network it may be cached by independent nodes worldwide.

If this matters to you, use a VPN and be mindful that publishing to a public
P2P network is, by design, public.

## 4. Who we share data with (Processors)

We use a small number of service providers to run the Service. Each acts as
a data processor under a data-processing agreement:

- **Email delivery** — Zoho (verification and notification emails).
- **Server hosting** — Oracle Cloud (our backend and bootstrap node run in
  the EU region, Frankfurt, Germany).
- **DNS** — Cloudflare (resolves panmox.org / api.panmox.org).

Some of these providers are global and may process data outside the European
Economic Area. Where that happens, transfers rely on an adequacy decision or
the European Commission's Standard Contractual Clauses. We do not otherwise
disclose your data, except where legally required (e.g. a valid court order)
or to act on an illegal-content notice.

## 5. How long we keep it

- **Account data:** until you delete your account (see §7), then removed.
- **Sessions:** until they expire, then deleted.
- **Verification / reset codes:** minutes to hours, then expire.
- **Abuse reports:** retained for an audit trail even after the reporting
  account is deleted (the reporter email is preserved for that purpose),
  because we may need to demonstrate how an illegal-content notice was
  handled. We keep these no longer than necessary for that legal purpose.
- **Server logs:** rotated regularly and kept only short-term.

## 6. Where data is processed

Backend account data is processed on EU-based infrastructure (Oracle Cloud,
Frankfurt). Email and DNS providers are listed in §4.

## 7. Your rights

Under the GDPR you have the right to: **access** your data, **rectify** it,
**erase** it ("right to be forgotten"), **restrict** or **object** to
processing, and **data portability**.

- **Erasure / access:** You can delete your account yourself at any time from
  the **Delete account** link in AltNet Studio. To request a copy of your
  data or any other right, email **abuse.report@panmox.org**.
  We respond within one month.
- **Deleting your account** removes your account record and sessions. Note:
  (a) abuse-report audit entries may be retained as described in §5; (b)
  content already published to the peer-to-peer network is not under our
  control and may persist on independent nodes until its name record expires
  (about 7 days) and caches clear.

You also have the right to lodge a complaint with your supervisory authority.
In the Czech Republic this is the **Office for Personal Data Protection
(Úřad pro ochranu osobních údajů, ÚOOÚ)** — www.uoou.gov.cz.

## 8. Security

Passwords are stored only as bcrypt hashes. The account API is served over
HTTPS. We apply reasonable technical measures, but no system is perfectly
secure; please use a strong, unique password.

## 9. Children

The Service is not directed at children. You must be at least 18 to
create an account. We do not knowingly collect data from children below this
age.

## 10. Changes

We may update this policy. Material changes will be announced on panmox.org.
The "Last updated" date above reflects the current version.

## 11. Contact

Questions or requests: **abuse.report@panmox.org**, or by post at the
address in §1 (available on request).

---

*This document is a good-faith draft, not legal advice. Have it reviewed by a
qualified lawyer before relying on it — see `legal/README.md`.*
