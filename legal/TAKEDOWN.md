# AltNet — Notice & Takedown Policy (DMCA + EU DSA)

**Effective date:** 31 May 2026

AltNet is an intermediary: content is published by users and served by a
decentralised network of nodes. We do not host or pre-screen content, but we
operate the `.alt` registration service and act on valid notices about
illegal or infringing content. This page is our **notice-and-action**
mechanism under the EU Digital Services Act (DSA) and our **DMCA** process
for copyright claims.

## Designated point of contact

> **abuse.report@panmox.org**
> Gabriel Wenzel (operating as PANMOX), Prague, Czech Republic
> (full postal address available on request)

This is our single point of contact for authorities, copyright holders, and
the public, and our DSA point of contact (Art. 11–12). Notices may be sent in
**English or Czech**.

---

## A. Reporting illegal content (EU DSA, Art. 16)

Anyone may report content they consider illegal. Use the in-app **"Report a
site"** link or email the contact above with:

1. The **`.alt` name** (and path, if relevant).
2. An **explanation of why** the content is illegal.
3. Enough detail to **locate** the content.
4. Your **name and email** (you may request confidentiality; reports may be
   made in good faith).
5. A statement that you believe the report is **accurate and complete**.

**What happens next:**
- We acknowledge receipt and **review within 72 hours**.
- If upheld, we **revoke** the name — broadcasting a signed deletion record
  that purges the content's chunks from nodes network-wide — and it stops
  resolving.
- We provide the affected publisher a **statement of reasons** (DSA Art. 17)
  where applicable, and they may **appeal** to the contact above.
- We act against **misuse** of this mechanism (repeated bad-faith reports).

---

## B. Copyright takedown (DMCA, 17 U.S.C. § 512)

If you are a copyright owner (or authorised agent) and believe content on a
`.alt` name infringes your copyright, send a notice to
**abuse.report@panmox.org** containing all of the following:

1. A **physical or electronic signature** of the owner or authorised agent.
2. **Identification of the copyrighted work** claimed to be infringed.
3. **Identification of the infringing material** (the `.alt` name and enough
   detail to locate it).
4. Your **contact information** (name, address, email).
5. A statement that you have a **good-faith belief** the use is not
   authorised by the owner, its agent, or the law.
6. A statement, **under penalty of perjury**, that the information is
   accurate and that you are authorised to act for the owner.

On a valid notice we will act expeditiously to revoke the name as described
above.

### Counter-notice

If your content was revoked and you believe this was a mistake or
misidentification, send a counter-notice to the contact above with: your
signature; identification of the removed material and where it appeared; a
statement under penalty of perjury that you have a good-faith belief it was
removed by mistake or misidentification; and your contact information and
consent to jurisdiction.

### Repeat infringers

We terminate the accounts of repeat infringers. In practice, **three**
revocations for abuse automatically suspend an account (see `legal/TERMS.md`,
§7).

---

## C. What we can and cannot do

- We **can**: stop a `.alt` name from resolving, broadcast a signed deletion
  that purges chunks from cooperating nodes, and suspend the publisher's
  account.
- We **cannot** guarantee instant erasure from every node worldwide — this is
  a peer-to-peer network and independent nodes may briefly retain cached
  chunks until revocation propagates and name records expire (about 7 days).
  We ship a content blocklist so nodes refuse known-bad hashes outright.

## D. Law enforcement

Law enforcement requests should go to **abuse.report@panmox.org** with the
relevant legal basis. We cooperate with valid legal process.

---

*This document is a good-faith draft, not legal advice. To claim U.S. DMCA
safe-harbour protection you must also register a designated agent with the
U.S. Copyright Office — see `legal/README.md`.*
