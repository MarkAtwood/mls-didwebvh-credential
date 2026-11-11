# Problem Statement: Provider-Independent Credential Validation for MLS/MIMI

Nov 2, 2026 · Mark Atwood

## Problem

In a cross-provider MIMI room, any single provider's Authentication Service (AS) can add a device that every other member's client will accept. MLS (RFC 9420) treats a credential as an opaque blob and leaves validation to the AS. MIMI federates many providers into one MLS group, so the room is only as trustworthy as its weakest AS.

The concrete attack: a provider, compelled or compromised, issues a credential binding an attacker's key to a real user's identity. The attacker's leaf joins the group, receives epoch secrets, and reads all content. This is the "ghost user" proposal implemented through federation. MLS's forward secrecy and post-compromise security do not help, because the ghost is a legitimate member by protocol rules.

DMA Article 7 requires designated gatekeepers to interoperate with other providers on request, so regulation widens this exposure.

## Why existing work doesn't close it

The attack is known: [RFC 9750 §8.4.3.1](https://www.rfc-editor.org/rfc/rfc9750) describes it, and [draft-mahy-mimi-identity-05](https://www.ietf.org/archive/id/draft-mahy-mimi-identity-05.txt) notes that federation makes it worse. Every current option either detects a ghost device after it has joined or bottoms out in one issuer the user cannot audit.

| Work | What it provides | Remaining gap |
| --- | --- | --- |
| [RFC 9750 §8.4.3.1](https://www.rfc-editor.org/rfc/rfc9750) (MLS Architecture) | Names the ghost-device attack; recommends key transparency, out-of-band comparison of `authentication_secret`, and showing every membership change | All three detect a ghost device after it has received epoch secrets; none prevents it |
| [draft-mahy-mimi-identity-05](https://www.ietf.org/archive/id/draft-mahy-mimi-identity-05.txt) (individual, Informational, July 2026) | States users "blindly trust their instant messaging service" and that federation exacerbates it; surveys certificate hierarchies, web of trust, cross-signing, VCs | Explores the problem space; defines no mechanism; does not consider did:webvh |
| X.509 credentials (RFC 9420) | CA-signed binding of key to identity | The CA is the provider or its delegate; same single point of trust |
| [draft-mahy-mls-sd-cwt-credential-02](https://www.ietf.org/archive/id/draft-mahy-mls-sd-cwt-credential-02.html) | SD-JWT / SD-CWT credentials, selective disclosure, suggested code points 0x0005 and 0x0006 | Issuer is still a single authority; subject is a key thumbprint or `mimi:` URI, not a user-controlled identifier |
| [draft-barnes-mls-addl-creds-00](https://www.ietf.org/archive/id/draft-barnes-mls-addl-creds-00.html) (expired January 2024) | VC credential whose subject must be a DID | Restricted to `did:jwk`: no resolution, no key history, no device authorization |
| IETF KEYTRANS | Auditable log of identity-to-key bindings | Not required by MIMI; each provider may run its own log or none |
| MIMI protocol and room policy | Hub ordering, room state bound into GroupContext | Delegates identity entirely to providers; discovery requirements draft expired |

No current work defines a credential whose device authorization is controlled by the user and verifiable by any client, independent of which provider hosts the user.

## Requirements

A solution is an MLS credential type that meets all five:

1. **User-controlled device authorization.** Adding a device requires a signature from a key the user controls, not one the provider holds.
2. **Verifiable history.** The identifier's key and device set evolve through an append-only, verifiable log (for example `did:webvh` or KERI), so a silent device insertion is detectable after the fact.
3. **Deterministic validation.** Every client reaches the same accept or reject decision from the same inputs. MLS assumes uniform credential validation; divergence forks membership views.
4. **Offline-verifiable at join time.** Validation must not require a live lookup that reveals who is checking whom to a resolver.
5. **Negotiable through existing MLS machinery.** Advertised via leaf `capabilities`, mandatable per room via `required_capabilities`.

The solution need not build on the SD-JWT / SD-CWT credential draft: a token needs an issuer, and the issuer is the single authority this work removes. The did:webvh log certifies itself.

## Candidate: did:webvh v1.0

[did:webvh v1.0](https://identity.foundation/didwebvh/v1.0/) (renamed from did:tdw at v0.5) meets requirements 1, 2 and 4 if the log is carried inside the credential. [draft-atwood-mls-didwebvh-credential-00](https://gist.github.com/MarkAtwood/871f8594d07c891948b47c7d74fbd0c6) adopts it and closes the remaining gaps with group rules; the last column shows how.

| Requirement | What did:webvh v1.0 provides | Gap | How the draft handles it |
| --- | --- | --- | --- |
| 1. User-controlled authorization | Every `did.jsonl` entry needs an `eddsa-jcs-2022` proof from a key in `updateKeys`; a host without those keys cannot write a valid entry | Only holds if the user, not the provider, holds `updateKeys` | Cannot be enforced by protocol. Update keys SHOULD stay off the provider; provider custody reduces to today's AS, and members cannot detect it |
| 2. Verifiable history | Entries are hash-chained via `versionId`; the DID embeds a SCID hashed from the first entry; `nextKeyHashes` enables pre-rotation | Spec lists "truncation or withholding of log entries" as a known attack on resolvers | No resolver: logs travel in leaves. The `did_webvh_heads` GroupContext extension records the highest head per SCID and never moves backwards |
| 3. Deterministic validation | Verification of a given log is deterministic | Clients holding different log versions disagree; the spec checks `versionTime` against the resolver's clock | Validation depends only on credential bytes, the ratchet tree and GroupContext. No clock check, did:webvh 1.0 and Ed25519 only, fixed 1 MiB log cap |
| 4. Offline at join | Spec allows logs from "sources other than its corresponding HTTPS location" with the same verification steps | Log grows with every device change | The full log travels in every leaf. No compaction; the size cap bounds the cost |
| 5. MLS negotiation | Not applicable to the DID method | Needs code points | New credential type `did_webvh` and GroupContext extension `did_webvh_heads`, suggested values 0x0008 and 0x0013 |

did:webvh defines no freshness mechanism. The draft makes freshness a property of the group instead: a Commit that brings in a newer log must remove every leaf that log no longer authorizes, and the recorded head keeps those keys out after the committing device leaves. What stays exposed is a group that never saw the revocation, including one to which a provider delivers a revoked device's old KeyPackages. Closing that needs key transparency.

## Non-goals

- **Trust-graph scoring as membership policy.** Reputation or web-of-trust scores are local and subjective. They may drive UI warnings, never group admission.
- **Discovery.** Mapping a phone number or handle to an identifier stays out of scope.
- **Replacing KEYTRANS.** The draft prevents provider-issued devices. Key transparency remains the answer for groups that never see a revocation and for auditing first contact.
- **Message ordering or hub trust.** Hub censorship and metadata exposure are separate problems.

## Decided in the draft

- **DID method:** did:webvh 1.0 only, Ed25519 only. KERI and other signature schemes would need new documents, because each additional method is another rule set every member must apply identically.
- **History offline:** the full log travels in the credential, capped at 1,048,576 bytes, with no compaction.
- **Freshness:** the group records the highest head per SCID in a GroupContext extension; revocation propagates through the Commit that carries the newer log.
- **Recovery (partly):** pre-rotation with an offline recovery key among the committed `nextKeyHashes`.

## Still open

- Who holds `updateKeys` in a consumer deployment? If the provider does, the credential adds nothing over today's AS, and members cannot tell.
- Will gatekeeper providers implement a credential type MIMI does not mandate? Without a MIMI requirement, rooms with mixed clients fall back to provider credentials.
- Concurrent updates fork the log. If different groups record different branches, the user must be removed from one and re-added. The draft says to use a single writer or witnesses; is that enough?
- Is there prior academic work on DID-anchored CGKA credentials that this search missed?

## Sources

- [draft-mahy-mls-sd-cwt-credential (datatracker)](https://datatracker.ietf.org/doc/draft-mahy-mls-sd-cwt-credential/)
- [draft-barnes-mls-addl-creds-00](https://www.ietf.org/archive/id/draft-barnes-mls-addl-creds-00.html)
- [IETF 125 slides: MLS web token credentials](https://datatracker.ietf.org/meeting/125/materials/slides-125-mls-web-token-credentials-and-others-00)
- [MLS working group](https://datatracker.ietf.org/wg/mls/)
- [did:webvh v1.0 specification](https://identity.foundation/didwebvh/v1.0/) (DIF)
- [RFC 9750, MLS Architecture, §8.4.3.1](https://www.rfc-editor.org/rfc/rfc9750)
- [draft-mahy-mimi-identity-05](https://www.ietf.org/archive/id/draft-mahy-mimi-identity-05.txt)
- [draft-atwood-mls-didwebvh-credential-00 (gist, not yet submitted)](https://gist.github.com/MarkAtwood/871f8594d07c891948b47c7d74fbd0c6)
- [Source repository for the draft](https://github.com/MarkAtwood/mls-didwebvh-credential) (kramdown-rfc source and built XML)
- RFC 9420 (MLS): cited from the original analysis, not re-checked here.
- [draft-ietf-mimi-protocol-07](https://datatracker.ietf.org/doc/draft-ietf-mimi-protocol/) (current revision per the datatracker as of 2026-11-04)
