# Proposed text: threat model for draft-ietf-mimi-protocol

Target: draft-ietf-mimi-protocol-07, Section 9 (Security Considerations),
which currently opens with "*TODO*: Add MIMI threat model, and great
expand this section."

This text states the trust assumption the current Section 9 leaves
implicit. Every provider acts as the MLS Authentication Service (AS) for
its own users, so a room's end-to-end confidentiality holds only if every
provider with a participant in the room is honest. The flow in Section
3.6 shows how a single provider can add a client to every room its users
are in without any other member acting.

The text records the risk without choosing a mitigation, so the WG can
decide in writing whether to require one or accept the risk.

Three changes:

1. Insert Section 9.1 "Threat Model" below, before the current
   "Franking" subsection (renumbering that subsection 9.2).
2. Qualify one sentence in the existing Section 9 text (see the end of
   this file).
3. Add the informative references listed at the end.

The text uses kramdown-rfc syntax, which -07 is generated with
(kramdown-rfc 1.7.43, per its published XML).

---

## Threat Model {#threat-model}

### Actors

Client:
: Software acting for one user on one device. Each client is one leaf in
  a room's MLS group.

User's provider:
: The provider that serves a user. It stores the user's KeyPackages and
  answers `/keyMaterial` requests for them ({{fetch-key-material}}). It
  issues or vouches for the credentials of its users' clients, and so
  acts as the MLS Authentication Service (AS) for those users
  ({{Section 5.3.1 of RFC9420}}).

Hub provider:
: The provider that hosts the room. It orders handshake messages,
  enforces the room's policy, serves the room's GroupInfo for external
  joins ({{claim-group-key-information}}), and fans messages out to
  follower providers.

Follower provider:
: Any other provider with a participant in the room.

Network attacker:
: An attacker who can observe and modify traffic between any of the
  above.

### What the Protocol Protects Against

Mutually authenticated TLS protects every protocol exchange between
providers against network attackers.

MLS protects the content of a room against the hub provider and every
follower provider, provided that every provider's AS function is honest
(see below). Servers can read room state changes, which are sent as
PublicMessage, but cannot read application messages and cannot forge
room state changes.

The hub provider is trusted to enforce the room's policy correctly, and
can delay, drop or reorder the messages it sequences.

### Trust in Each Provider's Authentication Service

Members of a room accept a client as belonging to a user because that
user's provider says it does. MLS gives no other member a way to check
this unless the credential type or an additional mechanism provides one.
This document does not currently say which credential types are
required or allowed ({{end-to-end-security-layer}}), so the trust
assumption is the one {{Section 8.4.3.1 of RFC9750}} describes: a
compromised AS "could validate a signature key pair (or generate a new
one) for an attacker", who could then "join a group as if it were
another of the user's clients".

In MIMI, a provider can do this to its own users without any
participation from the hub or from other members:

1. The provider generates a signature key pair and a credential binding
   it to one of its users, for example Cathy.
2. It requests the room's GroupInfo from the hub, presenting that
   credential ({{claim-group-key-information}}). Cathy is already in the
   participant list, so the room's policy allows a new client of hers to
   join.
3. It sends an External Commit adding the new client, exactly as in
   {{cathy-adds-a-new-device}}.

The participant list does not change, and no existing member has to
approve the change. The new client receives every subsequent epoch
secret and can read every later message in the room, including
messages sent by users of other providers. To other members it looks
the same as Cathy adding a device.

The same provider can also return KeyPackages it generated when another
user fetches Cathy's key material ({{fetch-key-material}}). The
attacker's client is then added at the moment Cathy is added to a new
room.

Consequences:

* A room's confidentiality is only as strong as the least trustworthy
  provider of any of its participants. Users of one provider depend on
  the honesty of every other provider in the room.
* The capability applies in every room that contains a user of the
  provider in question. One compromised or legally compelled provider
  can apply it to all of those rooms at once, without the cryptography
  showing any change.

{{RFC7258}} describes pervasive monitoring as "a technical attack that
should be mitigated in the design of IETF protocols, where possible".
{{RFC2804}} records that "the IETF has decided not to consider
requirements for wiretapping as part of the process for creating and
maintaining IETF standards." No MIMI document states such a
requirement, but the behavior above provides an equivalent capability
to any party that can compel a provider.

### Available Mitigations

None of the following is required by this document:

* Key transparency {{I-D.ietf-keytrans-protocol}}, which lets clients
  detect credentials issued without the user's knowledge, after the
  client has joined.
* Out-of-band comparison of the MLS `authentication_secret`, as
  {{Section 8.4.3.1 of RFC9750}} recommends.
* User interfaces that announce every new client of every participant.
* Credential types in which the user, not the provider, authorizes each
  of the user's clients, so that a provider cannot produce a valid
  credential for a client the user did not approve.

The first three detect the attack after the new client has received
epoch secrets; only the fourth prevents it.

---

## Change to the existing Section 9 text

Current:

> The usage of MLS ensures that the servers facilitating the exchange
> cannot read messages in the room or falsify room state changes, even
> though they can read the room state change messages.

Proposed:

> The usage of MLS ensures that the servers facilitating the exchange
> cannot read messages in the room or falsify room state changes, even
> though they can read the room state change messages, provided that no
> provider issues credentials for clients its users did not authorize
> ({{threat-model}}).

---

## References to add (informative)

```yaml
informative:
  RFC2804:
  RFC7258:
  RFC9750:
  I-D.ietf-keytrans-protocol:
```

RFC 9420 is assumed to be already present as a normative reference. The
section anchors used above (`fetch-key-material`,
`claim-group-key-information`, `cathy-adds-a-new-device`,
`end-to-end-security-layer`) match the anchors of Sections 5.2, 5.6,
3.6 and 4.2 in the published -07 XML.
