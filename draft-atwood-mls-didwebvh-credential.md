---
title: "User-Controlled Device Authorization for MLS using did:webvh Credentials"
abbrev: "MLS did:webvh Credential"
category: std
docname: draft-atwood-mls-didwebvh-credential-00
submissiontype: IETF
number:
date:
v: 3
ipr: trust200902
area: "Security"
workgroup: "Messaging Layer Security"
venue:
  group: "Messaging Layer Security"
  type: "Working Group"
  mail: "mls@ietf.org"
  arch: "https://mailarchive.ietf.org/arch/browse/mls/"
  github: "MarkAtwood/mls-didwebvh-credential"
keyword:
 - MLS
 - MIMI
 - credential
 - DID
 - did:webvh

author:
 -
    fullname: Mark Atwood
    email: mark@reviewcommit.com

normative:
  RFC9420:
  RFC8032:
  RFC7493:
  DIDWEBVH:
    title: "The did:webvh DID Method v1.0"
    target: https://identity.foundation/didwebvh/v1.0/
    author:
      org: Decentralized Identity Foundation
    date: 2026-09-23
    refcontent: "spec-v1.0 source at commit 91f3cba, https://github.com/decentralized-identity/didwebvh"
  W3C-CID:
    title: "Controlled Identifiers v1.0"
    target: https://www.w3.org/TR/2025/REC-cid-1.0-20250515/
    author:
      org: W3C
    date: 2025-05-15
  DID-CORE:
    title: "Decentralized Identifiers (DIDs) v1.0"
    target: https://www.w3.org/TR/2022/REC-did-core-20220719/
    author:
      org: W3C
    date: 2022-07-19

informative:
  RFC7258:
  RFC9750:
  I-D.mahy-mimi-identity:
  I-D.ietf-mimi-protocol:
  I-D.ietf-keytrans-protocol:
  I-D.mahy-mls-sd-cwt-credential:
  I-D.barnes-mls-addl-creds:
  I-D.ietf-mls-extensions:
  GHOST:
    title: "Principles for a More Informed Exceptional Access Debate"
    author:
      - name: Ian Levy
      - name: Crispin Robinson
    date: 2018-11-29
    refcontent: Lawfare
    target: https://www.lawfaremedia.org/article/principles-more-informed-exceptional-access-debate
  DMA:
    title: "Regulation (EU) 2022/1925 of the European Parliament and of the Council on contestable and fair markets in the digital sector (Digital Markets Act)"
    author:
      org: European Union
    date: 2022-09-14
    refcontent: "OJ L 265, 12.10.2022"
    target: https://eur-lex.europa.eu/eli/reg/2022/1925/oj

--- abstract

In Messaging Layer Security (MLS), whoever operates the Authentication
Service (AS) decides which devices belong to a user. When providers
federate MLS groups, as the More Instant Messaging Interoperability
(MIMI) work does, every member of a group must accept devices vouched for
by every other member's provider. Any one provider can therefore add a
device under one of its users' names to any group that user is in.
Other members cannot prevent this; at best they detect it after the
device has joined.

This document defines an MLS credential type in which the user, not the
provider, authorizes each device. The credential carries the user's
did:webvh log: a hash-chained, signed history of the user's device keys
that any member can verify offline. It also defines group rules that make
every member reach the same validity decision and that propagate device
revocation through ordinary Commits.

--- middle

# Introduction

## Why This Document Exists {#motivation}

MLS {{RFC9420}} delegates identity to an Authentication Service.
{{Section 5.3.1 of RFC9420}} says a credential is valid when "the AS
verifies that the credential's presented identifiers are correctly
associated with the signature_key field in the member's LeafNode". The
two credential types RFC 9420 defines both put that decision in the
hands of a single authority: a "basic" credential is a bare assertion,
and an "x509" credential is valid if a trusted certificate authority
signed it.

Within one provider, this is the provider's own risk; federation extends
it to every member of a shared group. In MIMI {{I-D.ietf-mimi-protocol}}, users of several providers share
one MLS group, and each provider acts as the AS for its own users. A
member on provider B accepts Alice's devices because provider A says
they are Alice's. If provider A is compromised or compelled, it can issue
a credential binding an attacker's signature key to Alice's identity. The
attacker's client joins as one of Alice's devices, receives every epoch
secret, and reads all content. {{Section 8.4.3.1 of RFC9750}} calls
this a "ghost user". The same technique has been proposed as an
exceptional-access mechanism {{GHOST}}; federation removes the need for
the cooperation of the service the target chose.

The attack is already known. {{Section 8.4.3.1 of RFC9750}} describes
it: a compromised AS "could validate a signature key pair (or generate a
new one) for an attacker", who could then "join a group as if it were
another of the user's clients", and "these attacks could be very
difficult to detect". {{I-D.mahy-mimi-identity}} observes that users
must "blindly trust their instant messaging service not to add and
remove participants" and that "this problem is exacerbated when these
systems federate or try to interoperate." This document proposes a way to
prevent it.

MLS's forward secrecy and post-compromise security do not help: the
ghost is a member by the protocol's own rules.

Interoperability obligations are likely to increase the number of groups
that span providers. Article 7 of the Digital Markets Act {{DMA}}, for
example, requires designated gatekeepers to interoperate with other
providers on request.

The mitigations {{Section 8.4.3.1 of RFC9750}} recommends detect the
attack rather than prevent it:

* Key transparency "would allow for detection of surreptitiously
  created false credentials". It needs every client to audit every
  contact's keys, and MIMI does not require it.
* Out-of-band comparison of the per-epoch `authentication_secret`
  depends on users comparing values for every member, which few do in
  large groups.
* Showing every membership change to users depends on users noticing an
  extra device among many.

In each case the ghost device has already received epoch secrets by the
time anyone could notice. Proposals for credentials also keep a single
authority:

* X.509 credentials move the authority to a certificate authority, which
  is chosen or operated by the provider or the user's organization, not
  by the user.
* SD-JWT and SD-CWT credentials {{I-D.mahy-mls-sd-cwt-credential}} add
  selective disclosure but still rely on one issuer's signature.
* An earlier draft {{I-D.barnes-mls-addl-creds}} used Decentralized
  Identifiers (DIDs) {{DID-CORE}}, but only the
  did:jwk method, which has no history and no way to authorize devices.
* {{I-D.mahy-mimi-identity}} surveys certificate hierarchies, webs of
  trust, cross-signing and Verifiable Credentials for MIMI, but does not
  define a mechanism.
* The key transparency protocol {{I-D.ietf-keytrans-protocol}} makes
  bindings auditable, but, as above, detects a ghost device after it has
  joined.

## What This Document Fixes

This document takes the decision about which devices belong to a user
away from the provider and gives it to keys the user controls. A
provider that holds no update key cannot authorize a device.

| Question | RFC 9420 with MIMI today | With this credential |
|---|---|---|
| Who can add a device to Alice's identity? | Alice's provider's AS, or anyone who compromises or compels it | Only a holder of one of Alice's did:webvh update keys |
| How does another member verify Alice's device? | Trusts the AS signature | Verifies Alice's signed, hash-chained log, offline |
| Can a provider add a device without Alice's keys? | Yes. Other members can detect it only after the device has joined | It cannot authorize a new key. It can still replay a revoked device's old KeyPackages to a group that has not seen the revocation ({{stale-log}}) |
| How is a revoked device removed from a group? | Application policy; no protocol rule | The Commit that carries Alice's newer log MUST remove it |
| Can two members disagree about a credential's validity? | Yes, if their AS policies differ | No: credential validity depends only on the credential and the group's state ({{deterministic-validation}}) |
| Does validation make network requests? | Possibly (AS, certificate status checks) | Never |
{: title="Trust model before and after"}

The provider keeps its roles as transport, KeyPackage directory and,
optionally, host of the user's did:webvh log. None of those roles lets
it change which devices are Alice's.

## What This Document Does Not Fix

* First contact. This document does not say how Bob learns which DID is
  Alice's. Once Bob has pinned it, substitution is detectable
  ({{first-contact}}). Discovery is out of scope.
* Custody. If the provider holds Alice's update keys, it can authorize
  devices and this credential adds nothing ({{custody}}).
* Metadata. The Delivery Service (DS) and the MIMI hub still see group membership and
  timing. This credential reveals more device history to them, not less
  ({{privacy}}).
* Ordering, censorship and hub trust. A hub can still delay or drop
  Commits, including Commits that remove a revoked device.

# Conventions and Definitions

{::boilerplate bcp14-tagged}

This document uses the terms from {{RFC9420}} and {{DIDWEBVH}}. In
addition:

DID controller:
: The user who holds the update keys of a did:webvh DID and whose devices
  its DID document lists.

Log:
: The did:webvh DID Log, the `did.jsonl` file defined in {{DIDWEBVH}}.

Version number:
: The integer before the dash in a log entry's `versionId`.

Head:
: The last entry of a log carried in a credential.

Prefix:
: Log A is a prefix of log B if B has at least as many entries as A and
  the `versionId` values of B's first entries equal those of A's entries,
  in order. Byte equality of the logs is not required.

Newest log:
: Of several logs, the one whose head has the highest version number.

SCID:
: The self-certifying identifier of a did:webvh DID: the value of the
  `scid` parameter of the log's first entry. It does not change when the
  DID moves to a different host.

Recorded head of S:
: For an SCID S, the entry for S in the group's `did_webvh_heads`
  GroupContext extension ({{heads-extension}}): the highest log version
  the group has accepted for S, and the keys that version authorizes.

Authorized key:
: An Ed25519 public key given by a verification method in a DID document
  that meets all of the following: its `type` is `Multikey` and its
  `controller` is the document's `id`; its `publicKeyMultibase` begins
  with `z` and base58btc-decodes to exactly 34 bytes, the prefix 0xed
  0x01 followed by a 32-byte public key in the format of {{RFC8032}};
  and it is in the document's `authentication` verification
  relationship, either embedded there or referenced by identifier
  ({{DID-CORE}}, {{W3C-CID}}). A relative reference is resolved against
  the document's `id` as {{DID-CORE}} specifies. A reference that does
  not resolve to a verification method in the same document, and a
  verification method that fails any of these conditions, authorizes no
  key; neither makes the document invalid.

# Overview

The user's DID document is the list of the user's devices. Each device
has its own MLS signature key, and each such key is listed in the DID
document as an authorized key. Adding a device means appending a log
entry that lists its key. That entry must be signed by an update key. So
the provider cannot add a device unless it holds an update key.

This document uses did:webvh only as a specified format for a
self-certifying, signed, hash-chained key log. It uses no DID
resolution, DID URL dereferencing, Verifiable Credentials or resolver
infrastructure.

Each device's LeafNode carries a credential containing the user's whole
log, up to a head that authorizes that device's key. Members verify the
log with no network access. Members do not consult the published log
location, a resolver, witnesses or watchers during validation.

Revocation works through the group itself. When Alice revokes a device,
one of her remaining devices appends an entry that drops the revoked
key, then sends a Commit whose UpdatePath carries the new log. The group
records the newest head it has accepted for each SCID in a GroupContext
extension, and that record never moves backwards. The rules in
{{group-rules}} require the Commit that raises the record to remove
every leaf whose key the new head no longer authorizes. Every member
checks the same rules against the same tree and GroupContext, so they
all accept or reject the Commit alike.

# The did:webvh Credential {#credential}

This document adds a new credential type, `did_webvh`, to the
`Credential` structure from {{Section 5.3 of RFC9420}}:

~~~ tls-presentation
struct {
    opaque did_log<V>;
    opaque witness_file<V>;
} DIDWebVHCredential;

struct {
    CredentialType credential_type;
    select (Credential.credential_type) {
        case basic:
            opaque identity<V>;
        case x509:
            Certificate certificates<V>;
        case did_webvh:
            DIDWebVHCredential did_webvh;
    };
} Credential;
~~~

`did_log`:
: The DID Log in the `did.jsonl` format of {{DIDWEBVH}}, from the first
  entry through the head, with no entries omitted and none after the
  head. It MUST NOT be longer than 1,048,576 bytes.

`witness_file`:
: The `did-witness.json` content defined in {{DIDWEBVH}}, holding the
  witness proofs for the carried entries. It MUST be empty if no carried
  entry has active witnesses, and MUST NOT be longer than 1,048,576
  bytes.

The size limits are fixed so that every member applies the same limit.
A limit that differed between implementations would let one member
accept a credential that another rejects.

This document supports only cipher suites whose signature scheme is
Ed25519, such as MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519 (0x0001)
and MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519 (0x0003). A
`did_webvh` credential in a group using any other cipher suite MUST be
rejected.

# Validation {#validation}

A `did_webvh` credential MUST be validated at each event listed in
{{Section 5.3.1 of RFC9420}}. Validation has three parts: verifying the
log ({{log-verification}}), binding the log to the LeafNode
({{leaf-binding}}), and checking it against the rest of the group
({{group-rules}}). A credential that fails any check MUST be rejected,
together with the message or object that introduced it.

## Log Verification {#log-verification}

The verifier MUST verify `did_log` and `witness_file` with the Read
(Resolve) verification steps of {{DIDWEBVH}}, with these changes:

1. The verifier treats `did_log` as the complete published log and
   `witness_file` as the complete witness file. It MUST NOT fetch either
   from the network, and MUST NOT consult watchers or resolver caches.
   The DID being resolved is the `id` of the head's DID document.
2. The `method` parameter of the first entry MUST be `did:webvh:1.0`,
   and no later entry may set `method` to any other value. A log that
   does MUST be rejected, so that every member applies one set of rules.
3. The verifier MUST NOT compare `versionTime` with its own clock. All
   other `versionTime` checks still apply, including that values strictly
   increase. The `ttl` parameter has no effect on validation.
4. Witness proofs MUST be verified as {{DIDWEBVH}} specifies for every
   entry that has active witnesses. Proofs in `witness_file` for
   versionIds not in `did_log` are ignored.
5. After every entry has been processed, the active value of the
   `deactivated` parameter MUST be false, and no entry may follow an
   entry that sets it to true.
6. Every carried entry MUST verify. The option {{DIDWEBVH}} gives
   resolvers to treat a log as valid up to its first invalid entry is
   not used.
7. The verifier MUST apply the profile in {{webvh-profile}}.

Change 3 is needed because {{DIDWEBVH}} rejects entries more than a
tolerance into the future relative to "the resolver's current time".
Clocks differ between members, so applying that check would let members
disagree about validity. Strict ordering of `versionTime` values does
not depend on the clock and is kept.

## did:webvh Profile {#webvh-profile}

{{DIDWEBVH}} leaves some choices to implementations. Members that chose
differently could disagree about a credential's validity, so this
document fixes them:

Encoding:
: `did_log` MUST be UTF-8 JSON Lines: one JSON object per line, each
  line ending in a single LF (0x0A), with no blank lines and nothing
  after the last LF. Each log entry, and `witness_file`, MUST be I-JSON
  {{RFC7493}}; in particular, an object with duplicate member names is
  rejected. `versionTime` values MUST have the form
  `YYYY-MM-DDTHH:MM:SSZ`. The version number MUST NOT have leading zeros.

Parameters:
: A parameter whose value is `null` MUST be rejected, although
  {{DIDWEBVH}} lets resolvers accept it.

Proofs:
: The `proof` member of each entry MUST be an array containing exactly
  one proof. The `created` and `expires` properties of log and witness
  proofs are not compared with any clock.

Witnesses:
: A witness proof that fails verification is ignored. An entry's witness
  requirement is met only if valid proofs from at least the threshold
  number of distinct witnesses cover it.

Portability:
: The portability rules of {{DIDWEBVH}}, including that `portable` can
  only be set in the first entry and that a moved DID lists its previous
  DID in `alsoKnownAs`, MUST be checked for every entry.

Domain:
: The DID string MUST match the method-specific identifier syntax of
  {{DIDWEBVH}} using only ASCII letters, digits, hyphens and dots. No
  internationalized domain name processing is performed.

## Binding to the LeafNode {#leaf-binding}

The `signature_key` of the LeafNode containing the credential MUST equal
the 32-byte public key of an authorized key in the head's DID document.

The SCID of the log is the credential's identity. The DID string can
change if the controller moves the DID, but the SCID cannot.

A `did_webvh` credential MUST NOT appear in the `external_senders`
GroupContext extension. A GroupContextExtensions proposal that would
put one there MUST be rejected.

## The Heads Extension {#heads-extension}

A client that lists `did_webvh` in the `credentials` field of its
LeafNode `capabilities` MUST list `did_webvh_heads` in the `extensions`
field and MUST implement the rules in {{group-rules}}. A GroupContext
that contains `did_webvh_heads` MUST also contain a
`required_capabilities` extension that lists `did_webvh_heads` in
`extension_types` and `did_webvh` in `credential_types`
({{Section 11.1 of RFC9420}}), so that every member enforces the rules.
A group whose tree contains a `did_webvh` credential MUST carry the
`did_webvh_heads` GroupContext extension, and a group that carries it
MUST NOT remove it:

~~~ tls-presentation
struct {
    opaque scid<V>;
    opaque version_id<V>;
    SignaturePublicKey authorized_keys<V>;
} DIDWebVHHead;

struct {
    DIDWebVHHead heads<V>;
} DIDWebVHHeads;
~~~

`scid`:
: The SCID, as the ASCII value of the first entry's `scid` parameter.

`version_id`:
: The `versionId` of the recorded head.

`authorized_keys`:
: The 32-byte public keys of every authorized key in the recorded head's
  DID document, each as a `SignaturePublicKey`, sorted in ascending
  lexicographic order of the key bytes (not of their encoding), with no
  duplicates.

`heads` MUST contain an entry for each SCID that appears in a leaf of
the ratchet tree. It also keeps the entry for every SCID the group has
recorded before, even when no leaf with that SCID remains: an entry is
never removed. At most one entry has a given `scid`. Entries are sorted
in ascending lexicographic byte order of `scid`, a shorter value that is
a prefix of a longer one sorting first.

The extension lets the group remember a revocation after every leaf
that carried the revoking log has left, and after every device of that
user has left. Without it, the newest log the group knew about could
leave with the last device that carried it, and an older log would make
a revoked key valid again. Because the extension
is part of the GroupContext, a new member receives it in the Welcome,
and it feeds the key schedule.

## Group Consistency Rules {#group-rules}

### When the Rules Apply

When a member receives a KeyPackage, an Add proposal or an Update
proposal, it verifies the log ({{log-verification}}) and the binding to
the LeafNode ({{leaf-binding}}) only. The group rules depend on every
proposal in a Commit, so they are checked once per Commit, against the
ratchet tree and GroupContext that result from applying all of the
Commit's proposals and its UpdatePath. A member joining through a
Welcome or an external Commit checks them against the tree and
GroupContext it receives.

### Expected Heads

For each SCID S that appears in a leaf of the resulting tree, let R be
the reference entry for S: the entry for S in the previous epoch's
`did_webvh_heads`, if any. Let L be the newest log among the resulting
tree's credentials with SCID S. The expected entry for S is computed as
follows:

* If R exists and L's head version number is not greater than R's, the
  expected entry is R.
* If R exists and L's head version number is greater than R's, L MUST
  contain an entry whose `versionId` is R's `version_id`; a Commit for
  which it does not MUST be rejected. The expected entry has L's head
  `versionId` and the authorized keys of L's head DID document.
* If R does not exist, the expected entry has L's head `versionId` and
  the authorized keys of L's head DID document.

For each SCID S that has an entry in the previous epoch's
`did_webvh_heads` but appears in no leaf of the resulting tree, the
expected entry is that previous entry, unchanged.

The `did_webvh_heads` extension in the resulting GroupContext MUST
contain exactly the expected entries. A Commit that changes the expected
value MUST therefore include a GroupContextExtensions proposal that sets
it. A Commit that only removes leaves never changes the expected value.

### Rules

The following MUST hold for the resulting tree and GroupContext. A
Commit, Welcome or GroupInfo for which any of them fails MUST be
rejected.

Extension matches:
: `did_webvh_heads` contains exactly the expected entries.

Consistency with the reference entry:
: Every credential with SCID S whose head version number is at least R's
  contains an entry whose `versionId` is R's `version_id`. Every
  credential with SCID S whose head is newer than R's is a prefix of L.

Authorization:
: Every leaf with SCID S has a `signature_key` in the `authorized_keys`
  of the recorded head of S.

A Commit that raises the recorded head of S to a version that no longer
authorizes some of S's leaves therefore has to remove those leaves in
the same Commit. Some consequences follow from {{RFC9420}} without
further rules:

* A committer whose own key the new head does not authorize cannot send
  that Commit, because a Commit cannot remove its committer
  ({{Section 12.2 of RFC9420}}). Another member has to commit it, for
  example by committing an Update proposal, sent by one of the user's
  other devices, that carries the new log.
* An external Commit cannot carry a GroupContextExtensions proposal, so
  it is valid only if it leaves `did_webvh_heads` unchanged. A device
  can rejoin by external Commit only if its key is already authorized by
  the recorded head and its log is not newer than the recorded head. A
  client whose SCID has no entry in `did_webvh_heads`, which includes
  every new user, cannot join by external Commit and has to be added by
  an existing member ({{open-issues}}).

A member joining by Welcome has no previous epoch, so it cannot compute
the expected entries. It instead checks that `did_webvh_heads` has an
entry for each SCID in the tree, in sorted order with no duplicates, and
the consistency and authorization rules, taking R for each SCID from the
GroupContext it receives. It also checks that no leaf's head version
number is greater than the recorded version for its SCID. For each
recorded head that some leaf's log contains as its head, it also checks
that `authorized_keys` matches that DID document. For an entry that no
leaf carries, including the entry of an SCID with no leaves, the joiner
relies on the GroupContext, which the existing members agreed on through
the key schedule.

### Successor Credentials

For the replacement check in {{Section 5.3.1 of RFC9420}}, a `did_webvh`
credential is a valid successor to an earlier `did_webvh` credential if
it has the same SCID and the earlier credential's log is a prefix of the
new one.

A leaf whose credential carries an older head than the recorded head
stays valid as long as its key is in the recorded `authorized_keys`.
Devices do not need to update their credentials each time another device
of the same user is added.

## Reference Identifiers

{{Section 5.3.1 of RFC9420}} has the application compare presented
identifiers with reference identifiers. For this credential, the
presented identifier is the SCID. Applications SHOULD pin the SCID for
each contact the first time it is learned, SHOULD compare it on every
later credential for that contact, and MUST alert the user if the SCID
for a contact changes. Applications SHOULD display the DID string from
the head, because the SCID alone means nothing to a person.

# Operation

## Adding a Device

1. The new device generates an MLS signature key pair.
2. A holder of a key authorized to sign the next entry {{DIDWEBVH}}
   appends a log entry whose DID
   document lists the new key as an authorized key. If witnesses are
   active, the holder collects the threshold of witness proofs.
3. The holder SHOULD publish the updated log and witness file at the
   location {{DIDWEBVH}} defines, so that new contacts can learn the DID.
   Group members do not need the published copy.
4. The new device publishes KeyPackages whose credential carries the
   updated log.

## Revoking a Device

1. A holder of a key authorized to sign the next entry appends an entry
   whose DID document no longer lists the revoked key.
2. For every group the user belongs to, one of the user's remaining
   devices sends a Commit whose UpdatePath LeafNode carries the new log,
   together with Remove proposals for the revoked device's leaves and a
   GroupContextExtensions proposal that updates `did_webvh_heads`. The
   rules in {{group-rules}} make the Remove mandatory.

The revocation reaches a group when one of the controller's own devices
commits to it, not when a resolver notices. {{stale-log}} covers the
case where none of the controller's devices is in the group.

## Custody of Update Keys {#custody}

This credential moves authority to whoever holds the `updateKeys`.
Update keys SHOULD be held only on the user's devices and in offline
recovery storage, and the provider SHOULD NOT hold them. A deployment in
which the provider holds update keys gives the provider the same power
the AS has today. A member cannot detect such a deployment from the
credential.

Controllers SHOULD enable pre-rotation by setting `nextKeyHashes`, and
SHOULD include among the committed hashes, in every entry, the hash of a
recovery key kept offline. Controllers SHOULD NOT commit the hash of a
key that has already been revealed.
Under pre-rotation, each entry must be signed by a key whose hash the
previous entry committed to, so an attacker needs one of those
committed next keys, not just a key that has already been used.
Controllers SHOULD NOT make every device an update key: any device that
holds one can add or revoke all the others. Keys listed in
`authentication` SHOULD be used only as MLS device keys, and update keys
SHOULD NOT appear in `authentication`, because every authorized key
there is accepted as a device.

Two update-key holders that append entries at the same time fork the
log, which {{DIDWEBVH}} names as a known risk. A group that has recorded
one branch rejects the other. The device whose entry lost can recover by
appending a new entry to the winning branch. If different groups have
recorded different branches, though, no later log can satisfy both
groups, and the user has to be removed from one of them and added back
once its record is gone. Controllers SHOULD therefore send every update
through a single writer, or use witnesses with a threshold greater than
half the number of witnesses. {{DIDWEBVH}} forbids a witness from
signing two children of the same parent entry, but two disjoint sets of
witnesses that each meet a lower threshold can approve different
children.

## Negotiation and Mandating the Credential

A client that supports this credential type lists `did_webvh` in the
`credentials` field of its LeafNode `capabilities`. A group, or a MIMI
room through its policy, can require this credential type for every
member by listing it in the `required_capabilities` GroupContext
extension and rejecting other credential types.

In a group that also admits `basic` or `x509` credentials, those leaves
keep the trust model of their AS, and the gap in {{motivation}}
remains for them. Applications SHOULD indicate to users which members
are authenticated by a `did_webvh` credential.

# Open Issues {#open-issues}

RFC Editor: please remove this section before publication.

The author would like the working group's view on these questions:

1. Extension or component. Carrying the record as a component of the
   `app_data_dictionary` extension {{I-D.ietf-mls-extensions}}, updated
   by AppDataUpdate proposals, would let an external Commit or an
   external sender update it. That would allow new users to join by
   external Commit, which this document does not, and would avoid a
   GroupContextExtensions proposal in every Commit that changes the
   record.
2. ReInit and branching. Neither carries the record into the new group,
   so a revocation known to the old group can be lost. A ReInit could be
   required to carry `did_webvh_heads` in its extensions.
3. Revocation without a controller's device. A newer log reaches a group
   only through a leaf that carries it. A proposal that carries a newer
   log as evidence would let any member raise the record, and would give
   a way to propagate deactivation.
4. Other signature schemes. Supporting cipher suites whose signature
   scheme is not Ed25519, such as 0x0002 with P-256, would admit
   deployments that need them.
5. Cost of GroupContextExtensions. Because a GroupContextExtensions
   proposal replaces the whole extension list and only one is allowed
   per Commit, a pending GroupContextExtensions proposal from another
   party cannot be combined with a change to the record.
6. Record growth. Entries are never removed, so the record grows with
   every user who has ever been a member. A way to retire entries
   without losing revocations, for example after the user's log has been
   deactivated, may be needed for long-lived groups.

# Security Considerations

## Provider-Issued Devices

A provider without an update key cannot produce a log entry that
authorizes a new key, because every entry needs an `eddsa-jcs-2022`
signature by an authorized update key {{DIDWEBVH}}. It also cannot present
an altered history, because entries are hash-chained and the SCID is
derived from the first entry. Whoever hosts the published log has no
more power than the provider: members never read the published log
during validation.

## Pervasive Monitoring

{{RFC7258}} states that "pervasive monitoring is a technical attack that
should be mitigated in the design of IETF protocols, where possible",
and calls for protocols that make it "significantly more expensive or
infeasible". Adding a ghost device targets one user, but the capability
exists in every room. A single compromised or compelled provider can use
it in every room that contains one of its users, without any change
visible in the MLS protocol. Federation adds every
other provider's users to the set of people exposed to that one
provider.

In groups that require the `did_webvh` credential, this document removes
that capability for existing identities: a provider cannot authorize a
new device under a user's SCID while the group holds that SCID's record.
A provider that wants to add a device to a user's identity needs one of
the user's update keys, and any entry it creates stays in a log that
every member of the group holds. This document does not stop a party
that can add members from adding a different identity, or from
substituting a DID at first contact ({{first-contact}}).

## Update Key Compromise

An attacker who can sign a valid next entry can add a device, or
revoke the user's honest devices and so get them removed from groups by
the rules in {{group-rules}}. With pre-rotation active, that requires
one of the keys committed in `nextKeyHashes`, not merely a key already
used. Either action leaves an entry in a log that every member of each
affected group holds. The user's own devices SHOULD alert the user when
a log entry appears that none of the user's devices created.

If the attacker branches from an entry older than a group's recorded
head, the group rejects the branch. If the attacker extends the current
head, the group accepts the extension, because it is indistinguishable
from an honest update. Detection then rests on the user's devices.

## Withheld or Stale Logs {#stale-log}

{{DIDWEBVH}} lists "truncation or withholding of log entries" as an
attack on resolvers: a host presents an older valid prefix of the log to
hide a revocation. This credential has no resolver, so the host has
nothing to withhold from. The newest log reaches a group when any of the
controller's devices sends a Commit.

Once a group has accepted a revoking log, the recorded head keeps the
revoked key out even after the device that committed it leaves, and
after every device of that user has left, because entries are never
removed.

The remaining exposure is a group that never saw the revocation. That
includes a group that contains a revoked device of the controller but
none of the controller's other devices, and any group to which the
provider, acting as KeyPackage directory, delivers one of the revoked
device's old KeyPackages. Nobody in such a group has the newer log, so
the revoked device stays until someone removes it. Clients SHOULD
remember the highest log version they have verified for
each SCID, across all groups, and SHOULD refuse to add a KeyPackage
whose log is older, which mirrors the cache-and-compare mitigation in
{{DIDWEBVH}}. This check is local, so it guides what a client proposes,
not what the group accepts. Applications SHOULD also let a controller's
device that is not in a group send the newer log to that group's
members, for example through the MIMI hub. Detecting revocations without
any device of the controller present needs an external freshness
mechanism such as key transparency {{I-D.ietf-keytrans-protocol}},
which is out of scope.

## First Contact {#first-contact}

The SCID protects a contact once it has been pinned. It does not protect
the first lookup, when an attacker who controls discovery can give Bob a
DID it created itself. Applications SHOULD offer out-of-band comparison
of the SCID, for example by QR code, as they do today for safety numbers.

## Delivery Service and Hub

A DS or MIMI hub cannot forge or alter a `did_webvh` credential. It can
delay or drop the Commit that carries a revocation, which extends the
window during which a revoked device remains a member. This credential
does not change the hub's ability to censor.

## Deterministic Validation {#deterministic-validation}

MLS assumes that all members agree on which credentials are valid. If
they disagree, they disagree about the membership of the group. This
document removes the inputs under its control that could differ between
members: network fetches, the verifier's clock, implementation-specific
size limits, the choices {{DIDWEBVH}} leaves open ({{webvh-profile}}),
and did:webvh versions other than 1.0. Credential validity is then a
function of the credential bytes, the ratchet tree and the previous
epoch's GroupContext. Two inputs remain outside this document: the
reference-identifier check of {{Section 5.3.1 of RFC9420}}, which is
application policy ({{reference-identifiers}}), and the RECOMMENDED
LeafNode `lifetime` check of {{Section 7.3 of RFC9420}}, which uses the
clock.

## Resource Use

A log grows by one entry for each device change. Each leaf carries the
whole log, so a user with many devices in a large group adds repeated
copies to the tree. Each leaf can carry up to 2 MiB (log and witness
file), so the ratchet tree in a Welcome or GroupInfo of a large group can
be very large, and a joiner validates every leaf's log, each entry with
its own signature verification. Implementations SHOULD verify a log
shared by several leaves once. The `did_webvh_heads` record grows by
one entry for each user who has ever been a member and is never
pruned. The 1,048,576-byte limits bound the cost
of a malicious log. This document defines no way to compact a log.

# Privacy Considerations {#privacy}

Every member of a group, and any DS or hub that can see LeafNodes,
learns the controller's whole device history: how many devices the
controller has had, when each was added and removed, the domain hosting
the DID, and any witnesses. So does anyone who can fetch the user's
KeyPackages from a directory. A basic or X.509 credential reveals much
less.

The SCID is a stable identifier across groups and providers, so it lets
those parties correlate a user's memberships. Users who need separate
identities in different contexts need separate DIDs.

Validation makes no network requests, so it does not tell the log host
or any resolver who is checking whom.

# IANA Considerations

RFC Editor: please replace "RFC XXXX" with the RFC number of this
document.

IANA is requested to add the following entry to the "MLS Credential
Types" registry defined in {{Section 17.5 of RFC9420}}:

| Value | Name | Recommended | Reference |
|---|---|---|---|
| TBD1 (suggested value 0x0008) | did_webvh | N | RFC XXXX |
{: title="New MLS credential type"}

IANA is also requested to add the following entry to the "MLS Extension
Types" registry defined in {{Section 17.3 of RFC9420}}:

| Value | Name | Message(s) | Recommended | Reference |
|---|---|---|---|---|
| TBD2 (suggested value 0x0013) | did_webvh_heads | GC | N | RFC XXXX |
{: title="New MLS extension type"}

--- back

# Design Rationale

Why not an SD-JWT or SD-CWT credential:
: A token needs an issuer, and an issuer is the single authority this
  document removes. The did:webvh log certifies itself.

Why not resolve the DID during validation:
: Resolution brings back the stale-log attack, tells the log host who is
  checking whom, and lets members who resolve at different times
  disagree.

Why the DID document lists device keys directly:
: A separate signed statement binding a device to the DID would be a
  second format to validate. Using the `authentication` relationship
  means a device is authorized exactly when the user's log says so.

Why only did:webvh 1.0 and Ed25519:
: Every additional method or version is another set of rules that all
  members must apply identically. Ed25519 matches the mandatory-to-implement
  MLS cipher suite and needs no conversion between key formats. Other
  methods and other signature schemes can be specified in future
  documents ({{open-issues}}).
