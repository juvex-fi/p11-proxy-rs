# The p11-proxy protocol, version 1

This document specifies what `libp11-proxy` and `p11-daemon` say to each
other. It is not compatible with the protocol of the C implementation; a C
peer is recognised at the first byte and refused with a clear error.

`crates/p11-wire` implements it and `crates/p11-wire/tests/vectors/` holds the
exact bytes of an example request and response for every call. If a test
there fails, the format changed: bump the version (below) instead of
regenerating.

## Transport

The protocol runs over a reliable byte stream that the transport has already
secured and authenticated:

| transport | security | identity of the client |
|---|---|---|
| `tcp://host:port` | TLS 1.3, certificates on both sides | subject common name, subject alternative names and the certificate's SHA-256 fingerprint |
| `psk://host:port` | TLS 1.2 with a pre-shared key (ECDHE-PSK/CHACHA20-POLY1305, DHE-PSK/AES-256-GCM, or PSK/AES-256-GCM) | the PSK identity |
| `unix:///path` | file permissions on the socket (mode 0660) | the peer's uid |
| `stdio` | whoever started the daemon | `stdio` |

There is no plaintext TCP. Identities are strings with a prefix that says how
the peer proved itself (`cert:cn=`, `cert:san:dns=`, `cert:sha256=`, `psk:`,
`unix:uid=`); the access policy is written against them.

## Encoding

Everything is big endian and fixed width. No native `long`, no padding.

| type | encoding |
|---|---|
| `u8`, `u16`, `u32`, `u64` | that many bytes |
| `bool` | one byte, 0 or 1; anything else is an error |
| byte string | `u32` length, bytes |
| array | `u32` count, elements |
| `Option<T>` | one presence byte (0 or 1), then the value if present |
| `[u8; N]` | exactly N bytes (the space-padded strings of the info structures) |

Every length and count is checked against a limit **before** memory is
reserved, and against the bytes left in the message, so a claimed size can
never exceed what was sent.

### Limits

| limit | value |
|---|---|
| frame payload | 16 MiB |
| byte string | 16 MiB |
| array of scalars or small records | 65 536 |
| attributes in one template | 4 096 |
| nesting depth of templates and parameter trees | 8 |
| nodes in one parameter tree | 16 384 |
| bytes held by one parameter tree | 4 MiB |
| text in the handshake | 256 |

A decoder that meets a larger value fails the message; the daemon then drops
the connection.

## Frames

```
u32 payload length | u8 kind | payload
```

| kind | value | payload |
|---|---|---|
| Hello | 1 | see below |
| HelloAck | 2 | see below |
| Request | 3 | `u32 request id`, `u16 call id`, the call's request body |
| Response | 4 | `u32 request id`, `u64 CK_RV`, `bool has_body`, the call's response body if `has_body` |
| Abort | 5 | `u16 reason`: 1 protocol error, 2 version, 3 unauthorized, 4 busy, 5 shutdown |
| VendorMechanisms | 6 | sent once, right after `HelloAck`, only if both sides asked for it (see "Handshake") |
| VendorFunctions | 7 | the same, after the `VendorMechanisms` frame if there is one |

A peer that sees the ASCII text `PRIV...` where a frame should start is talking
the old C protocol.

## Handshake and client contexts

The client sends `Hello`:

```
"P11P" | u16 min_version | u16 max_version | u64 features | bool join | [u8;16] token | text client
```

where text is a byte string of printable ASCII. The daemon answers `HelloAck`:

```
"P11P" | u16 version | u64 features | [u8;16] token | text server
```

The version is the highest both sides support; if there is none the daemon
sends `Abort(Version)`. Feature bits the receiver doesn't know are ignored.

Two features exist in version 1, bit 0, `VENDOR_MECHANISMS`, and bit 1, `VENDOR_FUNCTIONS` (below).

A client sets bit 0 in `Hello` to say it understands the list of vendor-defined mechanisms. A daemon
that has declared some (`[[vendor_mechanism]]` in its configuration) sets it in
`HelloAck` and sends a `VendorMechanisms` frame straight after the `HelloAck`,
before any request; a daemon without any, or a client that did not ask, sends no
frame. The payload:

```
u32 count | count x ( u64 mechanism id | u8 form | form's fields )
```

| form | value | fields | the parameter is |
|---|---|---|---|
| exact | 0 | `u32 length` | bytes without pointers of exactly `length` (0: none) |
| max | 1 | `u32 length` | bytes without pointers of at most `length` |
| handle | 2 | | one object handle (a `CK_ULONG`) |
| handles | 3 | `u32 length`, `u32 count`, `count` x `u32 offset` | bytes without pointers of exactly `length`, with object handles at these byte offsets |
| same as | 4 | `u64 mechanism id` | that of a mechanism the proxy carries by itself |
| struct | 5 | `bytes name` | the structure of that name, from the layouts that follow the entries |

After the entries come the layouts: `u32 count | count x layout`, at most 64, each
`bytes name | u32 size | u32 count | count x member`, at most 64 members, and a member is
`bytes name | u32 offset | u8 kind | u8 direction | bytes of | bytes by | u32 n`. The kinds are `ulong` 1, `handle` 2,
`bool` 3, `byte` 4, `bytes` 5 (a pointer, its length in the member `by`), `inline` 6 (`n` bytes), `ulong_ptr` 7,
`handle_ptr` 8, `struct` 9 (a pointer to the layout `of`), `embedded` 10 (the layout `of` inside), `array` 11
(a pointer to an array of `of`, the count in `by`), `attrs` 12 (a template, the count in `by`), `cstr` 13 and
`mech_ptr` 14, `mech` 15 (a `CK_MECHANISM` inside the structure) and `handle_array` 16 (a pointer to an array of
handles the module writes, the room in the `ulong_ptr` member `by`, which goes both ways and comes back holding
the number written); the direction is 0 in, 1 out (the module writes it and the caller gets it back), 2 both.
A client checks the layouts as the daemon does its configuration: members inside the structure, aligned, not
overlapping, every `of` and `by` resolving (a `by` is a `ulong`, `byte`, `bool` or `ulong_ptr` member of the same
structure), no structure containing itself.

`count` is at most 1024 and at most 64 offsets; a parameter is at most 4096 bytes. A client checks each entry
as the daemon does for its configuration (an id in the vendor range that the proxy does not carry itself,
offsets inside the parameter, increasing and at least 8 apart, a `same as` the proxy carries) and installs the
list for as long as the connection's daemon is the one it talks to; every connection of a client receives it,
and a daemon that sends none takes the list away. Handles in a parameter are translated as those of every other
call.

A **client context** is the daemon-side state of one client: its sessions and
the object handles it has seen. The first connection (`join = false`) creates
a context and receives its token. The client library keeps a small pool of
connections so calls run in parallel and a blocking `C_WaitForSlotEvent`
doesn't stall the others; every further connection presents the token with
`join = true` and shares the context. A join is accepted only from a
connection with the same identity as the one that created the context, and
only while the context exists (it ends when its last connection closes, at
which point the daemon closes the sessions it opened). A token the daemon
doesn't know is answered with `Abort(Protocol)`.

## Handles

Session and object handles on the wire are **virtual**: the daemon hands out
counters per context and maps them to the module's own. A client cannot name
another client's object, and an object handle it never received maps to a
value no object has, so the module answers with its own error. Slot ids are
passed through unchanged. Handles inside mechanism parameters are translated
the same way (see below).

## Calls

Each call has an id (never renumbered, only appended), a request body and a
response body. The bodies are the fields listed in the table, in order,
encoded as above. A request whose id the daemon doesn't know is answered with
`CKR_FUNCTION_NOT_SUPPORTED` and the connection stays up; a request whose body
does not decode makes the daemon send `Abort(Protocol)` and close.

The two-call convention of PKCS#11 (ask for the length with a NULL buffer,
then for the data) is carried by two types:

- `OutSpec` in a request: `u8 0` (length only) or `u8 1` + `u64 capacity`.
- `OutBytes` (and `OutU64s`) in a response: `u64 length`, then an optional
  byte string (array) that is present when a buffer was offered and the call
  succeeded.

A response carries a body when the call succeeded, or failed in a way that
still reports lengths (`CKR_BUFFER_TOO_SMALL`, `CKR_ATTRIBUTE_SENSITIVE`,
`CKR_ATTRIBUTE_TYPE_INVALID`).

<!-- BEGIN calls -->
### The calls

| id | call | since | rw | request | response |
|---:|---|---|---|---|---|
| 1 | `C_Initialize` | 2.40 |  |  |  |
| 2 | `C_Finalize` | 2.40 |  |  |  |
| 3 | `C_GetInfo` | 2.40 |  |  | `info: Info` |
| 4 | `C_GetSlotList` | 2.40 |  | `token_present: bool`, `slots: OutSpec` | `slots: OutU64s` |
| 5 | `C_GetSlotInfo` | 2.40 |  | `slot: u64` | `info: SlotInfo` |
| 6 | `C_GetTokenInfo` | 2.40 |  | `slot: u64` | `info: TokenInfo` |
| 7 | `C_GetMechanismList` | 2.40 |  | `slot: u64`, `mechanisms: OutSpec` | `mechanisms: OutU64s` |
| 8 | `C_GetMechanismInfo` | 2.40 |  | `slot: u64`, `mechanism: u64` | `info: MechanismInfo` |
| 9 | `C_InitToken` | 2.40 | yes | `slot: u64`, `pin: Option<Secret>`, `label: [u8; 32]` |  |
| 10 | `C_WaitForSlotEvent` | 2.40 |  | `flags: u64` | `slot: u64` |
| 11 | `C_OpenSession` | 2.40 |  | `slot: u64`, `flags: u64` | `session: u64` |
| 12 | `C_CloseSession` | 2.40 |  | `session: u64` |  |
| 13 | `C_CloseAllSessions` | 2.40 |  | `slot: u64` |  |
| 14 | `C_GetFunctionStatus` | 2.40 |  | `session: u64` |  |
| 15 | `C_CancelFunction` | 2.40 |  | `session: u64` |  |
| 16 | `C_GetSessionInfo` | 2.40 |  | `session: u64` | `info: SessionInfo` |
| 17 | `C_InitPIN` | 2.40 | yes | `session: u64`, `pin: Option<Secret>` |  |
| 18 | `C_SetPIN` | 2.40 | yes | `session: u64`, `old_pin: Option<Secret>`, `new_pin: Option<Secret>` |  |
| 19 | `C_GetOperationState` | 2.40 |  | `session: u64`, `state: OutSpec` | `state: OutBytes` |
| 20 | `C_SetOperationState` | 2.40 |  | `session: u64`, `state: Vec<u8>`, `encryption_key: u64`, `authentication_key: u64` |  |
| 21 | `C_Login` | 2.40 |  | `session: u64`, `user_type: u64`, `pin: Option<Secret>` |  |
| 22 | `C_Logout` | 2.40 |  | `session: u64` |  |
| 23 | `C_CreateObject` | 2.40 | yes | `session: u64`, `template: Template` | `object: u64` |
| 24 | `C_CopyObject` | 2.40 | yes | `session: u64`, `object: u64`, `template: Template` | `new_object: u64` |
| 25 | `C_DestroyObject` | 2.40 | yes | `session: u64`, `object: u64` |  |
| 26 | `C_GetObjectSize` | 2.40 |  | `session: u64`, `object: u64` | `size: u64` |
| 27 | `C_GetAttributeValue` | 2.40 |  | `session: u64`, `object: u64`, `template: Seq<Query>` | `template: Seq<Reply>` |
| 28 | `C_SetAttributeValue` | 2.40 | yes | `session: u64`, `object: u64`, `template: Template` |  |
| 29 | `C_FindObjectsInit` | 2.40 |  | `session: u64`, `template: Template` |  |
| 30 | `C_FindObjects` | 2.40 |  | `session: u64`, `objects: u64` | `objects: U64s` |
| 31 | `C_FindObjectsFinal` | 2.40 |  | `session: u64` |  |
| 32 | `C_EncryptInit` | 2.40 |  | `session: u64`, `mechanism: Mech`, `key: u64` | `mechanism_out: Option<Node>` |
| 33 | `C_Encrypt` | 2.40 |  | `session: u64`, `data: Vec<u8>`, `encrypted: OutSpec` | `encrypted: OutBytes` |
| 34 | `C_EncryptUpdate` | 2.40 |  | `session: u64`, `part: Vec<u8>`, `encrypted: OutSpec` | `encrypted: OutBytes` |
| 35 | `C_EncryptFinal` | 2.40 |  | `session: u64`, `last: OutSpec` | `last: OutBytes` |
| 36 | `C_DecryptInit` | 2.40 |  | `session: u64`, `mechanism: Mech`, `key: u64` | `mechanism_out: Option<Node>` |
| 37 | `C_Decrypt` | 2.40 |  | `session: u64`, `encrypted: Vec<u8>`, `data: OutSpec` | `data: OutBytes` |
| 38 | `C_DecryptUpdate` | 2.40 |  | `session: u64`, `encrypted: Vec<u8>`, `part: OutSpec` | `part: OutBytes` |
| 39 | `C_DecryptFinal` | 2.40 |  | `session: u64`, `last: OutSpec` | `last: OutBytes` |
| 40 | `C_DigestInit` | 2.40 |  | `session: u64`, `mechanism: Mech` | `mechanism_out: Option<Node>` |
| 41 | `C_Digest` | 2.40 |  | `session: u64`, `data: Vec<u8>`, `digest: OutSpec` | `digest: OutBytes` |
| 42 | `C_DigestUpdate` | 2.40 |  | `session: u64`, `part: Vec<u8>` |  |
| 43 | `C_DigestKey` | 2.40 |  | `session: u64`, `key: u64` |  |
| 44 | `C_DigestFinal` | 2.40 |  | `session: u64`, `digest: OutSpec` | `digest: OutBytes` |
| 45 | `C_SignInit` | 2.40 |  | `session: u64`, `mechanism: Mech`, `key: u64` | `mechanism_out: Option<Node>` |
| 46 | `C_Sign` | 2.40 |  | `session: u64`, `data: Vec<u8>`, `signature: OutSpec` | `signature: OutBytes` |
| 47 | `C_SignUpdate` | 2.40 |  | `session: u64`, `part: Vec<u8>` |  |
| 48 | `C_SignFinal` | 2.40 |  | `session: u64`, `signature: OutSpec` | `signature: OutBytes` |
| 49 | `C_SignRecoverInit` | 2.40 |  | `session: u64`, `mechanism: Mech`, `key: u64` | `mechanism_out: Option<Node>` |
| 50 | `C_SignRecover` | 2.40 |  | `session: u64`, `data: Vec<u8>`, `signature: OutSpec` | `signature: OutBytes` |
| 51 | `C_VerifyInit` | 2.40 |  | `session: u64`, `mechanism: Mech`, `key: u64` | `mechanism_out: Option<Node>` |
| 52 | `C_Verify` | 2.40 |  | `session: u64`, `data: Vec<u8>`, `signature: Vec<u8>` |  |
| 53 | `C_VerifyUpdate` | 2.40 |  | `session: u64`, `part: Vec<u8>` |  |
| 54 | `C_VerifyFinal` | 2.40 |  | `session: u64`, `signature: Vec<u8>` |  |
| 55 | `C_VerifyRecoverInit` | 2.40 |  | `session: u64`, `mechanism: Mech`, `key: u64` | `mechanism_out: Option<Node>` |
| 56 | `C_VerifyRecover` | 2.40 |  | `session: u64`, `signature: Vec<u8>`, `data: OutSpec` | `data: OutBytes` |
| 57 | `C_DigestEncryptUpdate` | 2.40 |  | `session: u64`, `part: Vec<u8>`, `encrypted: OutSpec` | `encrypted: OutBytes` |
| 58 | `C_DecryptDigestUpdate` | 2.40 |  | `session: u64`, `encrypted: Vec<u8>`, `part: OutSpec` | `part: OutBytes` |
| 59 | `C_SignEncryptUpdate` | 2.40 |  | `session: u64`, `part: Vec<u8>`, `encrypted: OutSpec` | `encrypted: OutBytes` |
| 60 | `C_DecryptVerifyUpdate` | 2.40 |  | `session: u64`, `encrypted: Vec<u8>`, `part: OutSpec` | `part: OutBytes` |
| 61 | `C_GenerateKey` | 2.40 | yes | `session: u64`, `mechanism: Mech`, `template: Template` | `mechanism_out: Option<Node>`, `key: u64` |
| 62 | `C_GenerateKeyPair` | 2.40 | yes | `session: u64`, `mechanism: Mech`, `public_template: Template`, `private_template: Template` | `mechanism_out: Option<Node>`, `public_key: u64`, `private_key: u64` |
| 63 | `C_WrapKey` | 2.40 |  | `session: u64`, `mechanism: Mech`, `wrapping_key: u64`, `key: u64`, `wrapped: OutSpec` | `mechanism_out: Option<Node>`, `wrapped: OutBytes` |
| 64 | `C_UnwrapKey` | 2.40 | yes | `session: u64`, `mechanism: Mech`, `unwrapping_key: u64`, `wrapped: Vec<u8>`, `template: Template` | `mechanism_out: Option<Node>`, `key: u64` |
| 65 | `C_DeriveKey` | 2.40 | yes | `session: u64`, `mechanism: Mech`, `base_key: u64`, `template: Template` | `mechanism_out: Option<Node>`, `key: u64` |
| 66 | `C_SeedRandom` | 2.40 | yes | `session: u64`, `seed: Vec<u8>` |  |
| 67 | `C_GenerateRandom` | 2.40 |  | `session: u64`, `random: u64` | `random: Vec<u8>` |
| 68 | `C_LoginUser` | 3.0 |  | `session: u64`, `user_type: u64`, `pin: Option<Secret>`, `username: Option<Secret>` |  |
| 69 | `C_SessionCancel` | 3.0 |  | `session: u64`, `flags: u64` |  |
| 70 | `C_MessageEncryptInit` | 3.0 |  | `session: u64`, `mechanism: Mech`, `key: u64` | `mechanism_out: Option<Node>` |
| 71 | `C_EncryptMessage` | 3.0 |  | `session: u64`, `parameter: MsgParam`, `associated_data: Vec<u8>`, `plaintext: Vec<u8>`, `ciphertext: OutSpec` | `parameter_out: Option<Node>`, `ciphertext: OutBytes` |
| 72 | `C_EncryptMessageBegin` | 3.0 |  | `session: u64`, `parameter: MsgParam`, `associated_data: Vec<u8>` | `parameter_out: Option<Node>` |
| 73 | `C_EncryptMessageNext` | 3.0 |  | `session: u64`, `parameter: MsgParam`, `plaintext: Vec<u8>`, `ciphertext: OutSpec`, `flags: u64` | `parameter_out: Option<Node>`, `ciphertext: OutBytes` |
| 74 | `C_MessageEncryptFinal` | 3.0 |  | `session: u64` |  |
| 75 | `C_MessageDecryptInit` | 3.0 |  | `session: u64`, `mechanism: Mech`, `key: u64` | `mechanism_out: Option<Node>` |
| 76 | `C_DecryptMessage` | 3.0 |  | `session: u64`, `parameter: MsgParam`, `associated_data: Vec<u8>`, `ciphertext: Vec<u8>`, `plaintext: OutSpec` | `parameter_out: Option<Node>`, `plaintext: OutBytes` |
| 77 | `C_DecryptMessageBegin` | 3.0 |  | `session: u64`, `parameter: MsgParam`, `associated_data: Vec<u8>` | `parameter_out: Option<Node>` |
| 78 | `C_DecryptMessageNext` | 3.0 |  | `session: u64`, `parameter: MsgParam`, `ciphertext: Vec<u8>`, `plaintext: OutSpec`, `flags: u64` | `parameter_out: Option<Node>`, `plaintext: OutBytes` |
| 79 | `C_MessageDecryptFinal` | 3.0 |  | `session: u64` |  |
| 80 | `C_MessageSignInit` | 3.0 |  | `session: u64`, `mechanism: Mech`, `key: u64` | `mechanism_out: Option<Node>` |
| 81 | `C_SignMessage` | 3.0 |  | `session: u64`, `parameter: MsgParam`, `data: Vec<u8>`, `signature: OutSpec` | `parameter_out: Option<Node>`, `signature: OutBytes` |
| 82 | `C_SignMessageBegin` | 3.0 |  | `session: u64`, `parameter: MsgParam` | `parameter_out: Option<Node>` |
| 83 | `C_SignMessageNext` | 3.0 |  | `session: u64`, `parameter: MsgParam`, `data: Vec<u8>`, `signature: OutSpec` | `parameter_out: Option<Node>`, `signature: OutBytes` |
| 84 | `C_MessageSignFinal` | 3.0 |  | `session: u64` |  |
| 85 | `C_MessageVerifyInit` | 3.0 |  | `session: u64`, `mechanism: Mech`, `key: u64` | `mechanism_out: Option<Node>` |
| 86 | `C_VerifyMessage` | 3.0 |  | `session: u64`, `parameter: MsgParam`, `data: Vec<u8>`, `signature: Vec<u8>` | `parameter_out: Option<Node>` |
| 87 | `C_VerifyMessageBegin` | 3.0 |  | `session: u64`, `parameter: MsgParam` | `parameter_out: Option<Node>` |
| 88 | `C_VerifyMessageNext` | 3.0 |  | `session: u64`, `parameter: MsgParam`, `data: Vec<u8>`, `signature: Vec<u8>` | `parameter_out: Option<Node>` |
| 89 | `C_MessageVerifyFinal` | 3.0 |  | `session: u64` |  |
| 90 | `C_EncapsulateKey` | 3.2 | yes | `session: u64`, `mechanism: Mech`, `public_key: u64`, `template: Template`, `ciphertext: OutSpec` | `mechanism_out: Option<Node>`, `ciphertext: OutBytes`, `key: u64` |
| 91 | `C_DecapsulateKey` | 3.2 | yes | `session: u64`, `mechanism: Mech`, `private_key: u64`, `template: Template`, `ciphertext: Vec<u8>` | `mechanism_out: Option<Node>`, `key: u64` |
| 92 | `C_VerifySignatureInit` | 3.2 |  | `session: u64`, `mechanism: Mech`, `key: u64`, `signature: Vec<u8>` | `mechanism_out: Option<Node>` |
| 93 | `C_VerifySignature` | 3.2 |  | `session: u64`, `data: Vec<u8>` |  |
| 94 | `C_VerifySignatureUpdate` | 3.2 |  | `session: u64`, `part: Vec<u8>` |  |
| 95 | `C_VerifySignatureFinal` | 3.2 |  | `session: u64` |  |
| 96 | `C_GetSessionValidationFlags` | 3.2 |  | `session: u64`, `kind: u64` | `flags: u64` |
| 97 | `C_AsyncComplete` | 3.2 |  | `session: u64`, `function_name: Vec<u8>`, `result: AsyncIn` | `result: AsyncOut` |
| 98 | `C_AsyncGetID` | 3.2 |  | `session: u64`, `function_name: Vec<u8>` | `id: u64` |
| 99 | `C_AsyncJoin` | 3.2 |  | `session: u64`, `function_name: Vec<u8>`, `id: u64`, `data: u64` | `data: Vec<u8>` |
| 100 | `C_WrapKeyAuthenticated` | 3.2 |  | `session: u64`, `mechanism: Mech`, `wrapping_key: u64`, `key: u64`, `associated_data: Vec<u8>`, `wrapped: OutSpec` | `mechanism_out: Option<Node>`, `wrapped: OutBytes` |
| 101 | `C_UnwrapKeyAuthenticated` | 3.2 | yes | `session: u64`, `mechanism: Mech`, `unwrapping_key: u64`, `wrapped: Vec<u8>`, `template: Template`, `associated_data: Vec<u8>` | `mechanism_out: Option<Node>`, `key: u64` |

<!-- END calls -->

### Attributes

A template is an array of attributes, each `u64 type`, `u8 tag`, value:
tag 0 unavailable (`CK_UNAVAILABLE_INFORMATION`), 1 bytes, 2 `u64` (for
attributes PKCS#11 defines as `CK_ULONG`), 3 array of `u64` (for
`CKA_ALLOWED_MECHANISMS` and similar), 4 nested template (wrap, unwrap,
derive, encapsulate and decapsulate templates). Nothing is ever sent as
native-endian memory.

`C_GetAttributeValue` sends, per attribute, what the caller offers (`Query`:
type and no buffer, a capacity, or nested queries) and gets back one `Reply`
per attribute (unavailable, needed length, bytes, `u64`, array, nested).

### Mechanism parameters

A mechanism is `u64 type` and an optional parameter **tree**. A tree node is a
tag byte and a value: 0 absent (a NULL pointer), 1 `u64`, 2 byte string,
3 list of nodes, 4 attribute template. A structure that PKCS#11 defines with
pointers is sent as a list of its members in declaration order (descriptors in
`crates/p11-params/src/descs.rs`); pointers become byte strings, nested
structures or absent nodes. The daemon rebuilds an equivalent structure in its
own memory from the tree; it never uses anything it received as a pointer.

Members the module fills in (TLS key material handles, IVs, PRF output,
returned versions, message-mode IVs and tags) come back in the response as a
tree of the same shape with the other members absent.

Parameters without pointers travel as a byte string of the exact length the
mechanism expects. Mechanisms the proxy doesn't carry (X3DH, X2Ratchet, and
the obsolete Skipjack, Baton, Juniper and GOST 28147 families) are refused
with `CKR_MECHANISM_INVALID` on both ends and left out of
`C_GetMechanismList`.

### Vendor-defined functions

A module can export functions that are not part of PKCS#11 (extensions of a vendor's SDK). The daemon
carries the ones its configuration declares (`[[vendor_function]]`), and only those. A client sets
`VENDOR_FUNCTIONS` (bit 1) in `Hello`; a daemon that has declared some echoes it in `HelloAck` and, after
the `VendorMechanisms` frame if there is one, sends a `VendorFunctions` frame:

```
u32 count | count x ( bytes name | bool rw | u8 argument count | argument count x u8 kind )
```

`count` is at most 256; a name is at most 128 bytes, a C identifier not starting `C_`; a function has at most
32 arguments standing for at most 20 C parameters. The client installs the list as it does the mechanisms.
`rw` means the function changes the token and is refused for a read-only client.

An argument's **kind** says how many C parameters it stands for and how it travels:

| kind | value | C parameters | request | reply |
|---|---|---|---|---|
| `u8`, `u16`, `u32`, `u64` | 1 to 4 | one integer by value (cut to its width) | `u64` | |
| `slot` | 5 | `CK_SLOT_ID` | `u64` | |
| `session` | 6 | `CK_SESSION_HANDLE` (translated) | `u64` | |
| `object` | 7 | `CK_OBJECT_HANDLE` (translated) | `u64` | |
| `bytes` | 8 | pointer, length | bytes | |
| `secret` | 9 | pointer, length; wiped after the call | bytes | |
| `cstr` | 10 | NUL-terminated string (at most 4096 bytes) | bytes | |
| `label` | 11 | 32 space-padded characters | 32 bytes | |
| `attrs` | 12 | `CK_ATTRIBUTE` array, count | template | |
| `o_u32` | 13 | pointer to a 32-bit integer | | `u64` |
| `o_u64` | 14 | pointer to a `CK_ULONG` | | `u64` |
| `o_object` | 15 | pointer to a `CK_OBJECT_HANDLE` (translated back) | | `u64` |
| `o_bytes` | 16 | buffer, pointer to its length (the two-call convention) | room | length and bytes |
| `o_buf` | 17 | buffer, capacity by value, pointer to the length written | room | length and bytes |

Only integers and pointers are carried, so a function that takes or returns a structure by value, or a
floating point number, cannot be declared.

**The call** has id 1000, outside the call table (which ends at 101), and uses the ordinary request and
response frames. The request body is `bytes name | u8 argument count`, then one value per argument, each with a
tag byte: 0 nothing (an output that takes nothing in), 1 `u64`, 2 bytes, 3 template, 4 no buffer (the length is
asked for), 5 `u64` room. The response's `rv` is the function's own return value; when it is `CKR_OK` or
`CKR_BUFFER_TOO_SMALL` the body carries one value per output argument in order: tag 1 and a `u64`, or tag 2 and
an `OutBytes` (`u64 length | optional bytes`). The daemon checks the request against its own declaration of
that name; a name it has not declared is answered with `CKR_FUNCTION_NOT_SUPPORTED`, and a body that does not
fit the declaration drops the connection like any malformed request. Handles are translated as for every
other call, an object handle the client does not have goes to the module as one no object has, and the
daemon reads what the function wrote only from buffers it allocated. Golden vectors: `frame.vendor_functions`,
`vendorfn.request`, `vendorfn.reply`.

## Versioning

A change that alters the bytes of any existing message needs a new protocol
version; adding calls at the end of the call table, or feature bits, doesn't.
The client offers the range it speaks and the daemon picks; version 1 is the
only one so far.
