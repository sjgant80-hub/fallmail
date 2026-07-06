# FallMail

**P2P encrypted messaging for the sovereign island.**

Address messages to **DIDs**, not email addresses. Delivered peer-to-peer over WebRTC. Encrypted end-to-end with ECDH + AES-GCM. Signed with your Ed25519 identity. No SMTP. No email provider. No server.

Live: **https://sjgant80-hub.github.io/fallmail/**

## What it is

FallMail is an inbox for the AI-Native Solutions estate. It runs entirely in your browser. It uses:

- **[FallID](https://sjgant80-hub.github.io/fallid/)** for your identity — a `did:key:z…` derived from an Ed25519 keypair that never leaves your device
- **[FallLink](https://sjgant80-hub.github.io/falllink/)** for delivery — WebRTC datachannels between peers, with BroadcastChannel auto-discovery on the same origin and manual offer/answer paste across networks
- **[FallPod](https://sjgant80-hub.github.io/fallpod/)** for the inbox / outbox / drafts / trash — one sovereign data pod at `/mail/…`
- **[FallStore](https://sjgant80-hub.github.io/fallstore/)** for attachments — content-addressed blobs (SHA-256 CIDs)

There is no SMTP, no IMAP, no email server, no "cloud." Your inbox is on your device. Delivery is peer-to-peer. Messages are encrypted before they leave.

## How the crypto works

1. Every FallMail user has a **did:key** — that's their address. It encodes their Ed25519 public key.
2. To send you a message, the sender:
   - Generates an **ephemeral X25519 keypair**
   - Converts your Ed25519 public key (from your DID) into an X25519 public key via the standard Edwards→Montgomery map: `u = (1 + y) / (1 - y) mod p`
   - Runs **X25519 scalar multiplication** with their ephemeral secret and your derived X25519 public key → a shared secret
   - Runs the shared secret through **HKDF-SHA256** → an AES-GCM key
   - Encrypts the message body with **AES-GCM**
   - **Signs** the message id (SHA-256 of ciphertext + your DID) with their Ed25519 identity
   - Attaches their ephemeral X25519 public key to the wire message
3. To read a message you receive, you:
   - Take the sender's ephemeral X25519 public key from the wire
   - Derive your own X25519 secret from your Ed25519 identity seed (SHA-512, clamp lower 32 bytes — the canonical Ed25519 → X25519 conversion)
   - Run X25519 with your derived secret and their ephemeral public → same shared secret
   - HKDF → AES-GCM key → decrypt body
   - **Verify** the sender's Ed25519 signature against their DID

Nobody in the middle can read the message. Only the recipient's device can compute the shared secret. Every message uses a fresh ephemeral keypair — so forward secrecy holds even if long-term keys are compromised later.

## Wire format

```json
{
  "id": "sha256hex(ciphertext || toDid)",
  "fromDid": "did:key:z…",
  "toDid": "did:key:z…",
  "subject": "…",
  "encryptedBody": "base64(AES-GCM ciphertext)",
  "ephPub": "base64(sender's ephemeral X25519 public key)",
  "attachments": [{ "cid": "sha256:…", "name": "…", "type": "…", "size": 12345 }],
  "timestamp": "ISO-8601",
  "signature": "base58btc(Ed25519 sig over id)",
  "v": 1
}
```

## Library API

```js
import * as FallID from 'https://sjgant80-hub.github.io/fallid/fallid.js';
import FallLink from 'https://sjgant80-hub.github.io/falllink/falllink.js';
import { FallPod } from 'https://sjgant80-hub.github.io/fallpod/fallpod.js';
import * as FallStore from 'https://sjgant80-hub.github.io/fallstore/fallstore.js';
import { FallMail } from 'https://sjgant80-hub.github.io/fallmail/fallmail.js';

const id = await FallID.getOrCreate();
const pod = new FallPod({ ownerDid: id.did });
await pod.ready();
const link = new FallLink({ ownId: id.did });
link.startBroadcast();

const mail = new FallMail({ fallid: FallID, falllink: link, fallpod: pod, fallstore: FallStore });
await mail.ready();

mail.onMessage(m => console.log('inbox ping:', m.subject));

await mail.send('did:key:z6Mk…', 'Hello', 'From my sovereign island to yours.');
const inbox = await mail.inbox();
const sent = await mail.outbox();
await mail.read(messageId);
await mail.delete(messageId);
await mail.reply(messageId, 'Reply body');
const attachment = await mail.attach(fileBlob); // → { cid, name, type, size }
```

## What lives where

- `fallmail.js` — the library (ES module)
- `index.html` — inbox UI: sidebar (inbox / sent / drafts / trash), message list, preview with reply, compose modal, attachment browser
- `sw.js`, `manifest.webmanifest` — installable PWA
- `LICENSE` — MIT

## Sovereignty

- No server. No SMTP. No email provider. No accounts.
- Your DID is your address. Your device is your inbox.
- Encryption keys never leave your device.
- Runs offline once loaded. Outbox retains messages if you send while no peers are connected — they transmit when peers come online.
- MIT license. Fork it, mint it, host it yourself.

## Estate context

FallMail is the messaging surface of the [AI-Native Solutions estate](https://sjgant80-hub.github.io/). It composes with FallID, FallLink, FallPod, and FallStore. It ships as a sovereign primitive — every estate tool that needs "notify the human" or "notify another agent" can import FallMail rather than reinventing.

Built by [AI-Native Solutions](https://ai-nativesolutions.com).
