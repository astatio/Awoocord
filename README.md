# Awoocord Plugins

## [Bubbles](plugins/Crocosmia) | [Download](https://github.com/cillynder/Awoocord/raw/builds/Bubbles.zip)

Wrap messages in bubbles inspired by Material 3 Expressive

## [Clump](plugins/Bocchi) | [Download](https://github.com/cillynder/Awoocord/raw/builds/Clump.zip)

Group messages more leniently (e.g. mentions, attachments, etc..), reducing clutter and wasted space.

## [Glance](plugins/Myosotis) | [Download](https://github.com/cillynder/Awoocord/raw/builds/Glance.zip)

Backports DM previews similar to latest RN. Shows you a line of the last message sent in a DM.

## [RoleBlocks](plugins/Zinnia) | [Download](https://github.com/cillynder/Awoocord/raw/builds/RoleBlocks.zip)

Apply the role colour as a background of usernames, improving contrast with some role colours

## [Scout](plugins/Scout) | [Download](https://github.com/cillynder/Awoocord/raw/builds/Scout.zip)

Vastly improves the search experience on Aliucord.

Features:
- Sort by oldest messages first
- Sort by oldest first
- Filter by date (before, during, after)
- Exclude certain messages (opposite of `in:`) (not even desktop has this!)
- Search by user ID
- Search in threads

Fixes:
- Removes the large padding from the top, most noticable if your device has a large status bar
- Removes the unnecessary #0000 discriminator

# WIP Backports

## [SlashCommandsFix](canary/SlashCommandsFix) | [Download](https://github.com/cillynder/Awoocord/raw/builds/SlashCommandsFixBeta.zip)

Fixes slash commands not showing up.

## [VoiceE2EE](plugins/VoiceE2EE) | [Download](https://github.com/astatio/Awoocord/raw/builds/VoiceE2EE.zip)

Makes voice work again now that Discord requires end-to-end encryption (DAVE) for calls, DMs, server voice channels and Go Live.

- The voice gateway (Java in 126.21) is upgraded to v8 and runs DAVE's MLS key exchange (BouncyCastle `bcmls`, bundled)
- The stock native voice engine is kept and pointed at a local UDP relay, which adds/removes DAVE frame encryption (Opus and VP8) and re-encrypts the transport with `aead_aes256_gcm_rtpsize` (or `aead_xchacha20_poly1305_rtpsize`)
- Video is offered as VP8 only (DAVE needs per-codec handling; the call then uses VP8 for everyone)
- `/voicee2ee` shows the call's E2EE status and voice privacy code; `/voicee2ee-engine-mode` switches how the engine talks to the local relay (default `xsalsa20_poly1305_lite_rtpsize`, the one that works with 126.21's engine)

Untested against Discord's live servers so far; please report how it goes.

## [ComponentsV2](canary/ComponentsV2) | [Download](https://github.com/cillynder/Awoocord/raw/builds/ComponentsV2Beta.zip)

Fix missing/empty bot messages using the new embed system. Such messages will be marked "CV2" as part of its tag.
