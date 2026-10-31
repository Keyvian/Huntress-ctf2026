# 🔎 Hear Me Out

| | |
|---|---|
| **Day** | 17 |
| **Lane** | 🔎 Metadata Forensics |
| **Challenge ID** | `metadata-forensics-day-17-hear-me-out` |
| **Modes** | Single Solve ✅ · Time Trial ✅ · Mastery ✅ |
| **Solver** | [`solvers/day17_quick/m17.py`](../solvers/day17_quick/m17.py) + audio probe [`media.py`](../solvers/day17_quick/media.py) |

## Prompt
> Voice notes have been transcoded, renamed, and embedded in mail. Determine the actual codecs, connect equivalent recordings, and find the stream that breaks the sender’s story.

## TL;DR
The new field is `media.primary_audio_codec_name` for `audio-001.wav`, answered with the **ffprobe codec name**:
a RIFF/WAVE file with format tag 1 (PCM) and 16-bit samples is `pcm_s16le`. CORRECT on the first single-solve try.
The agent wrote a pure-Python probe that returns ffprobe-style names for most audio containers, so no external tool sits
in the solve path.

## Artifact
- `audio-001.wav`: RIFF/WAVE, `fmt ` chunk with `wFormatTag = 1`, 16-bit, mono, 16 kHz, plus a `LIST/INFO` chunk whose
  `INAM` is `Huntress audio evidence <12 hex>`.
- Answer id `d17-audio-001-media-primary-audio-codec-name`.
- Time Trial: **22 questions** (cumulative contract + audio). Mastery: **5 sets × 22 = 110**, one `evidence-0N.zip`
  per set in the default ZIP. Every variant seen was the same `pcm_s16le` WAV. The "transcoded / embedded in mail /
  equivalent recordings" story never became a question.

## Solution
For WAV, walk the RIFF chunks to `fmt `, then map format tag + bits per sample to the ffprobe name (simplified from
`media.py`, which also has a table for ADPCM, A-law/µ-law, GSM, etc.):

```python
tag, ch, rate, _, _, bits = struct.unpack("<HHIIHH", fmt[:16])
if tag == 0xFFFE:                      # WAVE_FORMAT_EXTENSIBLE: real tag is in the SubFormat GUID
    tag = struct.unpack("<H", fmt[24:26])[0]
if tag == 1:                           # PCM integer
    name = {8: "pcm_u8", 16: "pcm_s16le", 24: "pcm_s24le", 32: "pcm_s32le"}[bits]
elif tag == 3:                         # IEEE float
    name = {32: "pcm_f32le", 64: "pcm_f64le"}[bits]
```

The answer wants the *codec*, not the container: "wav" or "PCM" would not match. ffprobe's naming encodes signedness,
width and byte order (`pcm_s16le` = signed 16-bit little-endian). 8-bit WAV PCM is unsigned (`pcm_u8`).

`media.py` covers much more than this day asked:

- WAV (including EXTENSIBLE), RF64, AIFF/AIFC, AU, CAF, AMR.
- MP3: ID3v2 skip, then the frame header gives `mp3` / `mp2` / `mp1`.
- Ogg (vorbis, opus, flac, speex) and native FLAC.
- MP4/M4A: `stsd` plus the `esds` object type → aac / mp3 / alac, etc.
- Matroska/WebM `CodecID`, ASF/WMA.
- `.eml`: the first audio attachment is probed.

It also returns sample rate, channels, bits, duration and title tags. `m17.py` wraps `m16` and routes `media.<snake>`
(aliases include `codec`, `container`, `sample_rate_hz`, `channels`, `bits_per_sample`, `duration_ms`,
`format_tag_u16_hex`).

## Time Trial & Mastery
Plain `start` gave regular untimed attempts (`deadline: None`), as on Day 16. Time Trial CORRECT 22/22, Mastery
CORRECT 110/110.

## Lessons / gotchas
- When a field says "codec name" without a vocabulary, ffprobe's names are the de facto standard. The grader used them
  here and again on [Day 18](../day18/metadata-frame-of-reference.md).
- Build the probe for the containers the prompt mentions (here audio embedded in mail), even if only the WAV case is
  graded.
