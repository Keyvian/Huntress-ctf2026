# 🔎 Frame of Reference

| | |
|---|---|
| **Day** | 18 |
| **Lane** | 🔎 Metadata Forensics |
| **Challenge ID** | `metadata-forensics-day-18-frame-of-reference` |
| **Modes** | Single Solve ✅ · Time Trial ✅ · Mastery ✅ |
| **Solver** | [`solvers/day18_quick/m18.py`](../solvers/day18_quick/m18.py) + geometry probe [`video.py`](../solvers/day18_quick/video.py) (debug: [`mp4dump.py`](../solvers/day18_quick/mp4dump.py)) |

## Prompt
> Clips, previews, and screen recordings have been mixed together. Use stream geometry to identify originals, crops, and the recording that could not have come from the claimed device.

## TL;DR
The new field is `media.primary_video_dimensions` for `video-001.mp4`, answered ffprobe-style as
`<width>x<height>` of the **decoder output**. The clip's H.264 SPS codes 320×192 macroblock-aligned frames with
`frame_crop_bottom_offset = 6`. After cropping that is **320x180**, which also matches the `tkhd` and `stsd`
dimensions. CORRECT on the first single-solve try.

## Artifact
- `video-001.mp4`:
  - Container: `isom` brand, an `avc1` track encoded by libx264, 10 fps, 5 frames, an AAC audio track, `ilst` title
    `Huntress MP4 evidence <12 hex>`.
  - Geometry: `tkhd` says 320×180, the `stsd` visual entry says 320×180, and the SPS says coded 320×192 with crop
    bottom 6.
- Answer id `d18-video-001-media-primary-video-dimensions`.
- Time Trial: **23 questions**. Mastery: **5 sets × 23 = 115**. Every variant seen was the same 320×180 clip. The
  "crops / screen recording that could not have come from the claimed device" story never became a question.

## Solution
H.264 encodes whole 16×16 macroblocks, so a 180-line picture is coded as 192 lines (12 macroblocks) and the SPS
cropping window removes the excess:

```text
coded_w = (pic_width_in_mbs_minus1 + 1) * 16                       = 320
coded_h = (pic_height_in_map_units_minus1 + 1) * 16 * (2 - frame_mbs_only_flag) = 192
crop units (4:2:0, progressive): CropUnitX = 2, CropUnitY = 2
height  = coded_h - CropUnitY * (frame_crop_top_offset + frame_crop_bottom_offset) = 192 - 2*6 = 180
```

ffprobe reports `width`/`height` after cropping (320×180) and `coded_width`/`coded_height` before it. The question asks
for "dimensions", which is the cropped decoder output. In this file every source agrees on 320×180, so the SPS check
only confirms the answer.

`video.py` is a pure-Python geometry probe:

- MP4/MOV: `tkhd` (with the rotation matrix and display size), the `stsd` visual entry, an `avcC` SPS parser
  (Exp-Golomb, cropping, chroma format, VUI sample aspect ratio), `hvcC` conformance window, `pasp`, `clap`, `stts` →
  frame rate, `ilst` / `keys` tags.
- Matroska/WebM pixel and display sizes with crops; AVI `avih` / `strf`.

`video_field()` answers dimensions, coded / display / stsd dimensions, rotation, SAR / DAR, frame rate, frame count,
pixel format, profile, level, crops and duration. `mp4dump.py` prints the full box tree.

## Time Trial & Mastery
Metadata time trial and mastery were again regular untimed attempts (`deadline: None`). Only the warmup lane had real
timers that day. Time Trial CORRECT 23/23, Mastery CORRECT 115/115.

## Lessons / gotchas
- Four sources can report "dimensions": `tkhd` (presentation, after any transform), `stsd`, the SPS before cropping,
  and the SPS after cropping. ffprobe's `width x height` is the cropped SPS value. For a phone video rotated through
  the `tkhd` matrix, the display size swaps but the stream size does not. Keep them separate.
- A mismatch between the container's size and the cropped SPS size is the kind of evidence the prompt's "crops"
  story points at. No such variant was served, but `video.py` prints all four values per file so one would be
  visible.
