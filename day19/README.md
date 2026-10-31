# Day 19

| Lane | Challenge | Modes | Summary |
|---|---|---|---|
| 👶 Warmups | [👶 Little Things](warmups-little-things.md) | Single Solve · Time Trial · Mastery | Hex of **UTF-16LE** text with a byte-order mark: `fffe 4e00 6900 6300 …` = BOM `FF FE`, then `N\0i\0c\0…`. |
| 🔎 Metadata | [🔎 Little Endian on the Prairie](metadata-little-endian-on-the-prairie.md) | Single Solve · Time Trial · Mastery | The new field is `elf.e_machine_u16_hex` for `collector-001.elf`: the `e_machine` field of the ELF header at offset `0x12`, read in the byte order that `EI_DATA` declares, formatted `0x%04x`. |
| 📜 Script | [📜 Sharp Practice](script-sharp-practice.md) | Single Solve · Time Trial · Mastery | **1,249 questions** = the Day-18 contract (1,194, unchanged) + 55 new: four **C# script** (`.csx`) polyglots and one ASPX host fixture that embeds a whole `.csx` specimen as a C# string literal. |
| 📱 Mobile | [📱 Reflection Maze](mobile-reflection-maze.md) | Single Solve · Time Trial · Mastery | The puzzle was `{"codec":"reflection","data":"ANS-…"}`, and **`data` was already the plain answer**. |
| ⚙️ Binary | [⚙️ Jack in the Box](binary-jack-in-the-box.md) | Single Solve · Time Trial · Mastery | Day-18 contract plus a 12-question `d19` unit: a GnuCOBOL ELF with a **packed overlay** appended after the section-header table. |
| 🌐 Web | [🌐 Trust the Webhook](web-trust-the-webhook.md) | Single Solve · Time Trial · Mastery (released GM day 26) | A **forged-webhook trust** flaw. |

[← Day 18](../day18/README.md) · [Index](../README.md) · [Day 20 →](../day20/README.md)
