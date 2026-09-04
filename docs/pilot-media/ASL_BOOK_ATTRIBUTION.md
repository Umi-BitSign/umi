# ASL BOOK component-pilot asset

This directory contains a format-only adaptation of `ASL BOOK.ogv` by Richard
Goodrow. The author signs: “BOOK. B-O-O-K. My daughter and I read everyday
together. BOOK.”

- Source page: <https://commons.wikimedia.org/wiki/File:ASL_BOOK.ogv>
- Original file: <https://upload.wikimedia.org/wikipedia/commons/2/29/ASL_BOOK.ogv>
- Pilot MP4: <https://pub-bfe43425f6564cc98cb3ad43b9662ae3.r2.dev/component-pilot/media/7558c4b41aa18a9dc8377b84bda06c1595b4fcdcf5e69dd154d5e210127a29ff.mp4>
- Author and required attribution: Richard Goodrow
- Source license: [Creative Commons Attribution 3.0
  Unported](https://creativecommons.org/licenses/by/3.0/)
- Original SHA-256: `a15f0922cdf15e5ed64c23de797fa222d2d2fdb13845a0af941e9967fdcea631`
- Derived MP4 SHA-256: `7558c4b41aa18a9dc8377b84bda06c1595b4fcdcf5e69dd154d5e210127a29ff`
- UMI RGB24 frame digest: `e74665ac340578d5b5bbb1837130c28fc8ebb50afbf8f3bd948d2f3a338d6be2`

The adaptation removes source metadata and any audio, converts the Theora source to
H.264 High Profile/YUV 4:2:0 at 30 frames per second, and adds an MP4 fast-start
index. It was produced with FFmpeg 8.1.2 using:

```text
ffmpeg -i source.ogv -map 0:v:0 -an -vf fps=30 -c:v libx264 \
  -flags:v +bitexact -fflags +bitexact -profile:v high -level 3.1 \
  -pix_fmt yuv420p -movflags +faststart \
  -map_metadata -1 asl-book.mp4
```

This 2010 recording is not fresh and has no UMI-specific consent or independent
review record. It is licensed public media used only for an explicitly nonconforming
`component_test_no_weight` pilot. It is not an eligible UMI challenge, protocol-
conformance result, validator input, or activation evidence. Its use does not imply
that Richard Goodrow endorses UMI.

The pilot references below are operator-authored variants of the source page's
published description. They are not blind reconstructions and do not satisfy the
reference-review requirements for a protocol window:

1. `book b o o k my daughter and i read every day together book`
2. `book b o o k my daughter and i read together every day book`
3. `book b o o k my daughter and i read daily together book`
