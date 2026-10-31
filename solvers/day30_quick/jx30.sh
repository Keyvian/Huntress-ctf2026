#!/bin/bash
# Decompile one saved APK directory with jadx (needs absolute paths) and print the sources compactly. usage: jx30.sh <dir with x/classes.dex>
d="$1"
rm -rf "$d/jx"
jadx -q -d "$d/jx" "$d/x/classes.dex" >/dev/null 2>&1
find "$d/jx" -name "*.java" | grep -v '/R\.java' | while read -r f; do
  echo "=== ${f##*/}"
  sed -e 's/^ *//' "$f" | grep -v '^import\|^package\|^$\|^/\*\|^\*' | cut -c1-230
done
