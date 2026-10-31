#!/bin/sh
# Game Master client from WSL via paired token over the public HTTPS endpoint (no Homebase credits).
#   gm.sh get      "?op=list"
#   gm.sh get      "?op=status&challenge=<id>"
#   gm.sh post     "{\"op\":\"start\",\"challenge\":\"<id>\"}"
#   gm.sh artifact "<id>" [delivery]   -> raw bytes to stdout
CRED="/mnt/c/Users/<user>/.huntress-ctf"
BASE="https://2026.huntress.ctf.games/"
TOKEN=$(grep -oE "\"token\"[[:space:]]*:[[:space:]]*\"[^\"]*\"" "$CRED/gm_token.json" | sed -E "s/.*:[[:space:]]*\"([^\"]*)\"/\1/")
AUTH="Authorization: Bearer $TOKEN"
case "$1" in
  get)      curl -sS -m 30 -H "$AUTH" "${BASE}$2" ;;
  post)     curl -sS -m 60 -X POST -H "$AUTH" -H "Content-Type: application/json" -d "$2" "$BASE" ;;
  artifact) q="?op=artifact&challenge=$2"; [ -n "$3" ] && q="$q&delivery=$3"; curl -sS -m 90 -H "$AUTH" "${BASE}${q}" ;;
  *) echo "usage: gm.sh get|post|artifact ..." >&2; exit 2 ;;
esac
