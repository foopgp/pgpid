#!/bin/bash
# Regenerate the transliteration table in src/translit.c from the reference.
#
# The reference, decided by JJB on 2026-08-22, is
#   iconv --from-code=utf-8 --to-code=ascii//TRANSLIT   under LC_ALL=C.utf8
# and C.utf8 is the point: it is present everywhere, so the answer does not
# depend on which locales a machine happens to carry.
#
# Generated rather than written, for the same reason as the country table: a
# hand-made mapping of several hundred codepoints is a set of typos waiting to
# mint wrong identifiers. Twenty of them were found that way.
#
# Usage: tools/gen-translit.sh > /tmp/table.inc
set -euo pipefail
python3 - <<'PY' |
# Latin-1 Supplement, Latin Extended-A and -B, and Latin Extended Additional:
# every letter a name written in Latin script uses.
for cp in list(range(0xA0, 0x250)) + list(range(0x1E00, 0x1F00)):
    print(f"{cp:04X}\t{chr(cp)}")
PY
while IFS=$'\t' read -r cp ch ; do
    out=$(printf '%s' "$ch" | LC_ALL=C.utf8 iconv --from-code=utf-8 --to-code=ascii//TRANSLIT 2>/dev/null) || continue
    # A character iconv leaves as itself carries no information for us.
    [[ "$out" != "$ch" ]] || continue
    printf '    { 0x%s, "%s" },\n' "$cp" "${out//\"/\\\"}"
done
