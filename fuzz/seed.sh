#!/usr/bin/env bash
# Builds a seed corpus for the fuzzers from real artifacts made with the
# bound CLI, using tiny fake launchers (just an ELF or PE header) so that
# inputs stay small.
#
#   fuzz/seed.sh [path/to/bound]   (default: target/debug/bound)
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
bound="$(cd "$(dirname "${1:-$root/target/debug/bound}")" && pwd)/$(basename "${1:-$root/target/debug/bound}")"
corpus="$root/fuzz/corpus"
mkdir -p "$corpus/artifact" "$corpus/manifest" "$corpus/names"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
cd "$work"

# 64-byte ELF header (x86_64) and a minimal PE header (x86_64).
python3 - <<'PY'
elf = bytearray(64); elf[0:4] = b"\x7fELF"; elf[4] = 2; elf[5] = 1; elf[18:20] = (0x3e).to_bytes(2, "little")
open("elf", "wb").write(elf)
pe = bytearray(0x48); pe[0:2] = b"MZ"; pe[0x3c:0x40] = (0x40).to_bytes(4, "little"); pe[0x40:0x44] = b"PE\0\0"; pe[0x44:0x46] = (0x8664).to_bytes(2, "little")
open("pe", "wb").write(pe)
PY

mkdir -p tree/sub/deeper && echo one > tree/a.txt && echo two > tree/sub/b.txt && : > tree/sub/deeper/empty
printf 'x%.0s' $(seq 1 3000) > tree/big.txt
echo cfg > config.toml && printf '#!/bin/sh\necho hi\n' > prog.sh && chmod +x prog.sh
ln -s ../a.txt tree/sub/link 2>/dev/null || true

n=0
build() {
  n=$((n + 1))
  "$bound" -q --force --launcher "$1" -o "a$n" "${@:2}" >/dev/null 2>&1 || return 0
  # Windows launchers produce aN.exe.
  if [ -f "a$n.exe" ]; then cp "a$n.exe" "$corpus/artifact/seed-$n"; else cp "a$n" "$corpus/artifact/seed-$n"; fi
}
for l in elf pe; do
  build $l -- grep -n ERROR
  build $l -- convert @args -strip out.jpg
  build $l -- cat @file:config.toml
  build $l --env MODE=prod --env CFG=@file:config.toml --cwd bundle -- run @@args @file:config.toml
  build $l --include-as data=config.toml -- prog
  build $l --embed-program -- ./prog.sh --flag
done
build elf --include tree -- ls
build elf --include tree --include-as other/x=config.toml -- "sp ace" "ünï" ""

# Manifests and names from the artifacts.
python3 - "$corpus" "$bound" <<'PY'
import json, os, subprocess, sys
corpus, bound = sys.argv[1], sys.argv[2]
for name in sorted(os.listdir(f"{corpus}/artifact")):
    path = f"{corpus}/artifact/{name}"
    data = open(path, "rb").read()
    footer = data[-88:]
    off = int.from_bytes(footer[16:24], "little"); ln = int.from_bytes(footer[24:32], "little")
    open(f"{corpus}/manifest/{name}", "wb").write(data[off:off + ln])
    doc = json.loads(subprocess.run([bound, "inspect", "--json", path], capture_output=True, check=True).stdout)
    for i, r in enumerate(doc["resources"]):
        if isinstance(r["path"], str):
            open(f"{corpus}/names/{name}-{i}", "w").write(r["path"])
PY
for s in "a/b" "../x" "C:\\x" "con.txt" "a/./b" "x:y" "trailing." '"quoted"' $'\x1b[31m'; do
  printf '%s' "$s" > "$corpus/names/manual-$(printf '%s' "$s" | shasum | cut -c1-8)"
done
echo "corpus: $(ls "$corpus/artifact" | wc -l) artifacts, $(ls "$corpus/manifest" | wc -l) manifests, $(ls "$corpus/names" | wc -l) names"
