#!/usr/bin/env bash
# Smoke test of the release binaries on Linux and macOS, following the
# README examples. Uses the real `bound` and the `bound-launcher` next to it.
#
#   scripts/smoke.sh [DIR]    # DIR holds bound and bound-launcher (default: target/release)
set -euo pipefail

bin="$(cd "${1:-target/release}" && pwd)"
bound="$bin/bound"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
cd "$work"

fail() { echo "smoke: FAIL: $*" >&2; exit 1; }
step() { echo "smoke: $*"; }

step "argument binding"
printf 'ok\nERROR one\nfine\nERROR two\n' > server.log
"$bound" -o grep-errors -- grep -n ERROR
[ "$(./grep-errors server.log)" = "$(printf '2:ERROR one\n4:ERROR two')" ] || fail "grep-errors output"

step "@args placement"
"$bound" -o greet -- printf '%s|' before @args after
[ "$(./greet x 'y z')" = "before|x|y z|after|" ] || fail "@args placement"

step "embedded file survives removal of the original"
printf '[db]\nurl = "x"\n' > config.toml
"$bound" -o show-config -- cat @file:./config.toml
rm config.toml
[ "$(./show-config)" = "$(printf '[db]\nurl = "x"')" ] || fail "show-config output"

step "included directory and BOUND_ROOT"
mkdir -p templates/partials
echo '<h1>hi</h1>' > templates/index.html
"$bound" -o render --include ./templates --cwd bundle -- sh -c 'cat templates/index.html; test "$PWD" = "$BOUND_ROOT"'
rm -r templates
[ "$(./render)" = "<h1>hi</h1>" ] || fail "render output"

step "a working directory in the bundle"
mkdir -p site/pages
echo page > site/pages/index.txt
"$bound" -q -o in-pages --include ./site --cwd @bundle:site/pages -- sh -c 'cat index.txt; test "$PWD" = "$BOUND_ROOT/site/pages"'
rm -r site
[ "$(./in-pages)" = "page" ] || fail "in-pages output"
"$bound" inspect --json ./in-pages | grep -q '"format": 2' || fail "a working directory in the bundle needs format 2"

step "a bundled directory put first in PATH"
mkdir -p tools
printf '#!/bin/sh\necho from-bundle\n' > tools/hello
chmod +x tools/hello
"$bound" -q -o hello --include ./tools --env-prepend PATH=@bundle:tools --env-append PATH=/nowhere -- hello
"$bound" -q -o show-path --include ./tools --env-prepend PATH=@bundle:tools --env-append PATH=/nowhere -- sh -c 'printf %s "$PATH"'
rm -r tools
[ "$(./hello)" = "from-bundle" ] || fail "hello output"
case "$(PATH=/usr/bin:/bin ./show-path)" in
  */tools:/usr/bin:/bin:/nowhere) ;;
  *) fail "PATH order: $(PATH=/usr/bin:/bin ./show-path)" ;;
esac

step "an artifact named like its program runs the next one in PATH"
mkdir -p wrappers
"$bound" -q -o wrappers/printf -- printf '[%s]'
[ "$(PATH="$work/wrappers:$PATH" ./wrappers/printf a)" = "[a]" ] || fail "self-lookup"

step "the program keeps the artifact's process ID"
echo data > data.txt
"$bound" -q -o pid --include data.txt -- sh -c 'echo $$'
./pid > pid.out & launched=$!
wait $launched
[ "$(cat pid.out)" = "$launched" ] || fail "PID changed: launched $launched, program $(cat pid.out)"

step "shared bundles"
export BOUND_CACHE_DIR="$work/cache"
"$bound" -q -o shared --bundle shared --include data.txt --cwd bundle -- sh -c 'pwd; cat data.txt'
first="$(./shared)"; second="$(./shared)"
[ "$first" = "$second" ] || fail "shared bundle changed between runs"
"$bound" cache list | grep -q "Shared bundles: 1" || fail "cache list"
"$bound" cache clean | grep -q "Removed 1 cache entry" || fail "cache clean"
unset BOUND_CACHE_DIR

step "exit status"
"$bound" -o fail -- sh -c 'exit 42'
set +e; ./fail; code=$?; set -e
[ "$code" = 42 ] || fail "expected exit status 42, got $code"

step "inspect and verify"
"$bound" inspect ./show-config
"$bound" inspect --json ./show-config > inspect.json
grep -q '"inspect_format": 1' inspect.json || fail "inspect --json"
"$bound" verify ./show-config

step "corruption is detected"
# Damage the bundled data. (Not the end of the file: on macOS that is the
# code signature, which bound leaves to codesign.)
offset=$(awk '/"payload"/ { found = 1 } found && /"offset"/ { gsub(/[^0-9]/, ""); print; exit }' inspect.json)
[ -n "$offset" ] || fail "no payload offset in inspect --json"
cp show-config broken
printf 'XXXX' | dd of=broken bs=1 seek="$offset" conv=notrunc 2>/dev/null
if "$bound" verify ./broken >/dev/null 2>&1; then fail "corruption was not detected"; fi

step "refuses to overwrite"
if "$bound" -o show-config -- true 2>/dev/null; then fail "overwrote an existing file"; fi

echo "smoke: all checks passed"
