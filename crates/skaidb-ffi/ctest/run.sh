#!/bin/bash
# C and C++ smoke tests for libskaidb.
#
#   crates/skaidb-ffi/ctest/run.sh                 # spawns target/debug/skaidb on free ports
#   SKAIDB_ENDPOINT=host:port SKAIDB_USER=u SKAIDB_PASSWORD=p crates/skaidb-ffi/ctest/run.sh
#
# Builds the static library, compiles smoke.c (C11) and smoke.cpp (C++17)
# against it with -Wall -Wextra -Werror, and runs both against a server.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../../.." && pwd)
cd "$root"
cargo build -q -p skaidb-ffi -p skaidb-server
lib=target/debug/libskaidb.a
tmp=$(mktemp -d "${TMPDIR:-/tmp}/skaidb-ctest.XXXXXX")
srv=""
cleanup() {
  if [[ -n "$srv" ]]; then kill "$srv" 2>/dev/null || true; wait "$srv" 2>/dev/null || true; fi
  rm -rf "$tmp"
}
trap cleanup EXIT
if [[ -z "${SKAIDB_ENDPOINT:-}" ]]; then
  base=$((20000 + RANDOM % 20000))
  cat > "$tmp/skaidb.toml" <<CFG
[server]
bind_addr = "127.0.0.1"
quic_port = $base
rest_port = $((base + 1))
data_dir = "$tmp/data"
[cluster]
internode_port = $((base + 2))
[auth]
superuser = "ctest"
superuser_password = "ctestpw"
[observability]
prometheus_port = $((base + 3))
[mqtt]
enabled = false
CFG
  target/debug/skaidb --config "$tmp/skaidb.toml" > "$tmp/server.log" 2>&1 &
  srv=$!
  for _ in $(seq 1 150); do
    if (exec 3<>"/dev/tcp/127.0.0.1/$base") 2>/dev/null; then break; fi
    sleep 0.2
  done
  export SKAIDB_ENDPOINT="127.0.0.1:$base" SKAIDB_USER=ctest SKAIDB_PASSWORD=ctestpw
fi
libs="-lpthread -ldl -lm"
gcc -std=c11 -Wall -Wextra -Werror -I "$here/../include" "$here/smoke.c" "$lib" $libs -o "$tmp/smoke_c"
g++ -std=c++17 -Wall -Wextra -Werror -I "$here/../include" "$here/smoke.cpp" "$lib" $libs -o "$tmp/smoke_cpp"
"$tmp/smoke_c"
"$tmp/smoke_cpp"
