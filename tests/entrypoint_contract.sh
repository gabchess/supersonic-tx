#!/bin/sh
set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
tmp_dir=$(mktemp -d)
trap 'rm -rf "$tmp_dir"' EXIT HUP INT TERM

mkdir -p "$tmp_dir/home/.cargo/bin" "$tmp_dir/bin" "$tmp_dir/caller with spaces"

cat >"$tmp_dir/home/.cargo/bin/cargo" <<'EOF'
#!/bin/sh
printf '%s\n' "$@"
EOF
chmod +x "$tmp_dir/home/.cargo/bin/cargo"

output=$(cd "$tmp_dir/caller with spaces" && \
  HOME="$tmp_dir/home" PATH="$tmp_dir/bin:/usr/bin:/bin" \
    "$repo_root/scripts/noisebench" audit relative-fixtures/ --json relative-report.json)

expected='run
--manifest-path
'"$repo_root"'/Cargo.toml
--release
--locked
--
audit
relative-fixtures/
--json
relative-report.json'

if [ "$output" != "$expected" ]; then
  printf 'unexpected launcher arguments:\n%s\n' "$output" >&2
  exit 1
fi

if HOME="$tmp_dir/missing" PATH="$tmp_dir/bin:/usr/bin:/bin" \
  "$repo_root/scripts/noisebench" --help >"$tmp_dir/stdout" 2>"$tmp_dir/stderr"; then
  printf 'launcher succeeded without Cargo\n' >&2
  exit 1
fi

grep -F 'Cargo was not found' "$tmp_dir/stderr" >/dev/null
