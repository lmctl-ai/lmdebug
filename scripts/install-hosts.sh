#!/usr/bin/env bash
set -euo pipefail
shopt -s globstar nullglob

if [[ ! -d examples ]]; then
  echo "install-hosts: no examples directory; nothing to install"
  exit 0
fi

mkdir -p build
host_bin="${LMCTL_HOST_BIN_DIR:-${RUNNER_TEMP:-/tmp}/lmctl-example-hosts}"
mkdir -p "$host_bin"
skip_file="${RUNNER_TEMP:-/tmp}/lmctl-unavailable-examples.tsv"
: > "$skip_file"

declare -A tags_by_repo=()
declare -A owner_by_repo=()
declare -A cli_names=()
declare -A cli_repo=()
declare -A unavailable_reason=()
declare -A resolved_latest=()
install_re="install[[:space:]]*=[[:space:]]*[\"'](github:[^\"']+)[\"']"
cli_re="cli[[:space:]]*=[[:space:]]*[\"']([^\"']+)[\"']"
examples=(examples/**/*.lms)

for example in "${examples[@]}"; do
  while IFS= read -r line || [[ -n "$line" ]]; do
    if [[ "$line" =~ $install_re ]]; then
      spec="${BASH_REMATCH[1]#github:}"
      if [[ "$spec" != *@* ]]; then
        echo "install-hosts: unsupported GitHub install (missing @TAG) in $example: $spec" >&2
        exit 1
      fi
      full_repo="${spec%@*}"
      tag="${spec##*@}"
      if [[ ! "$full_repo" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ || ! "$tag" =~ ^[A-Za-z0-9_.-]+$ ]]; then
        echo "install-hosts: invalid GitHub install in $example: $spec" >&2
        exit 1
      fi
      repo="${full_repo##*/}"
      case " ${tags_by_repo[$full_repo]-} " in
        *" $tag "*) ;;
        *) tags_by_repo["$full_repo"]="${tags_by_repo[$full_repo]-}${tags_by_repo[$full_repo]:+ }$tag" ;;
      esac
      owner_by_repo["$full_repo"]="$repo"
    fi
    if [[ "$line" =~ $cli_re ]]; then
      cli="${BASH_REMATCH[1]}"
      cli="${cli%%[[:space:]]*}"
      [[ -z "$cli" ]] || cli_names["$cli"]=1
    fi
  done < "$example"
done

for full_repo in "${!tags_by_repo[@]}"; do
  repo="${owner_by_repo[$full_repo]}"
  if [[ -n "${cli_names[$repo]+set}" ]]; then cli_repo["$repo"]="$full_repo"; fi

  if ! gh repo view "$full_repo" --json name >/dev/null 2>&1; then
    echo "install-hosts: cannot verify public repository $full_repo" >&2
    exit 1
  fi

  if ! release_tags="$(gh release list -R "$full_repo" -L 1000 --json tagName --jq '.[].tagName')"; then
    echo "install-hosts: release lookup failed for $full_repo" >&2
    exit 1
  fi
  # `gh release list` includes prereleases and is used only to validate exact
  # pins. Resolve `@latest` through GitHub's dedicated endpoint, which excludes
  # prereleases and drafts by contract. A staging prerelease must never replace
  # the host selected for an @latest public example.
  latest_tag=""
  if latest_tag="$(gh api "repos/$full_repo/releases/latest" --jq '.tag_name' 2>/dev/null)" && [[ -n "$latest_tag" ]]; then
    resolved_latest["$full_repo"]="$latest_tag"
  else
    latest_tag=""
  fi

  available_tags=()
  for requested_tag in ${tags_by_repo[$full_repo]}; do
    resolved_tag="$requested_tag"
    [[ "$requested_tag" == latest ]] && resolved_tag="$latest_tag"
    found=false
    if [[ -n "$resolved_tag" ]]; then
      while IFS= read -r listed_tag; do
        [[ "$listed_tag" == "$resolved_tag" ]] && found=true
      done <<< "$release_tags"
    fi
    if [[ "$found" != true ]]; then
      reason="$full_repo@$requested_tag has no published release; dependent examples are not checkable"
      echo "install-hosts: SKIP $full_repo@$requested_tag: $reason"
      unavailable_reason["$full_repo@$requested_tag"]="$reason"
    else
      available_tags+=("$resolved_tag")
    fi
  done

  # CLI lookup uses one PATH entry per executable name. Use the newest public
  # release binary for that name after verifying every pinned release exists.
  tag="$latest_tag"
  if [[ -z "$tag" && ${#available_tags[@]} -gt 0 ]]; then tag="${available_tags[-1]}"; fi
  if [[ -z "$tag" ]]; then
    echo "install-hosts: no released binary is available for $full_repo"
    continue
  fi

  tmp="$(mktemp -d "${RUNNER_TEMP:-/tmp}/lmctl-host-download.XXXXXX")"
  if ! gh release download "$tag" -R "$full_repo" --pattern "$repo-linux-x64" --dir "$tmp"; then
    rm -rf "$tmp"
    echo "install-hosts: release exists but $repo-linux-x64 could not be downloaded from $full_repo@$tag" >&2
    exit 1
  fi
  asset="$tmp/$repo-linux-x64"
  if [[ ! -s "$asset" ]]; then
    rm -rf "$tmp"
    echo "install-hosts: release exists but has no non-empty $repo-linux-x64 asset: $full_repo@$tag" >&2
    exit 1
  fi
  cp "$asset" "$host_bin/$repo"
  chmod +x "$host_bin/$repo"
  rm -rf "$tmp"
  echo "install-hosts: installed $repo from $full_repo@$tag for declared pins: ${tags_by_repo[$full_repo]}"
done

for cli in "${!cli_names[@]}"; do
  if [[ -z "${cli_repo[$cli]+set}" ]]; then
    echo "install-hosts: cli=\"$cli\" has no matching GitHub install declaration" >&2
    exit 1
  fi
done

for example in "${examples[@]}"; do
  while IFS= read -r line || [[ -n "$line" ]]; do
    if [[ "$line" =~ $install_re ]]; then
      spec="${BASH_REMATCH[1]#github:}"
      full_repo="${spec%@*}"
      requested_tag="${spec##*@}"
      if [[ "$requested_tag" == latest ]]; then
        requested_tag="${resolved_latest[$full_repo]-latest}"
      fi
      ref_key="$full_repo@$requested_tag"
      if [[ -n "${unavailable_reason[$ref_key]+set}" ]]; then
        printf '%s\t%s\n' "$example" "${unavailable_reason[$ref_key]}" >> "$skip_file"
        break
      fi
    fi
  done < "$example"
done

if [[ -n "${GITHUB_ENV:-}" ]]; then
  printf 'LMCTL_UNAVAILABLE_EXAMPLES_FILE=%s\n' "$skip_file" >> "$GITHUB_ENV"
fi
export PATH="$host_bin:$PATH"
if [[ -n "${GITHUB_PATH:-}" ]]; then printf '%s\n' "$host_bin" >> "$GITHUB_PATH"; fi
echo "install-hosts: host directory prepended to PATH: $host_bin"
