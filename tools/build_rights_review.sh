#!/usr/bin/env bash
# Rebuild the checked-in rights review from its canonical LaTeX source.
set -euo pipefail

root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
source="$root/docs/legal/rights-review.tex"
destination="$root/UMI Rights Review Sign-Language Datasets and Public Model Weights.pdf"
engine=${TECTONIC:-tectonic}
if ! command -v "$engine" >/dev/null 2>&1; then
  echo 'Install Tectonic (https://tectonic-typesetting.github.io/), then rerun this script.' >&2
  exit 1
fi
if (( $# > 1 )) || { (( $# == 1 )) && [[ $1 != --check ]]; }; then
  echo "Usage: $0 [--check]" >&2
  exit 2
fi

build=$(mktemp -d "${TMPDIR:-/tmp}/umi-rights-review.XXXXXX")
trap 'rm -rf -- "$build"' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
# Stable PDF dates; update this value with the dated policy revision.
export SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-1793145600}
export TZ=UTC
start=$SECONDS
echo 'Rights review: compiling LaTeX (1/2); planning ETA 10–120 s with cached packages, longer on first download.'
if ! "$engine" --untrusted --keep-logs --outdir "$build" "$source" >"$build/compiler-output.txt" 2>&1; then
  cat "$build/compiler-output.txt" >&2
  exit 1
fi
if grep -Eq 'Overfull \\[hv]box|Missing character|undefined references' "$build/rights-review.log"; then
  cat "$build/compiler-output.txt" >&2
  echo 'PDF has layout or unresolved-reference errors; the published PDF was not replaced.' >&2
  exit 1
fi
echo "Rights review: compiled (2/2), elapsed $((SECONDS-start)) s."
if [[ ${1:-} == --check ]]; then
  if ! cmp -s "$build/rights-review.pdf" "$destination"; then
    echo 'Checked-in PDF differs. Run tools/build_rights_review.sh and commit it with the source.' >&2
    exit 1
  fi
  echo 'Checked-in PDF matches the LaTeX build.'
else
  # Use a sibling temporary file so a failed build never leaves a partial PDF.
  staged=$(mktemp "$root/.rights-review-pdf.XXXXXX")
  trap 'rm -rf -- "$build"; rm -f -- "$staged"' EXIT
  cp -- "$build/rights-review.pdf" "$staged"
  chmod 644 "$staged"
  mv -f -- "$staged" "$destination"
  echo "Updated: $destination"
fi
