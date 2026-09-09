# Validate one service account's /etc/subuid or /etc/subgid allocation.
# The caller supplies `account` and numeric `uid`. Every non-comment input row
# must be canonical, at least one selected range must contain 65,536 IDs, and a
# selected range must not overlap any other allocation.

/^[[:space:]]*($|#)/ { next }

NF != 3 || $1 == "" || $2 !~ /^[0-9]+$/ || $3 !~ /^[0-9]+$/ {
  malformed = 1
  next
}

{
  start = $2 + 0
  count = $3 + 0
  end = start + count - 1
  if (count < 1 || start < 1 || end < start || end > 4294967295) {
    malformed = 1
    next
  }

  entries += 1
  starts[entries] = start
  ends[entries] = end
  if ($1 == account || $1 == uid) {
    selected[entries] = 1
    if (count >= 65536) {
      sufficient = 1
    }
  }
}

END {
  if (malformed || !sufficient) {
    exit 1
  }
  for (left = 1; left <= entries; left += 1) {
    for (right = left + 1; right <= entries; right += 1) {
      if (!selected[left] && !selected[right]) {
        continue
      }
      if (starts[left] <= ends[right] && starts[right] <= ends[left]) {
        exit 1
      }
    }
  }
}
