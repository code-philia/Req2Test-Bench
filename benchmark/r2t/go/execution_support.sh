#!/bin/bash
# Trusted coordinator-supplied source, run using pinned image Bash/coreutils.
set -euo pipefail
scan() {
    for entry in /proc/[0-9]*/stat; do
        [[ -r "$entry" ]] || continue
        IFS= read -r raw < "$entry" || continue
        pid=${raw%% *}
        [[ "$pid" == "$$" || "$pid" == "$BASHPID" ]] && continue
        rest=${raw##*) }
        read -r -a fields <<< "$rest"
        printf '%s %s %s %s %s\n' "$pid" "${fields[1]}" "${fields[2]}" "${fields[3]}" "${fields[19]}"
    done
}
case "$1" in
inventory)
    cd "$2"
    paths=$(find . -mindepth 1 ! -type d -print0 | base64 -w0)
    payload=$(printf '%s' "$paths" | base64 -d | while IFS= read -r -d '' path; do
        [[ -f "$path" && ! -L "$path" ]] || { printf 'nonregular input\n' >&2; exit 1; }
        sha256sum -z -- "$path"
    done | base64 -w0)
    printf 'R2T_INVENTORY/1\n%s\nR2T_INVENTORY_END\n' "$payload"
    ;;
read|read-optional)
    if [[ "$1" == read-optional && ! -e "$2/$3" && ! -L "$2/$3" ]]; then
        printf 'R2T_ABSENT/1\nR2T_ABSENT_END\n'
        exit 0
    fi
    [[ -f "$2/$3" && ! -L "$2/$3" ]]
    payload=$(base64 -w0 -- "$2/$3")
    printf 'R2T_BYTES/1\n%s\nR2T_BYTES_END\n' "$payload"
    ;;
metadata)
    [[ -f "$2/$3" && ! -L "$2/$3" ]]
    read -r mutation_mode mutation_uid mutation_gid < <(stat -c '%f %u %g' -- "$2/$3")
    payload=$(printf '{"mode":%d,"uid":%d,"gid":%d}' "$((16#$mutation_mode))" "$mutation_uid" "$mutation_gid" | base64 -w0)
    printf 'R2T_METADATA/1\n%s\nR2T_METADATA_END\n' "$payload"
    ;;
prepare-reference)
    mkdir /r2t-go/run/mutation-reference
    mkdir /r2t-go/run/mutation-reference/tmp
    # Per-worker reference GOCACHE (mutation_copy.REFERENCE_CACHE): outside
    # /r2t-go/run, so neither prepare/retire nor retire-reference removes it.
    mkdir -p /r2t-go/mutation-cache
    ;;
copy-reference)
    # The coordinator supplies a validated, hash-bound nonremovable whitelist.
    # Read only the immutable original mount, never the candidate execution copy.
    base64 -d | while IFS= read -r -d '' mutation_path; do
        [[ -f "/work/$mutation_path" && ! -L "/work/$mutation_path" ]]
        mkdir -p -- "/r2t-go/run/mutation-reference/source/$(dirname -- "$mutation_path")"
        cp -p -- "/work/$mutation_path" "/r2t-go/run/mutation-reference/source/$mutation_path"
    done
    ;;
retire-reference)
    rm -rf -- /r2t-go/run/mutation-reference
    [[ ! -e /r2t-go/run/mutation-reference ]]
    ;;
prepare)
    rm -rf -- /r2t-go/run /r2t-go/tmp
    mkdir -p /r2t-go/run/work /r2t-go/tmp /r2t-go/cache
    cp -a /work/. /r2t-go/run/work/
    ;;
write)
    mkdir -p -- "$(dirname -- "$2/$3")"
    base64 -d > "$2/$3"
    ;;
processes)
    printf 'R2T_PROCESSES/1\n'
    scan
    printf 'R2T_PROCESSES_END\n'
    ;;
execute)
    duration=$2
    shift 2
    cd /r2t-go/run/work
    export TMPDIR=/r2t-go/tmp GOTMPDIR=/r2t-go/tmp GOCACHE=/r2t-go/cache
    # DockerRunner enters through a login shell; restore the pinned image tool
    # directory for this command and children spawned by the typed planner.
    export PATH="/usr/local/go/bin:$PATH"
    export GOPROXY=off GOWORK=off GOTOOLCHAIN=local GOFLAGS=-mod=readonly
    set +e
    LC_ALL=C timeout --verbose --signal=TERM --kill-after=5s "$duration" /bin/bash -c '
        IFS= read -r raw < /proc/$$/stat
        rest=${raw##*) }
        read -r -a fields <<< "$rest"
        printf "%s %s %s %s\n" "$$" "${fields[2]}" "${fields[3]}" "${fields[19]}" > /r2t-go/run/command-identity.tsv
        exec "$@" > /r2t-go/run/stdout.log 2>&1
    ' r2t-execution "$@" 2> /r2t-go/run/timeout.log &
    monitor=$!
    printf '%s\n' "$monitor" > /r2t-go/run/timeout-monitor.pid
    wait "$monitor"
    result=$?
    printf '%s\n' "$result" > /r2t-go/run/exit-code.txt
    exit "$result"
    ;;
cleanup)
    baseline=$(printf '%s' "$2" | base64 -d)
    declare -A old groups
    while read -r pid ppid pgid sid start; do
        [[ -n "$pid" ]] || continue
        old[$pid]="$ppid $pgid $sid $start"
        groups[$pgid]=1
    done <<< "$baseline"
    IFS= read -r raw < /proc/$$/stat
    rest=${raw##*) }
    read -r -a self <<< "$rest"
    groups[${self[2]}]=1
    for attempt in 0 1 2 3 4 5 6 7; do
        current=$(scan)
        # scan runs in command substitution: exclude that child as well as
        # the helper parent, whose $$ remains Bash's original process ID.
        declare -A present=()
        extras=()
        while read -r pid ppid pgid sid start; do
            [[ -n "$pid" ]] || continue
            # BASHPID is different inside scan's command substitution. The
            # subshell is already gone here; ignoring gone identities is safe.
            [[ -r "/proc/$pid/stat" ]] || continue
            present[$pid]="$ppid $pgid $sid $start"
            if [[ -v old[$pid] ]]; then
                [[ "${old[$pid]}" == "${present[$pid]}" ]] || exit 70
            else
                extras+=("$pid $pgid $start")
            fi
        done <<< "$current"
        for pid in "${!old[@]}"; do
            [[ -v present[$pid] && "${present[$pid]}" == "${old[$pid]}" ]] || exit 70
        done
        if (( ${#extras[@]} == 0 )); then
            printf 'R2T_CLEANUP/1\ncomplete\nR2T_CLEANUP_END\n'
            exit 0
        fi
        signal=TERM
        (( attempt < 5 )) || signal=KILL
        for tuple in "${extras[@]}"; do
            read -r pid pgid start <<< "$tuple"
            [[ -r "/proc/$pid/stat" ]] || continue
            IFS= read -r raw < "/proc/$pid/stat" || continue
            rest=${raw##*) }
            read -r -a fields <<< "$rest"
            [[ "${fields[19]}" == "$start" ]] || continue
            if [[ ! -v groups[$pgid] && "$pgid" != 0 ]]; then
                kill -s "$signal" -- "-$pgid" 2>/dev/null || true
            fi
            kill -s "$signal" -- "$pid" 2>/dev/null || true
        done
        sleep 1
    done
    exit 70
    ;;
retire)
    rm -rf -- /r2t-go/run /r2t-go/tmp
    [[ ! -e /r2t-go/run && ! -e /r2t-go/tmp ]]
    ;;
*) exit 64 ;;
esac
