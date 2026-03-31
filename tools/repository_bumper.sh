#!/bin/bash

set -euo pipefail

# Variables
new_version=""
new_stage=""
skip_urls=""
VERSION_FILE="VERSION.json"
LOGFILE="tools/repository_bumper_$(date +'%Y-%m-%d_%H-%M-%S').log"

usage() {
    echo "Usage: $0 [--version <version>] [--stage <stage>] [--set-as-main]"
    echo ""
    echo "Options:"
    echo "  --version <version>   Target version (e.g. 5.0.0)"
    echo "  --stage <stage>       Version stage (e.g. alpha0)"
    echo "  --set-as-main         Update version values only, preserving main branch references"
    exit 1
}

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --version)
                new_version="$2"
                shift 2
                ;;
            --stage)
                new_stage="$2"
                shift 2
                ;;
            --set-as-main)
                skip_urls=true
                shift
                ;;
            -h|--help)
                usage
                ;;
            *)
                echo "Unknown argument: $1"
                usage
                ;;
        esac
    done
}

update_version_file() {
    if [ ! -f "$VERSION_FILE" ]; then
        echo "Version file not found: $VERSION_FILE"
        exit 1
    fi

    local current_version
    local current_stage
    current_version=$(jq -r '.version' "$VERSION_FILE")
    current_stage=$(jq -r '.stage' "$VERSION_FILE")

    local new_v="${new_version:-$current_version}"
    local new_s="${new_stage:-$current_stage}"

    jq --arg v "$new_v" --arg s "$new_s" \
        '.version = $v | .stage = $s' "$VERSION_FILE" > tmp.$$.json && mv tmp.$$.json "$VERSION_FILE"

    echo "$VERSION_FILE: version $current_version -> $new_v, stage $current_stage -> $new_s" | tee -a "$LOGFILE"
}

# ---- Main ----

parse_args "$@"

echo "Modified files:" | tee "$LOGFILE"
update_version_file
