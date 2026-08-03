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

update_changelog() {
    local changelog_file="CHANGELOG.md"
    local repo_url="https://github.com/wazuh/qa-integration-framework"

    [ -z "$new_version" ] && return 0

    # Skeleton for the new version: every block heading with an empty table
    # ready to receive entries.
    local table_header=$'| Issue | Comment |\n|-------|---------|'
    local skeleton=$'# Changelog\n\nAll notable changes to this project will be documented in this file.\n\n'"## [v${new_version}]"
    local block
    for block in Added Changed Removed Fixed; do
        skeleton+=$'\n\n'"### ${block}"$'\n\n'"${table_header}"
    done

    if [ ! -f "$changelog_file" ]; then
        echo "$skeleton" > "$changelog_file"
        echo "$changelog_file: created with version $new_version" | tee -a "$LOGFILE"
        return 0
    fi

    local version_escaped="${new_version//./\\.}"
    if grep -qE "^## \[v?${version_escaped}\]" "$changelog_file"; then
        echo "$changelog_file: version $new_version already present, skipping" | tee -a "$LOGFILE"
        return 0
    fi

    # Candidate prior versions: every version section being replaced by a link
    # plus the versions already listed under "## Prior versions", newest first.
    local candidates
    candidates=$(
        {
            grep -E '^## \[v?[0-9]+\.[0-9]+\.[0-9]+\]' "$changelog_file" \
                | sed -E 's/^## \[v?([0-9]+\.[0-9]+\.[0-9]+)\].*/\1/'
            sed -n '/^## Prior versions/,$p' "$changelog_file" \
                | grep -oE 'v?[0-9]+\.[0-9]+\.[0-9]+' | sed 's/^v//'
        } | sort -Vru || true
    )

    # Ignore versions older than 5.0.0 and keep every version belonging to the
    # two latest minor series.
    local prior_tags
    prior_tags=$(awk -F. -v min_major=5 '
        NF < 3 { next }
        $1 < min_major { next }
        { mm = $1 "." $2 }
        !(mm in minors) {
            if (nminors == 2) next
            minors[mm]; nminors++
        }
        { print }' <<< "$candidates")

    # Rebuild the changelog: the new version skeleton plus the prior-version links.
    local new_content="$skeleton"
    if [ -n "$prior_tags" ]; then
        new_content+=$'\n\n'"## Prior versions"$'\n'
        local tag
        while IFS= read -r tag; do
            [ -z "$tag" ] && continue
            new_content+=$'\n'"- [v${tag}](${repo_url}/blob/v${tag}/CHANGELOG.md)"
        done <<< "$prior_tags"
    fi

    echo "$new_content" > "$changelog_file"
    echo "$changelog_file: rebuilt for version $new_version" | tee -a "$LOGFILE"
}

# ---- Main ----

parse_args "$@"

echo "Modified files:" | tee "$LOGFILE"
update_version_file
update_changelog
