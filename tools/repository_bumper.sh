#!/bin/bash

# Check for the correct number of arguments
if [ "$#" -ne 2 ]; then
    echo "Usage: $0 <new_version> <stage>"
    exit 1
fi

NEW_VERSION="$1"
NEW_STAGE="$2"
VERSION_FILE="VERSION.json"
LOGFILE="tools/repository_bumper_$(date +'%Y-%m-%d_%H-%M-%S').log"

# Check if version.json exists
if [ ! -f "$VERSION_FILE" ]; then
    echo "Version file not found!"
    exit 1
fi

# Read the current version and stage from the JSON file
CURRENT_VERSION=$(jq -r '.version' "$VERSION_FILE")
CURRENT_STAGE=$(jq -r '.stage' "$VERSION_FILE")

echo "Current version: $CURRENT_VERSION"
echo "Current stage: $CURRENT_STAGE"

# Update the JSON file with the new version and stage
jq --arg new_version "$NEW_VERSION" --arg new_stage "$NEW_STAGE" \
   '.version = $new_version | .stage = $new_stage' "$VERSION_FILE" > tmp.$.json && mv tmp.$.json "$VERSION_FILE"

# Log the changes
echo "Modified files:" | tee "$LOGFILE"
echo "$VERSION_FILE: version $CURRENT_VERSION -> $NEW_VERSION, stage $CURRENT_STAGE -> $NEW_STAGE" | tee -a "$LOGFILE"
