#!/bin/bash

DIR="global-s3-assets"

# Check if jq is installed
if ! command -v jq &> /dev/null; then
  echo "jq is not installed. Please install jq to use this script."
  exit 1
fi

# Find and process each *.template file in the directory
find "$DIR" -type f -name '*.template' | while read -r file; do
  # Minify and replace the JSON content
  jq -c < "$file" > "$file.minified" && mv "$file.minified" "$file"
  echo "Minified: $file"
done