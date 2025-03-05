#!/bin/bash

# Read from stdin (handles here-document)
# awk '
#     BEGIN {first=1}
#     {
#         if (first) {
#             # Print first line as is
#             printf "%s\n", $0
#             first=0
#         } else {
#             # For subsequent lines, add formatting
#             if ($0 ~ /^--/) {
#                 # Line already starts with --, just print it
#                 printf "%s\n", $0
#             } else {
#                 # Add formatting for -- in the middle of the line
#                 gsub(/--/, "\\\n--")
#                 printf "%s\n", $0
#             }
#         }
#     }'
awk '
BEGIN {first=1}
{
    # Remove trailing whitespace
    sub(/[ \t]+$/, "")
    
    if ($0 ~ /\\$/) {
        # Line ends with backslash - print it as is
        printf "%s\n", $0
    } else if (first) {
        # Print first line as is
        printf "%s\n", $0
        first=0
    } else {
        # For subsequent lines, add formatting
        if ($0 ~ /^--/) {
            # Line already starts with --, just print it
            printf "%s\n", $0
        } else {
            # Add formatting for -- in the middle of the line
            gsub(/--/, "\\\n--")
            printf "%s\n", $0
        }
    }
}'
