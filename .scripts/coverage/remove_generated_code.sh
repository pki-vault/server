#!/bin/bash

# This script removes all generated files from the coverage report.

# Get the directory path of the script
script_dir=$(dirname "$(readlink -f "$0")")

# Path to the coverage file
coverage_file="$script_dir/../../coverage.out"

# Path to the file containing the filters
filter_file="$script_dir/filters.txt"

# Temp file to store the filtered coverage
temp_file=$(mktemp)

# Read each filter from the filter file and store them in an array
IFS=$'\r\n' filters=($(cat "$filter_file"))

# Iterate over each line in the coverage file
while IFS= read -r line; do
    # Flag to determine if the line should be filtered
    filter_line=false

    # Check if the line starts with any of the filters
    for filter in "${filters[@]}"; do
        if [[ $line == $filter* ]]; then
            filter_line=true
            break
        fi
    done

    # Append the line to the temp file if it doesn't match any filter
    if ! $filter_line; then
        echo "$line" >> "$temp_file"
    fi
done < "$coverage_file"

# Overwrite the original coverage file with the filtered contents
mv "$temp_file" "$coverage_file"
