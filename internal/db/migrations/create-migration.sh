#!/bin/sh

# Define an array of database types
db_types="postgresql"

script_dir=$(dirname "$0")

# Loop through the array and create a new migration file for each type
for type in $db_types
do
    migrate create -ext sql -dir "$script_dir/$type" -seq "$1"
done
