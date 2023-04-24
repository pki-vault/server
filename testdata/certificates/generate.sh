#!/bin/bash

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
cd $SCRIPT_DIR

cfssl genkey -initca alpha_ca.json | cfssljson -bare alpha_ca

# New subcommand so we don't mess up our last cd location
bash -c "./example.invalid/generate.sh"
bash -c "./wildcard.invalid/generate.sh"