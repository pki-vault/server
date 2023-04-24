#!/bin/bash

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
cd $SCRIPT_DIR

cfssl genkey -initca ca.json | cfssljson -bare ca
cfssl sign -ca ../alpha_ca.pem -ca-key ../alpha_ca-key.pem -config=profiles.json -profile=ca ca.csr | cfssljson -bare ca
cfssl gencert -ca ca.pem -ca-key ca-key.pem -config=profiles.json -profile=server server.json | cfssljson -bare server

cd -