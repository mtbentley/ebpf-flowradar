#!/bin/bash

if [[ -z $1 ]]; then
    echo "USAGE: $0 <prefix-num>"
    exit 1
fi

sudo rm -rf "/sys/fs/bpf/${1}"
