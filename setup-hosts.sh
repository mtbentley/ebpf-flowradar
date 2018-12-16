#!/bin/bash

set -e -o pipefail

if [[ -z $1 ]]; then
    echo "USAGE: $0 <prefix-num> [host1[ host2[ ...]]]"
    exit 1
fi

prefix_num=$1
ARGS=( "$@" );
hosts="${ARGS[@]:1}"
host_num=10101

for host in ${hosts[@]}; do
    echo "Setting up host $host with host num $host_num and prefix $prefix_num"
    pid=$(pgrep -f "mininet:${host}$")
    sudo ln -s "/proc/${pid}/ns/net" "/run/netns/${host}" || true

    sudo ./xdp-flowradar "${host}-eth0" "/run/netns/${host}" $host_num $prefix_num
    host_num=$((host_num+1))
done
