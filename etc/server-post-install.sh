#!/bin/sh
set -eu

mkdir -p /etc/ssh-inscribe
test -f /etc/ssh-inscribe/server_config.yaml ||
    ssh-inscribe defaults >/etc/ssh-inscribe/server_config.yaml
