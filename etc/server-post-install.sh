#!/bin/sh
set -eu

test -f /etc/ssh-inscribe/server_config.yaml ||
    ssh-inscribe defaults >/etc/ssh-inscribe/server_config.yaml
