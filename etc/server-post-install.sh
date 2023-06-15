#!/bin/sh
set -eu

test -f /etc/ssh-inscribe/server_config.yaml ||
    ssh-inscribe defaults >/etc/ssh-inscribe/server_config.yaml

if [ -d /run/systemd/system ]; then
    systemctl --system daemon-reload || :
    if test "${1-}" -gt 1 2>/dev/null ||
       { test "${1-}" = "configure" && test -n "${2-}"; }
    then
	systemctl try-restart ssh-inscribe.service
    fi
fi
