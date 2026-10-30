#!/bin/sh
set -eu

# The configuration may hold secrets (tokenSigningKey, pkcs11Pin, OIDC
# clientSecret); never create it world-readable.
if ! test -f /etc/ssh-inscribe/server_config.yaml; then
    (umask 027 && ssh-inscribe defaults >/etc/ssh-inscribe/server_config.yaml)
    chgrp sshi /etc/ssh-inscribe/server_config.yaml
fi

if [ -d /run/systemd/system ]; then
    systemctl --system daemon-reload || :
    if test "${1-}" -gt 1 2>/dev/null ||
       { test "${1-}" = "configure" && test -n "${2-}"; }
    then
	systemctl try-restart ssh-inscribe.service
    fi
fi
