#!/bin/sh
set -eu

getent group sshi >/dev/null || groupadd --system sshi
getent passwd sshi >/dev/null ||
    useradd --system \
            --gid sshi \
            --home-dir /var/lib/ssh-inscribe \
            --shell /sbin/nologin \
            sshi
