#!/bin/sh
set -eu

getent group sshi || groupadd --system sshi
getent passwd sshi ||
    useradd --system \
            --gid sshi \
            --home-dir /var/lib/ssh-inscribe \
            --shell /sbin/nologin \
            sshi
