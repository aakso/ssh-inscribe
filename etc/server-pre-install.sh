#!/bin/sh
set -eu

getent group sshi || groupadd --system sshi
getent passwd sshi ||
    useradd --system \
            --gid sshi \
            --home-dir /var/lib/ssh-inscribe \
            --shell /sbin/nologin \
            sshi
mkdir -p /var/lib/ssh-inscribe
chgrp sshi /var/lib/ssh-inscribe
chmod g+w /var/lib/ssh-inscribe
