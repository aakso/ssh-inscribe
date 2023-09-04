#!/bin/sh
set -eu

case ${1-} in
    0 | remove)
        [ ! -d /run/systemd/system ] || systemctl stop ssh-inscribe
        ;;
esac
