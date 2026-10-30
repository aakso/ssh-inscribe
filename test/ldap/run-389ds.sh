#!/bin/sh
# Run the authldap integration tests against 389 Directory Server in a
# container. Requires docker.
#
#   test/ldap/run-389ds.sh [go test arguments]
set -eu

IMAGE="389ds/dirsrv@sha256:af99ccf42c1cd02799d674ffdee3612a1bbd426c1a8a636da67ea349659ee5e0"
HERE=$(cd "$(dirname "$0")" && pwd)
NAME="ssh-inscribe-389ds-$$"
DM="cn=Directory Manager"

cleanup() {
    docker rm -f "$NAME" >/dev/null 2>&1 || :
}
trap cleanup EXIT INT TERM

docker run --detach --name "$NAME" \
    --publish 127.0.0.1::3389 --publish 127.0.0.1::3636 \
    --env DS_DM_PASSWORD=admin \
    "$IMAGE" >/dev/null

echo "waiting for ns-slapd" >&2
i=0
until docker exec "$NAME" ldapsearch -x -H ldap://localhost:3389 -D "$DM" -w admin \
    -b "" -s base >/dev/null 2>&1; do
    i=$((i + 1))
    if [ "$i" -gt 120 ]; then
        docker logs "$NAME" >&2
        echo "ns-slapd did not start" >&2
        exit 1
    fi
    sleep 1
done

docker exec "$NAME" dsconf localhost backend create --suffix dc=example,dc=com \
    --be-name userroot --create-suffix >/dev/null
docker cp "$HERE/389ds-aci.ldif" "$NAME:/tmp/aci.ldif"
docker cp "$HERE/openldap-seed.ldif" "$NAME:/tmp/seed.ldif"
docker exec "$NAME" ldapmodify -x -H ldap://localhost:3389 -D "$DM" -w admin -f /tmp/aci.ldif >/dev/null
docker exec "$NAME" ldapadd -x -H ldap://localhost:3389 -D "$DM" -w admin -f /tmp/seed.ldif >/dev/null

port() {
    docker port "$NAME" "$1/tcp" | head -n1 | sed 's/.*://'
}
LDAPIT_PLAIN_URL="ldap://127.0.0.1:$(port 3389)"
LDAPIT_LDAPS_URL="ldaps://127.0.0.1:$(port 3636)"
export LDAPIT_PLAIN_URL LDAPIT_LDAPS_URL

cd "$HERE/../.."
go test -count=1 -run '^TestIntegration' "$@" ./internal/auth/backend/authldap/
