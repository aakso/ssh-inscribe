#!/bin/sh
# Run the authldap integration tests against OpenLDAP 2.4.57 in a container.
# Requires docker.
#
#   test/ldap/run-openldap.sh [go test arguments]
set -eu

IMAGE="osixia/openldap:1.5.0@sha256:18742e9c449c9c1afe129d3f2f3ee15fb34cc43e5f940a20f3399728f41d7c28"
HERE=$(cd "$(dirname "$0")" && pwd)
NAME="ssh-inscribe-openldap-$$"

cleanup() {
    docker rm -f "$NAME" >/dev/null 2>&1 || :
}
trap cleanup EXIT INT TERM

docker run --detach --name "$NAME" \
    --publish 127.0.0.1::389 --publish 127.0.0.1::636 \
    --env LDAP_DOMAIN=example.com \
    --env LDAP_ADMIN_PASSWORD=admin \
    --env LDAP_TLS_VERIFY_CLIENT=never \
    "$IMAGE" >/dev/null

echo "waiting for slapd" >&2
i=0
until docker exec "$NAME" ldapsearch -x -H ldap://localhost -b dc=example,dc=com \
    -D cn=admin,dc=example,dc=com -w admin -s base >/dev/null 2>&1; do
    i=$((i + 1))
    if [ "$i" -gt 60 ]; then
        docker logs "$NAME" >&2
        echo "slapd did not start" >&2
        exit 1
    fi
    sleep 1
done

docker cp "$HERE/openldap-acl.ldif" "$NAME:/tmp/acl.ldif"
docker cp "$HERE/openldap-seed.ldif" "$NAME:/tmp/seed.ldif"
docker exec "$NAME" ldapmodify -Q -Y EXTERNAL -H ldapi:/// -f /tmp/acl.ldif >/dev/null
docker exec "$NAME" ldapadd -x -H ldap://localhost -D cn=admin,dc=example,dc=com -w admin -f /tmp/seed.ldif >/dev/null

port() {
    docker port "$NAME" "$1/tcp" | head -n1 | sed 's/.*://'
}
LDAPIT_PLAIN_URL="ldap://127.0.0.1:$(port 389)"
LDAPIT_LDAPS_URL="ldaps://127.0.0.1:$(port 636)"
export LDAPIT_PLAIN_URL LDAPIT_LDAPS_URL

cd "$HERE/../.."
go test -count=1 -run '^TestIntegration' "$@" ./internal/auth/backend/authldap/
