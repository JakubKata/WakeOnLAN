#!/bin/sh
set -eu
umask 077
: "${TLS_SERVER_NAME:?TLS_SERVER_NAME is required}"
: "${ACME_EMAIL:?ACME_EMAIL is required}"
trap 'exit 0' TERM INT

while :; do
    if [ -f /etc/letsencrypt/live/wol/fullchain.pem ]; then
        if certbot renew --cert-name wol --non-interactive \
            --deploy-hook 'python /opt/acme/deploy.py'; then
            renewed=true
        else
            renewed=false
        fi
    else
        if certbot certonly --standalone --non-interactive --agree-tos \
            --email "$ACME_EMAIL" --domain "$TLS_SERVER_NAME" --cert-name wol \
            --key-type ecdsa --deploy-hook 'python /opt/acme/deploy.py'; then
            renewed=true
        else
            renewed=false
        fi
    fi

    # Restore a missing runtime volume even when no renewal was due. A failed
    # hook must not mark the service healthy if Certbot itself returned 0.
    if [ "$renewed" = true ] && RENEWED_LINEAGE=/etc/letsencrypt/live/wol \
        python /opt/acme/deploy.py; then
        touch /run/wol-tls/renewal-ok
        delay=43200
    else
        echo 'ACME issuance/renewal or TLS deployment failed; retrying in one hour' >&2
        delay=3600
    fi
    # Jitter spreads renewal checks across installations; no forced renewals.
    jitter=$(python -c 'import secrets; print(secrets.randbelow(300))')
    sleep "$((delay + jitter))" &
    wait $!
done
