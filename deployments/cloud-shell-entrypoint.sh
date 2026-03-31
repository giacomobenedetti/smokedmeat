#!/bin/bash
# Copyright (C) 2026 boostsecurity.io
# SPDX-License-Identifier: AGPL-3.0-or-later

set -e

provider="${SM_PROVIDER:-}"
method="${SM_METHOD:-}"
expiry="${SM_EXPIRY:-}"
shell_home="${SM_SHELL_HOME:-/shell}"
gcp_init_script="${SM_GCP_INIT_SCRIPT:-/usr/local/lib/sm-cloud/gcp-init-creds.py}"

mkdir -p "$shell_home"

# ---------------------------------------------------------------------------
# Provider-specific credential setup
# ---------------------------------------------------------------------------

case "$provider" in
    gcp|google)
        cfg="${CLOUDSDK_CONFIG:-$HOME/.config/gcloud}"
        mkdir -p "$cfg"

        project="${CLOUDSDK_CORE_PROJECT:-${GCLOUD_PROJECT:-${GOOGLE_CLOUD_PROJECT:-}}}"
        [ -n "$project" ] && export CLOUDSDK_CORE_PROJECT="$project" GCLOUD_PROJECT="$project" GOOGLE_CLOUD_PROJECT="$project"

        {
            echo "[core]"
            [ -n "$project" ] && echo "project = $project"
            [ -n "$SM_GCP_ACCOUNT" ] && echo "account = $SM_GCP_ACCOUNT"
            echo "[auth]"
            echo "disable_credentials = false"
        } > "$cfg/properties"

        python3 "$gcp_init_script" || true

        {
            echo "[Credentials]"
            echo "[Boto]"
            echo "https_validate_certificates = True"
            echo "[GSUtil]"
            [ -n "$project" ] && echo "default_project_id = $project"
        } > "$HOME/.boto"
        export BOTO_CONFIG="$HOME/.boto"

        unset GOOGLE_APPLICATION_CREDENTIALS 2>/dev/null || true
        ;;
esac

# ---------------------------------------------------------------------------
# Generate .bashrc
# ---------------------------------------------------------------------------

tools=""
case "$provider" in
    aws)            tools="aws kubectl" ;;
    gcp|google)     tools="gcloud gsutil kubectl" ;;
    azure|az)       tools="az kubectl" ;;
    k8s|kubernetes) tools="kubectl" ;;
    ssh)            tools="git ssh" ;;
    *)              tools="aws gcloud gsutil az kubectl" ;;
esac

fit_banner_value() {
    local value="$1"
    local max_width="$2"
    if [ "${#value}" -le "$max_width" ]; then
        printf '%s' "$value"
        return
    fi
    if [ "$max_width" -le 3 ]; then
        printf '%.*s' "$max_width" "$value"
        return
    fi
    printf '...%s' "${value: -$((max_width - 3))}"
}

title_value="$(fit_banner_value "${provider} via ${method}" 21)"
title_padding=$((21 - ${#title_value}))
title_line=$(printf '│  SmokedMeat Cloud Shell (%s)%*s │' "$title_value" "$title_padding" "")

expiry_line=""
if [ -n "$expiry" ]; then
    expiry_line=$(printf '│  Expires:   %-35s │' "$(fit_banner_value "$expiry" 35)")
fi

runtime_line=$(printf '│  Runtime:   %-35s │' "$(fit_banner_value "ephemeral container" 35)")
persist_line=$(printf '│  Persist:   %-35s │' "$(fit_banner_value "/shell is host mounted" 35)")

transfer_line=""
if [ -n "$SM_SHARED" ]; then
    transfer_line=$(printf '│  Transfer:  %-35s │' "$(fit_banner_value "use /shared for copy in/out" 35)")
fi

shared_line=""
if [ -n "$SM_SHARED" ]; then
    shared_line=$(printf '│  Shared:    %-35s │' "$(fit_banner_value "$SM_SHARED" 35)")
fi

ssh_key_line=""
if [ -n "$SM_SSH_FINGERPRINT" ]; then
    ssh_key_line=$(printf '│  Key:       %-35s │' "$(fit_banner_value "$SM_SSH_FINGERPRINT" 35)")
fi

ssh_scope_line=""
if [ -n "$SM_SSH_SCOPE" ]; then
    ssh_scope_line=$(printf '│  Scope:     %-35s │' "$(fit_banner_value "$SM_SSH_SCOPE" 35)")
fi

ssh_helpers_line=""
if [ "$provider" = "ssh" ]; then
    ssh_helpers_line=$(printf '│  Helpers:   %-35s │' "$(fit_banner_value "sm-context | sm-clone | vim | nano" 35)")
fi

cat > "$shell_home/.bashrc" <<BASHRC
export PS1='[sm:${provider:-cloud}/${method:-shell}] \w\$ '
cd "\$HOME"
for f in /usr/share/bash-completion/bash_completion /etc/bash_completion /usr/local/etc/bash_completion; do
    [ -f "\$f" ] && . "\$f" && break
done 2>/dev/null
if [ -n "\${SM_SSH_IDENTITY:-}" ] && [ -n "\${SM_SSH_KNOWN_HOSTS:-}" ]; then
    ssh() {
        command ssh \
            -o IdentitiesOnly=yes \
            -o IdentityFile="\$SM_SSH_IDENTITY" \
            -o UserKnownHostsFile="\$SM_SSH_KNOWN_HOSTS" \
            -o StrictHostKeyChecking=yes \
            -o LogLevel=ERROR \
            "\$@"
    }
fi

echo ''
echo '╭─────────────────────────────────────────────────╮'
echo '$title_line'
echo '│                                                 │'
$(printf "echo '│  Provider:  %-35s │'" "$(fit_banner_value "$provider" 35)")
$(printf "echo '│  Method:    %-35s │'" "$(fit_banner_value "$method" 35)")
$([ -n "$expiry_line" ] && echo "echo '$expiry_line'")
$([ -n "$ssh_key_line" ] && echo "echo '$ssh_key_line'")
$([ -n "$ssh_scope_line" ] && echo "echo '$ssh_scope_line'")
echo '$runtime_line'
echo '$persist_line'
echo '│                                                 │'
$(printf "echo '│  Tools:     %-35s │'" "$(fit_banner_value "$tools" 35)")
$([ -n "$ssh_helpers_line" ] && echo "echo '$ssh_helpers_line'")
$([ -n "$transfer_line" ] && echo "echo '$transfer_line'")
$([ -n "$shared_line" ] && echo "echo '$shared_line'")
echo '│                                                 │'
echo '│  Type exit or Ctrl+D to return                  │'
echo '╰─────────────────────────────────────────────────╯'
echo ''
BASHRC

# Append sanity check
case "$provider" in
    gcp|google)
        sa="${SM_GCP_ACCOUNT:-unknown}"
        cat >> "$shell_home/.bashrc" <<SANITY
if ! command -v gcloud >/dev/null 2>&1; then
    echo "WARNING: gcloud not installed"
elif gcloud auth print-access-token >/dev/null 2>&1; then
    echo "gcloud: authenticated as $sa"
else
    echo "WARNING: gcloud credential bootstrap failed"
fi
if ! command -v gsutil >/dev/null 2>&1; then
    echo "WARNING: gsutil wrapper unavailable"
fi
project="\$(gcloud config get project 2>/dev/null || true)"
if [ -n "\$project" ] && [ "\$project" != "(unset)" ]; then
    echo "gcloud: project \$project"
else
    echo "WARNING: gcloud project is unset"
fi
SANITY
        ;;
    aws)
        echo 'aws sts get-caller-identity 2>/dev/null || echo "aws not available"' >> "$shell_home/.bashrc"
        ;;
    azure|az)
        echo 'az account show 2>/dev/null || echo "az not available"' >> "$shell_home/.bashrc"
        ;;
    k8s|kubernetes)
        echo 'kubectl cluster-info 2>/dev/null || echo "kubectl not available"' >> "$shell_home/.bashrc"
        ;;
    ssh)
        cat >> "$shell_home/.bashrc" <<SANITY
if ! command -v git >/dev/null 2>&1; then
    echo "WARNING: git not installed"
else
    echo "git: ready"
fi
if ! command -v ssh >/dev/null 2>&1; then
    echo "WARNING: ssh not installed"
elif ssh -G github.com >/dev/null 2>&1; then
    echo "ssh: config ready for github.com"
else
    echo "WARNING: ssh config bootstrap failed"
fi
echo
if command -v sm-context >/dev/null 2>&1; then
    sm-context || true
fi
SANITY
        ;;
esac

if [ "${SM_ENTRYPOINT_WRITE_ONLY:-0}" = "1" ]; then
    exit 0
fi

exec bash --rcfile "$shell_home/.bashrc"
