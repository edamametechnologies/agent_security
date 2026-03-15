#!/bin/bash
# Shared VM execution helper - uses SSH instead of limactl shell
# (limactl shell hangs on some macOS versions)
#
# Source this file in test scripts: source "$(dirname "$0")/lib/vm_exec.sh"

_VM_SSH_PORT=""
_vm_resolve_port() {
    if [ -n "$_VM_SSH_PORT" ]; then return; fi
    local vm="${VM_NAME:-agent-security}"
    _VM_SSH_PORT=$(limactl list 2>/dev/null | grep "$vm" | grep -oE '127\.0\.0\.1:[0-9]+' | head -1 | cut -d: -f2)
    if [ -z "$_VM_SSH_PORT" ]; then
        echo "ERROR: cannot resolve SSH port for VM '$vm'" >&2
        return 1
    fi
}

_vm_ssh_args() {
    _vm_resolve_port
    echo "-i" "$HOME/.lima/_config/user" "-o" "StrictHostKeyChecking=no" "-o" "ConnectTimeout=10" "-p" "$_VM_SSH_PORT" "$(whoami)@127.0.0.1"
}

vm_exec() {
    _vm_resolve_port
    local _user
    _user="$(whoami)"
    printf '%s\n' "$1" | ssh -i ~/.lima/_config/user -o StrictHostKeyChecking=no -o ConnectTimeout=10 \
        -p "$_VM_SSH_PORT" "${_user}@127.0.0.1" bash -l
}

vm_exec_raw() {
    _vm_resolve_port
    ssh -i ~/.lima/_config/user -o StrictHostKeyChecking=no -o ConnectTimeout=10 \
        -p "$_VM_SSH_PORT" "$(whoami)@127.0.0.1" "$@" 2>&1
}

vm_scp_to() {
    _vm_resolve_port
    scp -i ~/.lima/_config/user -o StrictHostKeyChecking=no \
        -P "$_VM_SSH_PORT" "$1" "$(whoami)@127.0.0.1:$2" 2>&1
}
