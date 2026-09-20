#!/usr/bin/env bash
# Debian/Ubuntu relay. Requires an existing, running OpenSSH service; no package
# installation or firewall changes. The first active sshd_config directive must
# be: Include /etc/ssh/sshd_config.d/*.conf
# Kit snippets must precede other snippets so earlier Match rules cannot weaken
# a device's restrictions. Registry files contain public keys only. Uses the
# standard ssh service and /etc/ssh/sshd_config (no alternate -f/-o overrides).
# GatewayPorts in Match must be supported; sshd -t rejects older implementations.
# The shared GatewayPorts=no snippet is retained after the last device revocation.
set -euo pipefail
export LC_ALL=C
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
umask 077

fail() { printf 'relay: %s\n' "$*" >&2; exit 1; }
usage() {
    printf 'Usage: bash relay.sh install DEVICE PORT TUNNEL_PUBLIC_KEY_FILE OPERATOR_PUBLIC_KEY_FILE\n       bash relay.sh {status|revoke} DEVICE\n' >&2
    exit 2
}
[[ $# -ge 2 ]] || usage
ACTION=$1 DEVICE=$2
[[ $DEVICE =~ ^[a-z][a-z0-9-]{0,15}$ ]] || fail 'invalid device name'
case $ACTION in
    install) [[ $# == 5 ]] || usage ;;
    status|revoke) [[ $# == 2 ]] || usage ;;
    *) usage ;;
esac

valid_port() { [[ $1 =~ ^[1-9][0-9]{3,4}$ ]] && (( $1 >= 1024 && $1 <= 65535 )); }
# Accept one bare Ed25519 public key, never authorized_keys options. Comments
# are discarded so changes to comments do not change a registration's identity.
read_key() {
    local file=$1 kind blob _comment key
    [[ -f $file && $(wc -c < "$file") -le 16384 ]] || fail 'public key file missing or too large'
    [[ $(awk 'END {print NR}' "$file") == 1 ]] || fail 'expected one public key line'
    read -r kind blob _comment < "$file" || [[ -n ${blob:-} ]] || fail 'empty key'
    [[ $kind == ssh-ed25519 && $blob =~ ^[A-Za-z0-9+/]+={0,2}$ ]] || fail 'expected a bare Ed25519 public key'
    key="$kind $blob"
    ssh-keygen -l -f /dev/stdin <<< "$key" >/dev/null 2>&1 || fail 'invalid public key'
    printf '%s\n' "$key"
}
if [[ $ACTION == install ]]; then
    PORT=$3
    valid_port "$PORT" || fail 'port must be 1024..65535 (no leading zeroes)'
    TKEY=$(read_key "$4")
    AKEY=$(read_key "$5")
    [[ $TKEY != "$AKEY" ]] || fail 'tunnel and operator keys must be different'
fi
[[ $(uname -s) == Linux && $EUID == 0 ]] || fail 'requires root on a Debian/Ubuntu Linux relay'
for cmd in sshd ssh-keygen getent useradd usermod userdel flock ss pkill pgrep cmp stat mktemp; do
    command -v "$cmd" >/dev/null || fail "missing prerequisite: $cmd"
done
ROOT=/etc/ssh/reverse-ssh-kit
SNIPPETS=/etc/ssh/sshd_config.d
GLOBAL=$SNIPPETS/00-reverse-ssh-kit.conf
DIR=$ROOT/$DEVICE
CONF=$SNIPPETS/00-rsk-$DEVICE.conf
TUSER=rsk-t-$DEVICE AUSER=rsk-a-$DEVICE

safe_dir() {
    [[ -d $1 && ! -L $1 && $(stat -c %u "$1") == 0 ]] || fail "unsafe directory: $1"
    (( (8#$(stat -c %a "$1") & 0022) == 0 )) || fail "directory writable by others: $1"
}
safe_file() {
    [[ -f $1 && ! -L $1 && $(stat -c %u "$1") == 0 ]] || fail "unsafe or missing file: $1"
    (( (8#$(stat -c %a "$1") & 0022) == 0 )) || fail "file writable by others: $1"
}
global_config() { printf '# Managed by reverse-ssh-kit v1\nGatewayPorts no\n'; }
device_config() {
    local name=$1 port=$2 role user
    printf '# Managed by reverse-ssh-kit v1: %s\n' "$name"
    for role in t a; do
        user=rsk-$role-$name
        cat <<CONFIG
Match User $user
    GatewayPorts no
    AuthenticationMethods publickey
    PubkeyAuthentication yes
    PasswordAuthentication no
    KbdInteractiveAuthentication no
    HostbasedAuthentication no
    AuthorizedKeysFile $ROOT/$name/$role.authorized_keys
    AuthorizedKeysCommand none
    TrustedUserCAKeys none
    MaxSessions 0
    PermitTTY no
    AllowAgentForwarding no
    X11Forwarding no
    PermitTunnel no
    AllowStreamLocalForwarding no
    DisableForwarding no
    ClientAliveInterval 30
    ClientAliveCountMax 3
CONFIG
        if [[ $role == t ]]; then
            printf '    AllowTcpForwarding remote\n    PermitListen 127.0.0.1:%s\n    PermitOpen none\n' "$port"
        else
            printf '    AllowTcpForwarding local\n    PermitOpen 127.0.0.1:%s\n    PermitListen none\n' "$port"
        fi
    done
    printf 'Match all\n'
}
atomic_write() {
    local dest=$1 tmp
    tmp=$(mktemp "${dest}.tmp.XXXXXX")
    cat > "$tmp"
    chmod 644 "$tmp"
    mv -f -- "$tmp" "$dest"
}
check_layout() {
    local first file base
    safe_dir /etc/ssh
    safe_dir "$SNIPPETS"
    safe_file /etc/ssh/sshd_config
    first=$(awk '{sub(/#.*/, ""); if (NF) { $1=$1; print; exit }}' /etc/ssh/sshd_config)
    [[ $first == 'Include /etc/ssh/sshd_config.d/*.conf' ]] || fail 'first active sshd_config directive must be Include /etc/ssh/sshd_config.d/*.conf; main configuration is never edited'
    # First matching value wins in sshd. Do not silently inherit a conditional
    # rule appearing before our device restrictions.
    for file in "$SNIPPETS"/*.conf; do
        [[ -e $file || -L $file ]] || continue
        base=${file##*/}
        if [[ $base == 00-reverse-ssh-kit.conf ]]; then
            safe_file "$file"
            cmp -s "$file" <(global_config) || fail 'unmanaged or modified global kit configuration'
        elif [[ $base == 00-rsk-*.conf ]]; then
            local name=${base#00-rsk-}; name=${name%.conf}
            [[ $name =~ ^[a-z][a-z0-9-]{0,15}$ && -d $ROOT/$name ]] || fail "unmanaged kit snippet: $file"
        elif [[ $base < 00-rsk-zzzzzzzzzzzzzzzz.conf ]]; then
            fail "snippet precedes kit restrictions: $file"
        fi
    done
}
check_registry() {
    if [[ -e $ROOT || -L $ROOT ]]; then
        safe_dir "$ROOT"
        safe_file "$ROOT/.owner"
        [[ $(cat "$ROOT/.owner") == reverse-ssh-kit-v1 ]] || fail 'unmanaged registry directory'
    else
        [[ ! -e $GLOBAL && ! -L $GLOBAL ]] || fail 'global kit snippet exists without registry'
    fi
}
load_device() {
    safe_dir "$DIR"
    safe_file "$DIR/port"
    PORT=$(cat "$DIR/port")
    valid_port "$PORT" || fail 'invalid stored port'
    safe_file "$DIR/phase"
    PHASE=$(cat "$DIR/phase")
    [[ $PHASE == active || $PHASE == installing || $PHASE == revoking ]] || fail 'invalid stored phase'
}
check_user() {
    local role=$1 user=$2 row uid
    safe_file "$DIR/$role.uid"
    uid=$(cat "$DIR/$role.uid")
    [[ $uid =~ ^[0-9]+$ && $uid -gt 0 ]] || fail 'invalid stored UID'
    row=$(getent passwd "$user") || fail "managed account missing: $user"
    [[ $(cut -d: -f3 <<< "$row") == "$uid" && $(cut -d: -f5-7 <<< "$row") == "reverse-ssh-kit-$DEVICE-$role:/nonexistent:/usr/sbin/nologin" ]] || fail "managed account ownership changed: $user"
}
check_device_config() {
    safe_file "$CONF"
    cmp -s "$CONF" <(device_config "$DEVICE" "$PORT") || fail 'device configuration was modified'
}
check_keys() {
    local role
    for role in t a; do
        safe_file "$DIR/$role.pub"
        safe_file "$DIR/$role.authorized_keys"
        cmp -s "$DIR/$role.authorized_keys" <(printf 'restrict,port-forwarding %s\n' "$(cat "$DIR/$role.pub")") || fail 'authorized key changed'
    done
}

service_ready() {
    if [[ -d /run/systemd/system ]]; then
        systemctl is-active --quiet ssh.service || fail 'ssh.service must already be running'
    else
        command -v service >/dev/null || fail 'requires ssh.service or Debian ssh init service'
        service ssh status >/dev/null || fail 'ssh service must already be running'
    fi
}
reload_sshd() {
    if [[ -d /run/systemd/system ]]; then systemctl reload ssh.service
    else service ssh reload
    fi
}
expect_setting() {
    grep -Fxq -- "$1" <<< "$EFFECTIVE" || fail "effective sshd setting differs for $user: $1"
}
verify_device() {
    local name=$1 port=$2 role user address expected
    for role in t a; do
        user=rsk-$role-$name
        for address in 127.0.0.1 192.0.2.1 ::1 2001:db8::1; do
            EFFECTIVE=$(sshd -T -C "user=$user,host=client.invalid,addr=$address") || fail "cannot evaluate sshd configuration for $user"
            for expected in 'gatewayports no' 'authenticationmethods publickey' 'pubkeyauthentication yes' \
                'passwordauthentication no' 'kbdinteractiveauthentication no' 'hostbasedauthentication no' \
                'authorizedkeyscommand none' 'trustedusercakeys none' 'maxsessions 0' 'permittty no' \
                'allowagentforwarding no' 'x11forwarding no' 'permittunnel no' 'allowstreamlocalforwarding no' \
                'disableforwarding no' 'strictmodes yes' 'clientaliveinterval 30' 'clientalivecountmax 3'; do
                expect_setting "$expected"
            done
            expect_setting "authorizedkeysfile $ROOT/$name/$role.authorized_keys"
            if [[ $role == t ]]; then
                expect_setting 'allowtcpforwarding remote'
                expect_setting "permitlisten 127.0.0.1:$port"
                expect_setting 'permitopen none'
            else
                expect_setting 'allowtcpforwarding local'
                expect_setting "permitopen 127.0.0.1:$port"
                expect_setting 'permitlisten none'
            fi
        done
    done
}
validate_all() {
    local dir port
    sshd -t || return $?
    for dir in "$ROOT"/*; do
        [[ -d $dir ]] || continue
        [[ -f $SNIPPETS/00-rsk-${dir##*/}.conf ]] || continue
        safe_dir "$dir"; safe_file "$dir/port"
        port=$(cat "$dir/port")
        valid_port "$port" || fail 'invalid registered port'
        verify_device "${dir##*/}" "$port"
    done
}
stop_user() {
    local uid=$1 rc
    # Both real/effective UID are exclusive to this device. Never kill sshd by
    # name or signal the service master: other devices retain their sessions.
    for flag in -u -U; do
        if pkill -KILL "$flag" "$uid"; then :
        else rc=$?; [[ $rc == 1 ]] || fail "cannot terminate UID $uid"
        fi
    done
}

# shellcheck disable=SC2174 # /run already exists; only the child is created.
mkdir -p -m 700 /run/reverse-ssh-kit
safe_dir /run/reverse-ssh-kit
exec 9>/run/reverse-ssh-kit/lock
flock -x 9
check_registry
check_layout
if [[ $ACTION == status ]]; then
    [[ -d $DIR ]] || fail 'device is not registered'
    load_device
    printf 'device=%s phase=%s port=%s tunnel_user=%s access_user=%s\n' "$DEVICE" "$PHASE" "$PORT" "$TUSER" "$AUSER"
    [[ $PHASE == active ]] || fail 'incomplete operation; run revoke before registering again'
    check_user t "$TUSER"; check_user a "$AUSER"; check_device_config
    check_keys
    validate_all
    service_ready
    printf 'configuration=verified\n'
    if ss -H -ltn "sport = :$PORT" | grep -q .; then
        printf 'listener=present (not an end-to-end health check)\n'
    else printf 'listener=absent (device may be offline)\n'
    fi
    exit 0
fi
if [[ $ACTION == install ]]; then
    service_ready
    sshd -t
    if [[ -e $DIR || -L $DIR ]]; then
        REQUESTED_PORT=$PORT
        load_device
        [[ $PHASE == active ]] || fail 'incomplete operation; run revoke before registering again'
        [[ $PORT == "$REQUESTED_PORT" ]] || fail 'device already registered with another port'
        [[ $(cat "$DIR/t.pub") == "$TKEY" && $(cat "$DIR/a.pub") == "$AKEY" ]] || fail 'device already registered with different keys'
        check_user t "$TUSER"; check_user a "$AUSER"; check_device_config
        check_keys
        validate_all
        printf 'Already installed: %s\n' "$DEVICE"
        exit 0
    fi
    for user in "$TUSER" "$AUSER"; do
        ! getent passwd "$user" >/dev/null || fail "unmanaged account collision: $user"
        ! getent group "$user" >/dev/null || fail "unmanaged group collision: $user"
    done
    [[ ! -e $CONF && ! -L $CONF ]] || fail 'unmanaged device configuration collision'
    for dir in "$ROOT"/*; do
        [[ -d $dir ]] || continue
        [[ $(cat "$dir/port") != "$PORT" ]] || fail 'port reserved by another device'
    done
    [[ -z $(ss -H -ltn "sport = :$PORT") ]] || fail 'port already listening'
    [[ -x /usr/sbin/nologin ]] || fail 'missing /usr/sbin/nologin'
    if [[ ! -d $ROOT ]]; then
        mkdir -m 755 "$ROOT"
        printf 'reverse-ssh-kit-v1\n' | atomic_write "$ROOT/.owner"
    fi
    mkdir -m 755 "$DIR"
    printf '%s\n' "$PORT" | atomic_write "$DIR/port"
    printf 'installing\n' | atomic_write "$DIR/phase"
    printf '%s\n' "$TKEY" | atomic_write "$DIR/t.pub"
    printf '%s\n' "$AKEY" | atomic_write "$DIR/a.pub"
    NEW_GLOBAL=0 CONFIG_WRITTEN=0 RELOADED=0 COMPLETE=0
    cleanup_install() {
        local rc=$? role
        trap - EXIT
        if [[ $COMPLETE != 1 ]]; then
            rm -f "$DIR/t.authorized_keys" "$DIR/a.authorized_keys"
            for role in t a; do
                if [[ -f $DIR/$role.uid ]]; then
                    usermod --lock --expiredate 1 "rsk-$role-$DEVICE"
                    stop_user "$(cat "$DIR/$role.uid")"
                fi
            done
            [[ $CONFIG_WRITTEN != 1 ]] || rm -f "$CONF"
            [[ $NEW_GLOBAL != 1 ]] || rm -f "$GLOBAL"
            if [[ $RELOADED == 1 ]]; then
                if (validate_all); then reload_sshd || printf 'relay: rollback reload failed\n' >&2; fi
            fi
            printf 'relay: installation incomplete; keys disabled. Run revoke %s before retrying.\n' "$DEVICE" >&2
        fi
        exit "$rc"
    }
    trap cleanup_install EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM
    for role in t a; do
        user=rsk-$role-$DEVICE
        useradd --user-group --no-create-home --home-dir /nonexistent \
            --shell /usr/sbin/nologin --expiredate 1 --comment "reverse-ssh-kit-$DEVICE-$role" --password '*' "$user"
        id -u "$user" | atomic_write "$DIR/$role.uid"
    done
    if [[ ! -e $GLOBAL ]]; then
        NEW_GLOBAL=1
        global_config | atomic_write "$GLOBAL"
    fi
    CONFIG_WRITTEN=1
    device_config "$DEVICE" "$PORT" | atomic_write "$CONF"
    validate_all
    # Keys are published only after the daemon has accepted the restrictive
    # configuration. Failed validation/reload leaves no usable credentials.
    RELOADED=1
    reload_sshd
    for role in t a; do
        printf 'restrict,port-forwarding %s\n' "$(cat "$DIR/$role.pub")" | atomic_write "$DIR/$role.authorized_keys"
    done
    for role in t a; do usermod --expiredate -1 "rsk-$role-$DEVICE"; done
    printf 'active\n' | atomic_write "$DIR/phase"
    COMPLETE=1
    printf 'Installed: %s (127.0.0.1:%s)\n' "$DEVICE" "$PORT"
else
    if [[ ! -e $DIR && ! -L $DIR ]]; then
        for user in "$TUSER" "$AUSER"; do
            ! getent passwd "$user" >/dev/null || fail 'unmanaged account exists; refusing deletion'
        done
        printf 'Not registered: %s\n' "$DEVICE"
        exit 0
    fi
    load_device
    # Check ownership of both accounts before disabling either one. Interrupted
    # revocations may already have removed an account; never delete a reused UID.
    for role in t a; do
        user=rsk-$role-$DEVICE
        if getent passwd "$user" >/dev/null; then check_user "$role" "$user"; fi
    done
    if [[ -e $CONF || -L $CONF ]]; then check_device_config; fi
    printf 'revoking\n' | atomic_write "$DIR/phase"
    rm -f "$DIR/t.authorized_keys" "$DIR/a.authorized_keys"
    for role in t a; do
        user=rsk-$role-$DEVICE
        if getent passwd "$user" >/dev/null; then
            usermod --lock --expiredate 1 "$user"
            stop_user "$(cat "$DIR/$role.uid")"
            # userdel refuses accounts still owning processes; leave recoverable
            # state and restrictions if session teardown has not finished.
            for _attempt in {1..30}; do
                pgrep -u "$(cat "$DIR/$role.uid")" >/dev/null || break
                sleep 0.1
            done
            userdel "$user"
        fi
    done
    # Keep the restrictive snippet until accounts and live sessions are gone.
    if [[ -e $CONF ]]; then mv "$CONF" "$DIR/revoked.conf"; fi
    if (validate_all) && reload_sshd; then
        rm -rf -- "$DIR"
        printf 'Revoked: %s (new logins and established device sessions)\n' "$DEVICE"
    else
        [[ ! -f $DIR/revoked.conf ]] || mv "$DIR/revoked.conf" "$CONF"
        fail 'accounts disabled; configuration reload failed, run revoke again after repair'
    fi
fi
