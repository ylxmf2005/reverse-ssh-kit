#!/usr/bin/env bash
# Destructive integration tests run ONLY in a disposable Docker container.
# Host: DOCKER_CONTEXT=your-context bash tests/test_relay.sh
# Exit 77 means Docker is unavailable; it is not a passing integration test.
set -euo pipefail
if [[ ${1:-} != --inside ]]; then
    if ! command -v docker >/dev/null || ! docker info >/dev/null 2>&1; then
        echo 'SKIP: Docker daemon unavailable (set DOCKER_CONTEXT if needed)' >&2
        exit 77
    fi
    REPO=$(cd "$(dirname "$0")/.." && pwd)
    IMAGE="reverse-ssh-kit-relay-test:$$"
    CONTAINER=
    # shellcheck disable=SC2317 # Invoked by EXIT trap.
    cleanup() {
        [[ -z $CONTAINER ]] || docker rm -f "$CONTAINER" >/dev/null
        docker image rm "$IMAGE" >/dev/null
    }
    trap cleanup EXIT
    docker build -t "$IMAGE" - <<'DOCKERFILE'
FROM debian:bookworm-slim
RUN apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
    openssh-server openssh-client procps iproute2 util-linux shellcheck python3 \
    && rm -rf /var/lib/apt/lists/* && mkdir -p /run/sshd /work/tests
DOCKERFILE
    CONTAINER=$(docker create --label reverse-ssh-kit.test=true "$IMAGE" bash /work/tests/test_relay.sh --inside)
    docker cp "$REPO/relay.sh" "$CONTAINER:/work/relay.sh"
    docker cp "$REPO/kit.py" "$CONTAINER:/work/kit.py"
    docker cp "$REPO/windows" "$CONTAINER:/work/windows"
    docker cp "$REPO/tests/test_relay.sh" "$CONTAINER:/work/tests/test_relay.sh"
    docker start -a "$CONTAINER"
    exit "$(docker inspect -f '{{.State.ExitCode}}' "$CONTAINER")"
fi
[[ -f /.dockerenv && $EUID == 0 && -f /work/relay.sh ]] || {
    echo 'REFUSE: --inside requires the disposable test container' >&2; exit 1;
}
R=/work/relay.sh
ROOT=/etc/ssh/reverse-ssh-kit
COUNT=0
ok() { COUNT=$((COUNT + 1)); printf 'ok %d - %s\n' "$COUNT" "$*"; }
fail() {
    printf 'FAIL: %s\n' "$*" >&2
    tail -40 /tmp/sshd-test.log >&2 || true
    pgrep -a sshd >&2 || true
    exit 1
}
reject() {
    local rc
    if "$@" > /tmp/rejected.log 2>&1; then cat /tmp/rejected.log; fail "unexpected success: $*"
    else rc=$?; fi
    [[ $rc != 124 && $rc != 137 ]] || fail "timed out instead of being rejected: $*"
}
new_key() { ssh-keygen -q -t ed25519 -N '' -f "/tmp/$1"; }
run() { bash "$R" "$@"; }
shellcheck "$R" /work/tests/test_relay.sh
bash -n "$R"
/usr/sbin/sshd -E /tmp/sshd-test.log
for key in tunnel2 operator2; do new_key "$key"; done
BUNDLE='/tmp/kit enrollment'
python3 /work/kit.py prepare example --relay-host 127.0.0.1 --relay-host-key /etc/ssh/ssh_host_ed25519_key.pub --remote-port 22001 --output "$BUNDLE"
for ext in '' .pub; do cp "$BUNDLE/operator_key$ext" "/tmp/operator$ext"; cp "$BUNDLE/windows-bundle/tunnel_key$ext" "/tmp/tunnel$ext"; done
printf '127.0.0.1 %s\n' "$(cat /etc/ssh/ssh_host_ed25519_key.pub)" > /tmp/known_hosts
SSH=(ssh -F /dev/null -o BatchMode=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile=/tmp/known_hosts
    -o HostKeyAlgorithms=ssh-ed25519 -o IdentitiesOnly=yes -o ConnectTimeout=3 -o ConnectionAttempts=3 -o LogLevel=ERROR)
MASTER_PID=$(cat /run/sshd.pid)

reject run install Bad 22001 /tmp/tunnel.pub /tmp/operator.pub
for port in 22 1023 65536 02201 -1 '22001 x'; do reject run install example "$port" /tmp/tunnel.pub /tmp/operator.pub; done
printf 'restrict %s\n' "$(cat /tmp/tunnel.pub)" > /tmp/options.pub
reject run install example 22001 /tmp/options.pub /tmp/operator.pub
cat /tmp/tunnel.pub /tmp/operator.pub > /tmp/multiline.pub
reject run install example 22001 /tmp/multiline.pub /tmp/operator.pub
reject run install example 22001 /tmp/tunnel.pub /tmp/tunnel.pub
printf 'ssh-ed25519 AAAA\n' > /tmp/bad.pub
reject run install example 22001 /tmp/bad.pub /tmp/operator.pub
[[ ! -e $ROOT ]] || fail 'invalid input mutated relay'
ok 'invalid names, ports, option-bearing/multiple/malformed/shared keys rejected'

useradd --system rsk-t-collision
reject run install collision 22003 /tmp/tunnel.pub /tmp/operator.pub
getent passwd rsk-t-collision >/dev/null
userdel rsk-t-collision
printf '# unmanaged\n' > /etc/ssh/sshd_config.d/00-rsk-orphan.conf
reject run install example 22001 /tmp/tunnel.pub /tmp/operator.pub
rm /etc/ssh/sshd_config.d/00-rsk-orphan.conf
printf '# early\n' > /etc/ssh/sshd_config.d/00-earlier.conf
reject run install example 22001 /tmp/tunnel.pub /tmp/operator.pub
rm /etc/ssh/sshd_config.d/00-earlier.conf
cp /etc/ssh/sshd_config /tmp/sshd_config.original
{ printf 'Port 22\n'; cat /tmp/sshd_config.original; } > /etc/ssh/sshd_config
cp /etc/ssh/sshd_config /tmp/sshd_config.unsupported
reject run install example 22001 /tmp/tunnel.pub /tmp/operator.pub
cmp /etc/ssh/sshd_config /tmp/sshd_config.unsupported
cp /tmp/sshd_config.original /etc/ssh/sshd_config
ok 'unmanaged accounts/snippets and unsupported Include ordering rejected without editing main config'

run install example 22001 /tmp/tunnel.pub /tmp/operator.pub
run install second 22002 /tmp/tunnel2.pub /tmp/operator2.pub
run install example 22001 /tmp/tunnel.pub /tmp/operator.pub
run status example
reject run install example 22003 /tmp/tunnel.pub /tmp/operator.pub
reject run install example 22001 /tmp/tunnel2.pub /tmp/operator.pub
reject run install third 22002 /tmp/tunnel.pub /tmp/operator.pub
[[ $(cat /run/sshd.pid) == "$MASTER_PID" ]] || fail 'sshd master restarted'
ok 'install/status/idempotence; key, device and reserved-port conflicts; reload preserves master'

# Later address-specific rules must not override kit restrictions.
cat > /etc/ssh/sshd_config.d/90-test.conf <<'CONFIG'
Match Address 192.0.2.123
    GatewayPorts yes
    AllowTcpForwarding yes
    MaxSessions 10
Match all
CONFIG
sshd -t
for user in rsk-t-example rsk-a-example; do
    EFFECTIVE=$(sshd -T -C "user=$user,host=client.invalid,addr=192.0.2.123")
    grep -Fxq 'gatewayports no' <<< "$EFFECTIVE"
    grep -Fxq 'maxsessions 0' <<< "$EFFECTIVE"
    grep -Fxq 'allowstreamlocalforwarding no' <<< "$EFFECTIVE"
done
rm /etc/ssh/sshd_config.d/90-test.conf
ok 'real sshd effective settings resist later address-specific weakening'

# A failed effective-policy validation must leave no usable authorization/config.
printf 'StrictModes no\n' > /etc/ssh/sshd_config.d/90-test.conf
reject run install broken 22003 /tmp/tunnel.pub /tmp/operator.pub
[[ ! -e $ROOT/broken/t.authorized_keys && ! -e /etc/ssh/sshd_config.d/00-rsk-broken.conf ]] || fail 'failed install left authorization/config'
sshd -t
rm /etc/ssh/sshd_config.d/90-test.conf
run revoke broken
ok 'failed effective validation fails closed and pending registration can be revoked'

# Inject only the service failure in this disposable container; sshd is real.
mv /usr/sbin/service /usr/sbin/service.real
cat > /usr/sbin/service <<'SERVICE'
#!/bin/sh
if [ "$1" = ssh ] && [ "$2" = reload ] && [ -e /tmp/fail-reload ]; then exit 1; fi
exec /usr/sbin/service.real "$@"
SERVICE
chmod +x /usr/sbin/service
touch /tmp/fail-reload
reject run install broken 22003 /tmp/tunnel.pub /tmp/operator.pub
[[ ! -e $ROOT/broken/t.authorized_keys && ! -e /etc/ssh/sshd_config.d/00-rsk-broken.conf ]] || fail 'reload failure enabled keys'
[[ $(getent shadow rsk-t-broken | cut -d: -f8) == 1 ]] || fail 'failed account was not expired'
rm /tmp/fail-reload
run revoke broken
ok 'reload failure disables keys and retains explicit recoverable state'

start_tunnel() {
    local name=$1 key=$2 port=$3
    "${SSH[@]}" -i "/tmp/$key" -o ExitOnForwardFailure=yes -M -S "/tmp/$name.sock" \
        -N -R "127.0.0.1:$port:127.0.0.1:22" "rsk-t-$name@127.0.0.1" >"/tmp/$name.log" 2>&1 &
    LAST_PID=$!
    for _attempt in {1..50}; do
        if [[ -S /tmp/$name.sock ]] && ss -H -ltn "sport = :$port" | grep -q .; then return; fi
        sleep 0.1
    done
    cat "/tmp/$name.log"; fail 'tunnel not ready'
}
# Test exact host restrictions while the authorized port is still free.
for bind in 0.0.0.0:22001 localhost:22001 '[::1]:22001'; do
    reject timeout 5 "${SSH[@]}" -i /tmp/tunnel -o ExitOnForwardFailure=yes -N -R "$bind:127.0.0.1:22" rsk-t-example@127.0.0.1
done
start_tunnel example tunnel 22001
TUNNEL_PID=$LAST_PID
start_tunnel second tunnel2 22002
SECOND_PID=$LAST_PID
ss -H -ltn 'sport = :22001' | grep -q '127.0.0.1:22001'
[[ $(ss -H -ltn 'sport = :22001' | wc -l) == 1 ]]
"${SSH[@]}" -i /tmp/operator -N -L 127.0.0.1:23001:127.0.0.1:22001 rsk-a-example@127.0.0.1 > /tmp/access.log 2>&1 &
ACCESS_PID=$!
for _attempt in {1..50}; do
    ss -H -ltn 'sport = :23001' | grep -q . && break
    sleep 0.1
done
# shellcheck disable=SC2016 # Expanded by the inner Bash.
BANNER=$(timeout 5 bash -c 'exec 3<>/dev/tcp/127.0.0.1/23001; IFS= read -r line <&3; printf "%s" "$line"')
[[ $BANNER == SSH-2.0-* ]] || fail 'authorized access did not reach forwarded SSH endpoint'
ok 'live reverse tunnel binds only IPv4 loopback; separate operator identity reaches its target'

# Linux target fixture exercises the CLI contract, not Windows installation/ACLs.
useradd --create-home --shell /bin/sh --password '*' rskremote
install -d -m 700 -o rskremote -g rskremote /home/rskremote/.ssh
install -m 600 -o rskremote -g rskremote "$BUNDLE/operator_key.pub" /home/rskremote/.ssh/authorized_keys
reject timeout 15 ssh -F "$BUNDLE/ssh_config" example hostname
FP=$(ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub | awk '{print $2}')
python3 /work/kit.py trust "$BUNDLE" --host-key /etc/ssh/ssh_host_ed25519_key.pub --fingerprint "$FP"
[[ $(timeout 15 ssh -F "$BUNDLE/ssh_config" example hostname) == "$(hostname)" ]] || fail 'generated two-hop config failed'
printf 'two-hop transfer fixture\n' > /tmp/payload.txt
timeout 15 scp -F "$BUNDLE/ssh_config" /tmp/payload.txt example:payload.txt
timeout 15 scp -F "$BUNDLE/ssh_config" example:payload.txt /tmp/download.txt
cmp /tmp/payload.txt /tmp/download.txt
for entry in 'relay_known_hosts 127.0.0.1' 'device_known_hosts rsk-device-example'; do
    read -r file alias <<< "$entry"
    cp "$BUNDLE/$file" /tmp/pin.backup
    printf '%s %s\n' "$alias" "$(cat /tmp/tunnel2.pub)" > "$BUNDLE/$file"
    reject timeout 15 ssh -F "$BUNDLE/ssh_config" example hostname
    grep -q 'Host key verification failed' /tmp/rejected.log
    mv /tmp/pin.backup "$BUNDLE/$file"
done
ok 'generated config in spaced path: hostname, scp round trip, absent target pin and both mismatched host keys'


for user in rsk-t-example rsk-a-example; do
    key=tunnel; [[ $user != rsk-a-example ]] || key=operator
    reject timeout 5 "${SSH[@]}" -i "/tmp/$key" "$user@127.0.0.1" id
    reject timeout 5 "${SSH[@]}" -i "/tmp/$key" -s "$user@127.0.0.1" sftp
    reject timeout 5 "${SSH[@]}" -i "/tmp/$key" -W 127.0.0.1:22 "$user@127.0.0.1"
    reject timeout 5 "${SSH[@]}" -i "/tmp/$key" -W 127.0.0.1:22002 "$user@127.0.0.1"
done
reject timeout 5 "${SSH[@]}" -i /tmp/tunnel -W 127.0.0.1:22001 rsk-t-example@127.0.0.1
reject timeout 5 "${SSH[@]}" -i /tmp/operator -W 127.0.0.1:22001 rsk-t-example@127.0.0.1
reject timeout 5 "${SSH[@]}" -i /tmp/tunnel -W 127.0.0.1:22001 rsk-a-example@127.0.0.1
for bind in 127.0.0.1:22004 0.0.0.0:22004 localhost:22004; do
    reject timeout 5 "${SSH[@]}" -i /tmp/tunnel -o ExitOnForwardFailure=yes -N -R "$bind:127.0.0.1:22" rsk-t-example@127.0.0.1
done
reject timeout 5 "${SSH[@]}" -i /tmp/operator -o ExitOnForwardFailure=yes -N -R 127.0.0.1:22004:127.0.0.1:22 rsk-a-example@127.0.0.1
reject timeout 5 "${SSH[@]}" -i /tmp/tunnel -o ExitOnForwardFailure=yes -N -R /tmp/forbidden.sock:127.0.0.1:22 rsk-t-example@127.0.0.1
ok 'live shell/subsystem, wrong key, lateral TCP, unauthorized remote and Unix-socket forwarding rejected'

reject run install occupied 23001 /tmp/tunnel.pub /tmp/operator.pub
[[ ! -d $ROOT/occupied ]] || fail 'occupied-port rejection left registration'
ok 'existing listener collision rejected before changes'

run revoke example
for _attempt in {1..50}; do
    if ! kill -0 "$TUNNEL_PID" 2>/dev/null && ! kill -0 "$ACCESS_PID" 2>/dev/null; then break; fi
    sleep 0.1
done
! kill -0 "$TUNNEL_PID" 2>/dev/null || fail 'tunnel survived revoke'
! kill -0 "$ACCESS_PID" 2>/dev/null || fail 'access session survived revoke'
[[ -z $(ss -H -ltn 'sport = :22001') ]] || fail 'revoked port remains bound'
kill -0 "$SECOND_PID" || fail 'another device was interrupted'
if getent passwd rsk-t-example >/dev/null; then fail "tunnel account survived"; fi
if getent passwd rsk-a-example >/dev/null; then fail "access account survived"; fi
[[ ! -d $ROOT/example && ! -e /etc/ssh/sshd_config.d/00-rsk-example.conf ]]
reject timeout 5 "${SSH[@]}" -i /tmp/operator -W 127.0.0.1:22001 rsk-a-example@127.0.0.1
run revoke example
[[ $(cat /run/sshd.pid) == "$MASTER_PID" ]] || fail 'sshd master restarted'
ok 'revoke removes credentials/accounts and existing sessions, preserves other device/master, repeats safely'

touch /tmp/fail-reload
reject run revoke second
[[ $(cat "$ROOT/second/phase") == revoking && ! -e $ROOT/second/t.authorized_keys ]]
[[ -f /etc/ssh/sshd_config.d/00-rsk-second.conf ]] || fail 'failed revoke did not restore restrictive snippet'
rm /tmp/fail-reload
run revoke second
ok 'interrupted revoke resumes after reload recovery'

run install broken 22003 /tmp/tunnel.pub /tmp/operator.pub
printf 'NotAnSSHOption yes\n' > /etc/ssh/sshd_config.d/90-test.conf
reject run revoke broken
[[ $(cat "$ROOT/broken/phase") == revoking && ! -e $ROOT/broken/t.authorized_keys ]]
if getent passwd rsk-t-broken >/dev/null; then fail 'bad unrelated config prevented account revocation'; fi
rm /etc/ssh/sshd_config.d/90-test.conf
run revoke broken
ok 'unrelated invalid sshd config cannot prevent credential/account revocation; repair permits completion'

printf '\nPASS: %s integration groups; real OpenSSH in %s\n' "$COUNT" "$(head -1 /etc/os-release)"
