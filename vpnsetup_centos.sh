#!/bin/sh
#
# Script for automatic setup of an IPsec VPN server on CentOS/RHEL 6 and 7.
# Works on any dedicated server or virtual private server (VPS) except OpenVZ.
#
# DO NOT RUN THIS SCRIPT ON YOUR PC OR MAC!
#
# The latest version of this script is available at:
# https://github.com/hwdsl2/setup-ipsec-vpn
# 
# modified version specific to Centmin Mod LEMP stacks with CSF Firewall
# modified by George Liu centminmod.com
# https://github.com/centminmod/setup-ipsec-vpn
# 
# curl -sL https://github.com/centminmod/setup-ipsec-vpn/raw/master/vpnsetup_centos.sh | bash
#
# Copyright (C) 2015-2017 Lin Song <linsongui@gmail.com>
# Based on the work of Thomas Sarlandie (Copyright 2012)
#
# This work is licensed under the Creative Commons Attribution-ShareAlike 3.0
# Unported License: http://creativecommons.org/licenses/by-sa/3.0/
#
# Attribution required: please include my name in any derivative and let me
# know how you have improved it!

# =====================================================

# Define your own values for these variables
# - IPsec pre-shared key, VPN username and password
# - All values MUST be placed inside 'single quotes'
# - DO NOT use these special characters within values: \ " '

YOUR_IPSEC_PSK=''
YOUR_USERNAME=''
YOUR_PASSWORD=''

# Important notes:   https://git.io/vpnnotes
# Setup VPN clients: https://git.io/vpnclients

# =====================================================

export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
SYS_DT="$(date +%F-%T)"

if [ -f /proc/user_beancounters ]; then
    CPUS=$(grep -c "processor" /proc/cpuinfo)
    if [[ "$CPUS" -gt '8' ]]; then
        CPUS=$(echo $(($CPUS+2)))
    else
        CPUS=$(echo $(($CPUS+1)))
    fi
    MAKETHREADS=" -j$CPUS"
else
    CPUS=$(grep -c "processor" /proc/cpuinfo)
    if [[ "$CPUS" -gt '8' ]]; then
        CPUS=$(echo $(($CPUS+4)))
    elif [[ "$CPUS" -eq '8' ]]; then
        CPUS=$(echo $(($CPUS+2)))
    else
        CPUS=$(echo $(($CPUS+1)))
    fi
    MAKETHREADS=" -j$CPUS"
fi

exiterr()  { echo "Error: $1" >&2; exit 1; }
exiterr2() { exiterr "'yum install' failed."; }
conf_bk() { /bin/cp -f "$1" "$1.old-$SYS_DT" 2>/dev/null; }
bigecho() { echo; echo "## $1"; echo; }

check_ip() {
  IP_REGEX='^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$'
  printf '%s' "$1" | tr -d '\n' | grep -Eq "$IP_REGEX"
}

vpnsetup() {

if ! grep -qs -e "release 6" -e "release 7" /etc/redhat-release; then
  exiterr "This script only supports CentOS/RHEL 6 and 7."
fi

if [[ -f /proc/user_beancounters && "$(cat /dev/net/tun 2>&1 | grep 'bad state' >/dev/null 2>&1; echo $?)" -ne '0' ]]; then
  echo "Error: This script does not support OpenVZ VPS." >&2
  echo "Try OpenVPN: https://github.com/Nyr/openvpn-install" >&2
  exit 1
elif [[ -f /proc/user_beancounters && "$(cat /dev/net/tun 2>&1 | grep 'bad state' >/dev/null 2>&1; echo $?)" -eq '0' ]]; then
  OPENVZ_OK=1
  if grep -qs "release 6" /etc/redhat-release; then
    mkdir -p /var/run/pluto
  else
    echo "d      /var/run/pluto/         0755 root root" > /etc/tmpfiles.d/ipsec.conf
    mkdir -p /var/run/pluto
    systemctl daemon-reload
  fi
fi

if [ "$(id -u)" != 0 ]; then
  exiterr "Script must be run as root. Try 'sudo sh $0'"
fi

net_iface=${VPN_NET_IFACE:-'eth0'}
def_iface="$(route 2>/dev/null | grep '^default' | grep -o '[^ ]*$')"
[ -z "$def_iface" ] && def_iface="$(ip -4 route list 0/0 2>/dev/null | grep -Po '(?<=dev )(\S+)')"

def_iface_state=$(cat "/sys/class/net/$def_iface/operstate" 2>/dev/null)
if [ -n "$def_iface_state" ] && [ "$def_iface_state" != "down" ]; then
  if ! grep -qs raspbian /etc/os-release; then
    case "$def_iface" in
      wl*)
        exiterr "Wireless interface '$def_iface' detected. DO NOT run this script on your PC or Mac!"
        ;;
    esac
  fi
  net_iface="$def_iface"
fi

net_iface_state=$(cat "/sys/class/net/$net_iface/operstate" 2>/dev/null)
if [ -z "$net_iface_state" ] || [ "$net_iface_state" = "down" ] || [ "$net_iface" = "lo" ]; then
  printf "Error: Network interface '%s' is not available.\n" "$net_iface" >&2
  if [ -z "$VPN_NET_IFACE" ]; then
cat 1>&2 <<EOF
Unable to detect the default network interface. Manually re-run this script with:
  sudo VPN_NET_IFACE="your_default_interface_name" sh "$0"
EOF
  fi
  exit 1
fi

[ -n "$YOUR_IPSEC_PSK" ] && VPN_IPSEC_PSK="$YOUR_IPSEC_PSK"
[ -n "$YOUR_USERNAME" ] && VPN_USER="$YOUR_USERNAME"
[ -n "$YOUR_PASSWORD" ] && VPN_PASSWORD="$YOUR_PASSWORD"

if [ -z "$VPN_IPSEC_PSK" ] && [ -z "$VPN_USER" ] && [ -z "$VPN_PASSWORD" ]; then
  bigecho "VPN credentials not set by user. Generating random PSK and password..."
  VPN_IPSEC_PSK="$(LC_CTYPE=C tr -dc 'A-HJ-NPR-Za-km-z2-9' < /dev/urandom | head -c 16)"
  VPN_USER=vpnuser
  VPN_PASSWORD="$(LC_CTYPE=C tr -dc 'A-HJ-NPR-Za-km-z2-9' < /dev/urandom | head -c 16)"
fi

if [ -z "$VPN_IPSEC_PSK" ] || [ -z "$VPN_USER" ] || [ -z "$VPN_PASSWORD" ]; then
  exiterr "All VPN credentials must be specified. Edit the script and re-enter them."
fi

if printf '%s' "$VPN_IPSEC_PSK $VPN_USER $VPN_PASSWORD" | LC_ALL=C grep -q '[^ -~]\+'; then
  exiterr "VPN credentials must not contain non-ASCII characters."
fi

case "$VPN_IPSEC_PSK $VPN_USER $VPN_PASSWORD" in
  *[\\\"\']*)
    exiterr "VPN credentials must not contain these special characters: \\ \" '"
    ;;
esac

bigecho "VPN setup in progress... Please be patient."

# Create and change to working dir
mkdir -p /opt/src
cd /opt/src || exiterr "Cannot enter /opt/src."

bigecho "Installing packages required for setup..."

setuppackages='wget bind-utils openssl iproute gawk grep sed net-tools'

for pkg in ${setuppackages[@]}; do
  echo Processing package: $pkg
  VPNRPMCHECK=$(rpm -ql $pkg >/dev/null 2>&1; echo $?)
  if [[ "$VPNRPMCHECK" = '0' ]]; then
    echo "----------------------------------------------------------------------------------"
    echo "$pkg already installed"
    echo "----------------------------------------------------------------------------------"
  else
    echo "----------------------------------------------------------------------------------"
    echo "Installing $pkg"
    echo "----------------------------------------------------------------------------------"
    yum -q -y install "$pkg"
    echo "----------------------------------------------------------------------------------"
  fi
done

bigecho "Trying to auto discover IP of this server..."

cat <<'EOF'
In case the script hangs here for more than a few minutes,
press Ctrl-C to abort. Then edit it and manually enter IP.
EOF

# In case auto IP discovery fails, enter server's public IP here.
PUBLIC_IP=${VPN_PUBLIC_IP:-''}

# Try to auto discover IP of this server
[ -z "$PUBLIC_IP" ] && PUBLIC_IP=$(dig @resolver1.opendns.com -t A -4 myip.opendns.com +short)

# Check IP for correct format
check_ip "$PUBLIC_IP" || PUBLIC_IP=$(wget -t 3 -T 15 -qO- http://ipv4.icanhazip.com)
check_ip "$PUBLIC_IP" || exiterr "Cannot detect this server's public IP. Edit the script and manually enter it."

if [ ! -f /etc/yum.repos.d/epel.repo ]; then
  bigecho "Adding the EPEL repository..."
  yum -y install epel-release || exiterr2
fi

bigecho "Installing packages required for the VPN..."

vpnpackages='nss-devel nspr-devel pkgconfig pam-devel libcap-ng-devel libselinux-devel curl-devel flex bison gcc make fipscheck-devel unbound-devel xmlto ppp xl2tpd'

for pkg in ${vpnpackages[@]}; do
  echo Processing package: $pkg
  VPNRPMCHECK=$(rpm -ql $pkg >/dev/null 2>&1; echo $?)
  if [[ "$VPNRPMCHECK" = '0' ]]; then
    echo "----------------------------------------------------------------------------------"
    echo "$pkg already installed"
    echo "----------------------------------------------------------------------------------"
  else
    echo "----------------------------------------------------------------------------------"
    echo "Installing $pkg"
    echo "----------------------------------------------------------------------------------"
    yum -q -y install "$pkg"
    echo "----------------------------------------------------------------------------------"
  fi
done

if grep -qs "release 6" /etc/redhat-release; then
  yum -y remove libevent-devel
  yum -y install libevent2-devel || exiterr2
else
  libeventpackages='libevent-devel systemd-devel iptables-services'
  
  for pkg in ${libeventpackages[@]}; do
    echo Processing package: $pkg
    VPNRPMCHECK=$(rpm -ql $pkg >/dev/null 2>&1; echo $?)
    if [[ "$VPNRPMCHECK" = '0' ]]; then
      echo "----------------------------------------------------------------------------------"
      echo "$pkg already installed"
      echo "----------------------------------------------------------------------------------"
    else
      echo "----------------------------------------------------------------------------------"
      echo "Installing $pkg"
      echo "----------------------------------------------------------------------------------"
      yum -q -y install "$pkg"
      echo "----------------------------------------------------------------------------------"
    fi
  done
fi

# skip fail2ban install if CSF Firewall is detected as
# SSH is already protected by CSF Firewall
if [ ! -f /etc/csf/csf.conf ]; then
  bigecho "Installing Fail2Ban to protect SSH..."
  yum -y install fail2ban || exiterr2
fi

bigecho "Compiling and installing Libreswan..."

SWAN_VER=3.22
swan_file="libreswan-$SWAN_VER.tar.gz"
swan_url1="https://github.com/libreswan/libreswan/archive/v$SWAN_VER.tar.gz"
swan_url2="https://download.libreswan.org/$swan_file"
if ! { wget -t 3 -T 30 -nv -O "$swan_file" "$swan_url1" || wget -t 3 -T 30 -nv -O "$swan_file" "$swan_url2"; }; then
  exiterr "Cannot download Libreswan source."
fi
/bin/rm -rf "/opt/src/libreswan-$SWAN_VER"
tar xzf "$swan_file" && /bin/rm -f "$swan_file"
cd "libreswan-$SWAN_VER" || exiterr "Cannot enter Libreswan source dir."
[ "$SWAN_VER" = "3.22" ] && sed -i '/^#define LSWBUF_CANARY/s/-2$/((char) -2)/' include/lswlog.h
cat > Makefile.inc.local <<'EOF'
WERROR_CFLAGS =
USE_DNSSEC = false
EOF
NPROCS="$(grep -c ^processor /proc/cpuinfo)"
[ -z "$NPROCS" ] && NPROCS=1
make "-j$((NPROCS+1))" -s base && make -s install-base

# Verify the install and clean up
cd /opt/src || exiterr "Cannot enter /opt/src."
/bin/rm -rf "/opt/src/libreswan-$SWAN_VER"
if ! /usr/local/sbin/ipsec --version 2>/dev/null | grep -qF "$SWAN_VER"; then
  exiterr "Libreswan $SWAN_VER failed to build."
fi

bigecho "Creating VPN configuration..."

L2TP_NET=${VPN_L2TP_NET:-'192.168.42.0/24'}
L2TP_LOCAL=${VPN_L2TP_LOCAL:-'192.168.42.1'}
L2TP_POOL=${VPN_L2TP_POOL:-'192.168.42.10-192.168.42.250'}
XAUTH_NET=${VPN_XAUTH_NET:-'192.168.43.0/24'}
XAUTH_POOL=${VPN_XAUTH_POOL:-'192.168.43.10-192.168.43.250'}
DNS_SRV1=${VPN_DNS_SRV1:-'8.8.8.8'}
DNS_SRV2=${VPN_DNS_SRV2:-'8.8.4.4'}

# Create IPsec (Libreswan) config
echo "setup /etc/ipsec.conf"
conf_bk "/etc/ipsec.conf"
cat > /etc/ipsec.conf <<EOF
version 2.0

config setup
  virtual-private=%v4:10.0.0.0/8,%v4:192.168.0.0/16,%v4:172.16.0.0/12,%v4:!$L2TP_NET,%v4:!$XAUTH_NET
  protostack=netkey
  interfaces=%defaultroute
  uniqueids=no

conn shared
  left=%defaultroute
  leftid=$PUBLIC_IP
  right=%any
  encapsulation=yes
  authby=secret
  pfs=no
  rekey=no
  keyingtries=5
  dpddelay=30
  dpdtimeout=120
  dpdaction=clear
  ike=3des-sha1,3des-sha2,aes-sha1,aes-sha1;modp1024,aes-sha2,aes-sha2;modp1024,aes256-sha2_512
  phase2alg=3des-sha1,3des-sha2,aes-sha1,aes-sha2,aes256-sha2_512
  sha2-truncbug=yes

conn l2tp-psk
  auto=add
  leftprotoport=17/1701
  rightprotoport=17/%any
  type=transport
  phase2=esp
  also=shared

conn xauth-psk
  auto=add
  leftsubnet=0.0.0.0/0
  rightaddresspool=$XAUTH_POOL
  modecfgdns1=$DNS_SRV1
  modecfgdns2=$DNS_SRV2
  leftxauthserver=yes
  rightxauthclient=yes
  leftmodecfgserver=yes
  rightmodecfgclient=yes
  modecfgpull=yes
  xauthby=file
  ike-frag=yes
  ikev2=never
  cisco-unity=yes
  also=shared
EOF

# Specify IPsec PSK
echo "setup /etc/ipsec.secrets"
conf_bk "/etc/ipsec.secrets"
cat > /etc/ipsec.secrets <<EOF
%any  %any  : PSK "$VPN_IPSEC_PSK"
EOF

# Create xl2tpd config
echo "setup /etc/xl2tpd/xl2tpd.conf"
conf_bk "/etc/xl2tpd/xl2tpd.conf"
cat > /etc/xl2tpd/xl2tpd.conf <<EOF
[global]
port = 1701

[lns default]
ip range = $L2TP_POOL
local ip = $L2TP_LOCAL
require chap = yes
refuse pap = yes
require authentication = yes
name = l2tpd
pppoptfile = /etc/ppp/options.xl2tpd
length bit = yes
EOF

# Set xl2tpd options
echo "setup /etc/ppp/options.xl2tpd"
conf_bk "/etc/ppp/options.xl2tpd"
cat > /etc/ppp/options.xl2tpd <<EOF
+mschap-v2
ipcp-accept-local
ipcp-accept-remote
ms-dns $DNS_SRV1
ms-dns $DNS_SRV2
noccp
auth
mtu 1280
mru 1280
proxyarp
lcp-echo-failure 4
lcp-echo-interval 30
connect-delay 5000
EOF

# Create VPN credentials
echo "setup /etc/ppp/chap-secrets"
conf_bk "/etc/ppp/chap-secrets"
cat > /etc/ppp/chap-secrets <<EOF
"$VPN_USER" l2tpd "$VPN_PASSWORD" *
EOF

echo "setup /etc/ipsec.d/passwd"
conf_bk "/etc/ipsec.d/passwd"
VPN_PASSWORD_ENC=$(openssl passwd -1 "$VPN_PASSWORD")
cat > /etc/ipsec.d/passwd <<EOF
$VPN_USER:$VPN_PASSWORD_ENC:xauth-psk
EOF

# /etc/sysctl.d/101-sysctl.conf
bigecho "Updating sysctl settings..."

# check if centminmod lemp stack installed
if [ -f /usr/local/src/centminmod/centmin.sh ]; then
  CENTMINMOD='y'
else
  CENTMINMOD='n'
fi

# non-centminmod centos 6 or 7
if [[ ! "$(grep -qs "hwdsl2 VPN script" /etc/sysctl.conf)" && "$CENTMINMOD" = [nN] ]]; then
  conf_bk "/etc/sysctl.conf"
  if [ "$(getconf LONG_BIT)" = "64" ]; then
    SHM_MAX=68719476736
    SHM_ALL=4294967296
  else
    SHM_MAX=4294967295
    SHM_ALL=268435456
  fi
cat >> /etc/sysctl.conf <<EOF

# Added by hwdsl2 VPN script
kernel.msgmnb = 65536
kernel.msgmax = 65536
kernel.shmmax = $SHM_MAX
kernel.shmall = $SHM_ALL

net.ipv4.ip_forward = 1
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.all.rp_filter = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.default.rp_filter = 0
net.ipv4.conf.$net_iface.send_redirects = 0
net.ipv4.conf.$net_iface.rp_filter = 0

net.core.wmem_max = 12582912
net.core.rmem_max = 12582912
net.ipv4.tcp_rmem = 10240 87380 12582912
net.ipv4.tcp_wmem = 10240 87380 12582912
EOF
  if [[ "$OPENVZ_OK" -eq '1' && ! "$(grep 'for openvz systems' /etc/sysctl.conf)" ]]; then
      echo "#for openvz systems" >> /etc/sysctl.conf
    for dev in $(ls /proc/sys/net/ipv4/conf/); do
      echo "net.ipv4.conf.${dev}.accept_source_route=0" >> /etc/sysctl.conf
      echo "net.ipv4.conf.${dev}.accept_redirects=0" >> /etc/sysctl.conf
      echo "net.ipv4.conf.${dev}.send_redirects=0" >> /etc/sysctl.conf
      echo "net.ipv4.conf.${dev}.rp_filter=0" >> /etc/sysctl.conf
    done
  fi
    sysctl -p
fi

# centminmod skips sysctl tunning when openvz is detected
# need to resetup
if [[ "$OPENVZ_OK" -eq '1' && "$CENTMINMOD" = [yY] ]]; then
  if grep -qs "release 6" /etc/redhat-release; then
    if [[ "$(grep 'centminmod added' /etc/sysctl.conf >/dev/null 2>&1; echo $?)" != '0' ]]; then
cat >> "/etc/sysctl.conf" <<EOF
# centminmod added
fs.nr_open=12000000
fs.file-max=9000000
net.core.wmem_max=16777216
net.core.rmem_max=16777216
net.ipv4.tcp_rmem=8192 87380 16777216                                          
net.ipv4.tcp_wmem=8192 65536 16777216
net.core.netdev_max_backlog=8192
net.core.somaxconn=8151
net.core.optmem_max=8192
net.ipv4.tcp_fin_timeout=10
net.ipv4.tcp_keepalive_intvl=30
net.ipv4.tcp_keepalive_probes=3
net.ipv4.tcp_keepalive_time=240
net.ipv4.tcp_max_syn_backlog=8192
net.ipv4.tcp_sack=1
net.ipv4.tcp_syn_retries=3
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_tw_recycle = 0
net.ipv4.tcp_tw_reuse = 0
net.ipv4.tcp_max_tw_buckets = 1440000
vm.swappiness=10
vm.min_free_kbytes=65536
net.ipv4.ip_local_port_range=1024 65535
net.ipv4.tcp_slow_start_after_idle=0
net.ipv4.tcp_rfc1337=1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.default.log_martians = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.netfilter.nf_conntrack_helper=0
net.netfilter.nf_conntrack_tcp_timeout_established = 28800
net.netfilter.nf_conntrack_generic_timeout = 60
net.ipv4.tcp_challenge_ack_limit = 999999999
EOF
    fi
  else
    touch /etc/sysctl.d/101-sysctl.conf
    if [[ "$(grep 'centminmod added' /etc/sysctl.d/101-sysctl.conf >/dev/null 2>&1; echo $?)" != '0' ]]; then
cat >> "/etc/sysctl.d/101-sysctl.conf" <<EOF
# centminmod added
fs.nr_open=12000000
fs.file-max=9000000
net.core.wmem_max=16777216
net.core.rmem_max=16777216
net.ipv4.tcp_rmem=8192 87380 16777216                                          
net.ipv4.tcp_wmem=8192 65536 16777216
net.core.netdev_max_backlog=8192
net.core.somaxconn=8151
net.core.optmem_max=8192
net.ipv4.tcp_fin_timeout=10
net.ipv4.tcp_keepalive_intvl=30
net.ipv4.tcp_keepalive_probes=3
net.ipv4.tcp_keepalive_time=240
net.ipv4.tcp_max_syn_backlog=8192
net.ipv4.tcp_sack=1
net.ipv4.tcp_syn_retries=3
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_tw_recycle = 0
net.ipv4.tcp_tw_reuse = 0
net.ipv4.tcp_max_tw_buckets = 1440000
vm.swappiness=10
vm.min_free_kbytes=65536
net.ipv4.ip_local_port_range=1024 65535
net.ipv4.tcp_slow_start_after_idle=0
net.ipv4.tcp_limit_output_bytes=65536
net.ipv4.tcp_rfc1337=1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.default.log_martians = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.netfilter.nf_conntrack_helper=0
net.netfilter.nf_conntrack_tcp_timeout_established = 28800
net.netfilter.nf_conntrack_generic_timeout = 60
net.ipv4.tcp_challenge_ack_limit = 999999999
EOF
    fi
  fi
fi

# centminmod + centos 6
# some settings already added by centminmod lemp installer
if [[ ! "$(grep -qs "hwdsl2 VPN script" /etc/sysctl.conf)" && "$CENTMINMOD" = [yY] && ! -f /etc/sysctl.d/101-sysctl.conf ]]; then
  conf_bk "/etc/sysctl.conf"
cat >> /etc/sysctl.conf <<EOF

# Added by hwdsl2 VPN script
kernel.msgmnb = 65536
kernel.msgmax = 65536
kernel.shmmax = 68719476736
kernel.shmall = 4294967296

net.ipv4.ip_forward = 1
net.ipv4.tcp_syncookies = 1
#net.ipv4.conf.all.accept_source_route = 0
#net.ipv4.conf.default.accept_source_route = 0
#net.ipv4.conf.all.accept_redirects = 0
#net.ipv4.conf.default.accept_redirects = 0
#net.ipv4.conf.all.send_redirects = 0
#net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.lo.send_redirects = 0
net.ipv4.conf.$NET_IFACE.send_redirects = 0
net.ipv4.conf.all.rp_filter = 0
net.ipv4.conf.default.rp_filter = 0
net.ipv4.conf.lo.rp_filter = 0
net.ipv4.conf.$NET_IFACE.rp_filter = 0
#net.ipv4.icmp_echo_ignore_broadcasts = 1
#net.ipv4.icmp_ignore_bogus_error_responses = 1
EOF
sed -i '/net.ipv4.conf.all.rp_filter = 1/d' /etc/sysctl.conf
  if [[ "$OPENVZ_OK" -eq '1' && ! "$(grep 'for openvz systems' /etc/sysctl.conf)" ]]; then
      echo "#for openvz systems" >> /etc/sysctl.conf
    for dev in $(ls /proc/sys/net/ipv4/conf/); do
      echo "net.ipv4.conf.${dev}.accept_source_route=0" >> /etc/sysctl.conf
      echo "net.ipv4.conf.${dev}.accept_redirects=0" >> /etc/sysctl.conf
      echo "net.ipv4.conf.${dev}.send_redirects=0" >> /etc/sysctl.conf
      echo "net.ipv4.conf.${dev}.rp_filter=0" >> /etc/sysctl.conf
    done
  fi
  sysctl -p
fi

# centminmod + centos 7
# some settings already added by centminmod lemp installer
if [[ ! "$(grep -qs "hwdsl2 VPN script" /etc/sysctl.d/101-sysctl.conf)" && "$CENTMINMOD" = [yY] && -f /etc/sysctl.d/101-sysctl.conf ]]; then
  conf_bk "/etc/sysctl.d/101-sysctl.conf"
cat >> /etc/sysctl.d/101-sysctl.conf <<EOF

# Added by hwdsl2 VPN script
kernel.msgmnb = 65536
kernel.msgmax = 65536
kernel.shmmax = 68719476736
kernel.shmall = 4294967296

net.ipv4.ip_forward = 1
net.ipv4.tcp_syncookies = 1
#net.ipv4.conf.all.accept_source_route = 0
#net.ipv4.conf.default.accept_source_route = 0
#net.ipv4.conf.all.accept_redirects = 0
#net.ipv4.conf.default.accept_redirects = 0
#net.ipv4.conf.all.send_redirects = 0
#net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.lo.send_redirects = 0
net.ipv4.conf.$NET_IFACE.send_redirects = 0
net.ipv4.conf.all.rp_filter = 0
net.ipv4.conf.default.rp_filter = 0
net.ipv4.conf.lo.rp_filter = 0
net.ipv4.conf.$NET_IFACE.rp_filter = 0
#net.ipv4.icmp_echo_ignore_broadcasts = 1
#net.ipv4.icmp_ignore_bogus_error_responses = 1
EOF
sed -i '/net.ipv4.conf.all.rp_filter = 1/d' /etc/sysctl.d/101-sysctl.conf
sed -i 's|net.ipv4.conf.default.rp_filter = .*|net.ipv4.conf.default.rp_filter = 0|' /usr/lib/sysctl.d/50-default.conf
sed -i 's|net.ipv4.conf.all.rp_filter = .*|net.ipv4.conf.all.rp_filter = 0|' /usr/lib/sysctl.d/50-default.conf
  if [[ "$OPENVZ_OK" -eq '1' && ! "$(grep 'for openvz systems' /etc/sysctl.d/101-sysctl.conf)" ]]; then
      echo "#for openvz systems" >> /etc/sysctl.d/101-sysctl.conf
    for dev in $(ls /proc/sys/net/ipv4/conf/); do
      echo "net.ipv4.conf.${dev}.accept_source_route=0" >> /etc/sysctl.d/101-sysctl.conf
      echo "net.ipv4.conf.${dev}.accept_redirects=0" >> /etc/sysctl.d/101-sysctl.conf
      echo "net.ipv4.conf.${dev}.send_redirects=0" >> /etc/sysctl.d/101-sysctl.conf
      echo "net.ipv4.conf.${dev}.rp_filter=0" >> /etc/sysctl.d/101-sysctl.conf
    done
  fi
fi

bigecho "Updating IPTables rules..."

# Check if IPTables rules need updating
ipt_flag=0
IPT_FILE="/etc/sysconfig/iptables"
if ! grep -qs "hwdsl2 VPN script" "$IPT_FILE" \
   || ! iptables -t nat -C POSTROUTING -s "$L2TP_NET" -o "$net_iface" -j MASQUERADE 2>/dev/null \
   || ! iptables -t nat -C POSTROUTING -s "$XAUTH_NET" -o "$net_iface" -m policy --dir out --pol none -j MASQUERADE 2>/dev/null; then
  ipt_flag=1
fi

if [[ "$CENTMINMOD" = [yY] ]]; then
  ipt_flag=1
fi

# Add IPTables rules for VPN
if [ "$ipt_flag" = "1" ]; then
  if [ ! -f /etc/csf/csf.conf ]; then
    service fail2ban stop >/dev/null 2>&1
    iptables-save > "$IPT_FILE.old-$SYS_DT"
    iptables -I INPUT 1 -p udp --dport 1701 -m policy --dir in --pol none -j DROP
    iptables -I INPUT 2 -m conntrack --ctstate INVALID -j DROP
    iptables -I INPUT 3 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
    iptables -I INPUT 4 -p udp -m multiport --dports 500,4500 -j ACCEPT
    iptables -I INPUT 5 -p udp --dport 1701 -m policy --dir in --pol ipsec -j ACCEPT
    iptables -I INPUT 6 -p udp --dport 1701 -j DROP
    iptables -I FORWARD 1 -m conntrack --ctstate INVALID -j DROP
  iptables -I FORWARD 2 -i "$net_iface" -o ppp+ -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
  iptables -I FORWARD 3 -i ppp+ -o "$net_iface" -j ACCEPT
    iptables -I FORWARD 4 -i ppp+ -o ppp+ -s "$L2TP_NET" -d "$L2TP_NET" -j ACCEPT
  iptables -I FORWARD 5 -i "$net_iface" -d "$XAUTH_NET" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
  iptables -I FORWARD 6 -s "$XAUTH_NET" -o "$net_iface" -j ACCEPT
    # Uncomment if you wish to disallow traffic between VPN clients themselves
    # iptables -I FORWARD 2 -i ppp+ -o ppp+ -s "$L2TP_NET" -d "$L2TP_NET" -j DROP
    # iptables -I FORWARD 3 -s "$XAUTH_NET" -d "$XAUTH_NET" -j DROP
    iptables -A FORWARD -j DROP
  iptables -t nat -I POSTROUTING -s "$XAUTH_NET" -o "$net_iface" -m policy --dir out --pol none -j MASQUERADE
  iptables -t nat -I POSTROUTING -s "$L2TP_NET" -o "$net_iface" -j MASQUERADE
    echo "# Modified by hwdsl2 VPN script" > "$IPT_FILE"
    iptables-save >> "$IPT_FILE"
  else
cat >/etc/csf/csfpre.sh<<EFF
#!/bin/bash
iptables -I INPUT 1 -p udp --dport 1701 -m policy --dir in --pol none -j DROP
iptables -I INPUT 2 -m conntrack --ctstate INVALID -j DROP
iptables -I INPUT 3 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
iptables -I INPUT 4 -p udp -m multiport --dports 500,4500 -j ACCEPT
iptables -I INPUT 5 -p udp --dport 1701 -m policy --dir in --pol ipsec -j ACCEPT
iptables -I INPUT 6 -p udp --dport 1701 -j DROP
iptables -I FORWARD 1 -m conntrack --ctstate INVALID -j DROP
iptables -I FORWARD 2 -i "$NET_IFACE" -o ppp+ -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
iptables -I FORWARD 3 -i ppp+ -o "$NET_IFACE" -j ACCEPT
iptables -I FORWARD 4 -i ppp+ -o ppp+ -s "$L2TP_NET" -d "$L2TP_NET" -j ACCEPT
iptables -I FORWARD 5 -i "$NET_IFACE" -d "$XAUTH_NET" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
iptables -I FORWARD 6 -s "$XAUTH_NET" -o "$NET_IFACE" -j ACCEPT
# Uncomment if you wish to disallow traffic between VPN clients themselves
# iptables -I FORWARD 2 -i ppp+ -o ppp+ -s "$L2TP_NET" -d "$L2TP_NET" -j DROP
# iptables -I FORWARD 3 -s "$XAUTH_NET" -d "$XAUTH_NET" -j DROP
iptables -A FORWARD -j DROP
iptables -t nat -I POSTROUTING -s "$XAUTH_NET" -o "$NET_IFACE" -m policy --dir out --pol none -j MASQUERADE
iptables -t nat -I POSTROUTING -s "$L2TP_NET" -o "$NET_IFACE" -j MASQUERADE
EFF
    chmod 0700 /etc/csf/csfpre.sh
    cat /etc/csf/csfpre.sh
  fi
fi

# skip fail2ban install if CSF Firewall is detected as
# SSH is already protected by CSF Firewall
if [ ! -f /etc/csf/csf.conf ]; then
  bigecho "Creating basic Fail2Ban rules..."

if [ ! -f /etc/fail2ban/jail.local ] ; then
cat > /etc/fail2ban/jail.local <<'EOF'
[ssh-iptables]
enabled  = true
filter   = sshd
action   = iptables[name=SSH, port=ssh, protocol=tcp]
logpath  = /var/log/secure
EOF
fi
fi

bigecho "Enabling services on boot..."

if grep -qs "release 6" /etc/redhat-release; then
  chkconfig iptables on
  if [ ! -f /etc/csf/csf.conf ]; then
    chkconfig fail2ban on
  fi
else
  if [ ! -f /etc/csf/csf.conf ]; then
    systemctl --now mask firewalld 2>/dev/null
    systemctl enable iptables fail2ban 2>/dev/null
  else
    systemctl enable iptables 2>/dev/null
  fi
fi
if [ ! "$(grep -qs "hwdsl2 VPN script" /etc/rc.local)" ]; then
  if [ -f /etc/rc.local ]; then
    conf_bk "/etc/rc.local"
  else
    echo '#!/bin/sh' > /etc/rc.local
  fi
cat >> /etc/rc.local <<'EOF'

# Added by hwdsl2 VPN script
(sleep 15
modprobe -q pppol2tp
service ipsec restart
service xl2tpd restart
echo 1 > /proc/sys/net/ipv4/ip_forward)&
EOF
fi

bigecho "Starting services..."

if [[ "$CENTMINMOD" = [nN] ]]; then
  # Restore SELinux contexts
  restorecon /etc/ipsec.d/*db 2>/dev/null
  restorecon /usr/local/sbin -Rv 2>/dev/null
  restorecon /usr/local/libexec/ipsec -Rv 2>/dev/null
fi

# Reload sysctl.conf
if [[ -f /etc/sysctl.d/101-sysctl.conf && "$CENTMINMOD" = [yY] ]]; then
  /sbin/sysctl --system
elif [[ "$OPENVZ_OK" -eq '1' && "$CENTMINMOD" = [yY] ]]; then
  /sbin/sysctl --system
else
  sysctl -e -q -p
fi

# Update file attributes
chmod +x /etc/rc.local
chmod 600 /etc/ipsec.secrets* /etc/ppp/chap-secrets* /etc/ipsec.d/passwd*

if [ ! -f /etc/csf/csf.conf ]; then
  # Apply new IPTables rules
  iptables-restore < "$IPT_FILE"
fi

# Fix xl2tpd on CentOS 7 for providers such as Linode,
# where kernel module "l2tp_ppp" is unavailable
if grep -qs "release 7" /etc/redhat-release; then
  if ! modprobe -q l2tp_ppp; then
    sed -i '/^ExecStartPre/s/^/#/' /usr/lib/systemd/system/xl2tpd.service
    systemctl daemon-reload
  fi
fi

# Restart services
modprobe -q pppol2tp
if [ ! -f /etc/csf/csf.conf ]; then
  service fail2ban restart 2>/dev/null
elif [ -f /etc/csf/csf.conf ]; then
  service csf restart
fi
service ipsec restart 2>/dev/null
service xl2tpd restart 2>/dev/null
# systemctl restart ipsec xl2tpd; csf -r; sleep 3; ipsec verify
sleep 3; ipsec verify

cat <<EOF

================================================

IPsec VPN server is now ready for use!

Connect to your new VPN with these details:

Server IP: $PUBLIC_IP
IPsec PSK: $VPN_IPSEC_PSK
Username: $VPN_USER
Password: $VPN_PASSWORD

Write these down. You'll need them to connect!

Important notes:   https://git.io/vpnnotes
Setup VPN clients: https://git.io/vpnclients

================================================

EOF

}

## Defer setup until we have the complete script
vpnsetup "$@"

exit 0
