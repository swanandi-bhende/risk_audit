#!/bin/sh
# SecureTech Solutions lab setup for the Metasploitable 2 company server (AST-009).
#
# Run as root inside the Metasploitable 2 VM console:
#   sudo sh metasploitable_configure.sh
#
# Intentionally weak settings for the isolated lab only. Never reuse these
# accounts or passwords outside the lab. Each change is listed in
# Docs/lab_setup/configuration_log.md.

set -e

if [ "$(id -u)" -ne 0 ]; then
    echo "Run as root: sudo sh $0" >&2
    exit 1
fi

echo "[1/5] Creating department test accounts (weak passwords by design)"
create_user() {
    user="$1"; pass="$2"
    id "$user" >/dev/null 2>&1 || useradd -m -s /bin/bash "$user"
    echo "$user:$pass" | chpasswd
}
create_user hr_user    hr2024
create_user fin_user   Finance1
create_user dev_user   password
create_user sales_user sales123
create_user helpdesk01 helpdesk
create_user admin_it   admin

echo "[2/5] Creating shared 'staff' group (HR and Finance members)"
groupadd -f staff
usermod -aG staff hr_user
usermod -aG staff fin_user

echo "[3/5] Creating Operations drive, readable by the shared group"
mkdir -p /srv/operations
chgrp staff /srv/operations
chmod 2775 /srv/operations
echo "Operations shared drive (lab sample data)" > /srv/operations/README.txt

echo "[4/5] Creating source code repository owned by a standard developer account"
mkdir -p /srv/repo
chown dev_user /srv/repo
chmod 755 /srv/repo

echo "[5/5] Granting excess sudo rights (helpdesk01 full root without password, admin_it full root)"
cp /etc/sudoers /etc/sudoers.bak
grep -q "^helpdesk01 " /etc/sudoers || echo "helpdesk01 ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers
grep -q "^admin_it " /etc/sudoers || echo "admin_it ALL=(ALL) ALL" >> /etc/sudoers
visudo -c

echo
echo "Done. Verify with:"
echo "  id hr_user; id fin_user; ls -ld /srv/operations /srv/repo; sudo -l -U helpdesk01"
