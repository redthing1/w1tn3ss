#!/bin/bash

###
# this script generates a code signing certificate and installs it in the system keychain.
# based on: https://github.com/llvm/llvm-project/blob/main/lldb/scripts/macos-setup-codesign.sh
###

# require a certificate name
if [ -z "$1" ]; then
    echo "usage: $0 <certificate name>"
    exit 1
fi

CERT="$1"

function error() {
    echo error: "$@" 1>&2
    exit 1
}

function cleanup {
    # Remove generated files
    rm -f "$TMPDIR/$CERT.tmpl" "$TMPDIR/$CERT.cer" "$TMPDIR/$CERT.key" > /dev/null 2>&1
}

trap cleanup EXIT

# Check if the certificate is already present in the system keychain
security find-certificate -Z -p -c "$CERT" /Library/Keychains/System.keychain > /dev/null 2>&1
if [ $? -eq 0 ]; then
    printf "certificate [%s] has already been generated and installed\n" "$CERT"
    exit 0
fi

# Create the certificate template
cat <<EOF >$TMPDIR/$CERT.tmpl
[ req ]
default_bits       = 2048        # RSA key size
encrypt_key        = no          # Protect private key
default_md         = sha512      # MD to use
prompt             = no          # Prompt for DN
distinguished_name = codesign_dn # DN template
[ codesign_dn ]
commonName         = "$CERT"
[ codesign_reqext ]
keyUsage           = critical,digitalSignature
extendedKeyUsage   = critical,codeSigning
EOF

printf "generating and installing certificate [%s]\n" "$CERT"

# generate a new certificate
openssl req -new -newkey rsa:2048 -x509 -days 3650 -nodes -config "$TMPDIR/$CERT.tmpl" -extensions codesign_reqext -batch -out "$TMPDIR/$CERT.cer" -keyout "$TMPDIR/$CERT.key" > /dev/null 2>&1
# [ $? -eq 0 ] || error something went wrong when generating the certificate
[ $? -eq 0 ] || error openssl failed to generate the certificate

# Install the certificate in the system keychain
sudo security authorizationdb read com.apple.trust-settings.admin > "$TMPDIR/rights"
sudo security authorizationdb write com.apple.trust-settings.admin allow
sudo security add-trusted-cert -d -r trustRoot -p codeSign -k /Library/Keychains/System.keychain "$TMPDIR/$CERT.cer" > /dev/null 2>&1
result=$?
sudo security authorizationdb write com.apple.trust-settings.admin < "$TMPDIR/rights"
# [ $result -eq 0 ] || error something went wrong when installing the certificate
[ $result -eq 0 ] || error security authorizationdb failed to install the certificate

# Install the key for the certificate in the system keychain
sudo security import "$TMPDIR/$CERT.key" -A -k /Library/Keychains/System.keychain > /dev/null 2>&1
# [ $? -eq 0 ] || error something went wrong when installing the key
[ $? -eq 0 ] || error security import failed to install the key

# Kill task_for_pid access control daemon
sudo pkill -f /usr/libexec/taskgated > /dev/null 2>&1

# Exit indicating the certificate is now generated and installed
printf "certificate [%s] has been generated and installed\n" "$CERT"
exit 0