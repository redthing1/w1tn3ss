#!/bin/bash

###
# this script signs an executable with a code signing certificate and entitlements.
###

if [ -z "$1" ] || [ -z "$2" ]; then
    echo "usage: $0 <key> <executable> [<entitlements>]"
    exit 1
fi

key="$1"
executable="$2"

if [ -z "$3" ]; then
    # get entitlement.xml from the same directory as this script
    entitlements=$(dirname "$0")/entitlement.xml
else
    entitlements="$3"
fi

printf "signing [%s] with key [%s], entitlements [%s]\n" "$executable" "$key" "$entitlements"

/usr/bin/codesign --entitlements "$entitlements" --force --sign "$key" "$executable"
