#!/bin/bash

# Optional
# export HOOK_HMAC_KEY="add random to override /etc/machine-id"

# source /path.to/env/bin/activate
# export RBTOOLS_CONFIG_PATH=/path.to/

# Add truststore for Git signatures
# export GNUPGHOME=/path.to/truststore/active
# export HOOK_SIGNATURE_TRUST=fully,ultimate

REPOS=/path.to/repos

if [ -n "$HG_PENDING" ]; then
   REPO=${HG_PENDING#"$REPOS"}
else
   REPO=${PWD#"$REPOS"}
fi

#if [[ "$REPO" == *"/Experimental/"* ]]; then
#   echo "Skip Review Board for: $REPO"
#   exit 0
#fi

if [[ "$REPO" == "/Test" ]]; then
   /path.to/mercurial_git_push_testing.py <&0
else
   /path.to/mercurial_git_push.py <&0
fi

