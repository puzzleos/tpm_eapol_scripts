#!/bin/bash

####
# config

TPM_POL_PUBKEY_ALG="rsa"

TPM_PCRS_DEF="sha256:7"

# dev/test nvindex values
TPM_NV_PASSWD="0x1500001"
TPM_NV_SECRET="0x1500030"

####
# functions

function notice() {
	echo ">>> notice: $@"
}

function warn() {
	echo ">>> warning: $@"
}

function error() {
	echo ">>> error: $@"
	exit 1
}

function error_check() {
	[[ $1 -eq 0 ]] && return
	shift
	error "$@"
}

function usage() {
	echo "usage: tpm-read-passwd.sh <pubkey.pem> <ea.policy.digest>"
	exit 1
}

function nvindex_len() {
	if [[ -z $1 ]]; then
		echo "0"
		return
	fi

	tpm2_nvreadpublic $1 | sed -n 's/[ \t]\+size:[  \t]\+//p'
}

####
# main

#
# arg processing

[[ $# -eq 2 ]] || usage
pubkey_file=$1
policy_file=$2
[[ -r $pubkey_file ]] || \
	error "unable to read the public key ($pubkey_file)"
[[ -r $policy_file ]] || \
	error "unable to read the policy file ($policy_file)"

#
# create some scratch space

tdir=$(mktemp -d -t tpm-XXXXXXXX)
trap '(rm -rf $tdir)' EXIT

#
# load the public signing key into the tpm

notice "loading password-reading tpm ea policy public key"
tpm2_loadexternal -C o -G $TPM_POL_PUBKEY_ALG -u $pubkey_file \
	-c $tdir/pubkey_ctx_a -n $tdir/pubkey_name_a
error_check $? "unable to load the public signing key($pubkey_file)"

#
# tpm passwd nvindex

passwd_len=$(nvindex_len $TPM_NV_PASSWD)
secret_len=$(nvindex_len $TPM_NV_SECRET)

tpm2_startauthsession -S $tdir/tpm_session_a --policy-session
tpm2_policypcr -S $tdir/tpm_session_a -l $TPM_PCRS_DEF -L $tdir/tpm_unseal_a
tpm2_verifysignature -c $tdir/pubkey_ctx_a -f rsassa -g sha256 \
	-m $tdir/tpm_unseal_a -s $policy_file -t $tdir/tpm_sigtkt_a
tpm2_policyauthorize -S $tdir/tpm_session_a -i $tdir/tpm_unseal_a \
	-n $tdir/pubkey_name_a -t $tdir/tpm_sigtkt_a
notice "TPM passwords (owner,endoresement,lockout) [$passwd_len bytes]"
passwd=$(tpm2_nvread -P "session:$tdir/tpm_session_a" \
	-s $passwd_len $TPM_NV_PASSWD)
echo $passwd
tpm2_flushcontext $tdir/tpm_session_a

notice "SECRET [$secret_len bytes]"
(tpm2_nvread -C o -P $passwd -s $secret_len $TPM_NV_SECRET; echo "")

# NOTE: trap command above will clean up $tdir (critical!)

exit 0
