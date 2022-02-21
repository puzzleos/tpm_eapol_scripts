#!/bin/bash

####
# config

# /dev/random for easier dev, /dev/hwrng for fips-140 compliance
RNG_SOURCE="/dev/random"

TPM_POL_PUBKEY_ALG="rsa"
TPM_POL_VERSION="0x00000001"

TPM_PCRS_DEF="sha256:7"

# dev/test nvindex values
TPM_NV_VERSION="0x1500020"

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
	echo "usage: $0 <pcrs_passwd.bin>"
	echo "  all pcr files should contain only $TPM_PCRS_DEF values"
	exit 1
}

####
# main

#
# arg processing

[[ $# -eq 1 ]] || usage
pcrs_passwd=$1
[[ -r $pcrs_passwd ]] || \
	error "unable to read the TPM administrative pcr values ($pcrs_passwd)"

#
# create some scratch space

tdir=$(mktemp -d -t tpm-XXXXXXXX)
trap '(rm -rf $tdir)' EXIT

#
# nvindex for the TPM administrative password

# NOTE: this policy file must be signed afterwards using the
# password-policy signing pubkey
pol_passwd="./tpm_passwd.policy"

notice "creating TPM_NV_PASSWD policy"

tpm2_createprimary -C p -c $tdir/tpm_ctx_b
tpm2_startauthsession -S $tdir/tpm_session_b -c $tdir/tpm_ctx_b
tpm2_policypcr -S $tdir/tpm_session_b -l $TPM_PCRS_DEF -f $pcrs_passwd \
    -L $pol_passwd
tpm2_flushcontext $tdir/tpm_session_b

# cleanup
rm -f $tdir/tpm_ctx_b $tdir/tpm_session_b

#
# done

notice "policy PASSWD($pol_passwd)"
exit 0
