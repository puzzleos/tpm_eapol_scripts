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
	echo "usage: tpm-policy.sh <pcr_prod.bin>"
	echo "  all pcr files should contain only $TPM_PCRS_DEF values"
	exit 1
}

####
# main

#
# arg processing

[[ $# -eq 1 ]] || usage
pcrs_prod=$1
[[ -r $pcrs_prod ]] || \
	error "unable to read the production pcr values ($pcrs_prod)"

#
# create some scratch space

tdir=$(mktemp -d -t tpm-XXXXXXXX)
trap '(rm -rf $tdir)' EXIT

#
# nvindex for the secret

# NOTE: this policy file must be signed afterwards
pol_secret="./tpm_secret.policy"

notice "creating TPM_NV_SECRET policy"

# define the nvindex
tpm2_createprimary -C p -c $tdir/tpm_ctx_b
tpm2_startauthsession -S $tdir/tpm_session_b -c $tdir/tpm_ctx_b
tpm2_policypcr -S $tdir/tpm_session_b -l $TPM_PCRS_DEF -f $pcrs_prod
echo $TPM_POL_VERSION | xxd -r -p | tpm2_policynv -S $tdir/tpm_session_b \
	-i- $TPM_NV_VERSION eq -L $pol_secret
tpm2_flushcontext $tdir/tpm_session_b

# cleanup
rm -f $tdir/tpm_ctx_b $tdir/tpm_session_b

#
# done

notice "policy SECRET($pol_secret)"
exit 0
