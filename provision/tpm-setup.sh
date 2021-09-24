#!/bin/bash

####
# config

# /dev/random for easier dev, /dev/hwrng for fips-140 compliance
RNG_SOURCE="/dev/random"

TPM_POL_PUBKEY_ALG="rsa"
TPM_POL_VERSION="0x00000001"

TPM_PCRS_DEF="sha256:7"

# dev/test nvindex values
TPM_NV_PASSWD="0x1500001"
TPM_NV_VERSION="0x1500020"
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
	echo "usage: tpm-setup.sh <pubkey.pem> <pcr_prod.bin> <pcr_tpm.bin>"
	echo "  all pcr files should contain only $TPM_PCRS_DEF values"
	exit 1
}

function rng_bytes() {
	local bytes=$1

	[[ $bytes -le 0 ]] && return

	dd if=$RNG_SOURCE bs=1 count=$bytes 2> /dev/null | xxd -p | tr -d '\n'
}

function str_len() {
	if [[ -z $1 ]]; then
		echo "0"
		return
	fi

	echo $(( $(echo $1 | wc -c) - 1 ))
}

####
# main

#
# arg processing

[[ $# -eq 3 ]] || usage
pubkey_file=$1
pcrs_prod=$2
pcrs_mgmt=$3
[[ -r $pubkey_file ]] || \
	error "unable to read the public key ($pubkey_file)"
[[ -r $pcrs_prod ]] || \
	error "unable to read the production pcr values ($pcrs_prod)"
[[ -r $pcrs_mgmt ]] || \
	error "unable to read the management pcr values ($pcrs_mgmt)"

#
# create some scratch space

tdir=$(mktemp -d -t tpm-XXXXXXXX)
trap '(rm -rf $tdir)' EXIT

#
# generate a tpm password and take ownership

passwd="tpm-$(rng_bytes 16)"
passwd_len=$(str_len $passwd)
for i in owner endorsement lockout; do
	tpm2_changeauth -c $i $passwd || \
		error "failed to set $i password, tpm must be cleared first"
done
notice "set tpm passwd ($passwd)"

#
# load the public signing key into the tpm

notice "loading tpm ea policy public key"
tpm2_loadexternal -C o -G $TPM_POL_PUBKEY_ALG -u $pubkey_file \
	-c $tdir/pubkey_ctx_a -n $tdir/pubkey_name_a
error_check $? "unable to load the public signing key($pubkey_file)"

#
# policy "version" nvindex

notice "setting TPM_NV_VERSION ($TPM_POL_VERSION)"
tpm2_nvdefine -a "ownerwrite|ownerread|authread" \
	-P $passwd -s 4 $TPM_NV_VERSION
error_check $? "failed defining $TPM_NV_VERSION"
echo $TPM_POL_VERSION | xxd -r -p | \
	tpm2_nvwrite -C o -P $passwd -i- $TPM_NV_VERSION
error_check $? "failed writing to $TPM_NV_VERSION"

#
# tpm passwd nvindex

# NOTE: this policy file must be signed afterwards
pol_passwd="./tpm_mgmt.policy"

notice "setting TPM_NV_PASSWD"

# define the nvindex
tpm2_createprimary -C p -c $tdir/tpm_ctx_a
tpm2_startauthsession -S $tdir/tpm_session_a -c $tdir/tpm_ctx_a
tpm2_policypcr -S $tdir/tpm_session_a -l $TPM_PCRS_DEF -f $pcrs_mgmt \
	-L $pol_passwd
tpm2_policyauthorize -S $tdir/tpm_session_a -n $tdir/pubkey_name_a \
	-L $tdir/tpm_policy_a
tpm2_nvdefine -a "ownerwrite|ownerread|policyread" \
	-P $passwd -L $tdir/tpm_policy_a -s $passwd_len $TPM_NV_PASSWD
tpm2_flushcontext $tdir/tpm_session_a

# set the nvindex value
echo -n $passwd | tpm2_nvwrite -C o -P $passwd -i- $TPM_NV_PASSWD

# cleanup
rm -f $tdir/tpm_ctx_a $tdir/tpm_session_a $tdir/tpm_policy_a

#
# nvindex for the secret

# NOTE: this policy file must be signed afterwards
pol_secret="./tpm_secret.policy"

notice "setting TPM_NV_SECRET"

# create the secret 
secret="secret-$(rng_bytes 16)"
secret_len=$(str_len $secret)

# define the nvindex
tpm2_createprimary -C p -c $tdir/tpm_ctx_b
tpm2_startauthsession -S $tdir/tpm_session_b -c $tdir/tpm_ctx_b
tpm2_policypcr -S $tdir/tpm_session_b -l $TPM_PCRS_DEF -f $pcrs_prod
echo $TPM_POL_VERSION | xxd -r -p | tpm2_policynv -S $tdir/tpm_session_b \
	-i- $TPM_NV_VERSION eq -L $pol_secret
tpm2_policyauthorize -S $tdir/tpm_session_b -n $tdir/pubkey_name_a \
	-L $tdir/tpm_policy_b
tpm2_nvdefine -a "ownerwrite|ownerread|policyread" \
	-P $passwd -L $tdir/tpm_policy_b -s $secret_len $TPM_NV_SECRET
tpm2_flushcontext $tdir/tpm_session_b

# set the nvindex value
echo -n $secret | tpm2_nvwrite -C o -P $passwd -i- $TPM_NV_SECRET

# cleanup
rm -f $tdir/tpm_ctx_b $tdir/tpm_session_b $tdir/tpm_policy_b

#
# done

notice "nvindices TPM($TPM_NV_PASSWD) VER($TPM_NV_VERSION) SECRET($TPM_NV_SECRET)"
notice "policy TPM($pol_passwd) SECRET($pol_secret)"
exit 0
