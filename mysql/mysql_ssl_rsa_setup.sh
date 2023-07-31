#!/bin/bash

ROOT_DIR=/tmp/ssl
if [ -n "$1" ]; then
	ROOT_DIR="$1"
fi
mkdir -p $ROOT_DIR
cd $ROOT_DIR

function die() {
	echo "$*" 1>&2
	exit 1
}

# Refs:
# https://dev.mysql.com/doc/refman/5.7/en/mysql-ssl-rsa-setup.html
# https://github.com/ltangvald/mysql-5.7/blob/master/client/mysql_ssl_rsa_setup.cc
#
# Manually test:
# - Connect to MySQL:
# mysql -ussl --ssl-ca=/tmp/ssl/ca.pem
# mysql -ussl --ssl-cert=/tmp/ssl/client-cert.pem --ssl-key=/tmp/ssl/client-key.pem
# - Check SSL connection status
# mysql> \s
# mysql> SHOW VARIABLES LIKE '%ssl%';

default_suffix=diesel
suffix_string="$default_suffix"

f_CA_CERT="ca.pem"
f_CA_KEY="ca-key.pem"
f_CA_REQ="ca-req.pem"
f_SERVER_CERT="server-cert.pem"
f_SERVER_KEY="server-key.pem"
f_SERVER_REQ="server-req.pem"
f_CLIENT_CERT="client-cert.pem"
f_CLIENT_KEY="client-key.pem"
f_CLIENT_REQ="client-req.pem"
f_PRIVATE_KEY="private_key.pem"
f_PUBLIC_KEY="public_key.pem"

function x509_key() {
	local validity=3650
	local suffix="$1"
	local key_file="$2"
	local req_file="$3"
	openssl req -newkey rsa:2048 \
		-days $validity -nodes \
		-keyout $key_file \
		-subj "/CN=MySQL_Server_${suffix_string}${suffix}" \
		-out $req_file
	local code=$?
	if [ $code -eq 0 ]; then
		return $code
	fi
	openssl rsa -in $key_file -out $key_file
	return $?
}
function x509_cert() {
	local validity=3650
	local req_file="$1"
	local cert_file="$2"
	local serial="$3"
	local self_signed="$4"
	local sign_key_file="$5"
	local sign_cert_file="$6"
	local append
	if [ "$self_signed" = "true" ]; then
		append="-signkey $sign_key_file"
	else
		append="-CA $sign_cert_file -CAkey $sign_key_file"
	fi
	openssl x509 -sha256 \
		-days $validity \
		-set_serial $serial -req \
		-in $req_file $append \
		-out $cert_file
	return $?
}
function RSA_priv() {
	local key_size=2048
	local key_file="$1"
	openssl genrsa -out $key_file $key_size
	return $?
}
function RSA_pub() {
	local priv_key_file="$1"
	local pub_key_file="$2"
	openssl rsa -in $priv_key_file -pubout -out $pub_key_file
	return $?
}
x509_key "_Auto_Generated_CA_Certificate" $f_CA_KEY $f_CA_REQ || die "Error generating ca_key.pem and ca_req.pem"
x509_cert $f_CA_REQ $f_CA_CERT 1 true $f_CA_KEY || die "Error generating ca_cert.pem"

x509_key "_Auto_Generated_Server_Certificate" $f_SERVER_KEY $f_SERVER_REQ || die "Error generating server_key.pem and server_req.pem"
x509_cert $f_SERVER_REQ $f_SERVER_CERT 2 false $f_CA_KEY $f_CA_CERT || die "Error generating server_cert.pem"

x509_key "_Auto_Generated_Client_Certificate" $f_CLIENT_KEY $f_CLIENT_REQ || die "Error generating client_key.pem and client_req.pem"
x509_cert $f_CLIENT_REQ $f_CLIENT_CERT 3 false $f_CA_KEY $f_CA_CERT || die "Error generating client_cert.pem"

openssl verify -CAfile $f_CA_CERT $f_SERVER_CERT $f_CLIENT_CERT || die "Verification of X509 certificates failed."

RSA_priv $f_PRIVATE_KEY || die "Error generating private_key.pem"
RSA_pub $f_PRIVATE_KEY $f_PUBLIC_KEY || die "Error generating public_key.pem"
