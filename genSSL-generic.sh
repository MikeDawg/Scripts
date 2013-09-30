#!/bin/bash 
# Version 0.12
# genSSL script by Mike Harris
#
# Generate a SSL private key and SSL certificate signing request.
#
#
# TODO: Can probably clean-up the openssl.cnf script in the genCnf function, probably don't need everything that is in there, but 
# it works, and it more-or-less just adds to the length of this script.
#
# Set the bitLength flag, to adjust from 2048 bits to 4096 (or really whatever you want)
# Can later change this to be read from CLI from the user running the command, just not this version.
bitLength=2048
rootTest() {
# Verify that this script isn't being ran as root
# I would hate for my simple config to overwrite anything that is super important
# that only root has access to do.
# Make sure only root can run our script
if [[ $EUID -eq 0 ]]; then
   echo "This script must NOT be run as root" 1>&2
   exit 1
fi
}
#
# Generate a random file name to use for our temporary openssl.cnf file
# Not cryptographically random, but random enough for us to use, for our purpose.
randomConfigName=openssl-`date +%y%d%m`-"$RANDOM".cnf
#
#
genCnf() {
# Generate our "generic" version of openssl.cnf for use with our configuration.
cat > $randomConfigName << '_EOF'
HOME                    = .
RANDFILE                = $ENV::HOME/.rnd
oid_section             = new_oids
[ new_oids ]
tsa_policy1 = 1.2.3.4.1
tsa_policy2 = 1.2.3.4.5.6
tsa_policy3 = 1.2.3.4.5.7
[ ca ]
default_ca      = CA_default            # The default ca section
[ CA_default ]
dir             = ./demoCA              # Where everything is kept
certs           = $dir/certs            # Where the issued certs are kept
crl_dir         = $dir/crl              # Where the issued crl are kept
database        = $dir/index.txt        # database index file.
                                        # several ctificates with same subject.
new_certs_dir   = $dir/newcerts         # default place for new certs.
certificate     = $dir/cacert.pem       # The CA certificate
serial          = $dir/serial           # The current serial number
crlnumber       = $dir/crlnumber        # the current crl number
                                        # must be commented out to leave a V1 CRL
crl             = $dir/crl.pem          # The current CRL
private_key     = $dir/private/cakey.pem# The private key
RANDFILE        = $dir/private/.rand    # private random number file
x509_extensions = usr_cert              # The extentions to add to the cert
name_opt        = ca_default            # Subject Name options
cert_opt        = ca_default            # Certificate field options
default_days    = 365                   # how long to certify for
default_crl_days= 30                    # how long before next CRL
default_md      = default               # use public key default MD
preserve        = no                    # keep passed DN ordering
policy          = policy_match
[ policy_match ]
countryName             = match
stateOrProvinceName     = match
organizationName        = match
organizationalUnitName  = optional
commonName              = supplied
emailAddress            = optional
[ policy_anything ]
countryName             = optional
stateOrProvinceName     = optional
localityName            = optional
organizationName        = optional
organizationalUnitName  = optional
commonName              = supplied
emailAddress            = optional
[ req ]
default_bits            = 2048
default_keyfile         = privkey.pem
distinguished_name      = req_distinguished_name
attributes              = req_attributes
x509_extensions = v3_ca # The extentions to add to the self signed cert
string_mask = utf8only
req_extensions = v3_req # The extensions to add to a certificate request
[ req_distinguished_name ]
countryName                     = Country Name (2 letter code)
countryName_default             = US
countryName_min                 = 2
countryName_max                 = 2
stateOrProvinceName             = State or Province Name (full name)
stateOrProvinceName_default     = <FILL IN WITH DEFAULT STATE NAME>
localityName                    = Locality Name (eg, city)
localityName_default            = <FILL IN WITH DEFAULT LOCALITY NAME>
0.organizationName              = Organization Name (eg, company)
0.organizationName_default      = <FILL IN WITH DEFAULT ORG NAME>
organizationalUnitName          = Organizational Unit Name (eg, section)
organizationalUnitName_default  = <FILL IN WITH DEFAULT UNIT NAME>
commonName                      = Common Name (e.g. server FQDN or YOUR name)
commonName_max                  = 64
[ req_attributes ]
[ usr_cert ]
basicConstraints=CA:FALSE
nsComment                       = "OpenSSL Generated Certificate"
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
[ v3_req ]
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
subjectAltName = @alt_names
[ v3_ca ]
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid:always,issuer
basicConstraints = CA:true
[ crl_ext ]
authorityKeyIdentifier=keyid:always
[ proxy_cert_ext ]
basicConstraints=CA:FALSE
nsComment                       = "OpenSSL Generated Certificate"
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
proxyCertInfo=critical,language:id-ppl-anyLanguage,pathlen:3,policy:foo
[ tsa ]
default_tsa = tsa_config1       # the default TSA section
[ tsa_config1 ]
dir             = ./demoCA              # TSA root directory
serial          = $dir/tsaserial        # The current serial number (mandatory)
crypto_device   = builtin               # OpenSSL engine to use for signing
signer_cert     = $dir/tsacert.pem      # The TSA signing certificate
                                        # (optional)
certs           = $dir/cacert.pem       # Certificate chain to include in reply
                                        # (optional)
signer_key      = $dir/private/tsakey.pem # The TSA private key (optional)
default_policy  = tsa_policy1           # Policy if request did not specify it
                                        # (optional)
other_policies  = tsa_policy2, tsa_policy3      # acceptable policies (optional)
digests         = md5, sha1             # Acceptable message digests (mandatory)
accuracy        = secs:1, millisecs:500, microsecs:100  # (optional)
clock_precision_digits  = 0     # number of digits after dot. (optional)
ordering                = yes   # Is ordering defined for timestamps?
                                # (optional, default: no)
tsa_name                = yes   # Must the TSA name be included in the reply?
                                # (optional, default: no)
ess_cert_id_chain       = no    # Must the ESS cert id chain be included?
                                # (optional, default: no)
_EOF
}

readDomain() {
# Read a list of domain names (or just 1) to use for subject alt names and the naming
# of the certificate
echo "Please enter a comma-delimited list of domain names to assign for this certificate:    "
read commaDelimitedHostNames
echo $commaDelimitedHostNames
IFS=","
initialValue=1
echo "[ alt_names ]" >> $randomConfigName
for commaDelimitedValue in $commaDelimitedHostNames; do
	echo "DNS.$initialValue = $commaDelimitedValue" >> $randomConfigName
	# Consider first name the primary hostname, and name the key after it
	if [ $initialValue == 1 ]; then
		hostName=$commaDelimitedValue
		sed -i "69i\commonName_default   =  $commaDelimitedValue" $randomConfigName
	fi
	initialValue=`expr $initialValue + 1`
done
#
# Unset variables that we aren't going to use any more
unset IFS
unset initialValue
unset commaDelimitedValue
unset commaDelimitedHostNames
}

genPrivKeyandCSR() {
# Generate the private key and the CSR using the values we entered above.
# This can easily be changed to a different bit-size key, by altering
# the line below, for example, change from 2048 to 4096
openssl req -out $hostName.csr -new -newkey rsa:$bitLength -nodes -keyout $hostName-privKey.key -config $randomConfigName
}

cleanUp() {
# Remove unnecessary files from system, and create zip file containing CSR and private key
rm -f ./$randomConfigName
zip $hostName-CertReq.zip $hostName-privKey.key $hostName.csr
rm $hostName-privKey.key $hostName.csr
echo "$hostName-CertReq.zip has been created for you"
}
#
#
# Actually do the work!
#
rootTest
genCnf
readDomain
genPrivKeyandCSR
cleanUp
#
# Let's give the old exit code
exit 0
