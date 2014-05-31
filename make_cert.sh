#!/bin/sh

CA_keyname=$3
CA_certname=$4
SDK_keyname=$1
SDK_certreqname=SDK.csr
SDK_certname=$2

echo "*** parameter test ***"
echo "\$1 = "$1
echo "\$2 = "$2
echo "\$3 = "$3
echo "\$4 = "$4
echo "\$5 = "$5

if [ $# -le 4 ]
then
	echo "[ERR] Check your input argument"
	echo "num of args" $#
	exit 1
fi
	
echo "*** pre-requirement ***"
mkdir ./demoCA
touch ./demoCA/serial
echo "00" > ./demoCA/serial
touch ./demoCA/index.txt

echo "*** make key pair for SDK ***"
openssl genrsa -out ${SDK_keyname} 1024

echo "*** make certificate request ***"
openssl req -new -days 3650 -key ${SDK_keyname} -out ${SDK_certreqname} \
-subj '/C=KR/ST=Kyung-gi do/L=SuWon-si/O=Samsung/OU=DMC/CN='$5


echo "*** make SDK cert ***"
openssl ca -in ${SDK_certreqname} -out ${SDK_certname} -keyfile ${CA_keyname} -cert ${CA_certname} -outdir . << EOF
y
y
EOF

echo "*** remove temporary files ***"
rm -f ${SDK_certreqname}
rm -f *.pem
rm -rf ./demoCA
