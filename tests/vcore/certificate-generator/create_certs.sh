#!/bin/bash
# Copyright (c) 2011 Samsung Electronics Co., Ltd All Rights Reserved
#
#    Licensed under the Apache License, Version 2.0 (the "License");
#    you may not use this file except in compliance with the License.
#    You may obtain a copy of the License at
#
#        http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS,
#    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#    See the License for the specific language governing permissions and
#    limitations under the License.
#

#Prerequisite to run script is to
#create root certificate and directory structure (demoCA) with command:
#/usr/lib/ssl/misc/CA.sh -newca
#for automated tests default structure is created in demoCA.init

#make sure current dir has no files from previous generation
rm -r 1* 2* 3* ca* respcert* demoCA
cp -R demoCA.init demoCA
echo "01" > ./demoCA/crlnumber

for index in 1 2 3
do
    #create certificate A
    openssl genrsa -out ${index}second_level.key 1024 -passin pass:1234 -config ./openssl.cnf
    openssl req -new -key ${index}second_level.key -out ${index}second_level.csr -passin pass:1234 -config ./openssl.cnf <<CONTENT
PL
Masovian
Warsaw
priv
priv
second_level${index}



CONTENT

    openssl ca -in ${index}second_level.csr -out ${index}second_level.pem -passin pass:1234 -config ./openssl.cnf -extensions v3_ca <<CONTENT
y
y
CONTENT

    #create certificate B
    openssl req -new -keyout ${index}third_level.key -out ${index}third_level.request -passin pass:1234 -passout pass:1234 -days 365  -config ./openssl.cnf  <<CONTENT
PL
Masovian
Warsaw
priv
priv
third_level${index}



CONTENT

    openssl ca -config ./openssl.cnf -extensions v3_ca -policy policy_anything -keyfile ${index}second_level.key -cert ${index}second_level.pem -out ${index}third_level.pem -infiles ${index}third_level.request <<CONTENT
y
y
CONTENT

done

#generate OCSP response signing certificate
openssl genrsa -out respcert.key 1024 -passin pass:1234 -config ./openssl.cnf
openssl req -new -key respcert.key -out respcert.csr -passin pass:1234 -config ./openssl.cnf <<CONTENT
PL
Masovian
Warsaw
priv
priv
responce_cert



CONTENT

openssl ca -in respcert.csr -out respcert.pem -passin pass:1234 -config ./openssl.cnf -extensions ocsp_cert <<CONTENT
y
y
CONTENT

#generate CRL
openssl ca -passin pass:1234 -gencrl -keyfile ./demoCA/private/cakey.pem -cert ./demoCA/cacert.pem -out cacrl1.pem -crldays 30 -config ./openssl.cnf
openssl ca -passin pass:1234 -revoke 1third_level.pem -keyfile ./demoCA/private/cakey.pem -cert ./demoCA/cacert.pem -config ./openssl.cnf
openssl ca -passin pass:1234 -gencrl -keyfile ./demoCA/private/cakey.pem -cert ./demoCA/cacert.pem -out cacrl1.pem -crldays 30 -config ./openssl.cnf

openssl ca -passin pass:1234 -gencrl -keyfile ./demoCA/private/cakey.pem -cert ./demoCA/cacert.pem -out cacrl2.pem -crldays 30 -config ./openssl.cnf
openssl ca -passin pass:1234 -revoke 2second_level.pem -keyfile ./demoCA/private/cakey.pem -cert ./demoCA/cacert.pem -config ./openssl.cnf
openssl ca -passin pass:1234 -gencrl -keyfile ./demoCA/private/cakey.pem -cert ./demoCA/cacert.pem -out cacrl2.pem -crldays 30 -config ./openssl.cnf
