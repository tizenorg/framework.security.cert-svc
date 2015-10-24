#!/bin/bash

# truncate sql
> /opt/share/cert-svc/root-cert.sql

# In a given subject, we need to loop through the field to get the valid field value #
SSL_DIRECTORY="/usr/share/ca-certificates/certs/"
for i in `find $SSL_DIRECTORY -maxdepth 1 -type f`
do
	var=`echo $i | cut -f 6 -d '/'`
	var1=`openssl x509 -in $i -subject -noout -nameopt multiline | grep commonName | cut -f 2 -d =`
	if [[ $var1 == "" ]]
	then
		var2=`openssl x509 -in $i -subject -noout -nameopt multiline | grep organizationalUnitName | cut -f 2 -d =`
		if [[ $var2 == "" ]]
		then
			var3=`openssl x509 -in $i -subject -noout -nameopt multiline | grep organizationName | cut -f 2 -d =`
			if [[ $var3 == "" ]]
			then
				var4=`openssl x509 -in $i -subject -noout -nameopt multiline | grep emailAddress | cut -f 2 -d =`
				if [[ $var4 != "" ]]
				then
					commonName=$var4
				fi
			else
				commonName=$var3
			fi
		else
			commonName=$var2
		fi
	else
		commonName=$var1
	fi

	filehash=`openssl x509 -in $i -hash -noout`;
	subjecthash=`openssl x509 -in $i -subject_hash_old -noout`;
	cert=`cat $i | sed -n '1,/END/p'`;
	commonname=$commonName;
	status=1;
	echo "INSERT INTO ssl (gname, certificate, file_hash, subject_hash, common_name, enabled, is_root_app_enabled) values (\"$var\", \"$cert\",\"$filehash\",\"$subjecthash\",\"$commonname\",$status, $status);" >> /opt/share/cert-svc/root-cert.sql
done
