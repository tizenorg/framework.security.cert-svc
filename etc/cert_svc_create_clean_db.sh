#!/bin/sh
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
for name in cert_svc_vcore
do
    /bin/rm -f /opt/dbspace/.$name.db
    /bin/rm -f /opt/dbspace/.$name.db-journal
    SQL="PRAGMA journal_mode = PERSIST;"
    /usr/bin/sqlite3 /opt/dbspace/.$name.db "$SQL"
    SQL=".read /usr/share/cert-svc/"$name"_db.sql"
    /usr/bin/sqlite3 /opt/dbspace/.$name.db "$SQL"
    /bin/touch /opt/dbspace/.$name.db-journal
    /bin/chown root:6026 /opt/dbspace/.$name.db
    /bin/chown root:6026 /opt/dbspace/.$name.db-journal
    /bin/chmod 660 /opt/dbspace/.$name.db
    /bin/chmod 660 /opt/dbspace/.$name.db-journal
    if [ -f /usr/lib/rpm-plugins/msm.so ]
    then
        /usr/bin/chsmack -a "cert-svc::db" /opt/dbspace/.$name.db
        /usr/bin/chsmack -a "cert-svc::db" /opt/dbspace/.$name.db-journal
    fi    
done


