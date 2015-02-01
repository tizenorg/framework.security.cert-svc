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

pkill -9 openssl # if previously it was launched and openssl didn't close sockets

OPENSSL_CONF=/opt/apps/widget/tests/vcore_certs/openssl.cnf openssl ocsp -nrequest 5 -index /opt/apps/widget/tests/vcore_certs/demoCA/index.txt -port 8881 -rsigner /opt/apps/widget/tests/vcore_certs/respcert.pem -rkey /opt/apps/widget/tests/vcore_certs/respcert.key -CA /opt/apps/widget/tests/vcore_certs/demoCA/cacert.pem

echo "--- OCSP server shutdown..."
