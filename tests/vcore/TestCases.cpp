/*
 *
 * Copyright (c) 2011 Samsung Electronics Co., Ltd All Rights Reserved
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 */
#include <string>

#include <dpl/test/test_runner.h>
#include <dpl/wrt-dao-ro/global_config.h>
#include <dpl/log/log.h>
#include <boost/optional.hpp>
#include <vcore/CryptoHash.h>
#include <vcore/ReferenceValidator.h>
#include <vcore/SignatureFinder.h>
#include <vcore/SignatureReader.h>
#include <vcore/SignatureValidator.h>
#include <vcore/WrtSignatureValidator.h>
#include "TestEnv.h"
#include <vcore/Base64.h>
#include <vcore/CertificateConfigReader.h>
#include <vcore/CertificateIdentifier.h>
#include <vcore/CertificateLoader.h>
#include <vcore/RevocationCheckerBase.h>
#ifdef TIZEN_FEATURE_CERT_SVC_OCSP_CRL
#include <vcore/OCSP.h>
#include <vcore/CachedOCSP.h>
#include <vcore/SSLContainers.h>
#include <vcore/CRL.h>
#include <vcore/CachedCRL.h>
#include "TestCRL.h"
#include <vcore/CertificateCacheDAO.h>
#endif

namespace {

const std::string widget_path =
    "/opt/apps/widget/tests/vcore_widget_uncompressed/";
const std::string widget_negative_hash_path =
    "/opt/apps/widget/tests/vcore_widget_uncompressed_negative_hash/";
const std::string widget_negative_signature_path =
    "/opt/apps/widget/tests/vcore_widget_uncompressed_negative_signature/";
const std::string widget_negative_certificate_path =
    "/opt/apps/widget/tests/vcore_widget_uncompressed_negative_certificate/";
const std::string widget_partner_path =
    "/opt/apps/widget/tests/vcore_widget_uncompressed_partner/";
const std::string widget_partner_operator_path =
    "/opt/apps/widget/tests/vcore_widget_uncompressed_partner_operator/";

const std::string keys_path = "/opt/apps/widget/tests/vcore_keys/";
const std::string widget_store_path = "/opt/apps/widget/tests/vcore_widgets/";
const std::string cert_store_path = "/opt/apps/widget/tests/vcore_certs/";
#ifdef TIZEN_FEATURE_CERT_SVC_OCSP_CRL
const std::string crl_URI = "http://localhost/my.crl";
#endif

const std::string anka_ec_key_type = "urn:oid:1.2.840.10045.3.1.7";
const std::string anka_ec_public_key =
        "BGi9RmTUjpqCpQjx6SSiKdfmtjQBFNSN7ghm6TuaH9r4x73WddeLxLioH3VEmFLC+QLiR"\
        "kPxDxL/6YmQdgfGrqk=";

const std::string rsa_modulus =
        "ocwjKEFaPxLNcPTz2PtT2Gyu5jzkWaPo4thjZo3rXuNbD4TzjY02UGnTxvflNeORLpSS1"\
        "PeYr/1E/Nhr7qQAzj9g0DwW7p8zQEdOUi3v76VykeB0pFJH+0Fxp6LVBX9Z+EvZk+dbOy"\
        "GJ4Njm9B6M09axXlV11Anj9B/HYUDfDX8=";
const std::string rsa_exponent = "AQAB";

const std::string magda_dsa_p =
        "2BYIQj0ePUVxzrdBT41eCblraa9Dqag7QXFMCRM2PtyS22JPDKuV77tBc/jg0V3htHWdR"\
        "q9n6/kQDwrP7FIPoLATLIiC3oAYWj46Mr6d9k/tt/JZU6PvULmB2k1wrrmvKUi+U+I5Ro"\
        "qe8ui8lqR9pp9u2WCh2QmFfCohKNjN5qs=";
const std::string magda_dsa_q = "4p4JcDqz+S7CbWyd8txApZw0sik=";
const std::string magda_dsa_g =
        "AQrLND1ZGFvzwBpPPXplmPh1ijPx1O2gQEvPvyjR88guWcGqQc0m7dTb6PEvbI/oZ0o91"\
        "k7VEkfthURnNR1WtOLT8dmAuKQfwTQLPwCwUM/QiuWSlCyKLTE4Ev8aOG7ZqWudsKm/td"\
        "n9pUNGtcod1wo1ZtP7PfEJ6rYZGQDOlz8=";

const std::string tizen_partner =
"MIICozCCAgwCCQD9IBoOxzq2hjANBgkqhkiG9w0BAQUFADCBlTELMAkGA1UEBhMC"
"S1IxDjAMBgNVBAgMBVN1d29uMQ4wDAYDVQQHDAVTdXdvbjEWMBQGA1UECgwNVGl6"
"ZW4gVGVzdCBDQTEiMCAGA1UECwwZVGl6ZW4gRGlzdHJpYnV0b3IgVGVzdCBDQTEq"
"MCgGA1UEAwwhVGl6ZW4gUGFydG5lciBEaXN0cmlidXRvciBSb290IENBMB4XDTEy"
"MTAyNjA4MTIzMVoXDTIyMTAyNDA4MTIzMVowgZUxCzAJBgNVBAYTAktSMQ4wDAYD"
"VQQIDAVTdXdvbjEOMAwGA1UEBwwFU3V3b24xFjAUBgNVBAoMDVRpemVuIFRlc3Qg"
"Q0ExIjAgBgNVBAsMGVRpemVuIERpc3RyaWJ1dG9yIFRlc3QgQ0ExKjAoBgNVBAMM"
"IVRpemVuIFBhcnRuZXIgRGlzdHJpYnV0b3IgUm9vdCBDQTCBnzANBgkqhkiG9w0B"
"AQEFAAOBjQAwgYkCgYEAnIBA2qQEaMzGalP0kzvwUxdCC6ybSC/fb+M9iGvt8QXp"
"ic2yARQB+bIhfbEu1XHwE1jCAGxKd6uT91b4FWr04YwnBPoRX4rBGIYlqo/dg+pS"
"rGyFjy7vfr0BOdWp2+WPlTe7SOS6bVauncrSoHxX0spiLaU5LU686BKr7YaABV0C"
"AwEAATANBgkqhkiG9w0BAQUFAAOBgQAX0Tcfmxcs1TUPBdr1U1dx/W/6Y4PcAF7n"
"DnMrR0ZNRPgeSCiVLax1bkHxcvW74WchdKIb24ZtAsFwyrsmUCRV842YHdfddjo6"
"xgUu7B8n7hQeV3EADh6ft/lE8nalzAl9tALTxAmLtYvEYA7thvDoKi1k7bN48izL"
"gS9G4WEAUg==";

const std::string tizen_partner_operator =
"MIICzDCCAjWgAwIBAgIJAJrv22F9wyp/MA0GCSqGSIb3DQEBBQUAMIGeMQswCQYD"
"VQQGEwJLUjEOMAwGA1UECAwFU3V3b24xDjAMBgNVBAcMBVN1d29uMRYwFAYDVQQK"
"DA1UaXplbiBUZXN0IENBMSIwIAYDVQQLDBlUaXplbiBEaXN0cmlidXRvciBUZXN0"
"IENBMTMwMQYDVQQDDCpUaXplbiBQYXJ0bmVyLU9wZXJhdG9yIERpc3RyaWJ1dG9y"
"IFJvb3QgQ0EwHhcNMTIxMjEzMDUzOTMyWhcNMjIxMjExMDUzOTMyWjCBnjELMAkG"
"A1UEBhMCS1IxDjAMBgNVBAgMBVN1d29uMQ4wDAYDVQQHDAVTdXdvbjEWMBQGA1UE"
"CgwNVGl6ZW4gVGVzdCBDQTEiMCAGA1UECwwZVGl6ZW4gRGlzdHJpYnV0b3IgVGVz"
"dCBDQTEzMDEGA1UEAwwqVGl6ZW4gUGFydG5lci1PcGVyYXRvciBEaXN0cmlidXRv"
"ciBSb290IENBMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC9X0Hw0EfAuagg"
"De9h6Jtvh8Df4fyVbvLm9VNea/iVP3/qTbG8tNqoQ32lu0SwzAZBnjpvpbxzsWs9"
"pSYo7Ys1fymHlu+gf+kmTGTVscBrAHWkr4O0m33x2FYfy/wmu+IImnRDYDud83rN"
"tjQmMO6BihN9Lb6kLiEtVIa8ITwdQwIDAQABoxAwDjAMBgNVHRMEBTADAQH/MA0G"
"CSqGSIb3DQEBBQUAA4GBAHS2M2UnfEsZf80/sT84xTcfASXgpFL/1M5HiAVpR+1O"
"UwLpLyqHiGQaASuADDeGEfcIqEf8gP1SzvnAZqLx9GchbOrOKRleooVFH7PRxFBS"
"VWJ5Fq46dJ1mCgTWSkrL6dN5j9hWCzzGfv0Wco+NAf61n9kVbCv7AScIJwQNltOy";

const std::string googleCA =
"MIICPDCCAaUCEHC65B0Q2Sk0tjjKewPMur8wDQYJKoZIhvcNAQECBQAwXzELMAkG"
"A1UEBhMCVVMxFzAVBgNVBAoTDlZlcmlTaWduLCBJbmMuMTcwNQYDVQQLEy5DbGFz"
"cyAzIFB1YmxpYyBQcmltYXJ5IENlcnRpZmljYXRpb24gQXV0aG9yaXR5MB4XDTk2"
"MDEyOTAwMDAwMFoXDTI4MDgwMTIzNTk1OVowXzELMAkGA1UEBhMCVVMxFzAVBgNV"
"BAoTDlZlcmlTaWduLCBJbmMuMTcwNQYDVQQLEy5DbGFzcyAzIFB1YmxpYyBQcmlt"
"YXJ5IENlcnRpZmljYXRpb24gQXV0aG9yaXR5MIGfMA0GCSqGSIb3DQEBAQUAA4GN"
"ADCBiQKBgQDJXFme8huKARS0EN8EQNvjV69qRUCPhAwL0TPZ2RHP7gJYHyX3KqhE"
"BarsAx94f56TuZoAqiN91qyFomNFx3InzPRMxnVx0jnvT0Lwdd8KkMaOIG+YD/is"
"I19wKTakyYbnsZogy1Olhec9vn2a/iRFM9x2Fe0PonFkTGUugWhFpwIDAQABMA0G"
"CSqGSIb3DQEBAgUAA4GBALtMEivPLCYATxQT3ab7/AoRhIzzKBxnki98tsX63/Do"
"lbwdj2wsqFHMc9ikwFPwTtYmwHYBV4GSXiHx0bH/59AhWM1pF+NEHJwZRDmJXNyc"
"AA9WjQKZ7aKQRUzkuxCkPfAyAw7xzvjoyVGM5mKf5p/AfbdynMk2OmufTqj/ZA1k";

const std::string google2nd =
"MIIDIzCCAoygAwIBAgIEMAAAAjANBgkqhkiG9w0BAQUFADBfMQswCQYDVQQGEwJV"
"UzEXMBUGA1UEChMOVmVyaVNpZ24sIEluYy4xNzA1BgNVBAsTLkNsYXNzIDMgUHVi"
"bGljIFByaW1hcnkgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkwHhcNMDQwNTEzMDAw"
"MDAwWhcNMTQwNTEyMjM1OTU5WjBMMQswCQYDVQQGEwJaQTElMCMGA1UEChMcVGhh"
"d3RlIENvbnN1bHRpbmcgKFB0eSkgTHRkLjEWMBQGA1UEAxMNVGhhd3RlIFNHQyBD"
"QTCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEA1NNn0I0Vf67NMf59HZGhPwtx"
"PKzMyGT7Y/wySweUvW+Aui/hBJPAM/wJMyPpC3QrccQDxtLN4i/1CWPN/0ilAL/g"
"5/OIty0y3pg25gqtAHvEZEo7hHUD8nCSfQ5i9SGraTaEMXWQ+L/HbIgbBpV8yeWo"
"3nWhLHpo39XKHIdYYBkCAwEAAaOB/jCB+zASBgNVHRMBAf8ECDAGAQH/AgEAMAsG"
"A1UdDwQEAwIBBjARBglghkgBhvhCAQEEBAMCAQYwKAYDVR0RBCEwH6QdMBsxGTAX"
"BgNVBAMTEFByaXZhdGVMYWJlbDMtMTUwMQYDVR0fBCowKDAmoCSgIoYgaHR0cDov"
"L2NybC52ZXJpc2lnbi5jb20vcGNhMy5jcmwwMgYIKwYBBQUHAQEEJjAkMCIGCCsG"
"AQUFBzABhhZodHRwOi8vb2NzcC50aGF3dGUuY29tMDQGA1UdJQQtMCsGCCsGAQUF"
"BwMBBggrBgEFBQcDAgYJYIZIAYb4QgQBBgpghkgBhvhFAQgBMA0GCSqGSIb3DQEB"
"BQUAA4GBAFWsY+reod3SkF+fC852vhNRj5PZBSvIG3dLrWlQoe7e3P3bB+noOZTc"
"q3J5Lwa/q4FwxKjt6lM07e8eU9kGx1Yr0Vz00YqOtCuxN5BICEIlxT6Ky3/rbwTR"
"bcV0oveifHtgPHfNDs5IAn8BL7abN+AqKjbc1YXWrOU/VG+WHgWv";

const std::string google3rd =
"MIIDIjCCAougAwIBAgIQK59+5colpiUUIEeCdTqbuTANBgkqhkiG9w0BAQUFADBM"
"MQswCQYDVQQGEwJaQTElMCMGA1UEChMcVGhhd3RlIENvbnN1bHRpbmcgKFB0eSkg"
"THRkLjEWMBQGA1UEAxMNVGhhd3RlIFNHQyBDQTAeFw0xMTEwMjYwMDAwMDBaFw0x"
"MzA5MzAyMzU5NTlaMGkxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpDYWxpZm9ybmlh"
"MRYwFAYDVQQHFA1Nb3VudGFpbiBWaWV3MRMwEQYDVQQKFApHb29nbGUgSW5jMRgw"
"FgYDVQQDFA9tYWlsLmdvb2dsZS5jb20wgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJ"
"AoGBAK85FZho5JL+T0/xu/8NLrD+Jaq9aARnJ+psQ0ynbcvIj36B7ocmJRASVDOe"
"qj2bj46Ss0sB4/lKKcMP/ay300yXKT9pVc9wgwSvLgRudNYPFwn+niAkJOPHaJys"
"Eb2S5LIbCfICMrtVGy0WXzASI+JMSo3C2j/huL/3OrGGvvDFAgMBAAGjgecwgeQw"
"DAYDVR0TAQH/BAIwADA2BgNVHR8ELzAtMCugKaAnhiVodHRwOi8vY3JsLnRoYXd0"
"ZS5jb20vVGhhd3RlU0dDQ0EuY3JsMCgGA1UdJQQhMB8GCCsGAQUFBwMBBggrBgEF"
"BQcDAgYJYIZIAYb4QgQBMHIGCCsGAQUFBwEBBGYwZDAiBggrBgEFBQcwAYYWaHR0"
"cDovL29jc3AudGhhd3RlLmNvbTA+BggrBgEFBQcwAoYyaHR0cDovL3d3dy50aGF3"
"dGUuY29tL3JlcG9zaXRvcnkvVGhhd3RlX1NHQ19DQS5jcnQwDQYJKoZIhvcNAQEF"
"BQADgYEANYARzVI+hCn7wSjhIOUCj19xZVgdYnJXPOZeJWHTy60i+NiBpOf0rnzZ"
"wW2qkw1iB5/yZ0eZNDNPPQJ09IHWOAgh6OKh+gVBnJzJ+fPIo+4NpddQVF4vfXm3"
"fgp8tuIsqK7+lNfNFjBxBKqeecPStiSnJavwSI4vw6e7UN0Pz7A=";

const std::string certVerisign =
"MIIG+DCCBeCgAwIBAgIQU9K++SSnJF6DygHkbKokdzANBgkqhkiG9w0BAQUFADCB"
"vjELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDlZlcmlTaWduLCBJbmMuMR8wHQYDVQQL"
"ExZWZXJpU2lnbiBUcnVzdCBOZXR3b3JrMTswOQYDVQQLEzJUZXJtcyBvZiB1c2Ug"
"YXQgaHR0cHM6Ly93d3cudmVyaXNpZ24uY29tL3JwYSAoYykwNjE4MDYGA1UEAxMv"
"VmVyaVNpZ24gQ2xhc3MgMyBFeHRlbmRlZCBWYWxpZGF0aW9uIFNTTCBTR0MgQ0Ew"
"HhcNMTAwNTI2MDAwMDAwWhcNMTIwNTI1MjM1OTU5WjCCASkxEzARBgsrBgEEAYI3"
"PAIBAxMCVVMxGTAXBgsrBgEEAYI3PAIBAhMIRGVsYXdhcmUxGzAZBgNVBA8TElYx"
"LjAsIENsYXVzZSA1LihiKTEQMA4GA1UEBRMHMjQ5Nzg4NjELMAkGA1UEBhMCVVMx"
"DjAMBgNVBBEUBTk0MDQzMRMwEQYDVQQIEwpDYWxpZm9ybmlhMRYwFAYDVQQHFA1N"
"b3VudGFpbiBWaWV3MSIwIAYDVQQJFBk0ODcgRWFzdCBNaWRkbGVmaWVsZCBSb2Fk"
"MRcwFQYDVQQKFA5WZXJpU2lnbiwgSW5jLjEmMCQGA1UECxQdIFByb2R1Y3Rpb24g"
"U2VjdXJpdHkgU2VydmljZXMxGTAXBgNVBAMUEHd3dy52ZXJpc2lnbi5jb20wggEi"
"MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCj+PvvK+fZOXwno0yT/OTy2Zm9"
"ehnZjTtO/X2IWBEa3jG30C52uHFQI4NmXiQVNvJHkBaAj0ilVjvGdxXmkyyFsugt"
"IWOTZ8pSKdX1tmGFIon6Ko9+lBFkVkudA1ogAUbtTB8IcdeOlpK78T4SjdVMhY18"
"150YzSw6hRKlw52wBaDxtGZElvOth41K7TUcaDnQVzz5SBPW5MUhi7AWrdoSk17O"
"BozOzmB/jkYDVDnwLcbR89SLHEOle/idSYSDQUmab3y0JS8RyQV1+DB70mnFALnD"
"fLiL47nMQQCGxXgp5voQ2YmSXhevKmEJ9vvtC6C7yv2W6yomfS/weUEce9pvAgMB"
"AAGjggKCMIICfjCBiwYDVR0RBIGDMIGAghB3d3cudmVyaXNpZ24uY29tggx2ZXJp"
"c2lnbi5jb22CEHd3dy52ZXJpc2lnbi5uZXSCDHZlcmlzaWduLm5ldIIRd3d3LnZl"
"cmlzaWduLm1vYmmCDXZlcmlzaWduLm1vYmmCD3d3dy52ZXJpc2lnbi5ldYILdmVy"
"aXNpZ24uZXUwCQYDVR0TBAIwADAdBgNVHQ4EFgQU8oBwK/WBXCZDWi0dbuDgPyTK"
"iJIwCwYDVR0PBAQDAgWgMD4GA1UdHwQ3MDUwM6AxoC+GLWh0dHA6Ly9FVkludGwt"
"Y3JsLnZlcmlzaWduLmNvbS9FVkludGwyMDA2LmNybDBEBgNVHSAEPTA7MDkGC2CG"
"SAGG+EUBBxcGMCowKAYIKwYBBQUHAgEWHGh0dHBzOi8vd3d3LnZlcmlzaWduLmNv"
"bS9ycGEwKAYDVR0lBCEwHwYIKwYBBQUHAwEGCCsGAQUFBwMCBglghkgBhvhCBAEw"
"HwYDVR0jBBgwFoAUTkPIHXbvN1N6T/JYb5TzOOLVvd8wdgYIKwYBBQUHAQEEajBo"
"MCsGCCsGAQUFBzABhh9odHRwOi8vRVZJbnRsLW9jc3AudmVyaXNpZ24uY29tMDkG"
"CCsGAQUFBzAChi1odHRwOi8vRVZJbnRsLWFpYS52ZXJpc2lnbi5jb20vRVZJbnRs"
"MjAwNi5jZXIwbgYIKwYBBQUHAQwEYjBgoV6gXDBaMFgwVhYJaW1hZ2UvZ2lmMCEw"
"HzAHBgUrDgMCGgQUS2u5KJYGDLvQUjibKaxLB4shBRgwJhYkaHR0cDovL2xvZ28u"
"dmVyaXNpZ24uY29tL3ZzbG9nbzEuZ2lmMA0GCSqGSIb3DQEBBQUAA4IBAQB9VZxB"
"wDMRGyhFWYkY5rwUVGuDJiGeas2xRJC0G4+riQ7IN7pz2a2BhktmZ5HbxXL4ZEY4"
"yMN68DEVErhtKiuL02ng27alhlngadKQzSL8pLdmQ+3jEwm9nva5C/7pbeqy+qGF"
"is4IWNYOc4HKNkABxXm5v0ouys8HPNkTLFLep0gLqRXW3gYN2XbKUWMs7z7hJpkY"
"GxP8YQSxi513O2dWVCXB8S6erIz9E/bcfdXoCPyQdn42y3IEoJvPvBS3S55fD4+Q"
"Q43GPhumSg9a6S3hnyw8DX5OiUGmqgQrtSeDRsNmWqtWizEQbe+fotZpEn/7zYTa"
"tk1ni/k5jDH/QeuG";

const std::string crlExampleCertificate =
"MIIFlDCCBHygAwIBAgIBADANBgkqhkiG9w0BAQUFADBDMRIwEAYKCZImiZPyLGQB"
"GRYCZXMxGDAWBgoJkiaJk/IsZAEZFghpcmlzZ3JpZDETMBEGA1UEAxMKSVJJU0dy"
"aWRDQTAeFw0wNTA2MjgwNTAyMjhaFw0xNTA2MjYwNTAyMjhaMEMxEjAQBgoJkiaJ"
"k/IsZAEZFgJlczEYMBYGCgmSJomT8ixkARkWCGlyaXNncmlkMRMwEQYDVQQDEwpJ"
"UklTR3JpZENBMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1CQiWlff"
"ajoMSTuismKqLQ+Mt33Tq4bBpCZvCBXhqan1R0ksILPtK1L7C8QWqPk6AZZpuNmY"
"cNVtJGc8ksgDWvX0EB3GKwZTZ8RrSRlSEe9Otq+Ur7S9uxM1JMmCr6zZTMFANzBS"
"4btnduV78C09IhFYG4OW8IPhNrbfPaeOR+PRPAa/qdSONAwTrM1sZkIvGpAkBWM6"
"Pn7TK9BAK6GLvwgii780fWj3Cwgmp8EDCTievBbWj+z8/apMEy9R0vyB2dWNNCnk"
"6q8VvrjgMsJt33O3BqOoBuZ8R/SS9OFWLFSU3s7cfrRaUSJk/Mx8OGFizRkcXSzX"
"0Nidcg7hX5i78wIDAQABo4ICkTCCAo0wDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4E"
"FgQUnUJkLlupXvH/bMg8NtPxtkOYrRowawYDVR0jBGQwYoAUnUJkLlupXvH/bMg8"
"NtPxtkOYrRqhR6RFMEMxEjAQBgoJkiaJk/IsZAEZFgJlczEYMBYGCgmSJomT8ixk"
"ARkWCGlyaXNncmlkMRMwEQYDVQQDEwpJUklTR3JpZENBggEAMA4GA1UdDwEB/wQE"
"AwIBxjARBglghkgBhvhCAQEEBAMCAAcwOwYJYIZIAYb4QgENBC4WLElSSVNHcmlk"
"IENlcnRpZmljYXRpb24gQXV0aG9yaXR5IENlcnRpZmljYXRlMIGZBgNVHR8EgZEw"
"gY4wLqAsoCqGKGh0dHA6Ly93d3cuaXJpc2dyaWQuZXMvcGtpL2NybC9jYWNybC5w"
"ZW0wXKBaoFiGVmxkYXA6Ly9sZGFwLmlyaXNncmlkLmVzOjEzODAvY249SVJJU0dy"
"aWRDQSxkYz1pcmlzZ3JpZCxkYz1lcz9jZXJ0aWZpY2F0ZVJldm9jYXRpb25MaXN0"
"MDcGCWCGSAGG+EIBAwQqFihodHRwOi8vd3d3LmlyaXNncmlkLmVzL3BraS9jcmwv"
"Y2FjcmwucGVtME4GCWCGSAGG+EIBCARBFj9odHRwOi8vd3d3LmlyaXNncmlkLmVz"
"L3BraS9wb2xpY3kvMS4zLjYuMS40LjEuNzU0Ny4yLjIuNC4xLjEuMS8waQYDVR0g"
"BGIwYDBeBg0rBgEEAbp7AgIEAQEBME0wSwYIKwYBBQUHAgEWP2h0dHA6Ly93d3cu"
"aXJpc2dyaWQuZXMvcGtpL3BvbGljeS8xLjMuNi4xLjQuMS43NTQ3LjIuMi40LjEu"
"MS4xLzANBgkqhkiG9w0BAQUFAAOCAQEAaqRfyLER+P2QOZLLdz66m7FGsgtFsAEx"
"wiNrIChFWfyHVZG7Ph1fn/GDD5LMsrU23lx3NBN5/feHuut1XNYKNs8vtV07D70r"
"DKjUlPbmWV0B+/GDxe1FDGop/tKQfyHSUaBuauXChFU/2INu5lhBerNl7QxNJ1ws"
"cWGiT7R+L/2EjgzWgH1V/0zmIOMep6kY7MUs8rlyF0O5MNFs232cA1trl9kvhAGU"
"9p58Enf5DWMrh17SPH586yIJeiWZtPez9G54ftY+XIqfn0X0zso0dnoXNJQYS043"
"/5vSnoHdRx/EmN8yjeEavZtC48moN0iJ38eB44uKgCD77rZW5s1XqA==";

//class TestCleanup
//{
//  public:
//    explicit TestCleanup(bool bCheckForFakeVerification = false)
//    {
//        if (bCheckForFakeVerification) {
//            bool bUnsetEnvVar = true;
//
//            m_strEnvVar = "CHECK_ONLY_DOMAIN_INSTEAD_OF_VALIDATION";
//            if (getenv(m_strEnvVar.c_str()) != NULL) {
//                bUnsetEnvVar = false;
//            } else {
//                setenv(m_strEnvVar.c_str(), "1", 0);
//            }
//        }
//    }
//
//    ~TestCleanup()
//    {
//        if (!m_strRootCAPath.empty()) {
//            removeCertGivenByFilename(m_strRootCAPath.c_str());
//        }
//
//        if (!m_strEnvVar.empty()) {
//            unsetenv(m_strEnvVar.c_str());
//        }
//    }
//
//    void setRootCAPath(const std::string& strRootCAPath)
//    {
//        m_strRootCAPath = strRootCAPath;
//    }
//
//  private:
//    std::string           m_strRootCAPath;
//    std::string           m_strEnvVar;
//};
//
//class PolicyChanger : public DPL::Event::EventListener<AceUpdateResponseEvent>
//{
//  public:
//    PolicyChanger()
//    {
//        DPL::Event::EventDeliverySystem::AddListener<AceUpdateResponseEvent>(this);
//    }
//
//    ~PolicyChanger()
//    {
//        DPL::Event::EventDeliverySystem::RemoveListener<AceUpdateResponseEvent>(this);
//    }
//
//    void OnEventReceived(const AceUpdateResponseEvent& event)
//    {
//        if (0 != event.GetArg0()) {
//            LogError("Policy change failed");
//        }
//        Assert(0 == event.GetArg0() && "Policy change failed");
//        LoopControl::finish_wait_for_wrt_init();
//    }
//
//    void updatePolicy(const std::string& path)
//    {
//        AceUpdateRequestEvent event(path);
//        DPL::Event::EventDeliverySystem::Publish(event);
//        LoopControl::wait_for_wrt_init();
//    }
//};

} // namespace anonymous

using namespace ValidationCore;

//////////////////////////////////////////////////
////////  VALIDATION CORE TEST SUITE  ////////////
//////////////////////////////////////////////////

/*
 * test: Class SignatureFinder
 * description: SignatureFinder should search directory passed as
 * param of constructor.
 * expected: Signature finder should put information about 3
 * signture files in SinatureFileInfoSet.
 */
RUNNER_TEST(test01_signature_finder)
{
    SignatureFileInfoSet signatureSet;
    SignatureFinder signatureFinder(widget_path);
    RUNNER_ASSERT_MSG(
        SignatureFinder::NO_ERROR == signatureFinder.find(signatureSet),
        "SignatureFinder failed");
    RUNNER_ASSERT_MSG(signatureSet.size() == 3,
                      "Some signature has not been found");

    SignatureFileInfo first = *(signatureSet.begin());
    RUNNER_ASSERT_MSG(
        std::string("author-signature.xml") == first.getFileName(),
        "Author Signature");
    RUNNER_ASSERT_MSG(-1 == first.getFileNumber(), "Wrong signature number.");
    first = *(signatureSet.rbegin());
    RUNNER_ASSERT_MSG(std::string("signature22.xml") == first.getFileName(),
                      "Wrong signature fileName.");
    RUNNER_ASSERT_MSG(22 == first.getFileNumber(), "Wrong signature number.");
}

/*
 * test: Class SignatureReader
 * description: SignatureReader should parse widget digigal signaturesignature
 * without any errors. Path to signature is passed to constructor.
 * param of destructor.
 * expected: SignatureReader should not throw any exception.
 */
RUNNER_TEST(test02_signature_reader)
{
    SignatureFileInfoSet signatureSet;
    SignatureFinder signatureFinder(widget_path);
    RUNNER_ASSERT_MSG(
        SignatureFinder::NO_ERROR == signatureFinder.find(signatureSet),
        "SignatureFinder failed");

    SignatureFileInfoSet::reverse_iterator iter = signatureSet.rbegin();

    for (; iter != signatureSet.rend(); ++iter) {
        SignatureData data(widget_path + iter->getFileName(),
                           iter->getFileNumber());
        SignatureReader xml;
        xml.initialize(data, WrtDB::GlobalConfig::GetSignatureXmlSchema());
        xml.read(data);
    }
}

/*
 * test: Integration test of SignatureFinder, SignatureReader,
 * SignatureValidator
 * description: Directory passed to SignatureFinded constructor should be searched
 * and 3 signature should be find. All signature should be parsed and verified.
 * expected: Verificator should DISREGARD author signature and VERIFY
 * distrubutor signature.
 */
RUNNER_TEST(test03t01_wrtsignature_validator)
{
    SignatureFileInfoSet signatureSet;
    SignatureFinder signatureFinder(widget_path);
    LogError("Size: " << signatureSet.size());
    RUNNER_ASSERT_MSG(
        SignatureFinder::NO_ERROR == signatureFinder.find(signatureSet),
        "SignatureFinder failed");

    SignatureFileInfoSet::reverse_iterator iter = signatureSet.rbegin();
    LogError("Size: " << signatureSet.size());
    for (; iter != signatureSet.rend(); ++iter) {
        SignatureData data(widget_path + iter->getFileName(),
                           iter->getFileNumber());
        SignatureReader xml;
        xml.initialize(data, WrtDB::GlobalConfig::GetSignatureXmlSchema());
        xml.read(data);

        WrtSignatureValidator validator(
            WrtSignatureValidator::WAC20,
            false,
            false,
            false);

        if (data.isAuthorSignature()) {
            LogError("Author");
            RUNNER_ASSERT_MSG(
                WrtSignatureValidator::SIGNATURE_DISREGARD ==
                    validator.check(data, widget_path),
                "Validation failed");
        } else {
            if (data.getSignatureNumber() == 1)
            {
                LogError("Distributor1");
                WrtSignatureValidator::Result temp = validator.check(data, widget_path);

                RUNNER_ASSERT_MSG(
                    WrtSignatureValidator::SIGNATURE_DISREGARD ==
                        temp,
                        "Validation failed");

                LogDebug("test03t01 result: " << temp);
            }
            else
            {
                LogError("DistributorN");
                WrtSignatureValidator::Result temp = validator.check(data, widget_path);

                RUNNER_ASSERT_MSG(
                    WrtSignatureValidator::SIGNATURE_VERIFIED ==
                        temp,
                        "Validation failed");

                LogDebug("test03t01 result: " << temp);
            }
        }
    }
}

RUNNER_TEST(test03t02_wrtsignature_validator_negative_hash_input)
{
    SignatureFileInfoSet signatureSet;
    SignatureFinder signatureFinder(widget_negative_hash_path);
    LogError("Size: " << signatureSet.size());
    RUNNER_ASSERT_MSG(
        SignatureFinder::NO_ERROR == signatureFinder.find(signatureSet),
        "SignatureFinder failed");

    SignatureFileInfoSet::reverse_iterator iter = signatureSet.rbegin();
    LogError("Size: " << signatureSet.size());
    for (; iter != signatureSet.rend(); ++iter) {
        SignatureData data(widget_negative_hash_path + iter->getFileName(),
                           iter->getFileNumber());
        SignatureReader xml;
        xml.initialize(data, WrtDB::GlobalConfig::GetSignatureXmlSchema());
        xml.read(data);

        WrtSignatureValidator validator(
            WrtSignatureValidator::WAC20,
            false,
            false,
            false);

        if (data.isAuthorSignature()) {
            LogError("Author");
            RUNNER_ASSERT_MSG(
                WrtSignatureValidator::SIGNATURE_INVALID ==
                    validator.check(data, widget_negative_hash_path),
                "Wrong input file but success..");
        } else {
            LogError("Distributor");
            RUNNER_ASSERT_MSG(
                WrtSignatureValidator::SIGNATURE_INVALID ==
                    validator.check(data, widget_negative_hash_path),
                "Wrong input file but success..");
        }
    }
}

RUNNER_TEST(test03t03_wrtsignature_validator_negative_signature_input)
{
    SignatureFileInfoSet signatureSet;
    SignatureFinder signatureFinder(widget_negative_signature_path);
    LogError("Size: " << signatureSet.size());
    RUNNER_ASSERT_MSG(
        SignatureFinder::NO_ERROR == signatureFinder.find(signatureSet),
        "SignatureFinder failed");

    SignatureFileInfoSet::reverse_iterator iter = signatureSet.rbegin();
    LogError("Size: " << signatureSet.size());
    for (; iter != signatureSet.rend(); ++iter) {
        SignatureData data(widget_negative_signature_path + iter->getFileName(),
                           iter->getFileNumber());
        SignatureReader xml;
        xml.initialize(data, WrtDB::GlobalConfig::GetSignatureXmlSchema());
        xml.read(data);

        WrtSignatureValidator validator(
            WrtSignatureValidator::WAC20,
            false,
            false,
            false);

        if (data.isAuthorSignature()) {
            LogError("Author");
            RUNNER_ASSERT_MSG(
                WrtSignatureValidator::SIGNATURE_INVALID ==
                    validator.check(data, widget_negative_signature_path),
                "Wrong input file but success..");
        } else {
            LogError("Distributor");
            RUNNER_ASSERT_MSG(
                WrtSignatureValidator::SIGNATURE_INVALID ==
                    validator.check(data, widget_negative_signature_path),
                "Wrong input file but success..");
        }
    }
}

RUNNER_TEST(test03t04_wrtsignature_validator_partner)
{
    SignatureFileInfoSet signatureSet;
    SignatureFinder signatureFinder(widget_partner_path);
    LogError("Size: " << signatureSet.size());
    RUNNER_ASSERT_MSG(
        SignatureFinder::NO_ERROR == signatureFinder.find(signatureSet),
        "SignatureFinder failed");

    SignatureFileInfoSet::reverse_iterator iter = signatureSet.rbegin();
    LogError("Size: " << signatureSet.size());
    for (; iter != signatureSet.rend(); ++iter) {
        SignatureData data(widget_partner_path + iter->getFileName(),
                           iter->getFileNumber());
        SignatureReader xml;
        xml.initialize(data, WrtDB::GlobalConfig::GetSignatureXmlSchema());
        xml.read(data);

        WrtSignatureValidator validator(
            WrtSignatureValidator::WAC20,
            false,
            false,
            false);

        if (data.isAuthorSignature()) {
            LogError("Author");
            RUNNER_ASSERT_MSG(
                WrtSignatureValidator::SIGNATURE_VERIFIED ==
                    validator.check(data, widget_partner_path),
                "Wrong input file but success..");
        } else {
            LogError("Distributor");
            RUNNER_ASSERT_MSG(
                WrtSignatureValidator::SIGNATURE_VERIFIED ==
                    validator.check(data, widget_partner_path),
                "Wrong input file but success..");

            RUNNER_ASSERT_MSG(
                    data.getVisibilityLevel() == CertStoreId::VIS_PARTNER,
                    "visibility check failed.");
        }
    }
}
/* // no partner_operator certificate in kiran emlulator
RUNNER_TEST(test03t05_wrtsignature_validator_partner_operator)
{
    SignatureFileInfoSet signatureSet;
    SignatureFinder signatureFinder(widget_partner_operator_path);
    LogError("Size: " << signatureSet.size());
    RUNNER_ASSERT_MSG(
        SignatureFinder::NO_ERROR == signatureFinder.find(signatureSet),
        "SignatureFinder failed");

    SignatureFileInfoSet::reverse_iterator iter = signatureSet.rbegin();
    LogError("Size: " << signatureSet.size());
    for (; iter != signatureSet.rend(); ++iter) {
        SignatureData data(widget_partner_operator_path + iter->getFileName(),
                           iter->getFileNumber());
        SignatureReader xml;
        xml.initialize(data, WrtDB::GlobalConfig::GetSignatureXmlSchema());
        xml.read(data);

        WrtSignatureValidator validator(
            WrtSignatureValidator::WAC20,
            false,
            false,
            false);

        if (data.isAuthorSignature()) {
            LogError("Author");
            RUNNER_ASSERT_MSG(
                WrtSignatureValidator::SIGNATURE_VERIFIED ==
                    validator.check(data, widget_partner_operator_path),
                "Wrong input file but success..");
        } else {
            LogError("Distributor");
            RUNNER_ASSERT_MSG(
                WrtSignatureValidator::SIGNATURE_VERIFIED ==
                    validator.check(data, widget_partner_operator_path),
                "Wrong input file but success..");

            RUNNER_ASSERT_MSG(
                    data.getVisibilityLevel() == CertStoreId::VIS_PLATFORM,
                    "visibility check failed.");
        }
    }
}
*/

/*
RUNNER_TEST(test03t04_wrtsignature_validator_negative_certificate_input)
{
    SignatureFileInfoSet signatureSet;
    SignatureFinder signatureFinder(widget_negative_certificate_path);
    LogError("Size: " << signatureSet.size());
    RUNNER_ASSERT_MSG(
        SignatureFinder::NO_ERROR == signatureFinder.find(signatureSet),
        "SignatureFinder failed");

    SignatureFileInfoSet::reverse_iterator iter = signatureSet.rbegin();
    LogError("Size: " << signatureSet.size());
    for (; iter != signatureSet.rend(); ++iter) {
        SignatureData data(widget_negative_certificate_path + iter->getFileName(),
                           iter->getFileNumber());
        SignatureReader xml;
        xml.initialize(data, WrtDB::GlobalConfig::GetSignatureXmlSchema());
        xml.read(data);

        WrtSignatureValidator validator(
            WrtSignatureValidator::WAC20,
            false,
            false,
            false);

        if (data.isAuthorSignature()) {
            LogError("Author");
            RUNNER_ASSERT_MSG(
                WrtSignatureValidator::SIGNATURE_INVALID ==
                    validator.check(data, widget_negative_certificate_path),
                "Wrong input file but success..");
        } else {
            LogError("Distributor");
            RUNNER_ASSERT_MSG(
                WrtSignatureValidator::SIGNATURE_DISREGARD ==
                    validator.check(data, widget_negative_certificate_path),
                "Wrong input file but success..");
        }
    }
}
*/

/*
 * test: Integration test of SignatureFinder, SignatureReader,
 * SignatureValidator
 * description: Directory passed to SignatureFinded constructor should be searched
 * and 3 signature should be find. All signature should be parsed and verified.
 * expected: Verificator should DISREGARD author signature and VERIFY
 * distrubutor signature.
 */
RUNNER_TEST(test04t01_signature_validator)
{
    SignatureFileInfoSet signatureSet;
    SignatureFinder signatureFinder(widget_path);
    LogError("Size: " << signatureSet.size());
    RUNNER_ASSERT_MSG(
        SignatureFinder::NO_ERROR == signatureFinder.find(signatureSet),
        "SignatureFinder failed");

    SignatureFileInfoSet::reverse_iterator iter = signatureSet.rbegin();
    LogError("Size: " << signatureSet.size());
    for (; iter != signatureSet.rend(); ++iter) {
        SignatureData data(widget_path + iter->getFileName(),
                           iter->getFileNumber());
        SignatureReader xml;
        xml.initialize(data, WrtDB::GlobalConfig::GetSignatureXmlSchema());
        xml.read(data);

        SignatureValidator validator(
            SignatureValidator::WAC20,
            false,
            false,
            false);

        if (data.isAuthorSignature()) {
            LogError("Author");
            RUNNER_ASSERT_MSG(
                SignatureValidator::SIGNATURE_DISREGARD ==
                    validator.check(data, widget_path),
                "Validation failed");
        } else {
            if (data.getSignatureNumber() == 1)
            {
                LogError("Distributor1");
                SignatureValidator::Result temp = validator.check(data, widget_path);

                RUNNER_ASSERT_MSG(
                    SignatureValidator::SIGNATURE_DISREGARD ==
                        temp,
                        "Validation failed");

                LogDebug("test04t01 result: " << temp);
            }
            else
            {
                LogError("DistributorN");
                SignatureValidator::Result temp = validator.check(data, widget_path);

                RUNNER_ASSERT_MSG(
                    SignatureValidator::SIGNATURE_VERIFIED ==
                        temp,
                        "Validation failed");

                LogDebug("test04t01 result: " << temp);
            }
        }
    }
}

RUNNER_TEST(test04t02_signature_validator_negative_hash_input)
{
    SignatureFileInfoSet signatureSet;
    SignatureFinder signatureFinder(widget_negative_hash_path);
    LogError("Size: " << signatureSet.size());
    RUNNER_ASSERT_MSG(
        SignatureFinder::NO_ERROR == signatureFinder.find(signatureSet),
        "SignatureFinder failed");

    SignatureFileInfoSet::reverse_iterator iter = signatureSet.rbegin();
    LogError("Size: " << signatureSet.size());
    for (; iter != signatureSet.rend(); ++iter) {
        SignatureData data(widget_negative_hash_path + iter->getFileName(),
                           iter->getFileNumber());
        SignatureReader xml;
        xml.initialize(data, WrtDB::GlobalConfig::GetSignatureXmlSchema());
        xml.read(data);

        SignatureValidator validator(
            SignatureValidator::WAC20,
            false,
            false,
            false);

        if (data.isAuthorSignature()) {
            LogError("Author");
            RUNNER_ASSERT_MSG(
                SignatureValidator::SIGNATURE_INVALID ==
                    validator.check(data, widget_negative_hash_path),
                "Wrong input file but success..");
        } else {
            LogError("Distributor");
            RUNNER_ASSERT_MSG(
                SignatureValidator::SIGNATURE_INVALID ==
                    validator.check(data, widget_negative_hash_path),
                "Wrong input file but success..");
        }
    }
}

RUNNER_TEST(test04t03_signature_validator_negative_signature_input)
{
    SignatureFileInfoSet signatureSet;
    SignatureFinder signatureFinder(widget_negative_signature_path);
    LogError("Size: " << signatureSet.size());
    RUNNER_ASSERT_MSG(
        SignatureFinder::NO_ERROR == signatureFinder.find(signatureSet),
        "SignatureFinder failed");

    SignatureFileInfoSet::reverse_iterator iter = signatureSet.rbegin();
    LogError("Size: " << signatureSet.size());
    for (; iter != signatureSet.rend(); ++iter) {
        SignatureData data(widget_negative_signature_path + iter->getFileName(),
                           iter->getFileNumber());
        SignatureReader xml;
        xml.initialize(data, WrtDB::GlobalConfig::GetSignatureXmlSchema());
        xml.read(data);

        SignatureValidator validator(
            SignatureValidator::WAC20,
            false,
            false,
            false);

        if (data.isAuthorSignature()) {
            LogError("Author");
            RUNNER_ASSERT_MSG(
                SignatureValidator::SIGNATURE_INVALID ==
                    validator.check(data, widget_negative_signature_path),
                "Wrong input file but success..");
        } else {
            LogError("Distributor");
            RUNNER_ASSERT_MSG(
                SignatureValidator::SIGNATURE_INVALID ==
                    validator.check(data, widget_negative_signature_path),
                "Wrong input file but success..");
        }
    }
}

RUNNER_TEST(test04t04_signature_validator_partner)
{
    SignatureFileInfoSet signatureSet;
    SignatureFinder signatureFinder(widget_partner_path);
    LogError("Size: " << signatureSet.size());
    RUNNER_ASSERT_MSG(
        SignatureFinder::NO_ERROR == signatureFinder.find(signatureSet),
        "SignatureFinder failed");

    SignatureFileInfoSet::reverse_iterator iter = signatureSet.rbegin();
    LogError("Size: " << signatureSet.size());
    for (; iter != signatureSet.rend(); ++iter) {
        SignatureData data(widget_partner_path + iter->getFileName(),
                           iter->getFileNumber());
        SignatureReader xml;
        xml.initialize(data, WrtDB::GlobalConfig::GetSignatureXmlSchema());
        xml.read(data);

        SignatureValidator validator(
            SignatureValidator::TIZEN,
            false,
            false,
            false);

        if (data.isAuthorSignature()) {
            LogError("Author");
            RUNNER_ASSERT_MSG(
                SignatureValidator::SIGNATURE_VERIFIED ==
                    validator.check(data, widget_partner_path),
                "Wrong input file but success..");
        } else {
            LogError("Distributor");
            RUNNER_ASSERT_MSG(
                SignatureValidator::SIGNATURE_VERIFIED ==
                    validator.check(data, widget_partner_path),
                "Wrong input file but success..");

            RUNNER_ASSERT_MSG(
                    data.getVisibilityLevel() == CertStoreId::VIS_PARTNER,
                    "visibility check failed.");
        }
    }
}
/* // no partner_operator certificate in kiran emulator
RUNNER_TEST(test04t05_signature_validator_partner_operator)
{
    SignatureFileInfoSet signatureSet;
    SignatureFinder signatureFinder(widget_partner_operator_path);
    LogError("Size: " << signatureSet.size());
    RUNNER_ASSERT_MSG(
        SignatureFinder::NO_ERROR == signatureFinder.find(signatureSet),
        "SignatureFinder failed");

    SignatureFileInfoSet::reverse_iterator iter = signatureSet.rbegin();
    LogError("Size: " << signatureSet.size());
    for (; iter != signatureSet.rend(); ++iter) {
        SignatureData data(widget_partner_operator_path + iter->getFileName(),
                           iter->getFileNumber());
        SignatureReader xml;
        xml.initialize(data, WrtDB::GlobalConfig::GetSignatureXmlSchema());
        xml.read(data);

        SignatureValidator validator(
            SignatureValidator::TIZEN,
            false,
            false,
            false);

        if (data.isAuthorSignature()) {
            LogError("Author");
            RUNNER_ASSERT_MSG(
                SignatureValidator::SIGNATURE_VERIFIED ==
                    validator.check(data, widget_partner_operator_path),
                "Wrong input file but success..");
        } else {
            LogError("Distributor");
            RUNNER_ASSERT_MSG(
                SignatureValidator::SIGNATURE_VERIFIED ==
                    validator.check(data, widget_partner_operator_path),
                "Wrong input file but success..");

            RUNNER_ASSERT_MSG(
                data.getVisibilityLevel() == CertStoreId::VIS_PLATFORM,
                "visibility check failed.");
        }
    }
}
*/

/*
RUNNER_TEST(test04t04_signature_validator_negative_certificate_input)
{
    SignatureFileInfoSet signatureSet;
    SignatureFinder signatureFinder(widget_negative_certificate_path);
    LogError("Size: " << signatureSet.size());
    RUNNER_ASSERT_MSG(
        SignatureFinder::NO_ERROR == signatureFinder.find(signatureSet),
        "SignatureFinder failed");

    SignatureFileInfoSet::reverse_iterator iter = signatureSet.rbegin();
    LogError("Size: " << signatureSet.size());
    for (; iter != signatureSet.rend(); ++iter) {
        SignatureData data(widget_negative_certificate_path + iter->getFileName(),
                           iter->getFileNumber());
        SignatureReader xml;
        xml.initialize(data, WrtDB::GlobalConfig::GetSignatureXmlSchema());
        xml.read(data);

        SignatureValidator validator(
            SignatureValidator::WAC20,
            false,
            false,
            false);

        if (data.isAuthorSignature()) {
            LogError("Author");
            RUNNER_ASSERT_MSG(
                SignatureValidator::SIGNATURE_DISREGARD ==
                    validator.check(data, widget_negative_certificate_path),
                "Wrong input file but success..");
        } else {
            LogError("Distributor");
            RUNNER_ASSERT_MSG(
                SignatureValidator::SIGNATURE_DISREGARD ==
                    validator.check(data, widget_negative_certificate_path),
                "Wrong input file but success..");
        }
    }
}
*/

/*
 * test: Integration test of SignatureFinder, SignatureReader,
 * SignatureValidator, ReferenceValidator
 * description: As above but this test also checks reference from signatures.
 * expected: All reference checks should return NO_ERROR.
 */
RUNNER_TEST(test05t01_signature_reference)
{
    SignatureFileInfoSet signatureSet;
    SignatureFinder signatureFinder(widget_path);
    RUNNER_ASSERT_MSG(
        SignatureFinder::NO_ERROR == signatureFinder.find(signatureSet),
        "SignatureFinder failed");

    SignatureFileInfoSet::reverse_iterator iter = signatureSet.rbegin();

    for (; iter != signatureSet.rend(); ++iter) {
        SignatureData data(widget_path + iter->getFileName(),
                           iter->getFileNumber());
        SignatureReader xml;
        xml.initialize(data, WrtDB::GlobalConfig::GetSignatureXmlSchema());
        xml.read(data);

        WrtSignatureValidator sval(
            WrtSignatureValidator::WAC20,
            false,
            false,
            false);

        if (data.isAuthorSignature()) {
            LogError("Author");
            RUNNER_ASSERT_MSG(
                WrtSignatureValidator::SIGNATURE_DISREGARD ==
                    sval.check(data, widget_path),
                "Validation failed");
        } else {
            if (data.getSignatureNumber() == 1)
            {
                LogError("Distributor1");
                RUNNER_ASSERT_MSG(
                    WrtSignatureValidator::SIGNATURE_DISREGARD ==
                        sval.check(data, widget_path),
                        "Validation failed");
            }
            else
            {
                LogError("DistributorN");
                RUNNER_ASSERT_MSG(
                    WrtSignatureValidator::SIGNATURE_VERIFIED ==
                        sval.check(data, widget_path),
                        "Validation failed");
            }
        }

        ReferenceValidator val(widget_path);
        RUNNER_ASSERT(
            ReferenceValidator::NO_ERROR == val.checkReferences(data));
    }
}

/*
 * test: ReferenceValidator::checkReference
 * description: Simple test. File "encoding test.empty" exists.
 * expected: checkReference should return NO_ERROR.
 */
RUNNER_TEST(test05t02_signature_reference_encoding_dummy)
{
    ReferenceSet referenceSet;
    SignatureData data;
    ReferenceValidator val("/opt/apps/widget/tests/reference");
    referenceSet.insert("encoding test.empty");
    data.setReference(referenceSet);

    RUNNER_ASSERT(
        ReferenceValidator::NO_ERROR == val.checkReferences(data));
}

/*
 * test: ReferenceValidator::checkReference
 * description: Negative test. File "encoding test" does not exists.
 * expected: checkReference should return ERROR_REFERENCE_NOT_FOUND
 */
RUNNER_TEST(test05t03_signature_reference_encoding_negative)
{
    ReferenceSet referenceSet;
    SignatureData data;
    ReferenceValidator val("/opt/apps/widget/tests/reference");
    referenceSet.insert("encoding test");
    data.setReference(referenceSet);

    RUNNER_ASSERT(
        ReferenceValidator::ERROR_REFERENCE_NOT_FOUND == val.checkReferences(data));
}

/*
 * test: ReferenceValidator::checkReference, ReferenceValidator::decodeProcent
 * description: File "encoding test.empty" exists. Name set in referenceSet must
 * be encoded first by decodeProcent function.
 * expected: checkReference should return NO_ERROR
 */
RUNNER_TEST(test05t04_signature_reference_encoding_space)
{
    ReferenceSet referenceSet;
    SignatureData data;
    ReferenceValidator val("/opt/apps/widget/tests/reference");
    referenceSet.insert("encoding%20test.empty");
    data.setReference(referenceSet);

    RUNNER_ASSERT(
        ReferenceValidator::NO_ERROR == val.checkReferences(data));
}

/*
 * test: ReferenceValidator::checkReference, ReferenceValidator::decodeProcent
 * description: Negative test. File "encoding test" does not exists. Name set in
 * referenceSet must be encoded first by decodeProcent function.
 * expected: checkReference should return ERROR_REFERENCE_NOT_FOUND
 */
RUNNER_TEST(test05t05_signature_reference_encoding_space_negative)
{
    ReferenceSet referenceSet;
    SignatureData data;
    ReferenceValidator val("/opt/apps/widget/tests/reference");
    referenceSet.insert("encoding%20test");
    data.setReference(referenceSet);

    RUNNER_ASSERT(
        ReferenceValidator::ERROR_REFERENCE_NOT_FOUND == val.checkReferences(data));
}

/*
 * test: ReferenceValidator::checkReference, ReferenceValidator::decodeProcent
 * description: File "encoding test.empty" exists. Name set in
 * referenceSet must be encoded first by decodeProcent function.
 * expected: checkReference should return NO_ERROR
 */
RUNNER_TEST(test05t06_signature_reference_encoding)
{
    ReferenceSet referenceSet;
    SignatureData data;
    ReferenceValidator val("/opt/apps/widget/tests/reference");
    referenceSet.insert("e%6Ec%6Fding%20te%73%74.e%6d%70ty");
    data.setReference(referenceSet);

    RUNNER_ASSERT(
        ReferenceValidator::NO_ERROR == val.checkReferences(data));
}

/*
 * test: ReferenceValidator::checkReference, ReferenceValidator::decodeProcent
 * description: Negative test. "%%" is illegal combination of char. decodeProcent
 * should throw exception.
 * expected: checkReference should return ERROR_DECODING_URL
 */
RUNNER_TEST(test05t07_signature_reference_encoding_negative)
{
    ReferenceSet referenceSet;
    SignatureData data;
    ReferenceValidator val("/opt/apps/widget/tests/reference");
    referenceSet.insert("e%6Ec%6Fding%%0test%2ete%73%74");
    data.setReference(referenceSet);

    RUNNER_ASSERT(
        ReferenceValidator::ERROR_DECODING_URL == val.checkReferences(data));
}

/*
 * test: Integration test of SignatureFinder, SignatureReader,
 * SignatureValidator, ReferenceValidator
 * description: As above but this test also checks reference from signatures.
 * expected: All reference checks should return NO_ERROR.
 */
RUNNER_TEST(test05t08_signature_reference)
{
    SignatureFileInfoSet signatureSet;
    SignatureFinder signatureFinder(widget_path);
    RUNNER_ASSERT_MSG(
        SignatureFinder::NO_ERROR == signatureFinder.find(signatureSet),
        "SignatureFinder failed");

    SignatureFileInfoSet::reverse_iterator iter = signatureSet.rbegin();

    for (; iter != signatureSet.rend(); ++iter) {
        SignatureData data(widget_path + iter->getFileName(),
                           iter->getFileNumber());
        SignatureReader xml;
        xml.initialize(data, WrtDB::GlobalConfig::GetSignatureXmlSchema());
        xml.read(data);

        SignatureValidator sval(
            SignatureValidator::WAC20,
            false,
            false,
            false);

        if (data.isAuthorSignature()) {
            LogError("Author");
            RUNNER_ASSERT_MSG(
                SignatureValidator::SIGNATURE_DISREGARD ==
                    sval.check(data, widget_path),
                "Validation failed");
        } else {
            if (data.getSignatureNumber() == 1)
            {
                LogError("Distributor1");
                RUNNER_ASSERT_MSG(
                    SignatureValidator::SIGNATURE_DISREGARD ==
                        sval.check(data, widget_path),
                        "Validation failed");
            }
            else
            {
                LogError("DistributorN");
                RUNNER_ASSERT_MSG(
                    SignatureValidator::SIGNATURE_VERIFIED ==
                        sval.check(data, widget_path),
                        "Validation failed");
            }
        }

        ReferenceValidator val(widget_path);
        RUNNER_ASSERT(
            ReferenceValidator::NO_ERROR == val.checkReferences(data));
    }
}

/*
 * test: class Base64Encoder and Base64Decoder
 * description: This test checks implementation of base64 decoder/encoder
 * algorithm implemented in Base64 classes. It uses printable characters.
 * expected: Encoded string should be equal to sample values.
 */
RUNNER_TEST(test07t01_base64)
{
    std::string strraw = "1234567890qwertyuiop[]asdfghjkl;'zxcvbnm,.";
    std::string strenc =
        "MTIzNDU2Nzg5MHF3ZXJ0eXVpb3BbXWFzZGZnaGprbDsnenhjdmJubSwu";

    Base64Encoder encoder;
    encoder.reset();
    encoder.append(strraw);
    encoder.finalize();
    RUNNER_ASSERT_MSG(strenc == encoder.get(), "Error in Base64Encoder.");

    Base64Decoder decoder;
    decoder.reset();
    decoder.append(strenc);
    RUNNER_ASSERT(decoder.finalize());
    RUNNER_ASSERT_MSG(strraw == decoder.get(), "Error in Base64Decoder.");
}

/*
 * test: class Base64Encoder and Base64Decoder
 * description: This test checks implementation of base64 decoder/encoder
 * algorithm. During tests it uses binary data.
 * expected: Encoded string should be equal to sample values.
 */
RUNNER_TEST(test07t02_base64)
{
    const size_t MAX = 40;
    char buffer[MAX];
    for (size_t i = 0; i<MAX; ++i) {
        buffer[i] = static_cast<char>(i);
    }

    std::string raw(&buffer[0], &buffer[MAX]);

    RUNNER_ASSERT(MAX == raw.size());

    Base64Encoder encoder;
    encoder.reset();
    encoder.append(raw);
    encoder.finalize();
    std::string enc = encoder.get();

    Base64Decoder decoder;
    decoder.reset();
    decoder.append(enc);
    RUNNER_ASSERT(decoder.finalize());
    RUNNER_ASSERT_MSG(raw == decoder.get(), "Error in Base64 conversion.");
}

/*
 * test: class Base64Decoder
 * description: Negative tests. This test will pass invalid string to decoder.
 * expected: Function finalize should fail and return false.
 */
RUNNER_TEST(test07t03_base64)
{
    std::string invalid = "1234)";

    Base64Decoder decoder;
    decoder.reset();
    decoder.append(invalid);
    RUNNER_ASSERT(false == decoder.finalize());
}

/*
 * test: class Base64Decoder
 * description: Negative tests. You are not allowed to call get function before
 * finalize.
 * expected: Function get should throw Base64Decoder::Exception::NotFinalized.
 */
RUNNER_TEST(test07t04_base64)
{
    std::string invalid = "12234";

    Base64Decoder decoder;
    decoder.reset();

    bool exception = false;
    Try {
        std::string temp = decoder.get();
    } Catch(Base64Decoder::Exception::NotFinalized) {
        exception = true;
    }

    RUNNER_ASSERT_MSG(exception, "Base64Decoder does not throw error.");
}

/*
 * test: class Certificate
 * description: Certificate should parse data passed to object constructor.
 * expected: Getters should be able to return certificate information.
 */
RUNNER_TEST(test08t01_Certificate)
{
    Certificate cert(certVerisign, Certificate::FORM_BASE64);
    #ifdef _WEARABLE
    DPL::OptionalString result;

    result = cert.getCommonName(Certificate::FIELD_SUBJECT);
    RUNNER_ASSERT_MSG(!result.IsNull(), "No common name");
    RUNNER_ASSERT_MSG(*result == DPL::FromUTF8String("www.verisign.com"),
                      "CommonName mismatch");

    result = cert.getCommonName(Certificate::FIELD_ISSUER);
    RUNNER_ASSERT_MSG(!result.IsNull(), "No common name");
    RUNNER_ASSERT_MSG(result == DPL::FromUTF8String(
            "VeriSign Class 3 Extended Validation SSL SGC CA"),
            "CommonName mismatch");

    result = cert.getCountryName();
    RUNNER_ASSERT_MSG(!result.IsNull(), "No country");
    RUNNER_ASSERT_MSG(*result == DPL::FromUTF8String("US"),
                      "Country mismatch");

    #else
    boost::optional<DPL::String> result;

    result = cert.getCommonName(Certificate::FIELD_SUBJECT);
    RUNNER_ASSERT_MSG(result, "No common name");
    RUNNER_ASSERT_MSG(*result == DPL::FromUTF8String("www.verisign.com"),
                      "CommonName mismatch");

    result = cert.getCommonName(Certificate::FIELD_ISSUER);
    RUNNER_ASSERT_MSG(result, "No common name");
    RUNNER_ASSERT_MSG(result == DPL::FromUTF8String(
            "VeriSign Class 3 Extended Validation SSL SGC CA"),
            "CommonName mismatch");

    result = cert.getCountryName();
    RUNNER_ASSERT_MSG(result, "No country");
    RUNNER_ASSERT_MSG(*result == DPL::FromUTF8String("US"),
                      "Country mismatch");
    #endif

}

/*
 * test: Certificate::getFingerprint
 * description: Certificate should parse data passed to object constructor.
 * expected: Function fingerprint should return valid fingerprint.
 */
RUNNER_TEST(test08t02_Certificate)
{
    Certificate cert(certVerisign, Certificate::FORM_BASE64);

    Certificate::Fingerprint fin =
        cert.getFingerprint(Certificate::FINGERPRINT_SHA1);

    unsigned char buff[20] = {
        0xb9, 0x72, 0x1e, 0xd5, 0x49,
        0xed, 0xbf, 0x31, 0x84, 0xd8,
        0x27, 0x0c, 0xfe, 0x03, 0x11,
        0x19, 0xdf, 0xc2, 0x2b, 0x0a};
    RUNNER_ASSERT_MSG(fin.size() == 20, "Wrong size of fingerprint");

    for (size_t i = 0; i<20; ++i) {
        RUNNER_ASSERT_MSG(fin[i] == buff[i], "Fingerprint mismatch");
    }
}

/*
 * test: Certificate::getAlternativeNameDNS
 * description: Certificate should parse data passed to object constructor.
 * expected: Function getAlternativeNameDNS should return list of
 * alternativeNames hardcoded in certificate.
 */
RUNNER_TEST(test08t03_Certificate)
{
    Certificate cert(certVerisign, Certificate::FORM_BASE64);

    Certificate::AltNameSet nameSet = cert.getAlternativeNameDNS();

    RUNNER_ASSERT(nameSet.size() == 8);

    DPL::String str = DPL::FromUTF8String("verisign.com");
    RUNNER_ASSERT(nameSet.find(str) != nameSet.end());

    str = DPL::FromUTF8String("fake.com");
    RUNNER_ASSERT(nameSet.find(str) == nameSet.end());

}

/*
 * test: Certificate::isCA
 * description: Certificate should parse data passed to object constructor.
 * expected: 1st and 2nd certificate should be identified as CA.
 */
RUNNER_TEST(test08t04_Certificate_isCA)
{
    Certificate cert1(googleCA, Certificate::FORM_BASE64);
    RUNNER_ASSERT(cert1.isCA() > 0);

    Certificate cert2(google2nd, Certificate::FORM_BASE64);
    RUNNER_ASSERT(cert2.isCA() > 0);

    Certificate cert3(google3rd, Certificate::FORM_BASE64);
    RUNNER_ASSERT(cert3.isCA() == 0);
}

#ifdef TIZEN_FEATURE_CERT_SVC_OCSP_CRL
/*
 * test: class CertificateCollection
 * description: It's not allowed to call function isChain before funciton sort.
 * expected: Function isChain should throw exception WrongUsage because
 * function sort was not called before.
 */
RUNNER_TEST(test09t01_CertificateCollection)
{
    CertificateList list;
    list.push_back(CertificatePtr(
        new Certificate(google2nd, Certificate::FORM_BASE64)));
    list.push_back(CertificatePtr(
        new Certificate(googleCA, Certificate::FORM_BASE64)));
    list.push_back(CertificatePtr(
        new Certificate(google3rd, Certificate::FORM_BASE64)));

    CertificateCollection collection;
    collection.load(list);

    bool exception = false;

    Try {
        RUNNER_ASSERT(collection.isChain());
    } Catch (CertificateCollection::Exception::WrongUsage) {
        exception = true;
    }

    RUNNER_ASSERT_MSG(exception, "Exception expected!");

    RUNNER_ASSERT_MSG(collection.sort(), "Sort failed");

    RUNNER_ASSERT(collection.isChain());

    std::string encoded = collection.toBase64String();

    collection.clear();

    RUNNER_ASSERT_MSG(collection.size() == 0, "Function clear failed.");

    collection.load(encoded);

    RUNNER_ASSERT_MSG(collection.sort(), "Sort failed");

    list = collection.getChain();

    RUNNER_ASSERT(
        DPL::ToUTF8String(*(list.front().get()->getCommonName())) ==
            "mail.google.com");
    RUNNER_ASSERT(
        DPL::ToUTF8String(*(list.back().get()->getOrganizationName())) ==
            "VeriSign, Inc.");
}

/*
 * test: class OCSP, VerificationStatusSet
 * description: OCSP should check certificate chain. One of the certificate
 * is GOOD and one is broken.
 * expected: Status from OCSP check should contain status GOOD and status
 * VERIFICATION_ERROR.
 */
RUNNER_TEST(test51t01_ocsp_validation_negative)
{
    CertificateCacheDAO::clearCertificateCache();

    CertificateList lOCSPCertificates;
    CertificatePtr certificatePtr;
    CertificatePtr pCert0;
    CertificatePtr pCert1;
    CertificatePtr pCert2;
    CertificatePtr pRootCert;
    std::string caRootPath(keys_path + "ocsp_rootca.crt"),
        certLevel0Path(keys_path + "ocsp_level0deprecated.crt"),
        certLevel1Path(keys_path + "ocsp_level1.crt"),
        certLevel2Path(keys_path + "ocsp_level2.crt");

    pRootCert = RevocationCheckerBase::loadPEMFile(caRootPath.c_str());
    if (!pRootCert) {
        RUNNER_ASSERT_MSG(false, "Couldn't load ocsp_rootca.crt");
    }
    lOCSPCertificates.push_back(pRootCert);

    pCert0 = RevocationCheckerBase::loadPEMFile(certLevel0Path.c_str());
    if (!pCert0) {
        RUNNER_ASSERT_MSG(false, "Couldn't load ocsp_level0.crt");
    }
    lOCSPCertificates.push_back(CertificatePtr(pCert0));

    pCert1 = RevocationCheckerBase::loadPEMFile(certLevel1Path.c_str());
    if (!pCert1) {
        RUNNER_ASSERT_MSG(false, "Couldn't load ocsp_level1.crt");
    }
    lOCSPCertificates.push_back(CertificatePtr(pCert1));

    pCert2 = RevocationCheckerBase::loadPEMFile(certLevel2Path.c_str());
    if (!pCert2) {
        RUNNER_ASSERT_MSG(false, "Couldn't load ocsp_level2.crt");
    }
    lOCSPCertificates.push_back(CertificatePtr(pCert2));

    OCSP ocsp;
    ocsp.setDigestAlgorithmForCertId(ValidationCore::OCSP::SHA1);
    ocsp.setDigestAlgorithmForRequest(ValidationCore::OCSP::SHA1);

    CertificateCollection collection;
    collection.load(lOCSPCertificates);
    RUNNER_ASSERT(collection.sort());
    CertificateList sorted = collection.getChain();

    ocsp.setTrustedStore(sorted);
    VerificationStatusSet status = ocsp.validateCertificateList(sorted);

    RUNNER_ASSERT_MSG(!status.contains(VERIFICATION_STATUS_CONNECTION_FAILED),
                      "Caught OCSP connection error from store exception");
    RUNNER_ASSERT_MSG(status.contains(VERIFICATION_STATUS_GOOD),
                      "Caught OCSP verification error exception");
    RUNNER_ASSERT_MSG(status.contains(VERIFICATION_STATUS_VERIFICATION_ERROR),
                      "Caught OCSP verification error exception");

    CertificateCacheDAO::clearCertificateCache();
}

/*
 * test: class OCSP, VerificationStatusSet
 * description: OCSP should check certificate chain. All certificates are GOOD.
 * expected: Status from OCSP check should contain only status GOOD.
 */
RUNNER_TEST(test51t02_ocsp_validation_positive)
{
    CertificateCacheDAO::clearCertificateCache();

    CertificateList lOCSPCertificates;
    CertificatePtr certificatePtr;
    CertificatePtr pCert0;
    CertificatePtr pCert1;
    CertificatePtr pCert2;
    CertificatePtr pRootCert;
    std::string caRootPath(keys_path + "ocsp_rootca.crt"),
        certLevel1Path(keys_path + "ocsp_level1.crt"),
        certLevel2Path(keys_path + "ocsp_level2.crt");

    pRootCert = RevocationCheckerBase::loadPEMFile(caRootPath.c_str());
    if (!pRootCert) {
        RUNNER_ASSERT_MSG(false, "Couldn't load ocsp_rootca.crt");
    }
    lOCSPCertificates.push_back(pRootCert);

    pCert1 = RevocationCheckerBase::loadPEMFile(certLevel1Path.c_str());
    if (!pCert1) {
        RUNNER_ASSERT_MSG(false, "Couldn't load ocsp_level1.crt");
    }
    lOCSPCertificates.push_back(CertificatePtr(pCert1));

    pCert2 = RevocationCheckerBase::loadPEMFile(certLevel2Path.c_str());
    if (!pCert2) {
        RUNNER_ASSERT_MSG(false, "Couldn't load ocsp_level2.crt");
    }
    lOCSPCertificates.push_back(CertificatePtr(pCert2));

    OCSP ocsp;
    ocsp.setDigestAlgorithmForCertId(ValidationCore::OCSP::SHA1);
    ocsp.setDigestAlgorithmForRequest(ValidationCore::OCSP::SHA1);

    CertificateCollection collection;
    collection.load(lOCSPCertificates);
    RUNNER_ASSERT(collection.sort());
    CertificateList sorted = collection.getChain();

    ocsp.setTrustedStore(sorted);
    VerificationStatusSet status = ocsp.validateCertificateList(sorted);

    RUNNER_ASSERT_MSG(!status.contains(VERIFICATION_STATUS_CONNECTION_FAILED),
                      "Caught OCSP connection error from store exception");
    RUNNER_ASSERT_MSG(status.contains(VERIFICATION_STATUS_GOOD),
                      "Caught OCSP verification error exception");
    RUNNER_ASSERT_MSG(!status.contains(VERIFICATION_STATUS_VERIFICATION_ERROR),
                      "Caught OCSP verification error exception");

    CertificateCacheDAO::clearCertificateCache();
}

/*
 * test: class OCSP, VerificationStatusSet
 * description: OCSP should check end entity certificate.
 * expected: Status from OCSP check should contain only status GOOD.
 */
RUNNER_TEST(test51t04_ocsp_request)
{
    CertificateList lTrustedCerts;

    lTrustedCerts.push_back(CertificatePtr(
        new Certificate(google3rd, Certificate::FORM_BASE64)));
    lTrustedCerts.push_back(CertificatePtr(
        new Certificate(google2nd, Certificate::FORM_BASE64)));
    lTrustedCerts.push_back(CertificatePtr(
        new Certificate(googleCA, Certificate::FORM_BASE64)));

    CertificateCollection chain;
    chain.load(lTrustedCerts);
    RUNNER_ASSERT(chain.sort());

    OCSP ocsp;
    ocsp.setDigestAlgorithmForCertId(OCSP::SHA1);
    ocsp.setDigestAlgorithmForRequest(OCSP::SHA1);
    ocsp.setTrustedStore(lTrustedCerts);
    VerificationStatus result = ocsp.checkEndEntity(chain);

    RUNNER_ASSERT(VERIFICATION_STATUS_GOOD == result);
}

/*
 * test: class OCSP, VerificationStatusSet, CertificateCachedDao
 * description: Call OCSP twice. Result of second call should be extracted
 * from cache.
 * expected: Both results should be equal.
 */
RUNNER_TEST(test51t05_cached_ocsp_validation_negative)
{
    CertificateCacheDAO::clearCertificateCache();

    CertificateList lOCSPCertificates;
    CertificatePtr certificatePtr;
    CertificatePtr pCert0;
    CertificatePtr pCert1;
    CertificatePtr pCert2;
    CertificatePtr pRootCert;
    std::string caRootPath(keys_path + "ocsp_rootca.crt"),
        certLevel0Path(keys_path + "ocsp_level0deprecated.crt"),
        certLevel1Path(keys_path + "ocsp_level1.crt"),
        certLevel2Path(keys_path + "ocsp_level2.crt");

    pRootCert = RevocationCheckerBase::loadPEMFile(caRootPath.c_str());
    RUNNER_ASSERT_MSG(pRootCert, "Couldn't load ocsp_rootca.crt");
    lOCSPCertificates.push_back(pRootCert);

    pCert0 = RevocationCheckerBase::loadPEMFile(certLevel0Path.c_str());
    RUNNER_ASSERT_MSG(pCert0, "Couldn't load ocsp_level0.crt");
    lOCSPCertificates.push_back(CertificatePtr(pCert0));

    pCert1 = RevocationCheckerBase::loadPEMFile(certLevel1Path.c_str());
    RUNNER_ASSERT_MSG(pCert1, "Couldn't load ocsp_level1.crt");
    lOCSPCertificates.push_back(CertificatePtr(pCert1));

    pCert2 = RevocationCheckerBase::loadPEMFile(certLevel2Path.c_str());
    RUNNER_ASSERT_MSG(pCert2, "Couldn't load ocsp_level2.crt");
    lOCSPCertificates.push_back(CertificatePtr(pCert2));

    CachedOCSP ocsp;

    CertificateCollection collection;
    collection.load(lOCSPCertificates);
    RUNNER_ASSERT(collection.sort());

    VerificationStatus status = ocsp.check(collection);

    RUNNER_ASSERT_MSG(status != VERIFICATION_STATUS_GOOD,
                      "Caught OCSP verification error exception");

    OCSPCachedStatusList respList;
    CertificateCacheDAO::getOCSPStatusList(&respList);
    unsigned len = respList.size();

    status = ocsp.check(collection);

    RUNNER_ASSERT_MSG(status != VERIFICATION_STATUS_GOOD,
                      "Caught OCSP verification error exception");

    respList.clear();
    CertificateCacheDAO::getOCSPStatusList(&respList);
    RUNNER_ASSERT_MSG(respList.size() == len && len > 0,
                      "Caught OCSP cache error exception");

    CertificateCacheDAO::clearCertificateCache();
}

/*
 * test: class OCSP, VerificationStatusSet, CertificateCachedDao
 * description: Call OCSP twice. Result of second call should be extracted
 * from cache.
 * expected: Both results should be equal.
 */
RUNNER_TEST(test51t06_cached_ocsp_validation_positive)
{
    CertificateCacheDAO::clearCertificateCache();

    CertificateList lOCSPCertificates;
    CertificatePtr certificatePtr;
    CertificatePtr pCert0;
    CertificatePtr pCert1;
    CertificatePtr pCert2;
    CertificatePtr pRootCert;
    std::string caRootPath(keys_path + "ocsp_rootca.crt"),
        certLevel1Path(keys_path + "ocsp_level1.crt"),
        certLevel2Path(keys_path + "ocsp_level2.crt");

    pRootCert = RevocationCheckerBase::loadPEMFile(caRootPath.c_str());
    RUNNER_ASSERT_MSG(pRootCert, "Couldn't load ocsp_rootca.crt");
    lOCSPCertificates.push_back(pRootCert);

    pCert1 = RevocationCheckerBase::loadPEMFile(certLevel1Path.c_str());
    RUNNER_ASSERT_MSG(pCert1, "Couldn't load ocsp_level1.crt");
    lOCSPCertificates.push_back(CertificatePtr(pCert1));

    pCert2 = RevocationCheckerBase::loadPEMFile(certLevel2Path.c_str());
    RUNNER_ASSERT_MSG(pCert2, "Couldn't load ocsp_level2.crt");
    lOCSPCertificates.push_back(CertificatePtr(pCert2));

    CachedOCSP ocsp;

    CertificateCollection collection;
    collection.load(lOCSPCertificates);
    RUNNER_ASSERT(collection.sort());

    VerificationStatus status = ocsp.check(collection);

    RUNNER_ASSERT_MSG(status == VERIFICATION_STATUS_GOOD,
                      "Caught OCSP verification error exception");

    OCSPCachedStatusList respList;
    CertificateCacheDAO::getOCSPStatusList(&respList);
    unsigned len = respList.size();

    status = ocsp.check(collection);

    RUNNER_ASSERT_MSG(status == VERIFICATION_STATUS_GOOD,
                      "Caught OCSP verification error exception");

    respList.clear();
    CertificateCacheDAO::getOCSPStatusList(&respList);
    RUNNER_ASSERT_MSG(respList.size() == len && len > 0,
                      "Caught OCSP cache error exception");

    CertificateCacheDAO::clearCertificateCache();
}

/*
 * test: class CRL
 * description: N/A
 * expected: checkCertificateChain should return invalid status.
 */
RUNNER_TEST(test61_crl_test_revocation_no_crl)
{
    //Clear CRL cache so there is no CRL for those certificates URI.
    CertificateCacheDAO::clearCertificateCache();
    //Prepare certificate chain
    TestCRL crl;
    std::string cacertStr(crl.getFileContent(cert_store_path + "cacert.pem"));
    std::string certAStr(
            crl.getFileContent(cert_store_path + "1second_level.pem"));
    std::string certBStr(
            crl.getFileContent(cert_store_path + "1third_level.pem"));

    CertificateLoader loader;
    CertificateList certList;
    CertificateCollection collection;
    RUNNER_ASSERT(loader.loadCertificateFromRawData(cacertStr) ==
                  CertificateLoader::NO_ERROR);
    RUNNER_ASSERT(!!loader.getCertificatePtr());
    certList.push_back(loader.getCertificatePtr());
    RUNNER_ASSERT(loader.loadCertificateFromRawData(certAStr) ==
                  CertificateLoader::NO_ERROR);
    RUNNER_ASSERT(!!loader.getCertificatePtr());
    certList.push_back(loader.getCertificatePtr());
    RUNNER_ASSERT(loader.loadCertificateFromRawData(certBStr) ==
                  CertificateLoader::NO_ERROR);
    RUNNER_ASSERT(!!loader.getCertificatePtr());
    certList.push_back(loader.getCertificatePtr());

    collection.load(certList);

    CRL::RevocationStatus status = crl.checkCertificateChain(collection);
    RUNNER_ASSERT_MSG(status.isCRLValid == false,
                      "Some certificate have no CRL extension!");

    CertificateCacheDAO::clearCertificateCache();
}

/*
 * test: class CRL
 * description: N/A
 * expected: checkCertificateChain should return valid and revoked.
 */
RUNNER_TEST(test62_crl_test_revocation_set1)
{
    CertificateCacheDAO::clearCertificateCache();

    //Prepare certificate chain
    TestCRL crl;
    std::string cacertStr(crl.getFileContent(cert_store_path + "cacert.pem"));
    std::string certAStr(
            crl.getFileContent(cert_store_path + "1second_level.pem"));
    std::string certBStr(
            crl.getFileContent(cert_store_path + "1third_level.pem"));
    crl.addCRLToStore(cert_store_path + "cacrl1.pem", crl_URI);

    CertificateLoader loader;
    CertificateList certList;
    CertificateCollection collection;
    RUNNER_ASSERT(loader.loadCertificateFromRawData(cacertStr) ==
                  CertificateLoader::NO_ERROR);
    RUNNER_ASSERT(!!loader.getCertificatePtr());
    certList.push_back(loader.getCertificatePtr());
    RUNNER_ASSERT(loader.loadCertificateFromRawData(certAStr) ==
                  CertificateLoader::NO_ERROR);
    RUNNER_ASSERT(!!loader.getCertificatePtr());
    certList.push_back(loader.getCertificatePtr());
    RUNNER_ASSERT(loader.loadCertificateFromRawData(certBStr) ==
                  CertificateLoader::NO_ERROR);
    RUNNER_ASSERT(!!loader.getCertificatePtr());
    certList.push_back(loader.getCertificatePtr());

    collection.load(certList);

    CRL::RevocationStatus status = crl.checkCertificateChain(collection);
    RUNNER_ASSERT(status.isCRLValid);
    RUNNER_ASSERT(status.isRevoked);

    CertificateCacheDAO::clearCertificateCache();
}

/*
 * test: class CRL
 * description: N/A
 * expected: checkCertificateChain should return valid and revoked.
 */
RUNNER_TEST(test63_crl_test_revocation_set1)
{
    CertificateCacheDAO::clearCertificateCache();

    //Prepare certificate chain
    TestCRL crl;
    std::string cacertStr(crl.getFileContent(cert_store_path + "cacert.pem"));
    std::string certAStr(
            crl.getFileContent(cert_store_path + "1second_level.pem"));
    std::string certBStr(
            crl.getFileContent(cert_store_path + "1third_level.pem"));
    crl.addCRLToStore(cert_store_path + "cacrl1.pem", crl_URI);

    CertificateLoader loader;
    CertificateList certList;
    CertificateCollection collection;
    RUNNER_ASSERT(loader.loadCertificateFromRawData(cacertStr) ==
                  CertificateLoader::NO_ERROR);
    RUNNER_ASSERT(!!loader.getCertificatePtr());
    certList.push_back(loader.getCertificatePtr());
    RUNNER_ASSERT(loader.loadCertificateFromRawData(certAStr) ==
                  CertificateLoader::NO_ERROR);
    RUNNER_ASSERT(!!loader.getCertificatePtr());
    certList.push_back(loader.getCertificatePtr());
    RUNNER_ASSERT(loader.loadCertificateFromRawData(certBStr) ==
                  CertificateLoader::NO_ERROR);
    RUNNER_ASSERT(!!loader.getCertificatePtr());
    certList.push_back(loader.getCertificatePtr());

    collection.load(certList);

    CRL::RevocationStatus status = crl.checkCertificateChain(collection);
    RUNNER_ASSERT(status.isCRLValid);
    RUNNER_ASSERT(status.isRevoked);

    CertificateCacheDAO::clearCertificateCache();
}

/*
 * test: class CRL
 * description: N/A
 * expected: checkCertificateChain should return valid and revoked.
 */
RUNNER_TEST(test64_crl_test_revocation_set2)
{
    CertificateCacheDAO::clearCertificateCache();

    //Prepare certificate chain
    TestCRL crl;
    std::string cacertStr(crl.getFileContent(cert_store_path + "cacert.pem"));
    std::string certAStr(
            crl.getFileContent(cert_store_path + "2second_level.pem"));
    std::string certBStr(
            crl.getFileContent(cert_store_path + "2third_level.pem"));
    crl.addCRLToStore(cert_store_path + "cacrl1.pem", crl_URI);

    CertificateLoader loader;
    CertificateList certList;
    CertificateCollection collection;
    RUNNER_ASSERT(loader.loadCertificateFromRawData(cacertStr) ==
                  CertificateLoader::NO_ERROR);
    RUNNER_ASSERT(!!loader.getCertificatePtr());
    certList.push_back(loader.getCertificatePtr());
    RUNNER_ASSERT(loader.loadCertificateFromRawData(certAStr) ==
                  CertificateLoader::NO_ERROR);
    RUNNER_ASSERT(!!loader.getCertificatePtr());
    certList.push_back(loader.getCertificatePtr());
    RUNNER_ASSERT(loader.loadCertificateFromRawData(certBStr) ==
                  CertificateLoader::NO_ERROR);
    RUNNER_ASSERT(!!loader.getCertificatePtr());
    certList.push_back(loader.getCertificatePtr());

    collection.load(certList);

    CRL::RevocationStatus status = crl.checkCertificateChain(collection);
    RUNNER_ASSERT(status.isCRLValid);
    RUNNER_ASSERT(!status.isRevoked);

    CertificateCacheDAO::clearCertificateCache();
}

/*
 * test: class CRL
 * description: N/A
 * expected: checkCertificateChain should return valid and revoked.
 */
RUNNER_TEST(test65_crl_test_revocation_set2)
{
    CertificateCacheDAO::clearCertificateCache();

    //Prepare certificate chain
    TestCRL crl;
    std::string cacertStr(crl.getFileContent(cert_store_path + "cacert.pem"));
    std::string certAStr(
            crl.getFileContent(cert_store_path + "2second_level.pem"));
    std::string certBStr(
            crl.getFileContent(cert_store_path + "2third_level.pem"));
    crl.addCRLToStore(cert_store_path + "cacrl2.pem", crl_URI);

    CertificateLoader loader;
    CertificateList certList;
    CertificateCollection collection;
    RUNNER_ASSERT(loader.loadCertificateFromRawData(cacertStr) ==
                  CertificateLoader::NO_ERROR);
    RUNNER_ASSERT(!!loader.getCertificatePtr());
    certList.push_back(loader.getCertificatePtr());
    RUNNER_ASSERT(loader.loadCertificateFromRawData(certAStr) ==
                  CertificateLoader::NO_ERROR);
    RUNNER_ASSERT(!!loader.getCertificatePtr());
    certList.push_back(loader.getCertificatePtr());
    RUNNER_ASSERT(loader.loadCertificateFromRawData(certBStr) ==
                  CertificateLoader::NO_ERROR);
    RUNNER_ASSERT(!!loader.getCertificatePtr());
    certList.push_back(loader.getCertificatePtr());

    collection.load(certList);

    CRL::RevocationStatus status = crl.checkCertificateChain(collection);
    RUNNER_ASSERT(status.isCRLValid);
    RUNNER_ASSERT(status.isRevoked);

    CertificateCacheDAO::clearCertificateCache();
}

/*
 * test: class CRL::updateList
 * description: N/A
 * expected: checkCertificateChain should return valid and revoked.
 */
RUNNER_TEST(test66_crl_update_expired_lists)
{
    CertificateCacheDAO::clearCertificateCache();

    CertificatePtr rootCA(new Certificate(googleCA, Certificate::FORM_BASE64));

    CertificateLoader loader;
    RUNNER_ASSERT(loader.loadCertificateFromRawData(google2nd) ==
                  CertificateLoader::NO_ERROR);
    RUNNER_ASSERT(!!loader.getCertificatePtr());
    TestCRL crl;
    crl.addToStore(rootCA);

    RUNNER_ASSERT_MSG(
            crl.updateList(loader.getCertificatePtr(), CRL::UPDATE_ON_EXPIRED),
            "CRL update on expired succeeded");

    CertificateCacheDAO::clearCertificateCache();
}

/*
 * test: class CRL::updateList
 * description: N/A
 * expected: checkCertificateChain should return valid and revoked.
 */
RUNNER_TEST(test67_crl_update_lists_on_demand)
{
    CertificateCacheDAO::clearCertificateCache();

    CertificatePtr rootCA(new Certificate(googleCA, Certificate::FORM_BASE64));

    CertificateLoader loader;
    RUNNER_ASSERT(loader.loadCertificateFromRawData(google2nd) ==
                  CertificateLoader::NO_ERROR);
    RUNNER_ASSERT(!!loader.getCertificatePtr());
    TestCRL crl;
    crl.addToStore(rootCA);

    RUNNER_ASSERT_MSG(
            crl.updateList(loader.getCertificatePtr(), CRL::UPDATE_ON_DEMAND),
            "CRL update on demand succeeded");

    CertificateCacheDAO::clearCertificateCache();
}

/*
 * test: class CRL::updateList
 * description: N/A
 * expected: N/A
 */
RUNNER_TEST(test68_cached_crl_test_positive)
{
    CertificateCacheDAO::clearCertificateCache();

    TestCRL crl;

    std::string cacertStr(crl.getFileContent(cert_store_path + "cacert.pem"));
    std::string certAStr(
            crl.getFileContent(cert_store_path + "2second_level.pem"));
    std::string certBStr(
            crl.getFileContent(cert_store_path + "2third_level.pem"));
    crl.addCRLToStore(cert_store_path + "cacrl1.pem", crl_URI);

    CertificateLoader loader;
    CertificateList certList;
    CertificateCollection collection;
    RUNNER_ASSERT(loader.loadCertificateFromRawData(cacertStr) ==
                  CertificateLoader::NO_ERROR);
    RUNNER_ASSERT(!!loader.getCertificatePtr());
    certList.push_back(loader.getCertificatePtr());
    RUNNER_ASSERT(loader.loadCertificateFromRawData(certAStr) ==
                  CertificateLoader::NO_ERROR);
    RUNNER_ASSERT(!!loader.getCertificatePtr());
    certList.push_back(loader.getCertificatePtr());
    RUNNER_ASSERT(loader.loadCertificateFromRawData(certBStr) ==
                  CertificateLoader::NO_ERROR);
    RUNNER_ASSERT(!!loader.getCertificatePtr());
    certList.push_back(loader.getCertificatePtr());

    collection.load(certList);

    CRL::RevocationStatus status = crl.checkCertificateChain(collection);

    CachedCRL cached;
    VerificationStatus cached_status = cached.check(collection);
    CRLCachedDataList list;
    CertificateCacheDAO::getCRLResponseList(&list);
    unsigned len = list.size();

    RUNNER_ASSERT(status.isCRLValid);
    RUNNER_ASSERT(!status.isRevoked &&
                  cached_status == VERIFICATION_STATUS_GOOD);

    cached_status = cached.check(collection);
    list.clear();
    CertificateCacheDAO::getCRLResponseList(&list);

    RUNNER_ASSERT(len == list.size());
    RUNNER_ASSERT(!status.isRevoked &&
                  cached_status == VERIFICATION_STATUS_GOOD);

    CertificateCacheDAO::clearCertificateCache();
}

/*
 * test: class CRL::updateList
 * description: N/A
 * expected: N/A
 */
RUNNER_TEST(test69_cached_crl_test_negative)
{
    CertificateCacheDAO::clearCertificateCache();

    //Prepare certificate chain
    TestCRL crl;
    std::string cacertStr(crl.getFileContent(cert_store_path + "cacert.pem"));
    std::string certAStr(
            crl.getFileContent(cert_store_path + "2second_level.pem"));
    std::string certBStr(
            crl.getFileContent(cert_store_path + "2third_level.pem"));
    crl.addCRLToStore(cert_store_path + "cacrl2.pem", crl_URI);

    CertificateLoader loader;
    CertificateList certList;
    CertificateCollection collection;
    RUNNER_ASSERT(loader.loadCertificateFromRawData(cacertStr) ==
                  CertificateLoader::NO_ERROR);
    RUNNER_ASSERT(!!loader.getCertificatePtr());
    certList.push_back(loader.getCertificatePtr());
    RUNNER_ASSERT(loader.loadCertificateFromRawData(certAStr) ==
                  CertificateLoader::NO_ERROR);
    RUNNER_ASSERT(!!loader.getCertificatePtr());
    certList.push_back(loader.getCertificatePtr());
    RUNNER_ASSERT(loader.loadCertificateFromRawData(certBStr) ==
                  CertificateLoader::NO_ERROR);
    RUNNER_ASSERT(!!loader.getCertificatePtr());
    certList.push_back(loader.getCertificatePtr());

    collection.load(certList);

    CRL::RevocationStatus status = crl.checkCertificateChain(collection);
    CachedCRL cached;
    VerificationStatus cached_status = cached.check(collection);
    CRLCachedDataList list;
    CertificateCacheDAO::getCRLResponseList(&list);
    unsigned len = list.size();

    RUNNER_ASSERT(status.isCRLValid);
    RUNNER_ASSERT(status.isRevoked &&
                  cached_status == VERIFICATION_STATUS_REVOKED);

    cached_status = cached.check(collection);
    list.clear();
    CertificateCacheDAO::getCRLResponseList(&list);

    RUNNER_ASSERT(len == list.size());
    RUNNER_ASSERT(status.isRevoked &&
                  cached_status == VERIFICATION_STATUS_REVOKED);

    CertificateCacheDAO::clearCertificateCache();
}

/*
 * test: class OCSP
 * description: All certificates are valid.
 * expected: Only status VERIFICATION_STATUS_GOOD should be set.
 */
RUNNER_TEST(test70_ocsp_local_validation_positive)
{
    CertificateCacheDAO::clearCertificateCache();

    CertificateList lOCSPCertificates;
    CertificatePtr certificatePtr;
    CertificatePtr pCert0;
    CertificatePtr pRootCert;
    std::string caRootPath(cert_store_path + "cacert.pem"),
        certLevel0Path(cert_store_path + "1second_level.pem");

    pRootCert = RevocationCheckerBase::loadPEMFile(caRootPath.c_str());
    if (!pRootCert) {
        RUNNER_ASSERT_MSG(false, "Couldn't load cacert.pem");
    }
    lOCSPCertificates.push_back(pRootCert);

    pCert0 = RevocationCheckerBase::loadPEMFile(certLevel0Path.c_str());
    if (!pCert0) {
        RUNNER_ASSERT_MSG(false, "Couldn't load 1second_level.pem");
    }
    lOCSPCertificates.push_back(CertificatePtr(pCert0));

    OCSP ocsp;
    ocsp.setDigestAlgorithmForCertId(ValidationCore::OCSP::SHA1);
    ocsp.setDigestAlgorithmForRequest(ValidationCore::OCSP::SHA1);

    CertificateCollection collection;
    collection.load(lOCSPCertificates);
    RUNNER_ASSERT(collection.sort());
    CertificateList sorted = collection.getChain();

    ocsp.setTrustedStore(sorted);
    VerificationStatusSet status = ocsp.validateCertificateList(sorted);

    RUNNER_ASSERT_MSG(!status.contains(VERIFICATION_STATUS_CONNECTION_FAILED),
                      "Caught OCSP connection error - check if "
                      "wrt-tests-vcore-ocsp-server.sh is running!");
    RUNNER_ASSERT_MSG(status.contains(VERIFICATION_STATUS_GOOD),
                      "Caught OCSP verification error exception");
    RUNNER_ASSERT_MSG(!status.contains(VERIFICATION_STATUS_VERIFICATION_ERROR),
                      "Caught OCSP verification error exception");

    CertificateCacheDAO::clearCertificateCache();
}

/*
 * test: class OCSP
 * description: All certificates are valid.
 * expected: Only status VERIFICATION_STATUS_GOOD should be set.
 */
RUNNER_TEST(test71_ocsp_local_validation_positive)
{
    CertificateCacheDAO::clearCertificateCache();

    CertificateList lOCSPCertificates;
    CertificatePtr certificatePtr;
    CertificatePtr pCert0;
    CertificatePtr pRootCert;
    std::string caRootPath(cert_store_path + "cacert.pem"),
        certLevel0Path(cert_store_path + "3second_level.pem");

    pRootCert = RevocationCheckerBase::loadPEMFile(caRootPath.c_str());
    if (!pRootCert) {
        RUNNER_ASSERT_MSG(false, "Couldn't load cacert.pem");
    }
    lOCSPCertificates.push_back(pRootCert);

    pCert0 = RevocationCheckerBase::loadPEMFile(certLevel0Path.c_str());
    if (!pCert0) {
        RUNNER_ASSERT_MSG(false, "Couldn't load 3second_level.pem");
    }
    lOCSPCertificates.push_back(CertificatePtr(pCert0));

    OCSP ocsp;
    ocsp.setDigestAlgorithmForCertId(ValidationCore::OCSP::SHA1);
    ocsp.setDigestAlgorithmForRequest(ValidationCore::OCSP::SHA1);

    CertificateCollection collection;
    collection.load(lOCSPCertificates);
    RUNNER_ASSERT(collection.sort());
    CertificateList sorted = collection.getChain();

    ocsp.setTrustedStore(sorted);
    VerificationStatusSet status = ocsp.validateCertificateList(sorted);

    RUNNER_ASSERT_MSG(!status.contains(VERIFICATION_STATUS_CONNECTION_FAILED),
                      "Caught OCSP connection error - check if "
                      "wrt-tests-vcore-ocsp-server.sh is running!");
    RUNNER_ASSERT_MSG(status.contains(VERIFICATION_STATUS_GOOD),
                      "Caught OCSP verification error exception");
    RUNNER_ASSERT_MSG(!status.contains(VERIFICATION_STATUS_VERIFICATION_ERROR),
                      "Caught OCSP verification error exception");

    CertificateCacheDAO::clearCertificateCache();
}

/*
 * test: class OCSP
 * description: Second certificate is revoked. Root CA certificate wont be checked.
 * expected: Only status VERIFICATION_STATUS_REVOKED should be set.
 */
RUNNER_TEST(test72_ocsp_local_validation_revoked)
{
    CertificateCacheDAO::clearCertificateCache();

    CertificateList lOCSPCertificates;
    CertificatePtr certificatePtr;
    CertificatePtr pCert0;
    CertificatePtr pRootCert;
    std::string caRootPath(cert_store_path + "cacert.pem"),
        certLevel0Path(cert_store_path + "2second_level.pem");

    pRootCert = RevocationCheckerBase::loadPEMFile(caRootPath.c_str());
    if (!pRootCert) {
        RUNNER_ASSERT_MSG(false, "Couldn't load cacert.pem");
    }
    lOCSPCertificates.push_back(pRootCert);

    pCert0 = RevocationCheckerBase::loadPEMFile(certLevel0Path.c_str());
    if (!pCert0) {
        RUNNER_ASSERT_MSG(false, "Couldn't load 2second_level.pem");
    }
    lOCSPCertificates.push_back(CertificatePtr(pCert0));

    OCSP ocsp;
    ocsp.setDigestAlgorithmForCertId(ValidationCore::OCSP::SHA1);
    ocsp.setDigestAlgorithmForRequest(ValidationCore::OCSP::SHA1);

    CertificateCollection collection;
    collection.load(lOCSPCertificates);
    RUNNER_ASSERT(collection.sort());
    CertificateList sorted = collection.getChain();

    ocsp.setTrustedStore(sorted);
    VerificationStatusSet status = ocsp.validateCertificateList(sorted);

    RUNNER_ASSERT_MSG(!status.contains(VERIFICATION_STATUS_CONNECTION_FAILED),
                      "Caught OCSP connection error - check if "
                      "wrt-tests-vcore-ocsp-server.sh is running!");
    RUNNER_ASSERT_MSG(!status.contains(VERIFICATION_STATUS_GOOD),
                      "Caught OCSP verification error exception");
    RUNNER_ASSERT_MSG(status.contains(VERIFICATION_STATUS_REVOKED),
                      "Caught OCSP verification error exception");
    RUNNER_ASSERT_MSG(!status.contains(VERIFICATION_STATUS_UNKNOWN),
                      "Caught OCSP verification error exception");
    RUNNER_ASSERT_MSG(!status.contains(VERIFICATION_STATUS_VERIFICATION_ERROR),
                      "Caught OCSP verification error exception");

    CertificateCacheDAO::clearCertificateCache();
}

/*
 * test: class OCSP
 * description: N/A
 * expected: Status VERIFICATION_STATUS_GOOD and VERIFICATION_STATUS_VERIFICATION_ERROR
 * should be set.
 */
RUNNER_TEST(test73_ocsp_local_validation_error_unknown_cert)
{
    CertificateCacheDAO::clearCertificateCache();

    CertificateList lOCSPCertificates;
    CertificatePtr certificatePtr;
    CertificatePtr pCert0;
    CertificatePtr pCert1;
    CertificatePtr pRootCert;
    std::string caRootPath(cert_store_path + "cacert.pem"),
        certLevel0Path(cert_store_path + "1second_level.pem"),
        certLevel1Path(cert_store_path + "1third_level.pem");

    pRootCert = RevocationCheckerBase::loadPEMFile(caRootPath.c_str());
    if (!pRootCert) {
        RUNNER_ASSERT_MSG(false, "Couldn't load cacerr.pem");
    }
    lOCSPCertificates.push_back(pRootCert);

    pCert0 = RevocationCheckerBase::loadPEMFile(certLevel0Path.c_str());
    if (!pCert0) {
        RUNNER_ASSERT_MSG(false, "Couldn't load 1second_level.pem");
    }
    lOCSPCertificates.push_back(CertificatePtr(pCert0));

    pCert1 = RevocationCheckerBase::loadPEMFile(certLevel1Path.c_str());
    if (!pCert1) {
        RUNNER_ASSERT_MSG(false, "Couldn't load 1third_level.pem");
    }
    lOCSPCertificates.push_back(CertificatePtr(pCert1));

    OCSP ocsp;
    ocsp.setDigestAlgorithmForCertId(ValidationCore::OCSP::SHA1);
    ocsp.setDigestAlgorithmForRequest(ValidationCore::OCSP::SHA1);

    CertificateCollection collection;
    collection.load(lOCSPCertificates);
    RUNNER_ASSERT(collection.sort());
    CertificateList sorted = collection.getChain();

    ocsp.setTrustedStore(sorted);
    VerificationStatusSet status = ocsp.validateCertificateList(sorted);

    RUNNER_ASSERT_MSG(!status.contains(VERIFICATION_STATUS_CONNECTION_FAILED),
                      "Caught OCSP connection error - check if "
                      "wrt-tests-vcore-ocsp-server.sh is running!");
    RUNNER_ASSERT_MSG(status.contains(VERIFICATION_STATUS_GOOD),
                      "Caught OCSP verification error exception");
    RUNNER_ASSERT_MSG(!status.contains(VERIFICATION_STATUS_REVOKED),
                      "Caught OCSP verification error exception");
    RUNNER_ASSERT_MSG(status.contains(VERIFICATION_STATUS_VERIFICATION_ERROR),
                      "Caught OCSP verification error exception");
    RUNNER_ASSERT_MSG(!status.contains(VERIFICATION_STATUS_UNKNOWN),
                          "Caught OCSP verification error exception");

    CertificateCacheDAO::clearCertificateCache();
}
#endif

#define CRYPTO_HASH_TEST(text,expected,FUN)                    \
    do {                                                       \
        ValidationCore::Crypto::Hash::Base *crypto;            \
        crypto = new ValidationCore::Crypto::Hash::FUN();      \
        std::string input = text;                              \
        crypto->Append(text);                                  \
        crypto->Finish();                                      \
        std::string result = crypto->ToBase64String();         \
        RUNNER_ASSERT_MSG(result == expected,                  \
            "Hash function failed");                           \
    } while(0)

/*
 * test: class ValidationCore::Crypto::Hash::MD4
 * description: Test implementation of MD4 hash algorithm
 * expected: Value counted by algorithm should be eqal to value encoded in test.
 */
RUNNER_TEST(test80_crypto_md4)
{
    CRYPTO_HASH_TEST("Hi, my name is Bart.",
        "Rj5V34qqMQmHh2bn3Cb/vQ==",
        MD4);
}

/*
 * test: class ValidationCore::Crypto::Hash::MD5
 * description: Test implementation of hash algorithm
 * expected: Value counted by algorithm should be eqal to value encoded in test.
 */
RUNNER_TEST(test81_crypto_md5)
{
    CRYPTO_HASH_TEST("Hi, my name is Bart.",
        "4y2iI6QtFC7+0xurBOfcsg==",
        MD5);
}

/*
 * test: class ValidationCore::Crypto::Hash::SHA
 * description: Test implementation of hash algorithm
 * expected: Value counted by algorithm should be eqal to value encoded in test.
 */
RUNNER_TEST(test82_crypto_sha)
{
    CRYPTO_HASH_TEST("Hi, my name is Bart.",
        "v7w8XNvzQkZPoID+bbdrLwI6zPA=",
        SHA);
}

/*
 * test: class ValidationCore::Crypto::Hash::SHA1
 * description: Test implementation of hash algorithm
 * expected: Value counted by algorithm should be eqal to value encoded in test.
 */
RUNNER_TEST(test83_crypto_sha1)
{
    CRYPTO_HASH_TEST("Hi, my name is Bart.",
        "Srydq14dzpuLn+xlkGz7ZyFLe1w=",
        SHA1);
}

/*
 * test: class ValidationCore::Crypto::Hash::SHA224
 * description: Test implementation of hash algorithm
 * expected: Value counted by algorithm should be eqal to value encoded in test.
 */
RUNNER_TEST(test84_crypto_sha224)
{
    CRYPTO_HASH_TEST("Hi, my name is Bart.",
        "Ss2MKa2Mxrf0/hrl8bf0fOSz/e5nQv4J/yX6ig==",
        SHA224);
}

/*
 * test: class ValidationCore::Crypto::Hash::SHA256
 * description: Test implementation of hash algorithm
 * expected: Value counted by algorithm should be eqal to value encoded in test.
 */
RUNNER_TEST(test85_crypto_sha256)
{
    CRYPTO_HASH_TEST("Hi, my name is Bart.",
        "Bja/IuUJHLPlHYYB2hBcuuOlRWPy1RdF6gzL0VWxeps=",
        SHA256);
}

/*
 * test: class ValidationCore::Crypto::Hash::SHA384
 * description: Test implementation of hash algorithm
 * expected: Value counted by algorithm should be eqal to value encoded in test.
 */
RUNNER_TEST(test86_crypto_sha384)
{
    CRYPTO_HASH_TEST("Hi, my name is Bart.",
        "5RjtzCnGAt+P6J8h32Dzrmka+5i5MMvDRVz+s9jA7TW508sUZOnKliliad5nUJrj",
        SHA384);
}

/*
 * test: class ValidationCore::Crypto::Hash::SHA512
 * description: Test implementation of hash algorithm
 * expected: Value counted by algorithm should be eqal to value encoded in test.
 */
RUNNER_TEST(test87_crypto_sha512)
{
    CRYPTO_HASH_TEST("Hi, my name is Bart.",
        "LxemzcQNf5erjA4a6PnTXfL+putB3uElitOjc5QCQ9Mg4ZuxTpre8VIBAviwRcTnui2Y0/Yg7cB40OG3XJMfbA==",
        SHA512);
}

/*
 * test: class ValidationCore::Crypto::Hash::SHA1
 * description: This example was implemented to show how to count SHA1 value from certificate.
 * expected: Value counted by algorithm should be eqal to value encoded in test.
 */
RUNNER_TEST(test88_crypto_sha1_certificate)
{
    Certificate cert(certVerisign, Certificate::FORM_BASE64);

    ValidationCore::Crypto::Hash::SHA1 sha1;
    sha1.Append(cert.getDER());
    sha1.Finish();
    std::string result = sha1.ToBase64String();

    RUNNER_ASSERT_MSG(result == "uXIe1UntvzGE2CcM/gMRGd/CKwo=",
        "Certificate hash does not match.");
}

/*
 * test: CertificateIdentifier::find(Fingerprint)
 * description: Check implementation of fingerprint_list.
 * expected: Google CA certificate was added to TIZEN_MEMBER group
 * and ORANGE_LEGACY. Both domain should be found.
 */
/*
RUNNER_TEST(test90_certificate_identifier_find_fingerprint)
{
    CertificateIdentifier certIdent;
    CertificateConfigReader reader;
    reader.initialize(
        "/opt/apps/widget/tests/vcore_config/fin_list.xml",
        "/opt/apps/widget/tests/vcore_config/fin_list.xsd");
    reader.read(certIdent);

    Certificate cert(googleCA, Certificate::FORM_BASE64);

    CertStoreId::Set domain =
        certIdent.find(cert.getFingerprint(Certificate::FINGERPRINT_SHA1));

    RUNNER_ASSERT(!domain.contains(CertStoreId::WAC_PUBLISHER));
    RUNNER_ASSERT(!domain.contains(CertStoreId::DEVELOPER));
    RUNNER_ASSERT(!domain.contains(CertStoreId::WAC_ROOT));
    RUNNER_ASSERT(!domain.contains(CertStoreId::WAC_MEMBER));
    RUNNER_ASSERT(domain.contains(CertStoreId::TIZEN_MEMBER));
    RUNNER_ASSERT(domain.contains(CertStoreId::ORANGE_LEGACY));
}
*/

/*
 * test: CertificateIdentifier::find(CertificatePtr)
 * description: Check implementation of fingerprint_list.
 * expected: Google CA certificate was added to TIZEN_MEMBER group
 * and ORANGE_LEGACY. Both domain should be found.
 */
/*
RUNNER_TEST(test91_certificate_identifier_find_cert)
{
    CertificateIdentifier certIdent;
    CertificateConfigReader reader;
    reader.initialize(
        "/opt/apps/widget/tests/vcore_config/fin_list.xml",
        "/opt/apps/widget/tests/vcore_config/fin_list.xsd");
    reader.read(certIdent);

    CertificatePtr cert(new Certificate(googleCA, Certificate::FORM_BASE64));

    CertStoreId::Set domain = certIdent.find(cert);

    RUNNER_ASSERT(!domain.contains(CertStoreId::WAC_PUBLISHER));
    RUNNER_ASSERT(!domain.contains(CertStoreId::DEVELOPER));
    RUNNER_ASSERT(!domain.contains(CertStoreId::WAC_ROOT));
    RUNNER_ASSERT(!domain.contains(CertStoreId::WAC_MEMBER));
    RUNNER_ASSERT(domain.contains(CertStoreId::TIZEN_MEMBER));
    RUNNER_ASSERT(domain.contains(CertStoreId::ORANGE_LEGACY));
}
*/

/*
 * test: CertificateIdentifier::find(Fingerprint)
 * description: Check implementation of fingerprint_list.
 * expected: google2nd certificate was not added to any group so
 * no domain should be found.
 */
/*
RUNNER_TEST(test92_certificate_identifier_negative)
{
    CertificateIdentifier certIdent;
    CertificateConfigReader reader;
    reader.initialize(
        "/opt/apps/widget/tests/vcore_config/fin_list.xml",
        "/opt/apps/widget/tests/vcore_config/fin_list.xsd");
    reader.read(certIdent);

    Certificate cert(google2nd, Certificate::FORM_BASE64);

    CertStoreId::Set domain =
        certIdent.find(cert.getFingerprint(Certificate::FINGERPRINT_SHA1));

    RUNNER_ASSERT(!domain.contains(CertStoreId::WAC_PUBLISHER));
    RUNNER_ASSERT(!domain.contains(CertStoreId::DEVELOPER));
    RUNNER_ASSERT(!domain.contains(CertStoreId::WAC_ROOT));
    RUNNER_ASSERT(!domain.contains(CertStoreId::WAC_MEMBER));
    RUNNER_ASSERT(!domain.contains(CertStoreId::TIZEN_MEMBER));
    RUNNER_ASSERT(!domain.contains(CertStoreId::ORANGE_LEGACY));
}
*/
/*
 * test: CertificateIdentifier::find(Fingerprint)
 * description: Check implementation of fingerprint_list.
 * expected: Google CA certificate was added to TIZEN_MEMBER group
 * and ORANGE_LEGACY. Both domain should be found.
 */
/*
RUNNER_TEST(test93_certificate_identifier_find_fingerprint)
{
    CertificateIdentifier certIdent;
    CertificateConfigReader reader;
    reader.initialize(
        "/opt/apps/widget/tests/vcore_config/fin_list.xml",
        "/opt/apps/widget/tests/vcore_config/fin_list.xsd");
    reader.read(certIdent);

    Certificate cert(googleCA, Certificate::FORM_BASE64);

    CertStoreId::Set visibilityLevel =
        certIdent.find(cert.getFingerprint(Certificate::FINGERPRINT_SHA1));

    RUNNER_ASSERT(!visibilityLevel.contains(CertStoreId::WAC_PUBLISHER));
    RUNNER_ASSERT(!visibilityLevel.contains(CertStoreId::DEVELOPER));
    RUNNER_ASSERT(!visibilityLevel.contains(CertStoreId::WAC_ROOT));
    RUNNER_ASSERT(!visibilityLevel.contains(CertStoreId::WAC_MEMBER));
    RUNNER_ASSERT(visibilityLevel.contains(CertStoreId::TIZEN_MEMBER));
    RUNNER_ASSERT(visibilityLevel.contains(CertStoreId::ORANGE_LEGACY));

    RUNNER_ASSERT(visibilityLevel.contains(CertStoreId::VIS_PUBLIC));
    RUNNER_ASSERT(!visibilityLevel.contains(CertStoreId::VIS_PARTNER));
    RUNNER_ASSERT(!visibilityLevel.contains(CertStoreId::VIS_PARTNER_OPERATOR));
    RUNNER_ASSERT(!visibilityLevel.contains(CertStoreId::VIS_PARTNER_MANUFACTURER));
}
*/

/*
 * test: CertificateIdentifier::find(CertificatePtr)
 * description: Check implementation of fingerprint_list.
 * expected: Google CA certificate was added to TIZEN_MEMBER group
 * and ORANGE_LEGACY. Both domain should be found.
 */
/*
RUNNER_TEST(test94_certificate_identifier_find_cert)
{
    CertificateIdentifier certIdent;
    CertificateConfigReader reader;
    reader.initialize(
        "/opt/apps/widget/tests/vcore_config/fin_list.xml",
        "/opt/apps/widget/tests/vcore_config/fin_list.xsd");
    reader.read(certIdent);

    CertificatePtr cert(new Certificate(googleCA, Certificate::FORM_BASE64));

    CertStoreId::Set visibilityLevel = certIdent.find(cert);

    RUNNER_ASSERT(!visibilityLevel.contains(CertStoreId::WAC_PUBLISHER));
    RUNNER_ASSERT(!visibilityLevel.contains(CertStoreId::DEVELOPER));
    RUNNER_ASSERT(!visibilityLevel.contains(CertStoreId::WAC_ROOT));
    RUNNER_ASSERT(!visibilityLevel.contains(CertStoreId::WAC_MEMBER));
    RUNNER_ASSERT(visibilityLevel.contains(CertStoreId::TIZEN_MEMBER));
    RUNNER_ASSERT(visibilityLevel.contains(CertStoreId::ORANGE_LEGACY));

    RUNNER_ASSERT(visibilityLevel.contains(CertStoreId::VIS_PUBLIC));
    RUNNER_ASSERT(!visibilityLevel.contains(CertStoreId::VIS_PARTNER));
    RUNNER_ASSERT(!visibilityLevel.contains(CertStoreId::VIS_PARTNER_OPERATOR));
    RUNNER_ASSERT(!visibilityLevel.contains(CertStoreId::VIS_PARTNER_MANUFACTURER));
}
*/

/*
 * test: CertificateIdentifier::find(Fingerprint)
 * description: Check implementation of fingerprint_list.
 * expected: google2nd certificate was not added to any group so
 * no domain should be found.
 */
/*
RUNNER_TEST(test95_certificate_identifier_negative)
{
    CertificateIdentifier certIdent;
    CertificateConfigReader reader;
    reader.initialize(
        "/opt/apps/widget/tests/vcore_config/fin_list.xml",
        "/opt/apps/widget/tests/vcore_config/fin_list.xsd");
    reader.read(certIdent);

    Certificate cert(google2nd, Certificate::FORM_BASE64);

    CertStoreId::Set domain =
        certIdent.find(cert.getFingerprint(Certificate::FINGERPRINT_SHA1));

    RUNNER_ASSERT(!domain.contains(CertStoreId::WAC_PUBLISHER));
    RUNNER_ASSERT(!domain.contains(CertStoreId::DEVELOPER));
    RUNNER_ASSERT(!domain.contains(CertStoreId::WAC_ROOT));
    RUNNER_ASSERT(!domain.contains(CertStoreId::WAC_MEMBER));
    RUNNER_ASSERT(!domain.contains(CertStoreId::TIZEN_MEMBER));
    RUNNER_ASSERT(!domain.contains(CertStoreId::ORANGE_LEGACY));
    RUNNER_ASSERT(!domain.contains(CertStoreId::VIS_PUBLIC));
    RUNNER_ASSERT(!domain.contains(CertStoreId::VIS_PARTNER));
    RUNNER_ASSERT(!domain.contains(CertStoreId::VIS_PARTNER_OPERATOR));
    RUNNER_ASSERT(!domain.contains(CertStoreId::VIS_PARTNER_MANUFACTURER));
}
*/
