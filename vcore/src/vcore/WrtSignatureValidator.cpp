/*
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
/*
 * @file        WrtSignatureValidator.cpp
 * @author      Bartlomiej Grzelewski (b.grzelewski@samsung.com)
 * @version     1.0
 * @brief       Implementatin of tizen signature validation protocol.
 */
#include <vcore/WrtSignatureValidator.h>

#include <dpl/log/log.h>

#include <vcore/CertificateVerifier.h>
#include <vcore/Certificate.h>
#include <vcore/OCSPCertMgrUtil.h>
#include <vcore/ReferenceValidator.h>
#include <vcore/ValidatorFactories.h>
#include <vcore/XmlsecAdapter.h>

namespace {
const time_t TIMET_DAY = 60 * 60 * 24;

const std::string TOKEN_ROLE_AUTHOR_URI =
    "http://www.w3.org/ns/widgets-digsig#role-author";
const std::string TOKEN_ROLE_DISTRIBUTOR_URI =
    "http://www.w3.org/ns/widgets-digsig#role-distributor";
const std::string TOKEN_PROFILE_URI =
    "http://www.w3.org/ns/widgets-digsig#profile";
} // namespace anonymouse

namespace ValidationCore {

class WrtSignatureValidator::Impl {
public:
    virtual WrtSignatureValidator::Result check(
        SignatureData &data,
        const std::string &widgetContentPath) = 0;

    explicit Impl(bool ocspEnable,
                  bool crlEnable,
                  bool complianceMode)
      : m_ocspEnable(ocspEnable)
      , m_crlEnable(crlEnable)
      , m_complianceModeEnabled(complianceMode)
    {}

    virtual ~Impl(){}

    bool checkRoleURI(const SignatureData &data) {
        std::string roleURI = data.getRoleURI();

        if (roleURI.empty()) {
            LogWarning("URI attribute in Role tag couldn't be empty.");
            return false;
        }

        if (roleURI != TOKEN_ROLE_AUTHOR_URI && data.isAuthorSignature()) {
            LogWarning("URI attribute in Role tag does not "
              "match with signature filename.");
            return false;
        }

        if (roleURI != TOKEN_ROLE_DISTRIBUTOR_URI && !data.isAuthorSignature()) {
            LogWarning("URI attribute in Role tag does not "
              "match with signature filename.");
            return false;
        }
        return true;
    }

    bool checkProfileURI(const SignatureData &data) {
        if (TOKEN_PROFILE_URI != data.getProfileURI()) {
            LogWarning(
              "Profile tag contains unsupported value in URI attribute(" <<
              data.getProfileURI() << ").");
            return false;
        }
        return true;
    }

    bool checkObjectReferences(const SignatureData &data) {
        ObjectList objectList = data.getObjectList();
        ObjectList::const_iterator iter;
        for (iter = objectList.begin(); iter != objectList.end(); ++iter) {
            if (!data.containObjectReference(*iter)) {
                LogWarning("Signature does not contain reference for object " <<
                  *iter);
                return false;
            }
        }
        return true;
    }
protected:
    bool m_ocspEnable;
    bool m_crlEnable;
    bool m_complianceModeEnabled;
};

class ImplTizen : public WrtSignatureValidator::Impl
{
  public:
    WrtSignatureValidator::Result check(SignatureData &data,
            const std::string &widgetContentPath);

    explicit ImplTizen(bool ocspEnable,
                       bool crlEnable,
                       bool complianceMode)
      : Impl(ocspEnable, crlEnable, complianceMode)
    {}

    virtual ~ImplTizen() {}
};

WrtSignatureValidator::Result ImplTizen::check(
        SignatureData &data,
        const std::string &widgetContentPath)
{
    bool disregard = false;

    if (!checkRoleURI(data)) {
        return WrtSignatureValidator::SIGNATURE_INVALID;
    }

    if (!checkProfileURI(data)) {
        return WrtSignatureValidator::SIGNATURE_INVALID;
    }

    //  CertificateList sortedCertificateList = data.getCertList();

    CertificateCollection collection;
    collection.load(data.getCertList());

    // First step - sort certificate
    if (!collection.sort()) {
        LogWarning("Certificates do not form valid chain.");
        return WrtSignatureValidator::SIGNATURE_INVALID;
    }

    // Check for error
    if (collection.empty()) {
        LogWarning("Certificate list in signature is empty.");
        return WrtSignatureValidator::SIGNATURE_INVALID;
    }

    CertificateList sortedCertificateList = collection.getChain();

    // TODO move it to CertificateCollection
    // Add root CA and CA certificates (if chain is incomplete)
    sortedCertificateList =
        OCSPCertMgrUtil::completeCertificateChain(sortedCertificateList);

    CertificatePtr root = sortedCertificateList.back();

    // Is Root CA certificate trusted?
    CertStoreId::Set storeIdSet = createCertificateIdentifier().find(root);

    LogDebug("Is root certificate from TIZEN_DEVELOPER domain:  "
        << storeIdSet.contains(CertStoreId::TIZEN_DEVELOPER));
    LogDebug("Is root certificate from TIZEN_TEST domain:  "
        << storeIdSet.contains(CertStoreId::TIZEN_TEST));
    LogDebug("Is root certificate from TIZEN_PUBLIC domain:  "
        << storeIdSet.contains(CertStoreId::VIS_PUBLIC));
    LogDebug("Is root certificate from TIZEN_PARTNER domain:  "
        << storeIdSet.contains(CertStoreId::VIS_PARTNER));
    LogDebug("Is root certificate from TIZEN_PLATFORM domain:  "
        << storeIdSet.contains(CertStoreId::VIS_PLATFORM));

    LogDebug("Visibility level is public :  "
        << storeIdSet.contains(CertStoreId::VIS_PUBLIC));
    LogDebug("Visibility level is partner :  "
        << storeIdSet.contains(CertStoreId::VIS_PARTNER));
	LogDebug("Visibility level is platform :  "
		<< storeIdSet.contains(CertStoreId::VIS_PLATFORM));

	if (data.isAuthorSignature())
	{
		if (!storeIdSet.contains(CertStoreId::TIZEN_DEVELOPER))
		{
            LogWarning("author-signature.xml has got unrecognized Root CA "
                       "certificate. Signature will be disregarded.");
            disregard = true;
		}
        LogDebug("Root CA for author signature is correct.");
	}
	else
	{
		LogDebug("signaturefile name = " <<  data.getSignatureFileName().c_str());
		if (data.getSignatureNumber() == 1)
		{
			if (storeIdSet.contains(CertStoreId::VIS_PUBLIC) || storeIdSet.contains(CertStoreId::VIS_PARTNER) || storeIdSet.contains(CertStoreId::VIS_PLATFORM))
			{
				LogDebug("Root CA for signature1.xml is correct.");
			}
			else
			{
				LogWarning("author-signature.xml has got unrecognized Root CA "
				        "certificate. Signature will be disregarded.");
				disregard = true;
			}
		}
	}

    data.setStorageType(storeIdSet);
    data.setSortedCertificateList(sortedCertificateList);

    // We add only Root CA certificate because WAC ensure that the rest
    // of certificates are present in signature files ;-)
    XmlSec::XmlSecContext context;
    context.signatureFile = data.getSignatureFileName();
    context.certificatePtr = root;

    // Now we should have full certificate chain.
    // If the end certificate is not ROOT CA we should disregard signature
    // but still signature must be valid... Aaaaaa it's so stupid...
    if (!(root->isSignedBy(root))) {
        LogWarning("Root CA certificate not found. Chain is incomplete.");
        context.allowBrokenChain = true;
    }

    // WAC 2.0 SP-2066 The wrt must not block widget installation
    // due to expiration of the author certificate.
    time_t nowTime = time(NULL);
#define CHECK_TIME
#ifdef CHECK_TIME

    ASN1_TIME* notAfterTime = data.getEndEntityCertificatePtr()->getNotAfterTime();
    ASN1_TIME* notBeforeTime = data.getEndEntityCertificatePtr()->getNotBeforeTime();

	if (data.isAuthorSignature())
	{
		if (X509_cmp_time(notBeforeTime, &nowTime) > 0)
		{
			LogDebug("notBeforeTime is greater then current time");
			return WrtSignatureValidator::SIGNATURE_INVALID;
		}

		if (X509_cmp_time(notAfterTime, &nowTime) < 0)
		{
			LogDebug("notAfterTime is less then current time");
			return WrtSignatureValidator::SIGNATURE_INVALID;
		}
	}
#endif

#if 0
    time_t notAfter = data.getEndEntityCertificatePtr()->getNotAfter();
    time_t notBefore = data.getEndEntityCertificatePtr()->getNotBefore();

	struct tm *t;

	if (data.isAuthorSignature())
	{
		// time_t 2038 year bug exist. So, notAtter() cann't check...
		/*
		if (notAfter < nowTime)
		{
			context.validationTime = notAfter - TIMET_DAY;
			LogWarning("Author certificate is expired. notAfter...");
		}
		*/

		if (notBefore > nowTime)
		{
			LogWarning("Author certificate is expired. notBefore time is greater than system-time.");

			t = localtime(&nowTime);
			LogDebug("System's current Year : " << t->tm_year + 1900);
			LogDebug("System's current month : " << t->tm_mon + 1);
			LogDebug("System's current day : " << t->tm_mday);

			t = localtime(&notBefore);
			LogDebug("Author certificate's notBefore Year : " << t->tm_year + 1900);
			LogDebug("Author certificate's notBefore month : " << t->tm_mon + 1);
			LogDebug("Author certificate's notBefore day : " << t->tm_mday);

			context.validationTime = notBefore + TIMET_DAY;

			t = localtime(&context.validationTime);
			LogDebug("Modified current Year : " << t->tm_year + 1900);
			LogDebug("Modified current notBefore month : " << t->tm_mon + 1);
			LogDebug("Modified current notBefore day : " << t->tm_mday);
		}
	}
#endif
    // WAC 2.0 SP-2066 The wrt must not block widget installation
	//context.allowBrokenChain = true;

	// end
    if (XmlSec::NO_ERROR != XmlSecSingleton::Instance().validate(&context)) {
        LogWarning("Installation break - invalid package!");
        return WrtSignatureValidator::SIGNATURE_INVALID;
    }

    data.setReference(context.referenceSet);

    if (!checkObjectReferences(data)) {
        return WrtSignatureValidator::SIGNATURE_INVALID;
    }

    ReferenceValidator fileValidator(widgetContentPath);
    if (ReferenceValidator::NO_ERROR != fileValidator.checkReferences(data)) {
        LogWarning("Invalid package - file references broken");
        return WrtSignatureValidator::SIGNATURE_INVALID;
    }

    // It is good time to do OCSP check
    // ocspCheck will throw an exception on any error.
    // TODO Probably we should catch this exception and add
    // some information to SignatureData.
    if (!m_complianceModeEnabled && !data.isAuthorSignature()) {
        CertificateCollection coll;
        coll.load(sortedCertificateList);

        if (!coll.sort()) {
            LogDebug("Collection does not contain chain!");
            return WrtSignatureValidator::SIGNATURE_INVALID;
        }

        CertificateVerifier verificator(m_ocspEnable, m_crlEnable);
        VerificationStatus result = verificator.check(coll);

        if (result == VERIFICATION_STATUS_REVOKED) {
            return WrtSignatureValidator::SIGNATURE_REVOKED;
        }

        if (result == VERIFICATION_STATUS_UNKNOWN ||
            result == VERIFICATION_STATUS_ERROR)
        {
            disregard = true;
        }
    }

    if (disregard) {
        LogWarning("Signature is disregard. RootCA is not a member of Tizen");
        return WrtSignatureValidator::SIGNATURE_DISREGARD;
    }
    return WrtSignatureValidator::SIGNATURE_VERIFIED;
}

class ImplWac : public WrtSignatureValidator::Impl
{
  public:
    WrtSignatureValidator::Result check(SignatureData &data,
            const std::string &widgetContentPath);

    explicit ImplWac(bool ocspEnable,
                     bool crlEnable,
                     bool complianceMode)
      : Impl(ocspEnable, crlEnable, complianceMode)
    {}

    virtual ~ImplWac() {}
};

WrtSignatureValidator::Result ImplWac::check(
    SignatureData &data,
    const std::string &widgetContentPath)
{
    bool disregard = false;

    if (!checkRoleURI(data)) {
        return WrtSignatureValidator::SIGNATURE_INVALID;
    }

    if (!checkProfileURI(data)) {
        return WrtSignatureValidator::SIGNATURE_INVALID;
    }

    //  CertificateList sortedCertificateList = data.getCertList();

    CertificateCollection collection;
    collection.load(data.getCertList());

    // First step - sort certificate
    if (!collection.sort()) {
        LogWarning("Certificates do not form valid chain.");
        return WrtSignatureValidator::SIGNATURE_INVALID;
    }

    // Check for error
    if (collection.empty()) {
        LogWarning("Certificate list in signature is empty.");
        return WrtSignatureValidator::SIGNATURE_INVALID;
    }

    CertificateList sortedCertificateList = collection.getChain();

    // TODO move it to CertificateCollection
    // Add root CA and CA certificates (if chain is incomplete)
    sortedCertificateList =
        OCSPCertMgrUtil::completeCertificateChain(sortedCertificateList);

    CertificatePtr root = sortedCertificateList.back();

    // Is Root CA certificate trusted?
    CertStoreId::Set storeIdSet = createCertificateIdentifier().find(root);

    LogDebug("Is root certificate from TIZEN_DEVELOPER domain:  "
        << storeIdSet.contains(CertStoreId::TIZEN_DEVELOPER));
    LogDebug("Is root certificate from TIZEN_TEST domain:  "
        << storeIdSet.contains(CertStoreId::TIZEN_TEST));
    LogDebug("Is root certificate from TIZEN_PUBLIC domain:  "
        << storeIdSet.contains(CertStoreId::VIS_PUBLIC));
    LogDebug("Is root certificate from TIZEN_PARTNER domain:  "
        << storeIdSet.contains(CertStoreId::VIS_PARTNER));
    LogDebug("Is root certificate from TIZEN_PLATFORM domain:  "
        << storeIdSet.contains(CertStoreId::VIS_PLATFORM));

    LogDebug("Visibility level is public :  "
        << storeIdSet.contains(CertStoreId::VIS_PUBLIC));
    LogDebug("Visibility level is partner :  "
        << storeIdSet.contains(CertStoreId::VIS_PARTNER));
	LogDebug("Visibility level is platform :  "
		<< storeIdSet.contains(CertStoreId::VIS_PLATFORM));

	if (data.isAuthorSignature())
	{
		if (!storeIdSet.contains(CertStoreId::TIZEN_DEVELOPER))
		{
            LogWarning("author-signature.xml has got unrecognized Root CA "
                       "certificate. Signature will be disregarded.");
            disregard = true;
		}
        LogDebug("Root CA for author signature is correct.");
	}
	else
	{
		LogDebug("signaturefile name = " <<  data.getSignatureFileName().c_str());
		if (data.getSignatureNumber() == 1)
		{
			if (storeIdSet.contains(CertStoreId::VIS_PUBLIC) || storeIdSet.contains(CertStoreId::VIS_PARTNER) || storeIdSet.contains(CertStoreId::VIS_PLATFORM))
			{
				LogDebug("Root CA for signature1.xml is correct.");
			}
			else
			{
				LogWarning("author-signature.xml has got unrecognized Root CA "
				        "certificate. Signature will be disregarded.");
				disregard = true;
			}
		}
	}

    data.setStorageType(storeIdSet);
    data.setSortedCertificateList(sortedCertificateList);

    // We add only Root CA certificate because WAC ensure that the rest
    // of certificates are present in signature files ;-)
    XmlSec::XmlSecContext context;
    context.signatureFile = data.getSignatureFileName();
    context.certificatePtr = root;

    // Now we should have full certificate chain.
    // If the end certificate is not ROOT CA we should disregard signature
    // but still signature must be valid... Aaaaaa it's so stupid...
    if (!(root->isSignedBy(root))) {
        LogWarning("Root CA certificate not found. Chain is incomplete.");
        context.allowBrokenChain = true;
    }

    time_t nowTime = time(NULL);
    // WAC 2.0 SP-2066 The wrt must not block widget installation
	// due to expiration of the author certificate.
#define CHECK_TIME
#ifdef CHECK_TIME

    ASN1_TIME* notAfterTime = data.getEndEntityCertificatePtr()->getNotAfterTime();
    ASN1_TIME* notBeforeTime = data.getEndEntityCertificatePtr()->getNotBeforeTime();

	if (data.isAuthorSignature())
	{
		if (X509_cmp_time(notBeforeTime, &nowTime) > 0)
		{
			LogDebug("notBeforeTime is greater then current time");
			return WrtSignatureValidator::SIGNATURE_INVALID;
		}

		if (X509_cmp_time(notAfterTime, &nowTime) < 0)
		{
			LogDebug("notAfterTime is less then current time");
			return WrtSignatureValidator::SIGNATURE_INVALID;
		}
	}
#endif

#if 0
	time_t notAfter = data.getEndEntityCertificatePtr()->getNotAfter();
	time_t notBefore = data.getEndEntityCertificatePtr()->getNotBefore();

	struct tm *t;

	if (data.isAuthorSignature())
	{
		// time_t 2038 year bug exist. So, notAtter() cann't check...
		/*
		if (notAfter < nowTime)
		{
			context.validationTime = notAfter - TIMET_DAY;
			LogWarning("Author certificate is expired. notAfter...");
		 }
		 */

		if (notBefore > nowTime)
		{
			LogWarning("Author certificate is expired. notBefore time is greater than system-time.");

			t = localtime(&nowTime);
			LogDebug("System's current Year : " << t->tm_year + 1900);
			LogDebug("System's current month : " << t->tm_mon + 1);
			LogDebug("System's current day : " << t->tm_mday);

			t = localtime(&notBefore);
			LogDebug("Author certificate's notBefore Year : " << t->tm_year + 1900);
			LogDebug("Author certificate's notBefore month : " << t->tm_mon + 1);
			LogDebug("Author certificate's notBefore day : " << t->tm_mday);

			context.validationTime = notBefore + TIMET_DAY;

			t = localtime(&context.validationTime);
			LogDebug("Modified current Year : " << t->tm_year + 1900);
			LogDebug("Modified current notBefore month : " << t->tm_mon + 1);
			LogDebug("Modified current notBefore day : " << t->tm_mday);
		}
	}
#endif
    if (XmlSec::NO_ERROR != XmlSecSingleton::Instance().validate(&context)) {
        LogWarning("Installation break - invalid package!");
        return WrtSignatureValidator::SIGNATURE_INVALID;
    }

    data.setReference(context.referenceSet);

    if (!checkObjectReferences(data)) {
        return WrtSignatureValidator::SIGNATURE_INVALID;
    }

    ReferenceValidator fileValidator(widgetContentPath);
    if (ReferenceValidator::NO_ERROR != fileValidator.checkReferences(data)) {
        LogWarning("Invalid package - file references broken");
        return WrtSignatureValidator::SIGNATURE_INVALID;
    }

    // It is good time to do OCSP check
    // ocspCheck will throw an exception on any error.
    // TODO Probably we should catch this exception and add
    // some information to SignatureData.
    if (!m_complianceModeEnabled && !data.isAuthorSignature()) {
        CertificateCollection coll;
        coll.load(sortedCertificateList);

        if (!coll.sort()) {
            LogDebug("Collection does not contain chain!");
            return WrtSignatureValidator::SIGNATURE_INVALID;
        }

        CertificateVerifier verificator(m_ocspEnable, m_crlEnable);
        VerificationStatus result = verificator.check(coll);

        if (result == VERIFICATION_STATUS_REVOKED) {
            return WrtSignatureValidator::SIGNATURE_REVOKED;
        }

        if (result == VERIFICATION_STATUS_UNKNOWN ||
            result == VERIFICATION_STATUS_ERROR)
        {
            disregard = true;
        }
    }

    if (disregard) {
        LogWarning("Signature is disregard. RootCA is not a member of Tizen.");
        return WrtSignatureValidator::SIGNATURE_DISREGARD;
    }
    return WrtSignatureValidator::SIGNATURE_VERIFIED;
}

// Implementation of WrtSignatureValidator

WrtSignatureValidator::WrtSignatureValidator(
    AppType appType,
    bool ocspEnable,
    bool crlEnable,
    bool complianceMode)
  : m_impl(0)
{
    if (appType == TIZEN)
        m_impl = new ImplTizen(ocspEnable,crlEnable,complianceMode);
    else
        m_impl = new ImplWac(ocspEnable,crlEnable,complianceMode);
}

WrtSignatureValidator::~WrtSignatureValidator() {
    delete m_impl;
}

WrtSignatureValidator::Result WrtSignatureValidator::check(
    SignatureData &data,
    const std::string &widgetContentPath)
{
    return m_impl->check(data, widgetContentPath);
}

} // namespace ValidationCore

