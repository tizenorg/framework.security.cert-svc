/*
 * Copyright (c) 2015 Samsung Electronics Co., Ltd All Rights Reserved
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
 * @file        verify-signature.cpp
 * @author      Kyungwook Tak (k.tak@samsung.com)
 * @version     1.0
 * @brief       verify signature API test for tpk type app
 */

#include <unistd.h>
#include <iostream>
#include <string>
#include <vector>

#include <glib.h>
#include <dpl/test/test_runner.h>

/* just for extract cert data from signature */
#include "vcore/Certificate.h"
#include "vcore/CertificateCollection.h"
#include "vcore/ParserSchema.h"
#include "vcore/SignatureReader.h"
#include "vcore/SignatureData.h"
#include "vcore/SignatureValidator.h"

#include <cert-service.h>

namespace {

const std::string SCHEMA_PATH("/usr/share/wrt-engine/schema.xsd");

const std::string NORMAL_TPK_DECOMPRESSED_DIR("/opt/apps/tpk/tests/verify-sig-tpk/normal-tpk/");
const std::string ATTACKED_TPK_DECOMPRESSED_DIR("/opt/apps/tpk/tests/verify-sig-tpk/attacked-tpk/");
const std::string NORMAL_TPK_DECOMPRESSED_WITH_USERDATA_DIR("/opt/apps/tpk/tests/verify-sig-tpk/normal-tpk-with-userdata/");
const std::string ATTACKED_TPK_DECOMPRESSED_WITH_USERDATA_DIR("/opt/apps/tpk/tests/verify-sig-tpk/attacked-tpk-with-userdata/");

std::vector<std::string> REF_LIST_ITEMS = {
	std::string("author-signature.xml"),
	std::string("bin/preference"),
	std::string("res/edje/pref_buttons_panel.edj"),
	std::string("res/edje/pref_edit_panel.edj"),
	std::string("res/edje/preference.edj"),
	std::string("res/images/icon_delete.png"),
	std::string("res/res.xml"),
	std::string("shared/res/preference.png"),
	std::string("tizen-manifest.xml")
};

std::vector<std::string> REF_LIST_ITEMS_WITH_MALFILE = {
	std::string("author-signature.xml"),
	std::string("bin/preference"),
	std::string("res/edje/pref_buttons_panel.edj"),
	std::string("res/edje/pref_edit_panel.edj"),
	std::string("res/edje/preference.edj"),
	std::string("res/images/icon_delete.png"),
	std::string("res/res.xml"),
	std::string("shared/res/preference.png"),
	std::string("tizen-manifest.xml"),
	std::string("malfile")
};

} // namespace anonymous

namespace ValidationCore {

RUNNER_TEST_GROUP_INIT(T01_VERIFY_SIGNATURE);

/*
 *  core tpk app install step in rpm-installer
 *
 *  1 unzip on app dir
 *  2 find signature xml file
 *  3 parse signature xml file
 *    - extract two certs (author, intermediate) from signature
 *    - push certs to cert svc context
 *  4 call cert_svc_verify_certificate to verify
 *    - root ca cert is pushed in cert svc context automatically here
 *  5 call cert_svc_get_visibility to get visibility of app
 */

RUNNER_TEST(T0101_verify_signature_positive)
{
	try {
		std::string sigfileFullpath = NORMAL_TPK_DECOMPRESSED_DIR + "signature1.xml";

		SignatureData data(sigfileFullpath, 1);
		SignatureReader reader;
		CertificateCollection collection;

		reader.initialize(data, SCHEMA_PATH.c_str());
		reader.read(data);

		collection.load(data.getCertList());
		RUNNER_ASSERT_MSG(collection.sort(), "failed to certs sort in signature");
		RUNNER_ASSERT_MSG(
			collection.size() == 2,
			"certs size in signature should be 2 : " << collection.size());
		CertificateList certList = collection.getCertificateList();

		CertificateList::iterator it = certList.begin();
		CertificatePtr firstCertPtr = *it;
		it++;
		CertificatePtr secondCertPtr = *it;

		unsigned char *cert1 = new unsigned char[firstCertPtr->getBase64().length() + 1];
		unsigned char *cert2 = new unsigned char[secondCertPtr->getBase64().length() + 1];

		memcpy(cert1, firstCertPtr->getBase64().c_str(), firstCertPtr->getBase64().length() + 1);
		memcpy(cert2, secondCertPtr->getBase64().c_str(), secondCertPtr->getBase64().length() + 1);

		CERT_CONTEXT *ctx = cert_svc_cert_context_init();

		int ret = cert_svc_load_buf_to_context(ctx, cert1);

		RUNNER_ASSERT_MSG(
			ret == CERT_SVC_ERR_NO_ERROR,
			"failed to load buf to context. ret : " << ret);

		ret = cert_svc_push_buf_into_context(ctx, cert2);
		RUNNER_ASSERT_MSG(
			ret == CERT_SVC_ERR_NO_ERROR,
			"failed to push buf to context. ret : " << ret);

		int validity = 0;
		ret = cert_svc_verify_certificate(ctx, &validity);
		RUNNER_ASSERT_MSG(
			ret == CERT_SVC_ERR_NO_ERROR,
			"failed to verify certificate. ret : " << ret);
		RUNNER_ASSERT_MSG(
			validity == 1,
			"certificate is invalid from verify_certificate. validity : " << validity);

		std::string filename(ctx->fileNames->filename);
		cert_svc_cert_context_final(ctx);

		ret = cert_svc_verify_package_signature_file(
				sigfileFullpath.c_str(),
				filename.c_str());
		RUNNER_ASSERT_MSG(
			ret == CERT_SVC_ERR_NO_ERROR,
			"failed to verify package signature file. ret : " << ret);

		delete []cert1;
		delete []cert2;

	} catch (Certificate::Exception::Base &e) {
		RUNNER_ASSERT_MSG(0, e.DumpToString());
	} catch (SignatureReader::Exception::Base &e) {
		RUNNER_ASSERT_MSG(0, e.DumpToString());
	} catch (CertificateCollection::Exception::Base &e) {
		RUNNER_ASSERT_MSG(0, e.DumpToString());
	} catch (ParserSchemaException::Base &e) {
		RUNNER_ASSERT_MSG(0, e.DumpToString());
	} catch (std::exception &e) {
		RUNNER_ASSERT_MSG(0, "std::exception occured : " << e.what());
	}
}

RUNNER_TEST(T0102_verify_signature_negative)
{
	try {
		std::string sigfileFullpath = ATTACKED_TPK_DECOMPRESSED_DIR + "signature1.xml";
		SignatureData data(sigfileFullpath, 1);
		SignatureReader reader;
		CertificateCollection collection;

		reader.initialize(data, SCHEMA_PATH.c_str());
		reader.read(data);

		collection.load(data.getCertList());
		RUNNER_ASSERT_MSG(collection.sort(), "failed to certs sort in signature");
		RUNNER_ASSERT_MSG(
			collection.size() == 2,
			"certs size in signature should be 2 : " << collection.size());
		CertificateList certList = collection.getCertificateList();

		CertificateList::iterator it = certList.begin();
		CertificatePtr firstCertPtr = *it;
		it++;
		CertificatePtr secondCertPtr = *it;

		unsigned char *cert1 = new unsigned char[firstCertPtr->getBase64().length() + 1];
		unsigned char *cert2 = new unsigned char[secondCertPtr->getBase64().length() + 1];

		memcpy(cert1, firstCertPtr->getBase64().c_str(), firstCertPtr->getBase64().length() + 1);
		memcpy(cert2, secondCertPtr->getBase64().c_str(), secondCertPtr->getBase64().length() + 1);

		CERT_CONTEXT *ctx = cert_svc_cert_context_init();

		int ret = cert_svc_load_buf_to_context(ctx, cert1);

		RUNNER_ASSERT_MSG(
			ret == CERT_SVC_ERR_NO_ERROR,
			"failed to load buf to context. ret : " << ret);

		ret = cert_svc_push_buf_into_context(ctx, cert2);
		RUNNER_ASSERT_MSG(
			ret == CERT_SVC_ERR_NO_ERROR,
			"failed to push buf to context. ret : " << ret);

		int validity = 0;
		ret = cert_svc_verify_certificate(ctx, &validity);
		RUNNER_ASSERT_MSG(
			ret == CERT_SVC_ERR_NO_ERROR,
			"failed to verify certificate. ret : " << ret);
		RUNNER_ASSERT_MSG(
			validity == 1,
			"certificate is invalid from verify_certificate. validity : " << validity);

		std::string filename(ctx->fileNames->filename);
		cert_svc_cert_context_final(ctx);

		ret = cert_svc_verify_package_signature_file(
				sigfileFullpath.c_str(),
				filename.c_str());
		RUNNER_ASSERT_MSG(
			ret == CERT_SVC_ERR_INVALID_SIGNATURE,
			"verify package signature file *should be* failed. ret : " << ret);

		delete []cert1;
		delete []cert2;

	} catch (Certificate::Exception::Base &e) {
		RUNNER_ASSERT_MSG(0, e.DumpToString());
	} catch (SignatureReader::Exception::Base &e) {
		RUNNER_ASSERT_MSG(0, e.DumpToString());
	} catch (CertificateCollection::Exception::Base &e) {
		RUNNER_ASSERT_MSG(0, e.DumpToString());
	} catch (ParserSchemaException::Base &e) {
		RUNNER_ASSERT_MSG(0, e.DumpToString());
	} catch (std::exception &e) {
		RUNNER_ASSERT_MSG(0, "std::exception occured : " << e.what());
	}
}

RUNNER_TEST(T0103_verify_signature_with_references_positive)
{
	try {
		std::string sigfileFullpath = NORMAL_TPK_DECOMPRESSED_WITH_USERDATA_DIR + "signature1.xml";
		SignatureData data(sigfileFullpath, 1);
		SignatureReader reader;
		CertificateCollection collection;

		reader.initialize(data, SCHEMA_PATH.c_str());
		reader.read(data);

		collection.load(data.getCertList());
		RUNNER_ASSERT_MSG(collection.sort(), "failed to certs sort in signature");
		RUNNER_ASSERT_MSG(
			collection.size() == 2,
			"certs size in signature should be 2 : " << collection.size());
		CertificateList certList = collection.getCertificateList();

		CertificateList::iterator it = certList.begin();
		CertificatePtr firstCertPtr = *it;
		it++;
		CertificatePtr secondCertPtr = *it;

		unsigned char *cert1 = new unsigned char[firstCertPtr->getBase64().length() + 1];
		unsigned char *cert2 = new unsigned char[secondCertPtr->getBase64().length() + 1];

		memcpy(cert1, firstCertPtr->getBase64().c_str(), firstCertPtr->getBase64().length() + 1);
		memcpy(cert2, secondCertPtr->getBase64().c_str(), secondCertPtr->getBase64().length() + 1);

		CERT_CONTEXT *ctx = cert_svc_cert_context_init();

		int ret = cert_svc_load_buf_to_context(ctx, cert1);

		RUNNER_ASSERT_MSG(
			ret == CERT_SVC_ERR_NO_ERROR,
			"failed to load buf to context. ret : " << ret);

		ret = cert_svc_push_buf_into_context(ctx, cert2);
		RUNNER_ASSERT_MSG(
			ret == CERT_SVC_ERR_NO_ERROR,
			"failed to push buf to context. ret : " << ret);

		int validity = 0;
		ret = cert_svc_verify_certificate(ctx, &validity);
		RUNNER_ASSERT_MSG(
			ret == CERT_SVC_ERR_NO_ERROR,
			"failed to verify certificate. ret : " << ret);
		RUNNER_ASSERT_MSG(
			validity == 1,
			"certificate is invalid from verify_certificate. validity : " << validity);

		std::string filename(ctx->fileNames->filename);
		cert_svc_cert_context_final(ctx);

		GList *refList = new GList[REF_LIST_ITEMS.size()];
		size_t refListIdx = 0;

		for (auto &item : REF_LIST_ITEMS) {
			refList[refListIdx].data = const_cast<char *>(item.c_str());

			if (refListIdx > 0)
				refList[refListIdx].prev = &refList[refListIdx - 1];
			else
				refList[refListIdx].prev = NULL;

			if (refListIdx < REF_LIST_ITEMS.size() - 1)
				refList[refListIdx].next = &refList[refListIdx + 1];
			else
				refList[refListIdx].next = NULL;

			refListIdx++;
		}

		ret = cert_svc_verify_package_signature_with_references(
				sigfileFullpath.c_str(),
				filename.c_str(),
				refList);

		delete []refList;

		RUNNER_ASSERT_MSG(
			ret == CERT_SVC_ERR_NO_ERROR,
			"verify package signature file with references failed. ret : " << ret);

		delete []cert1;
		delete []cert2;

	} catch (Certificate::Exception::Base &e) {
		RUNNER_ASSERT_MSG(0, e.DumpToString());
	} catch (SignatureReader::Exception::Base &e) {
		RUNNER_ASSERT_MSG(0, e.DumpToString());
	} catch (CertificateCollection::Exception::Base &e) {
		RUNNER_ASSERT_MSG(0, e.DumpToString());
	} catch (ParserSchemaException::Base &e) {
		RUNNER_ASSERT_MSG(0, e.DumpToString());
	} catch (std::exception &e) {
		RUNNER_ASSERT_MSG(0, "std::exception occured : " << e.what());
	}
}

RUNNER_TEST(T0104_verify_signature_with_references_negative)
{
	try {
		std::string sigfileFullpath = ATTACKED_TPK_DECOMPRESSED_WITH_USERDATA_DIR + "signature1.xml";
		SignatureData data(sigfileFullpath, 1);
		SignatureReader reader;
		CertificateCollection collection;

		reader.initialize(data, SCHEMA_PATH.c_str());
		reader.read(data);

		collection.load(data.getCertList());
		RUNNER_ASSERT_MSG(collection.sort(), "failed to certs sort in signature");
		RUNNER_ASSERT_MSG(
			collection.size() == 2,
			"certs size in signature should be 2 : " << collection.size());
		CertificateList certList = collection.getCertificateList();

		CertificateList::iterator it = certList.begin();
		CertificatePtr firstCertPtr = *it;
		it++;
		CertificatePtr secondCertPtr = *it;

		unsigned char *cert1 = new unsigned char[firstCertPtr->getBase64().length() + 1];
		unsigned char *cert2 = new unsigned char[secondCertPtr->getBase64().length() + 1];

		memcpy(cert1, firstCertPtr->getBase64().c_str(), firstCertPtr->getBase64().length() + 1);
		memcpy(cert2, secondCertPtr->getBase64().c_str(), secondCertPtr->getBase64().length() + 1);

		CERT_CONTEXT *ctx = cert_svc_cert_context_init();

		int ret = cert_svc_load_buf_to_context(ctx, cert1);

		RUNNER_ASSERT_MSG(
			ret == CERT_SVC_ERR_NO_ERROR,
			"failed to load buf to context. ret : " << ret);

		ret = cert_svc_push_buf_into_context(ctx, cert2);
		RUNNER_ASSERT_MSG(
			ret == CERT_SVC_ERR_NO_ERROR,
			"failed to push buf to context. ret : " << ret);

		int validity = 0;
		ret = cert_svc_verify_certificate(ctx, &validity);
		RUNNER_ASSERT_MSG(
			ret == CERT_SVC_ERR_NO_ERROR,
			"failed to verify certificate. ret : " << ret);
		RUNNER_ASSERT_MSG(
			validity == 1,
			"certificate is invalid from verify_certificate. validity : " << validity);

		std::string filename(ctx->fileNames->filename);
		cert_svc_cert_context_final(ctx);

		GList *refList = new GList[REF_LIST_ITEMS_WITH_MALFILE.size()];
		size_t refListIdx = 0;

		for (auto &item : REF_LIST_ITEMS_WITH_MALFILE) {
			refList[refListIdx].data = const_cast<char *>(item.c_str());

			if (refListIdx > 0)
				refList[refListIdx].prev = &refList[refListIdx - 1];
			else
				refList[refListIdx].prev = NULL;

			if (refListIdx < REF_LIST_ITEMS_WITH_MALFILE.size() - 1)
				refList[refListIdx].next = &refList[refListIdx + 1];
			else
				refList[refListIdx].next = NULL;

			refListIdx++;
		}

		ret = cert_svc_verify_package_signature_with_references(
				sigfileFullpath.c_str(),
				filename.c_str(),
				refList);

		delete []refList;

		RUNNER_ASSERT_MSG(
			ret == CERT_SVC_ERR_INVALID_SIGNATURE,
			"verify package signature with references *should be* failed. ret : " << ret);

		delete []cert1;
		delete []cert2;

	} catch (Certificate::Exception::Base &e) {
		RUNNER_ASSERT_MSG(0, e.DumpToString());
	} catch (SignatureReader::Exception::Base &e) {
		RUNNER_ASSERT_MSG(0, e.DumpToString());
	} catch (CertificateCollection::Exception::Base &e) {
		RUNNER_ASSERT_MSG(0, e.DumpToString());
	} catch (ParserSchemaException::Base &e) {
		RUNNER_ASSERT_MSG(0, e.DumpToString());
	} catch (std::exception &e) {
		RUNNER_ASSERT_MSG(0, "std::exception occured : " << e.what());
	}
}

}
