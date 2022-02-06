#define _DEFAULT_SOURCE
#ifndef _FILE_OFFSET_BITS
#define _FILE_OFFSET_BITS 64
#endif
#include <cstring>
#include <exception>
#include <stdexcept>
#include "Cert.hpp"

void NintendoData::ProcessCertChain(CertList& list, const void* certchain, size_t data_length) {
	try {
		while (data_length) {
			Cert* cert = new Cert(certchain, data_length);
			size_t size = cert->FullSize();
			certchain = (void*)(((u8*)certchain) + size);
			data_length -= size;
			list.emplace_back(cert);
		}
	} catch (...) {}
}

std::string NintendoData::Cert::GetFullIssuer() const {
	char buf[2][65];
	buf[0][64] = buf[1][64] = 0;
	memcpy(&buf[0][0], header->Issuer, 64);
	memcpy(&buf[1][0], header->Name, 64);
	return std::string(buf[0]) + '-' + buf[1];
}

NintendoData::Cert::Cert(const void* ptr, size_t ptrlen) {
	if(!ptr || ptrlen < 4) throw std::invalid_argument("Invalid Cert pointer");
	size_t minexpectedlen = sizeof(struct Header) - sizeof(union Header::PublicKey);
	size_t headeroffset;
	switch((enum SignatureType)Endian::Be((const u32*)ptr)) {
	case RSA_4096_SHA1:
	case RSA_4096_SHA256:
		minexpectedlen += 0x240u;
		headeroffset = 0x240u;
		break;
	case RSA_2048_SHA1:
	case RSA_2048_SHA256:
		minexpectedlen += 0x140u;
		headeroffset = 0x140u;
		break;
	case ECDSA_SHA1:
	case ECDSA_SHA256:
		minexpectedlen += 0x80u;
		headeroffset = 0x80u;
		break;
	default:
		throw std::invalid_argument("Invalid Cert Signature Type");
	}

	if(minexpectedlen > ptrlen) throw std::invalid_argument("Cert too small");

	const struct Header* tmp_header = (const struct Header*)&((const u8*)ptr)[headeroffset];

	switch(tmp_header->GetKeyType()) {
	case RSA_4096:
		minexpectedlen += sizeof(struct Header::PublicKey::RSA2048);
		break;
	case RSA_2048:
		minexpectedlen += sizeof(struct Header::PublicKey::RSA2048);
		break;
	case ECDSA:
		minexpectedlen += sizeof(struct Header::PublicKey::EC);
		break;
	default:
		throw std::invalid_argument("Invalid Cert Signature Type");
	}
	if(minexpectedlen > ptrlen) throw std::invalid_argument("Cert too small");

	rawcert = (u8*)calloc(minexpectedlen, 1);

	if(!rawcert) throw std::runtime_error("Can't allocate memory for Cert.");
	memcpy(rawcert, ptr, minexpectedlen);
	header = (struct Header*)&rawcert[headeroffset];
}

NintendoData::Cert::~Cert() {
	free(rawcert);
}
