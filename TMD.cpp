#include <cstring>
#include <cstdlib>
#include <exception>
#include <stdexcept>
#include "TMD.hpp"

NintendoData::TMD::TMD(const void* ptr, size_t ptrlen) {
	if(!ptr || ptrlen < 4) throw std::invalid_argument("Invalid pointer.");
	size_t minexpectedlen = sizeof(struct Header) + sizeof(struct ContentInfoRecords)*64;
	size_t headeroffset;
	//attempt at future-proofing in the events tmds lose their signature type consistency
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
		throw std::invalid_argument("Invalid Signature Type");
	}
	if(sizeof(struct Header) + headeroffset > ptrlen) throw std::invalid_argument("TMD too small");
	u16 ContentCount = Endian::Be(((const struct Header*)&((const u8*)ptr)[headeroffset])->ContentCount);
	if(!ContentCount) throw std::invalid_argument("TMD has no contents?");
	minexpectedlen += sizeof(struct ContentChunkRecords) * ContentCount;
	if(minexpectedlen > ptrlen) throw std::invalid_argument("TMD too small"); //otherwise, any extra data after would be cert data
	rawtmd = (u8*)calloc(minexpectedlen, 1);
	if(!rawtmd) throw std::runtime_error("Can't allocate memory for TMD.");
	memcpy(rawtmd, ptr, minexpectedlen);
	header = (struct Header*)&rawtmd[headeroffset];
	inforecords = (struct ContentInfoRecords*)&rawtmd[headeroffset + sizeof(struct Header)];
	chunkrecords = (struct ContentChunkRecords*)&rawtmd[headeroffset + sizeof(struct Header) + sizeof(struct ContentInfoRecords)*64];
}

NintendoData::TMD::~TMD() noexcept {
	free(rawtmd);
}
