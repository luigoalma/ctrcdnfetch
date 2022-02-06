#include <cstring>
#include <cstdlib>
#include <exception>
#include <stdexcept>
#include "TMD.hpp"
#include "types.h"

namespace {
	static ALIGN(4) u8 stub[2676] = {};
	struct stubbuilder {
		stubbuilder() {
			memset(stub, 0, sizeof(stub));
			*(u32*)&stub[0] = Endian::Be((u32)NintendoData::TMD::SignatureType::ECDSA_SHA1); //this just because its smaller, and its just a stub.
			((struct NintendoData::TMD::Header*)&stub[0x80])->ContentCount = Endian::Be((u16)1);
		}
	} builder;
}

NintendoData::TMD& NintendoData::TMD::operator=(const TMD& other) {
	if(this != &other) {
		if(!other.IsStubbed()) {
			size_t tmdlen = ((uptr)other.header - (uptr)other.rawtmd) + sizeof(struct Header) + 64u * sizeof(struct ContentInfoRecords) + other.GetContentCount() * sizeof(struct ContentChunkRecords);
			u8* tmp = (u8*)calloc(tmdlen, 1);
			if(!tmp) throw std::bad_alloc();
			this->~TMD();
			memcpy(tmp, other.rawtmd, tmdlen);
			this->rawtmd = tmp;
			this->header = (struct Header*)&this->rawtmd[(uptr)other.header - (uptr)other.rawtmd];
			this->inforecords = (struct ContentInfoRecords*)&this->rawtmd[((uptr)other.header - (uptr)other.rawtmd) + sizeof(struct Header)];
			this->chunkrecords = (struct ContentChunkRecords*)&this->rawtmd[((uptr)other.header - (uptr)other.rawtmd) + sizeof(struct Header) + sizeof(struct ContentInfoRecords)*64];
		} else this->~TMD();
	}
	return *this;
}

NintendoData::TMD& NintendoData::TMD::operator=(TMD&& other) {
	if(this != &other) {
		if(!other.IsStubbed()) {
			this->~TMD();
			this->rawtmd = other.rawtmd;
			this->header = other.header;
			this->inforecords = other.inforecords;
			this->chunkrecords = other.chunkrecords;
			other.rawtmd = stub;
			other.header = (struct Header*)&stub[0x80];
			other.inforecords = (struct ContentInfoRecords*)&stub[0x80 + sizeof(struct Header)];
			other.chunkrecords = (struct ContentChunkRecords*)&stub[0x80 + sizeof(struct Header) + sizeof(struct ContentInfoRecords)*64];
		} else this->~TMD();
	}
	return *this;
}

bool NintendoData::TMD::IsStubbed() const {
	return rawtmd == stub;
}

NintendoData::TMD::TMD() {
	rawtmd = stub;
	header = (struct Header*)&stub[0x80];
	inforecords = (struct ContentInfoRecords*)&stub[0x80 + sizeof(struct Header)];
	chunkrecords = (struct ContentChunkRecords*)&stub[0x80 + sizeof(struct Header) + sizeof(struct ContentInfoRecords)*64];
}

NintendoData::TMD::TMD(const void* ptr, size_t ptrlen) {
	if(!ptr || ptrlen < 4) throw std::invalid_argument("Invalid TMD pointer.");
	size_t minexpectedlen = sizeof(struct Header) + sizeof(struct ContentInfoRecords)*64;
	size_t headeroffset;
	//attempt at future-proofing in the events tmds lose their signature type consistency
	switch((enum SignatureType)Endian::Be((const u32*)ptr)) {
	case SignatureType::RSA_4096_SHA1:
	case SignatureType::RSA_4096_SHA256:
		minexpectedlen += 0x240u;
		headeroffset = 0x240u;
		break;
	case SignatureType::RSA_2048_SHA1:
	case SignatureType::RSA_2048_SHA256:
		minexpectedlen += 0x140u;
		headeroffset = 0x140u;
		break;
	case SignatureType::ECDSA_SHA1:
	case SignatureType::ECDSA_SHA256:
		minexpectedlen += 0x80u;
		headeroffset = 0x80u;
		break;
	default:
		throw std::invalid_argument("Invalid TMD Signature Type");
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

NintendoData::TMD::~TMD() {
	if(!IsStubbed()) {
		free(rawtmd);
		rawtmd = stub;
		header = (struct Header*)&stub[0x80];
		inforecords = (struct ContentInfoRecords*)&stub[0x80 + sizeof(struct Header)];
		chunkrecords = (struct ContentChunkRecords*)&stub[0x80 + sizeof(struct Header) + sizeof(struct ContentInfoRecords)*64];
	}
}
