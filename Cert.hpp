#pragma once
#include <memory>
#include <vector>
#include <string>
#include <cstddef>
#include <string>
#include "Endian.hpp"
#include "types.h"

namespace NintendoData {
	class Cert {
	public:
		enum SignatureType : u32 {
			RSA_4096_SHA1 = 0x10000,
			RSA_2048_SHA1,
			ECDSA_SHA1,
			RSA_4096_SHA256,
			RSA_2048_SHA256,
			ECDSA_SHA256
		};
		enum PublicKeyType : u32 {
			RSA_4096 = 0,
			RSA_2048,
			ECDSA
		};
		#pragma pack(push,1)
		struct Header {
			char Issuer[64];
			u32 Type;
			char Name[64];
			u32 Unknown;
			union PublicKey {
				struct RSA4096 {
					u8 Modulus[0x200];
					u32 PublicExponent;
					u8 Padding[0x34];
				} RSA4096;
				struct RSA2048 {
					u8 Modulus[0x100];
					u32 PublicExponent;
					u8 Padding[0x34];
				} RSA2048;
				struct EC {
					u8 Key[0x3C];
					u8 Padding[0x3C];
				} EC;
			} PublicKey;
			#pragma pack(pop)
			enum PublicKeyType GetKeyType() const {return (enum PublicKeyType)Endian::Be(Type);}
			u32 GetPublicExponent() const {
				u32 ret = 0;
				switch(GetKeyType()) {
				case RSA_4096:
					ret = Endian::Be(PublicKey.RSA4096.PublicExponent);
					break;
				case RSA_2048:
					ret = Endian::Be(PublicKey.RSA2048.PublicExponent);
					break;
				case ECDSA: //ECDSA doesn't have exponent
				default:
					break;
				}
				return ret;
			}
			size_t GetKeyLength() const {return (GetKeyType() == RSA_4096 ? 0x200 : (GetKeyType() == RSA_2048 ? 0x100 : 0x3C));}
			size_t FullSize() const {
				size_t size = sizeof(struct Header) - sizeof(union Header::PublicKey);
				switch(GetKeyType()) {
				case RSA_4096:
					size += sizeof(struct Header::PublicKey::RSA4096);
					break;
				case RSA_2048:
					size += sizeof(struct Header::PublicKey::RSA2048);
					break;
				case ECDSA: //ECDSA doesn't have exponent
					size += sizeof(struct Header::PublicKey::EC);
					break;
				}
				return size;
			}
		};
	private:
		u8* rawcert;
		struct Header* header;
	public:
		const struct Header &GetHeader() const {return *header;}
		enum PublicKeyType KeyType() const {return header->GetKeyType();}
		u32 PublicExponent() const {return header->GetPublicExponent();}
		static size_t MaxCertSize() {return 0x500u;}
		size_t FullSize() const {
			return (uptr)header - (uptr)rawcert + header->FullSize();
		}
		std::string GetFullIssuer() const;
		Cert(const void* ptr, size_t ptrlen);
		~Cert();
	};
	typedef std::vector<std::shared_ptr<Cert>> CertList;
	void ProcessCertChain(CertList& list, const void* certchain, size_t data_length);
}
