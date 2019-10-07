#define _DEFAULT_SOURCE
#ifndef _FILE_OFFSET_BITS
#define _FILE_OFFSET_BITS 64
#endif
#include <cstdio>
#include <cstring>
#include <mutex>
#include <algorithm>
#include <utility>
#include <new>
#include <openssl/sha.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include "SharedStorage.hpp"
#include "Keys.hpp"
#include "Endian.hpp"

namespace {
	static std::recursive_mutex readwritelock;
	static bool loaded = false;
	namespace Retail {
		static u8 KeyXs[8][16] = {};
		static u8 KeyYs[8][16] = {};
		static u8 KeyNormals[20][16] = {};
		static u8 CommonKey0[16] = {};
		static u8 NCCHKeys[3][16] = {};
		namespace SHA1Checksums {
			const static u8 KeyXs[8][20] = {
				{0x54, 0x70, 0x16, 0x86, 0x28, 0x3A, 0x18, 0xCA, 0x54, 0xFF, 0x76, 0xB6, 0x91, 0x0C, 0x49, 0xDE, 0xC2, 0xD6, 0xCF, 0x13}, //0x2C to 0x2F
				{0x00, 0x2B, 0xFC, 0x02, 0x27, 0xB7, 0x78, 0x30, 0xD6, 0x3E, 0x83, 0x6B, 0xA7, 0xCA, 0x7D, 0x1A, 0x94, 0x12, 0x7B, 0x18}, //0x30 to 0x33
				{0xDA, 0xAF, 0x39, 0xF4, 0x83, 0x25, 0x83, 0x6F, 0xA1, 0x72, 0x73, 0xF2, 0x78, 0x8B, 0x63, 0x21, 0x8C, 0x00, 0xCB, 0x42}, //0x34 to 0x37
				{0xCD, 0x40, 0x80, 0x1B, 0xB3, 0x4B, 0x8A, 0x9F, 0xE5, 0xBD, 0x58, 0xAD, 0x60, 0x47, 0x1F, 0x6B, 0x88, 0x76, 0x4C, 0x57}, //0x38 to 0x3B
				{0x5C, 0x7F, 0x64, 0xD4, 0xAB, 0x7A, 0xDF, 0xE1, 0x91, 0x05, 0x68, 0x8D, 0x57, 0xB2, 0xBA, 0xAC, 0x52, 0x2A, 0xCE, 0xB7}, //0x3C
				{0x6E, 0x46, 0x09, 0x5C, 0x58, 0x41, 0x3F, 0xC0, 0x8B, 0x54, 0xA8, 0x18, 0x1A, 0x06, 0xBE, 0xDA, 0xEC, 0x00, 0x64, 0xEA}, //0x3D
				{0x3E, 0xC4, 0xF5, 0x2F, 0x27, 0x1C, 0xE4, 0xD6, 0x7F, 0xD1, 0x99, 0x6F, 0xFA, 0x2F, 0x5C, 0xF1, 0xB8, 0x6A, 0x25, 0xE3}, //0x3E
				{0x54, 0xC5, 0x48, 0xD9, 0x21, 0x53, 0xA8, 0x6A, 0xB6, 0xDD, 0x08, 0x6B, 0x82, 0x27, 0x5D, 0x7D, 0x6E, 0x50, 0xB4, 0xB1}  //0x3F
			};
			const static u8 KeyYs[8][20] = {
				{0xEF, 0xCB, 0x89, 0x44, 0x9C, 0x66, 0x72, 0x63, 0x14, 0xF2, 0x0A, 0xE7, 0x77, 0xF7, 0x88, 0x25, 0x45, 0xC4, 0x52, 0x60}, //0x4
				{0x7E, 0x08, 0x93, 0x40, 0x58, 0xB7, 0x00, 0x10, 0xEF, 0x52, 0xCF, 0xE3, 0xEA, 0x64, 0x4A, 0x63, 0xED, 0x6F, 0xA7, 0xE9}, //0x5
				{0xBB, 0x91, 0xFF, 0xF9, 0xEE, 0x77, 0x07, 0x28, 0x25, 0x0C, 0x1F, 0xB3, 0xB4, 0x60, 0x48, 0x12, 0x49, 0x92, 0xB0, 0xF1}, //0x6
				{0x95, 0x41, 0xBC, 0x87, 0xA1, 0x8F, 0xE0, 0xD7, 0x35, 0xF3, 0x50, 0x25, 0xEE, 0xCF, 0x2F, 0x0F, 0xE9, 0x65, 0xF2, 0xF4}, //0x7
				{0x67, 0x3B, 0x82, 0x65, 0xFA, 0x9D, 0xE3, 0x85, 0x83, 0xEA, 0xEF, 0x24, 0xCF, 0xF5, 0xAE, 0x22, 0x33, 0x85, 0xC0, 0x4F}, //0x8
				{0x60, 0xD3, 0x7E, 0xD8, 0x19, 0xD1, 0xFC, 0xD7, 0xE1, 0x06, 0x45, 0xD3, 0x8C, 0xF3, 0xEA, 0x33, 0x9B, 0xFC, 0x1B, 0x14}, //0x9
				{0x03, 0xCC, 0xD8, 0x20, 0xF1, 0xDC, 0x75, 0xA2, 0x10, 0xDE, 0xD6, 0x35, 0x90, 0xA5, 0x30, 0x8E, 0x88, 0x53, 0xFB, 0x0A}, //0xA
				{0xCC, 0x45, 0xD8, 0x77, 0x87, 0x36, 0xD5, 0xB2, 0x27, 0x38, 0x1F, 0x10, 0x65, 0x12, 0x93, 0x2C, 0x25, 0xA0, 0x42, 0x01}  //0xB
			};
			const static u8 KeyNormals[20][20] = {
				{0x80, 0xB9, 0xE5, 0x19, 0xA0, 0x99, 0x0E, 0x38, 0x6B, 0xF8, 0x4F, 0xB9, 0xAE, 0x01, 0xDA, 0x48, 0x8C, 0xA7, 0x5B, 0xBC}, //0xC-0xF
				{0x2B, 0x72, 0x27, 0x63, 0x70, 0x04, 0xD6, 0x08, 0x52, 0x4D, 0xC5, 0x8F, 0x57, 0x69, 0x9A, 0xA4, 0xF8, 0x52, 0x73, 0xD2}, //0x10-0x13
				{0x9C, 0x7A, 0x42, 0x72, 0x91, 0x1B, 0xB6, 0xCC, 0x71, 0x9F, 0x40, 0x90, 0xEB, 0xC2, 0xB0, 0x12, 0x9A, 0x86, 0x73, 0xAD}, //0x14
				{0xFF, 0xBA, 0xD8, 0x55, 0xAA, 0x5E, 0xF3, 0x88, 0x11, 0x9F, 0xEA, 0x2F, 0x68, 0x8D, 0xB4, 0xA5, 0x3C, 0x03, 0xBF, 0x3B}, //0x15
				{0x2E, 0x02, 0xEF, 0xDA, 0x52, 0x8B, 0x68, 0x98, 0x0B, 0x75, 0xB1, 0xD9, 0x7C, 0x31, 0x20, 0xFF, 0x84, 0xFC, 0x8C, 0x61}, //0x16
				{0x66, 0xB2, 0x96, 0x5A, 0x72, 0x12, 0xA3, 0xD8, 0xAB, 0x28, 0x72, 0xFC, 0x14, 0xDC, 0x46, 0xBB, 0xC5, 0x0A, 0xC8, 0x86}, //0x17
				{0x4A, 0xA4, 0x3F, 0x63, 0xF7, 0xEC, 0x2C, 0x6C, 0xFD, 0xF0, 0xD2, 0x80, 0x61, 0xB6, 0x0E, 0xFE, 0xFE, 0x8C, 0x8D, 0xC5}, //0x18-0x1B
				{0x0D, 0x25, 0x38, 0x3A, 0x5D, 0x0D, 0xDF, 0x2C, 0xF6, 0x7A, 0xD6, 0xD1, 0xB7, 0xF5, 0x6F, 0x79, 0x4E, 0x33, 0x3E, 0xB8}, //0x1C-0x1F
				{0x21, 0x1A, 0x66, 0xF4, 0xF0, 0x42, 0xCC, 0xA0, 0x0E, 0xAC, 0x94, 0xB9, 0x7F, 0xDF, 0xDB, 0xF0, 0xCD, 0xD0, 0xCB, 0x12}, //0x20-0x23
				{0x1F, 0xFD, 0x76, 0x04, 0x44, 0x4A, 0x90, 0x0C, 0x89, 0x18, 0xF9, 0xB9, 0x9E, 0x36, 0x6A, 0xCC, 0x8F, 0xDC, 0x13, 0xEE}, //0x24-0x28
				{0xAB, 0x24, 0xD5, 0x3E, 0xE2, 0x1F, 0x68, 0xDC, 0x18, 0x91, 0x69, 0x9A, 0x99, 0xB2, 0x14, 0x69, 0x56, 0xF2, 0xAE, 0x48}, //0x29
				{0x4F, 0x66, 0xF7, 0x5E, 0x78, 0xFE, 0x1A, 0x70, 0x07, 0xFA, 0x97, 0xCF, 0x6D, 0x36, 0x28, 0xC2, 0xC7, 0x00, 0x78, 0x3B}, //0x2A
				{0x5B, 0xC5, 0xCA, 0x60, 0x2B, 0x5A, 0x44, 0x68, 0x4E, 0x27, 0xFC, 0x61, 0xA4, 0x68, 0x57, 0xBE, 0xFF, 0xFE, 0x82, 0xED}, //0x2B
				{0x55, 0x68, 0x3F, 0xD3, 0xF0, 0x54, 0x64, 0xF2, 0x44, 0xEA, 0x74, 0x7F, 0xC9, 0x7F, 0x02, 0x24, 0xC0, 0x28, 0xC6, 0x63}, //0x2C-0x2F
				{0xE2, 0x01, 0x2D, 0xD5, 0xEC, 0x53, 0x80, 0x12, 0x39, 0x5E, 0x42, 0x07, 0x92, 0x4F, 0x0E, 0xD1, 0x77, 0x7A, 0x40, 0x98}, //0x30-0x33
				{0xB3, 0xEB, 0x14, 0x1C, 0xD7, 0xE8, 0x10, 0xF1, 0x53, 0xC3, 0xAB, 0xA6, 0x72, 0x3F, 0x5A, 0x6C, 0x49, 0xFB, 0x50, 0x6E}, //0x34-0x37
				{0xC0, 0x42, 0x58, 0x9F, 0x1D, 0x74, 0xCD, 0x4B, 0x89, 0x8C, 0x86, 0x03, 0xA8, 0x09, 0xC3, 0x60, 0xC8, 0xB9, 0x72, 0xD1}, //0x38-0x3C
				{0x0B, 0x74, 0x91, 0x5F, 0x6F, 0xBF, 0x45, 0xD7, 0xBC, 0xE8, 0x5F, 0x07, 0x64, 0x48, 0xFF, 0xD7, 0xB0, 0xD0, 0xFA, 0x01}, //0x3D
				{0x79, 0x49, 0x71, 0xEC, 0x73, 0x46, 0x1E, 0xD6, 0xAE, 0x0D, 0xED, 0xD4, 0x1E, 0x67, 0x3E, 0x38, 0xBC, 0xD8, 0x92, 0xBB}, //0x3E
				{0x0F, 0xBB, 0xBE, 0x63, 0x1B, 0x80, 0xEF, 0x32, 0x6B, 0x56, 0xC8, 0x0D, 0x7C, 0x9F, 0xB1, 0x5A, 0x99, 0x74, 0xB4, 0x1D}  //0x3F
			};
			const static u8 CommonKey0[20] = {0x20, 0x14, 0x6C, 0xD1, 0x63, 0x4B, 0x99, 0x08, 0x3B, 0x35, 0x3F, 0xE6, 0x1B, 0xD0, 0xD4, 0x42, 0xFB, 0xB7, 0xE8, 0xA2};
			const static u8 NCCHKeys[3][20] = {
				{0xFB, 0xEA, 0xA9, 0x33, 0xDC, 0x7D, 0x49, 0x97, 0x46, 0x3E, 0x89, 0x73, 0xAD, 0x18, 0x67, 0xC0, 0xB2, 0x45, 0xE0, 0xBD}, //0x18
				{0x1E, 0x96, 0xBE, 0x52, 0x7A, 0xC6, 0x4E, 0x6F, 0x69, 0x29, 0xB3, 0x87, 0x60, 0xB1, 0xA4, 0x87, 0x3D, 0x05, 0x1B, 0x96}, //0x1B
				{0x42, 0x31, 0xF2, 0xB4, 0x35, 0xEC, 0x7A, 0x45, 0x6C, 0x0A, 0xCC, 0x5F, 0xAF, 0xCD, 0x4C, 0xB9, 0x49, 0xF8, 0x3B, 0xC0}  //0x25
			};
		}
	}
	namespace Dev {
		static u8 KeyXs[8][16] = {};
		static u8 KeyYs[8][16] = {};
		static u8 KeyNormals[20][16] = {};
		static u8 CommonKey0[16] = {};
		static u8 NCCHKeys[3][16] = {};
		namespace SHA1Checksums {
			const static u8 KeyXs[8][20] = {
				{0x5F, 0xD1, 0xE3, 0x59, 0xFD, 0x54, 0xBA, 0x78, 0x6D, 0xCE, 0x5B, 0x57, 0x57, 0x0C, 0x73, 0xA3, 0x56, 0xDC, 0x29, 0xFC}, //0x2C to 0x2F
				{0xF0, 0xA9, 0x37, 0x21, 0x56, 0xCE, 0x24, 0xA8, 0x17, 0xBE, 0xD2, 0x76, 0xF8, 0x21, 0xE1, 0x88, 0x2B, 0x77, 0x04, 0x82}, //0x30 to 0x33
				{0xF7, 0x60, 0xB4, 0x16, 0x03, 0xE9, 0x61, 0x22, 0x22, 0x86, 0x9C, 0xBC, 0x2C, 0xD5, 0x92, 0x9F, 0x00, 0x09, 0xDC, 0x0E}, //0x34 to 0x37
				{0x11, 0x31, 0x4E, 0x50, 0x0D, 0xEB, 0xB2, 0x7A, 0xB5, 0x58, 0xB9, 0x5C, 0x2F, 0x5B, 0xA1, 0xC7, 0x26, 0x22, 0x3D, 0x12}, //0x38 to 0x3B
				{0x73, 0xE0, 0x98, 0x32, 0x3E, 0x3A, 0xF7, 0xD3, 0x1D, 0x83, 0xFC, 0x4A, 0x4F, 0xDA, 0x12, 0xE7, 0x72, 0x79, 0x98, 0xAD}, //0x3C
				{0x9B, 0x7F, 0x54, 0xF5, 0xD7, 0x57, 0xA6, 0xB6, 0xC5, 0xC6, 0x96, 0x52, 0x92, 0x0E, 0x07, 0x15, 0xE8, 0x06, 0xBF, 0x65}, //0x3D
				{0xE0, 0xAC, 0x06, 0x48, 0xF5, 0x2B, 0x26, 0xE5, 0x36, 0x90, 0x14, 0x51, 0x54, 0xAB, 0xC4, 0x02, 0x17, 0x37, 0x38, 0xF9}, //0x3E
				{0x82, 0x9F, 0xEB, 0x41, 0x00, 0xF3, 0xE2, 0x5C, 0xC2, 0xCE, 0xE7, 0x87, 0x0B, 0x8B, 0x14, 0x6D, 0xD7, 0xED, 0x40, 0x6C}  //0x3F
			};
			const static u8 KeyYs[8][20] = {
				{0x49, 0x91, 0x05, 0xCC, 0x92, 0x13, 0x7D, 0x1A, 0x8E, 0xF5, 0x61, 0x27, 0xEA, 0x8D, 0xCB, 0xC2, 0xAF, 0x24, 0x06, 0xC7}, //0x4
				{0xCD, 0x05, 0xF9, 0x32, 0x31, 0x15, 0x0D, 0x62, 0xF2, 0xC1, 0xA1, 0xB9, 0xA3, 0x78, 0x4B, 0xA7, 0x27, 0xBC, 0x91, 0x6A}, //0x5
				{0xE6, 0xB3, 0xC8, 0x5F, 0x2B, 0xA8, 0xA5, 0x26, 0xBD, 0xEE, 0x09, 0x50, 0x28, 0x34, 0xE5, 0x25, 0xA2, 0xA7, 0x8B, 0x37}, //0x6
				{0x1F, 0xFB, 0xA9, 0x59, 0x04, 0x75, 0xA0, 0x2E, 0x9E, 0xF6, 0x2F, 0x26, 0xDB, 0x87, 0x37, 0x8E, 0xD9, 0x6E, 0x05, 0x3F}, //0x7
				{0x23, 0xD4, 0x6B, 0xAA, 0x25, 0x07, 0xFB, 0xA5, 0x1E, 0x67, 0x2D, 0x6E, 0x68, 0xE0, 0x2A, 0x3D, 0xE5, 0x19, 0xA5, 0xAA}, //0x8
				{0x2D, 0xB2, 0xC0, 0xBD, 0x3A, 0x84, 0x56, 0xE7, 0xDF, 0x7E, 0x9A, 0x5B, 0xBF, 0xB7, 0x69, 0x62, 0x4D, 0x07, 0xC4, 0x6C}, //0x9
				{0xAC, 0x5B, 0xF9, 0x60, 0x47, 0xDE, 0xE9, 0x9C, 0xF8, 0x44, 0xE3, 0x07, 0x1A, 0xD0, 0x3B, 0x86, 0xAF, 0x3B, 0xF7, 0x0C}, //0xA
				{0x73, 0xCD, 0x32, 0xA8, 0xD3, 0x84, 0xDB, 0x01, 0xDE, 0x6D, 0xBC, 0x09, 0x64, 0x87, 0x2D, 0x6F, 0x7C, 0x3C, 0x00, 0xB0}  //0xB
			};
			const static u8 KeyNormals[20][20] = {
				{0xFA, 0x43, 0x55, 0xA3, 0xE1, 0x09, 0x64, 0x1E, 0x86, 0x77, 0xFF, 0x68, 0xE2, 0x4A, 0x89, 0x34, 0x76, 0xB4, 0xE2, 0x4C}, //0xC-0xF
				{0x1D, 0xA5, 0x61, 0x14, 0x95, 0x96, 0xC1, 0x2E, 0x3A, 0xD0, 0x4C, 0x16, 0x66, 0xC0, 0xF2, 0x48, 0xE0, 0x60, 0x41, 0x10}, //0x10-0x13
				{0x5B, 0x35, 0x71, 0x07, 0xE3, 0x28, 0xA7, 0xE6, 0x68, 0x0B, 0x92, 0x16, 0x21, 0x90, 0xB6, 0xD3, 0x0B, 0x85, 0xD2, 0x86}, //0x14
				{0x47, 0x9C, 0x08, 0x35, 0xE8, 0x14, 0xF0, 0x2F, 0xC9, 0x9A, 0xC7, 0xE9, 0x71, 0x4B, 0xC5, 0xB5, 0x60, 0x9C, 0xA6, 0xE6}, //0x15
				{0x13, 0x7C, 0x22, 0xCB, 0x70, 0x99, 0x49, 0xF8, 0x8E, 0xCB, 0x75, 0x0D, 0xC9, 0xCB, 0xCF, 0xAF, 0xD4, 0xA1, 0x22, 0xA2}, //0x16
				{0x99, 0x7E, 0x3C, 0xE5, 0x29, 0x1E, 0xB2, 0x59, 0x57, 0x20, 0xFF, 0x42, 0xDB, 0x40, 0x7C, 0xF5, 0x48, 0x9A, 0x8E, 0x4C}, //0x17
				{0xD6, 0xDE, 0xF8, 0xC4, 0x9E, 0x53, 0x58, 0x60, 0x84, 0xEF, 0xD1, 0xDC, 0xD8, 0xD3, 0xED, 0x01, 0x4B, 0x46, 0xC1, 0x2B}, //0x18-0x1B
				{0x26, 0xCD, 0x9C, 0x0D, 0xC3, 0x82, 0xDB, 0x44, 0xC1, 0x8B, 0xAF, 0x85, 0x43, 0x24, 0x08, 0x9E, 0x82, 0x60, 0x56, 0x7D}, //0x1C-0x1F
				{0xEE, 0x67, 0x1C, 0x64, 0x06, 0x28, 0xC5, 0x68, 0xD4, 0x25, 0x7D, 0x40, 0x8B, 0x68, 0xA2, 0x5C, 0xA2, 0x1C, 0x92, 0x8A}, //0x20-0x23
				{0xE0, 0x46, 0x49, 0x52, 0x62, 0xCA, 0x6A, 0x7E, 0xAC, 0xD6, 0xF4, 0xD8, 0xF1, 0xEF, 0x5A, 0xBD, 0xB8, 0x32, 0x7D, 0xBD}, //0x24-0x28
				{0xF5, 0xAA, 0x19, 0x69, 0x36, 0xE1, 0x99, 0xF9, 0x42, 0x5E, 0x84, 0x84, 0xAB, 0x45, 0x22, 0xB5, 0x2A, 0xE3, 0xD0, 0xB1}, //0x29
				{0xD9, 0xA8, 0xBE, 0xFB, 0xBA, 0x45, 0xF3, 0x95, 0x9F, 0x46, 0x7B, 0x99, 0xD8, 0x73, 0xE3, 0x31, 0x2C, 0xCE, 0x50, 0x82}, //0x2A
				{0x9E, 0x50, 0x10, 0xBE, 0x7E, 0x08, 0xC7, 0xFE, 0x82, 0x49, 0x16, 0x6A, 0xED, 0xE7, 0x8F, 0x5C, 0x4B, 0xB6, 0x66, 0x64}, //0x2B
				{0x76, 0xC2, 0x52, 0xFB, 0x62, 0x88, 0xD5, 0xC4, 0x89, 0x12, 0x87, 0x9B, 0xA3, 0xAF, 0x46, 0x70, 0x60, 0xBA, 0xA6, 0x10}, //0x2C-0x2F
				{0xFD, 0xC9, 0x46, 0x1A, 0x0F, 0x4A, 0xF1, 0x77, 0xFC, 0xFC, 0x36, 0x50, 0xD2, 0xE8, 0x8D, 0xC8, 0xB9, 0x90, 0x80, 0x20}, //0x30-0x33
				{0x95, 0x0D, 0x16, 0xD6, 0xF9, 0xF6, 0xFC, 0xF6, 0xB5, 0xE8, 0xC0, 0xDD, 0x0A, 0x22, 0xC7, 0xE8, 0x16, 0x5B, 0x8D, 0x4C}, //0x34-0x37
				{0xF0, 0x09, 0xBC, 0x18, 0xDE, 0xD6, 0x5A, 0x60, 0x6A, 0x46, 0x52, 0x4A, 0x1D, 0x17, 0x3C, 0xE5, 0xE7, 0x0C, 0xC9, 0x4F}, //0x38-0x3C
				{0x0C, 0xE1, 0x35, 0xAC, 0x5E, 0x48, 0x02, 0xD3, 0x80, 0x3F, 0x93, 0xDD, 0xCC, 0x88, 0x60, 0x95, 0xB6, 0x84, 0x9E, 0x0A}, //0x3D
				{0x85, 0xC6, 0xF9, 0x21, 0x86, 0x6C, 0xC4, 0x2E, 0x03, 0xFE, 0x77, 0x28, 0x19, 0x42, 0xF9, 0xDA, 0x0C, 0xF7, 0x0F, 0xC9}, //0x3E
				{0x45, 0x89, 0x3C, 0x25, 0x09, 0x48, 0x1A, 0xCC, 0xFB, 0xC1, 0x6B, 0xA3, 0xF7, 0xBB, 0x08, 0x3E, 0x7D, 0xD8, 0xAF, 0x92}  //0x3F
			};
			const static u8 CommonKey0[20] = {0x6E, 0x2D, 0x13, 0xDA, 0x98, 0xFF, 0x4F, 0x51, 0xB6, 0xA0, 0x5C, 0x09, 0x37, 0xE4, 0xDC, 0x2D, 0x85, 0x2F, 0xBC, 0x9B};
			const static u8 NCCHKeys[3][20] = {
				{0x7C, 0x10, 0xEC, 0x49, 0xE1, 0xBD, 0x67, 0x7E, 0xDE, 0x9F, 0x2F, 0x92, 0x96, 0xF2, 0x5E, 0x75, 0x77, 0x07, 0xE4, 0x32}, //0x18
				{0x8D, 0xD9, 0xB7, 0x73, 0x59, 0x8F, 0x78, 0xE7, 0xEF, 0x37, 0x54, 0xAB, 0x78, 0xEB, 0xBD, 0xFA, 0xBA, 0x9C, 0xB2, 0xE0}, //0x1B
				{0x3B, 0x01, 0x22, 0xFB, 0x83, 0xEE, 0x5B, 0x75, 0xBF, 0x36, 0xA5, 0x77, 0xBF, 0x0A, 0xFA, 0x32, 0xE0, 0x60, 0x64, 0xFC}  //0x25
			};
		}
	}
	static u8 Constant_C[16] = {};
	static u8 TWLConstant[16] = {};
	static u8 CommonKeys[5][16] = {};
	static u8 FixedKey[16] = {};
	namespace SHA1Checksums {
		const static u8 Constant_C[20] = {0x90, 0xEE, 0x1F, 0xF2, 0x9F, 0xD7, 0x03, 0x21, 0x76, 0xAD, 0x6D, 0x22, 0x22, 0xFA, 0x01, 0xC8, 0x4B, 0xA6, 0xBF, 0x88};
		const static u8 TWLConstant[20] = {0x31, 0x1B, 0x23, 0xD5, 0xDA, 0xD5, 0xEA, 0x6D, 0x98, 0xBD, 0xBF, 0x3D, 0xB3, 0xF8, 0x0C, 0x51, 0x04, 0xE4, 0xAD, 0xDE};
		const static u8 CommonKeys[5][20] = {
			{0x3B, 0xF7, 0xBB, 0x0C, 0x03, 0xC9, 0xEF, 0x30, 0x3D, 0x1F, 0x23, 0x99, 0xD4, 0xB7, 0xA7, 0x6B, 0x1B, 0x12, 0xB3, 0xB2},
			{0xC0, 0x8F, 0xB0, 0xE2, 0x26, 0xF5, 0x33, 0x10, 0x32, 0x49, 0x10, 0xFA, 0xBE, 0xDA, 0x67, 0xE3, 0xDA, 0x2B, 0x58, 0x43},
			{0xA8, 0xA9, 0x76, 0x2E, 0x51, 0x64, 0x90, 0xD2, 0xCA, 0xA6, 0x3F, 0x6F, 0xB9, 0x88, 0x94, 0xC9, 0x2B, 0xF4, 0x1E, 0xB2},
			{0x74, 0x6A, 0xAF, 0x90, 0x90, 0xD6, 0x72, 0xAF, 0x04, 0xE2, 0x89, 0x9F, 0xC2, 0xD9, 0xB4, 0xB7, 0x45, 0x11, 0xD3, 0xF0},
			{0x40, 0x60, 0x49, 0x2C, 0x4E, 0xCA, 0x02, 0x31, 0x9A, 0x90, 0x7D, 0xA4, 0x36, 0x67, 0xF1, 0x69, 0x79, 0xE8, 0x4B, 0xBA}
		};
		const static u8 FixedKey[20] = {0xAC, 0x6D, 0xFE, 0x47, 0x0E, 0x70, 0x55, 0x06, 0x8D, 0x19, 0x2B, 0x21, 0x25, 0x99, 0x28, 0x28, 0x02, 0x9D, 0xD1, 0x10};
	}
	#define swapnibbles(x) ((((x) << 4) & 0xF0) | (((x) >> 4) & 0x0F))
	#define hi_nibble(x) (((x) >> 4) & 0xF)
	#define hi_mask_nibble(x) ((x) & 0xF0)
	#define lo_nibble(x) ((x) & 0xF)
	#define bytenot(x) (((x) ^ 0xFF) & 0xFF)
	static bool LoadBoot9Protected(FILE* fp) {
		bool success = false;
		auto startoffset = ftell(fp);
		if(startoffset == -1L) return false;
		do {
			if(fseek(fp, 0x59D0, SEEK_CUR)) break;
			if(fread(&Retail::KeyXs[0][0], 1, 128, fp) != 128) break;
			if(fread(&Retail::KeyYs[0][0], 1, 128, fp) != 128) break;
			if(fread(&Retail::KeyNormals[0][0], 1, 320, fp) != 320) break;
			if(fseek(fp, 0x1C0, SEEK_CUR)) break;
			if(fread(&Dev::KeyXs[0][0], 1, 128, fp) != 128) break;
			if(fread(&Dev::KeyYs[0][0], 1, 128, fp) != 128) break;
			if(fread(&Dev::KeyNormals[0][0], 1, 320, fp) != 320) break;

			/* 
			 * It's either make code that reads from a special file with just the other keys,
			 * or make code that reads the bootrom9 for a few bytes and then make them.
			 * Any other devs may feel free to use this as-is.
			 * You can either load chunks of the other keys, or load only the first part and do this.
			 * Objective here was, not have any constants,
			 * besides the amount of shifts and offsets.
			 * Consider this my way of somewhat obfuscating it instead of direct hardcode
			 */

			/* Constant C */

			Constant_C[0] = Retail::KeyXs[0][8]; //same byte as first const C byte
			Constant_C[8] = hi_nibble(Constant_C[0]) << 1;
			Constant_C[6] = Constant_C[8] << 1;
			Constant_C[7] = Constant_C[8] << 2;
			Constant_C[1] = swapnibbles(Constant_C[0]) + Constant_C[7];
			Constant_C[2] = Constant_C[1] - swapnibbles(hi_nibble(Constant_C[0]));
			Constant_C[3] = Constant_C[7] | Constant_C[8];
			Constant_C[4] = ((Constant_C[6] | Constant_C[7]) << 4) | (Constant_C[3] >> 1);
			Constant_C[15] = (Constant_C[7] << 4) | Constant_C[3];
			Constant_C[3] |= Constant_C[3] << 4;
			Constant_C[5] = bytenot(hi_nibble(Constant_C[0]));
			Constant_C[10] = hi_nibble(Constant_C[0]) | (Constant_C[1] << 4);
			Constant_C[11] = swapnibbles(Constant_C[4] + Constant_C[7]);
			Constant_C[12] = swapnibbles(Constant_C[4]) + hi_nibble(Constant_C[0]);
			Constant_C[13] = swapnibbles(Constant_C[4]) - (Constant_C[7] | Constant_C[8]);
			Constant_C[9] = swapnibbles(Constant_C[13] + Constant_C[8]);
			Constant_C[14] = Constant_C[6] | Constant_C[8];
			Constant_C[14] |= (Constant_C[14] + hi_nibble(Constant_C[0])) << 4;

			/* Common Keys */

			CommonKeys[0][0] = Constant_C[6] | Constant_C[7];
			CommonKeys[0][8] = hi_mask_nibble(Constant_C[9]) | Constant_C[6] | Constant_C[8];
			CommonKeys[0][15] = hi_mask_nibble(Constant_C[9]) | CommonKeys[0][0];
			CommonKeys[3][9] = hi_mask_nibble(Constant_C[9]) | hi_nibble(Constant_C[9]);
			Dev::CommonKey0[12] = CommonKeys[0][7] = hi_mask_nibble(Constant_C[0]) | CommonKeys[0][0];
			CommonKeys[2][5] = CommonKeys[2][12] = swapnibbles(CommonKeys[0][0]);
			Retail::CommonKey0[4] = CommonKeys[2][6] = CommonKeys[3][3] = CommonKeys[0][0] | ((hi_nibble(Constant_C[0]) | Constant_C[7]) << 4);
			Dev::CommonKey0[15] = CommonKeys[1][5] = CommonKeys[2][5] | hi_nibble(Constant_C[14]);
			Dev::CommonKey0[4] = CommonKeys[1][2] = CommonKeys[2][5] | lo_nibble(Constant_C[3]) | lo_nibble(Constant_C[10]);
			CommonKeys[1][0] = CommonKeys[2][5] | Constant_C[6];
			CommonKeys[4][1] = CommonKeys[2][9] = Constant_C[14] ^ hi_mask_nibble(Constant_C[0]);
			CommonKeys[4][2] = CommonKeys[0][5] = bytenot(CommonKeys[4][1]);
			Retail::CommonKey0[0] = CommonKeys[2][4] = CommonKeys[2][5] | hi_mask_nibble(Constant_C[0]);
			CommonKeys[3][15] = Constant_C[5] ^ Constant_C[8];
			CommonKeys[4][15] = bytenot(Constant_C[3]);
			Retail::CommonKey0[5] = Dev::CommonKey0[8] = CommonKeys[1][15] = hi_mask_nibble(Constant_C[3]) | Constant_C[6];
			Dev::CommonKey0[2] = CommonKeys[4][0] = CommonKeys[1][9] = bytenot(hi_mask_nibble(Constant_C[3]) | lo_nibble(Constant_C[10]));
			CommonKeys[0][9] = CommonKeys[0][10] = hi_mask_nibble(Constant_C[15]) | Constant_C[8];
			CommonKeys[0][1] = Constant_C[14];
			CommonKeys[0][2] = Constant_C[14] ^ Constant_C[6];
			Dev::CommonKey0[0] = CommonKeys[4][9] = swapnibbles(hi_mask_nibble(Constant_C[12]) | Constant_C[7]);
			CommonKeys[0][4] = hi_mask_nibble(Constant_C[1]);
			CommonKeys[4][10] = swapnibbles(CommonKeys[0][4]);
			CommonKeys[4][12] = CommonKeys[1][11] = bytenot(CommonKeys[4][0]);
			Dev::CommonKey0[9] = CommonKeys[4][4] = Dev::CommonKey0[8] | hi_mask_nibble(Constant_C[0]);
			CommonKeys[3][4] = CommonKeys[3][14] = Constant_C[6];
			Retail::CommonKey0[12] = Retail::CommonKey0[13] = bytenot(Retail::CommonKey0[0] | CommonKeys[0][0]);
			CommonKeys[0][3] = hi_mask_nibble(bytenot(CommonKeys[2][5]));
			CommonKeys[0][11] = Constant_C[8];
			Retail::CommonKey0[11] = CommonKeys[1][8] = hi_mask_nibble(CommonKeys[1][9]) | (lo_nibble(CommonKeys[1][9]) >> 1);
			CommonKeys[2][1] = CommonKeys[2][10] = lo_nibble(CommonKeys[2][9]) | (Constant_C[7] << 4);
			CommonKeys[1][4] = CommonKeys[1][14] = CommonKeys[0][8] ^ Constant_C[5];
			Retail::CommonKey0[8] = swapnibbles(Retail::CommonKey0[12]);
			CommonKeys[4][3] = Constant_C[15];
			CommonKeys[4][11] = CommonKeys[4][14] = swapnibbles(bytenot(CommonKeys[0][9]));
			CommonKeys[2][7] = CommonKeys[2][6] ^ CommonKeys[0][0];
			Retail::CommonKey0[9] = bytenot(Constant_C[12]);
			CommonKeys[1][1] = swapnibbles(CommonKeys[1][8]);
			CommonKeys[0][6] = Retail::KeyXs[1][4];
			CommonKeys[2][2] = Retail::KeyXs[2][14];
			CommonKeys[1][6] = Retail::KeyYs[0][2];
			Retail::CommonKey0[3] = Retail::KeyNormals[3][12];
			Dev::CommonKey0[3] = swapnibbles(Retail::KeyNormals[8][15]);
			CommonKeys[0][12] = swapnibbles(Retail::KeyYs[5][0]);
			Dev::CommonKey0[11] = Retail::KeyYs[3][8];
			CommonKeys[4][8] = lo_nibble(Dev::CommonKey0[3]);
			Dev::CommonKey0[7] = Retail::KeyYs[0][3];
			Retail::CommonKey0[7] = bytenot(lo_nibble(Dev::CommonKey0[3]) | hi_mask_nibble(Retail::CommonKey0[5]));
			Retail::CommonKey0[1] = swapnibbles(bytenot(Dev::CommonKey0[11] << 1) ^ CommonKeys[1][6]);
			Dev::CommonKey0[1] = (bytenot(Retail::CommonKey0[1]) & 0xFF) >> 2;
			Retail::CommonKey0[2] = lo_nibble(Dev::CommonKey0[1]) ^ hi_nibble(Dev::CommonKey0[1]);
			Retail::CommonKey0[2] |= Retail::CommonKey0[2] << 4;
			Retail::CommonKey0[6] = hi_mask_nibble(Retail::CommonKey0[2]) | lo_nibble(CommonKeys[1][6]);
			CommonKeys[1][10] = swapnibbles(Dev::CommonKey0[1]);
			CommonKeys[3][8] = Dev::CommonKey0[11] ^ (Dev::CommonKey0[11] >> 3);
			CommonKeys[4][13] = CommonKeys[3][8] ^ lo_nibble(CommonKeys[4][12]);
			CommonKeys[2][14] = Dev::CommonKey0[11] ^ Constant_C[6];
			CommonKeys[2][3] = hi_mask_nibble(CommonKeys[2][2]) | lo_nibble(Retail::CommonKey0[2]);
			Dev::CommonKey0[5] = swapnibbles(Retail::CommonKey0[7]);
			CommonKeys[3][6] = swapnibbles(CommonKeys[0][1]);
			CommonKeys[2][15] = swapnibbles(Constant_C[1]);
			CommonKeys[1][3] = hi_mask_nibble(Retail::CommonKey0[2]) | lo_nibble(CommonKeys[0][12]);
			CommonKeys[2][0] = hi_nibble(Dev::CommonKey0[1] << 1) | hi_mask_nibble(CommonKeys[2][2]);
			CommonKeys[3][0] = swapnibbles(bytenot(Dev::CommonKey0[1]));
			CommonKeys[3][7] = swapnibbles(bytenot(CommonKeys[0][12]));
			CommonKeys[2][8] = Retail::CommonKey0[3] ^ CommonKeys[3][7];
			CommonKeys[2][13] = hi_mask_nibble(Dev::CommonKey0[1] << 1) ^ CommonKeys[2][8];
			CommonKeys[3][1] = Dev::CommonKey0[1] ^ (lo_nibble(Dev::CommonKey0[1]) << 4);
			CommonKeys[4][7] = swapnibbles(Dev::CommonKey0[1]) | CommonKeys[4][8];
			CommonKeys[3][2] = swapnibbles(swapnibbles(CommonKeys[3][0]) ^ CommonKeys[1][1]);
			Dev::CommonKey0[6] = Dev::CommonKey0[1] ^ CommonKeys[1][6];
			Dev::CommonKey0[10] = swapnibbles(CommonKeys[3][0]);
			Retail::CommonKey0[15] = Dev::CommonKey0[3] ^ Retail::CommonKey0[3] ^ CommonKeys[3][7];
			Retail::CommonKey0[14] = (Dev::CommonKey0[1] << 1) ^ Retail::CommonKey0[3] ^ swapnibbles(CommonKeys[3][1]);
			Retail::CommonKey0[10] = swapnibbles(Retail::CommonKey0[14]);
			CommonKeys[1][7] = Retail::CommonKey0[6] ^ CommonKeys[0][6] ^ CommonKeys[0][0];
			CommonKeys[1][13] = CommonKeys[0][6] ^ CommonKeys[1][6];
			CommonKeys[1][12] = CommonKeys[0][6] ^ CommonKeys[2][10];
			CommonKeys[2][11] = Retail::CommonKey0[6] ^ Dev::CommonKey0[7];
			CommonKeys[3][10] = (CommonKeys[1][12] << 4) | CommonKeys[1][13];
			CommonKeys[3][12] = swapnibbles(Retail::CommonKey0[1]) ^ Dev::CommonKey0[7];
			Dev::CommonKey0[13] = swapnibbles(CommonKeys[3][12]);
			CommonKeys[4][6] = Dev::CommonKey0[7] ^ Retail::CommonKey0[3];
			CommonKeys[0][13] = Retail::CommonKey0[2] ^ CommonKeys[2][15];
			CommonKeys[0][14] = Dev::CommonKey0[4] ^ CommonKeys[0][12] ^ CommonKeys[0][6];
			Dev::CommonKey0[14] = CommonKeys[0][14] ^ CommonKeys[3][1] ^ CommonKeys[3][0];
			CommonKeys[3][5] = CommonKeys[1][3] ^ CommonKeys[4][3];
			CommonKeys[4][5] = CommonKeys[3][2] ^ Retail::CommonKey0[2] ^ swapnibbles(CommonKeys[4][7]);
			CommonKeys[3][11] = Dev::CommonKey0[9] ^ Retail::CommonKey0[6] ^ CommonKeys[2][8];
			CommonKeys[3][13] = Dev::CommonKey0[3] ^ CommonKeys[2][2];

			/* TWL constant */

			TWLConstant[0]  = Retail::CommonKey0[1] ^ CommonKeys[2][5] ^ CommonKeys[3][9];
			TWLConstant[1]  = TWLConstant[0] ^ hi_nibble(Constant_C[0]);
			TWLConstant[2]  = Dev::CommonKey0[0] ^ Retail::KeyXs[1][12] ^ Constant_C[6];
			TWLConstant[3]  = Retail::KeyXs[0][4] ^ Retail::KeyXs[1][15] ^ CommonKeys[0][1];
			TWLConstant[4]  = Retail::KeyXs[0][7] ^ CommonKeys[0][6] ^ Retail::KeyNormals[4][3];
			TWLConstant[5]  = Retail::CommonKey0[1] ^ Retail::KeyXs[3][2];
			TWLConstant[6]  = bytenot(TWLConstant[3] ^ Retail::KeyXs[1][1] ^ Retail::KeyXs[3][4]);
			TWLConstant[7]  = swapnibbles(Retail::KeyXs[1][11] ^ TWLConstant[6]);
			TWLConstant[8]  = swapnibbles(Retail::KeyXs[2][6]) ^ Retail::KeyXs[3][0];
			TWLConstant[9]  = Retail::KeyXs[2][8] ^ hi_mask_nibble(Retail::CommonKey0[1]);
			TWLConstant[10] = hi_nibble(TWLConstant[1]);
			TWLConstant[11] = swapnibbles(Dev::CommonKey0[15]) ^ Retail::KeyXs[1][2];
			TWLConstant[12] = Retail::KeyXs[1][7] ^ Retail::KeyXs[3][1];
			TWLConstant[13] = Retail::CommonKey0[1] ^ Retail::KeyXs[0][13];
			TWLConstant[14] = Retail::KeyXs[1][12] ^ CommonKeys[3][9];
			TWLConstant[15] = Retail::KeyXs[0][13] ^ Retail::KeyNormals[9][10];

			/* Fixed Key */

			FixedKey[15] = Retail::KeyXs[0][9] ^ Retail::KeyXs[4][1] ^ Retail::KeyYs[3][8];
			FixedKey[14] = (swapnibbles(Retail::KeyXs[1][4]) & Retail::KeyXs[0][11]) ^ Retail::KeyNormals[8][5];
			FixedKey[13] = bytenot(Retail::KeyYs[0][14] ^ Retail::KeyYs[4][8] ^ swapnibbles(Retail::KeyXs[0][15]));
			FixedKey[12] = Retail::KeyYs[6][3] ^ Retail::KeyYs[6][13];
			FixedKey[11] = swapnibbles(Retail::KeyXs[1][1]) ^ Retail::KeyYs[0][0] ^ Retail::KeyXs[4][7];
			FixedKey[10] = swapnibbles(bytenot(Retail::KeyNormals[12][2])) ^ Retail::KeyXs[2][10] ^ Retail::KeyXs[6][0];
			FixedKey[9]  = Retail::KeyXs[7][11] ^ Retail::KeyXs[4][13];
			FixedKey[8]  = swapnibbles(bytenot(Retail::KeyXs[4][11])) ^ Retail::KeyNormals[17][9];
			FixedKey[7]  = swapnibbles(bytenot(Retail::KeyNormals[4][7])) ^ Retail::KeyNormals[13][15] ^ Retail::KeyNormals[14][1];
			FixedKey[6]  = swapnibbles(Retail::KeyNormals[19][8]) ^ Retail::KeyYs[2][2];
			FixedKey[5]  = swapnibbles(swapnibbles(Retail::KeyNormals[6][13]) + FixedKey[8]);
			FixedKey[4]  = Retail::KeyNormals[15][1] ^ Retail::KeyNormals[16][10];
			FixedKey[3]  = FixedKey[12] - swapnibbles(Retail::KeyNormals[15][3]);
			FixedKey[2]  = Retail::KeyNormals[2][15] ^ FixedKey[15];
			FixedKey[1]  = FixedKey[5] ^ bytenot(Retail::KeyYs[4][14]) ^ bytenot(Retail::KeyNormals[0][4]);
			FixedKey[0]  = FixedKey[2] ^ swapnibbles(FixedKey[15]);

			/* 0x18, 0x1B, 0x25 */
			// autogenerated
			// warning supression pramga added to shut up suggestions that aren't needed here
			// `suggest parentheses around arithmetic in operand of ‘^’`

			#if defined __GNUC__
			#pragma GCC diagnostic push
			#pragma GCC diagnostic ignored "-Wparentheses"
			#elif defined __clang__
			#pragma clang diagnostic push
			#pragma clang diagnostic ignored "-Wparentheses"
			#endif

			Retail::NCCHKeys[0][0]  = bytenot(hi_nibble(Retail::KeyNormals[8][3])) + swapnibbles(Retail::KeyNormals[18][5]) - bytenot(Retail::KeyYs[3][15]) ^ hi_mask_nibble(bytenot(Retail::KeyNormals[19][3]));
			Retail::NCCHKeys[1][0]  = bytenot(hi_nibble(Retail::KeyYs[2][2])) + swapnibbles(Retail::KeyXs[4][7]) - bytenot(Retail::KeyXs[6][9]) ^ hi_mask_nibble(bytenot(Retail::KeyXs[6][13]));
			Retail::NCCHKeys[2][0]  = swapnibbles(Retail::KeyNormals[10][2]) * bytenot(Retail::KeyNormals[18][2]) + lo_nibble(Retail::KeyXs[7][11]) ^ bytenot(Retail::KeyXs[1][3]);
			Retail::NCCHKeys[0][1]  = (swapnibbles(Retail::KeyXs[2][8]) ^ bytenot(Retail::KeyXs[6][5])) + lo_nibble(Retail::KeyNormals[17][9]) ^ bytenot(Retail::KeyYs[6][11]);
			Retail::NCCHKeys[1][1]  = bytenot(hi_nibble(Retail::KeyXs[6][15])) + swapnibbles(Retail::KeyYs[3][2]) - bytenot(Retail::KeyYs[4][4]) ^ hi_mask_nibble(bytenot(Retail::KeyYs[4][2]));
			Retail::NCCHKeys[2][1]  = bytenot(Retail::KeyNormals[11][1]) ^ hi_nibble(Retail::KeyNormals[7][11]) ^ swapnibbles(Retail::KeyYs[5][1]) ^ Retail::KeyNormals[13][8];
			Retail::NCCHKeys[0][2]  = bytenot(hi_nibble(Retail::KeyNormals[18][13])) + swapnibbles(Retail::KeyNormals[9][10]) - bytenot(Retail::KeyYs[4][4]) ^ hi_mask_nibble(bytenot(Retail::KeyNormals[16][15]));
			Retail::NCCHKeys[1][2]  = (swapnibbles(Retail::KeyYs[5][1]) ^ bytenot(Retail::KeyYs[1][6])) + lo_nibble(Retail::KeyNormals[4][1]) ^ bytenot(Retail::KeyYs[0][8]);
			Retail::NCCHKeys[2][2]  = (bytenot(Retail::KeyXs[0][8]) ^ hi_nibble(Retail::KeyXs[1][2])) - swapnibbles(Retail::KeyNormals[18][8]) ^ Retail::KeyNormals[14][14];
			Retail::NCCHKeys[0][3]  = (swapnibbles(Retail::KeyYs[1][8]) ^ bytenot(Retail::KeyXs[4][10])) + lo_nibble(Retail::KeyYs[3][1]) ^ bytenot(Retail::KeyNormals[8][9]);
			Retail::NCCHKeys[1][3]  = swapnibbles(Retail::KeyYs[5][11]) * bytenot(Retail::KeyNormals[11][6]) + lo_nibble(Retail::KeyXs[0][8]) ^ bytenot(Retail::KeyXs[4][8]);
			Retail::NCCHKeys[2][3]  = swapnibbles(Retail::KeyXs[4][11]) * bytenot(Retail::KeyYs[1][7]) + lo_nibble(Retail::KeyXs[1][1]) ^ bytenot(Retail::KeyNormals[7][13]);
			Retail::NCCHKeys[0][4]  = bytenot(Retail::KeyXs[7][11]) ^ hi_nibble(Retail::KeyYs[1][0]) ^ swapnibbles(Retail::KeyXs[3][8]) ^ Retail::KeyYs[2][14];
			Retail::NCCHKeys[1][4]  = bytenot(hi_nibble(Retail::KeyXs[6][13])) + swapnibbles(Retail::KeyXs[4][5]) - bytenot(Retail::KeyYs[4][11]) ^ hi_mask_nibble(bytenot(Retail::KeyYs[3][5]));
			Retail::NCCHKeys[2][4]  = (bytenot(Retail::KeyYs[1][15]) ^ hi_nibble(Retail::KeyNormals[10][3])) - swapnibbles(Retail::KeyXs[1][0]) ^ Retail::KeyYs[1][9];
			Retail::NCCHKeys[0][5]  = (swapnibbles(Retail::KeyXs[5][9]) ^ bytenot(Retail::KeyYs[4][4])) + lo_nibble(Retail::KeyYs[3][11]) ^ bytenot(Retail::KeyXs[2][3]);
			Retail::NCCHKeys[1][5]  = bytenot(Retail::KeyNormals[0][15]) ^ hi_nibble(Retail::KeyNormals[19][2]) ^ swapnibbles(Retail::KeyNormals[9][10]) ^ Retail::KeyNormals[1][5];
			Retail::NCCHKeys[2][5]  = bytenot(hi_nibble(Retail::KeyXs[6][4])) + swapnibbles(Retail::KeyNormals[15][7]) - bytenot(Retail::KeyYs[2][8]) ^ hi_mask_nibble(bytenot(Retail::KeyXs[3][2]));
			Retail::NCCHKeys[0][6]  = (swapnibbles(Retail::KeyNormals[5][12]) ^ bytenot(Retail::KeyXs[3][2])) + lo_nibble(Retail::KeyYs[0][4]) ^ bytenot(Retail::KeyYs[5][2]);
			Retail::NCCHKeys[1][6]  = bytenot(hi_nibble(Retail::KeyXs[0][11])) + swapnibbles(Retail::KeyYs[5][5]) - bytenot(Retail::KeyXs[0][5]) ^ hi_mask_nibble(bytenot(Retail::KeyYs[4][3]));
			Retail::NCCHKeys[2][6]  = swapnibbles(Retail::KeyNormals[6][14]) * bytenot(Retail::KeyNormals[15][7]) + lo_nibble(Retail::KeyNormals[11][4]) ^ bytenot(Retail::KeyYs[0][14]);
			Retail::NCCHKeys[0][7]  = (swapnibbles(Retail::KeyYs[3][12]) ^ bytenot(Retail::KeyNormals[7][13])) + lo_nibble(Retail::KeyYs[2][3]) ^ bytenot(Retail::KeyXs[0][15]);
			Retail::NCCHKeys[1][7]  = swapnibbles(Retail::KeyXs[4][14]) * bytenot(Retail::KeyNormals[16][12]) + lo_nibble(Retail::KeyYs[6][10]) ^ bytenot(Retail::KeyXs[7][5]);
			Retail::NCCHKeys[2][7]  = bytenot(Retail::KeyYs[0][6]) ^ hi_nibble(Retail::KeyNormals[9][12]) ^ swapnibbles(Retail::KeyXs[3][9]) ^ Retail::KeyXs[5][1];
			Retail::NCCHKeys[0][8]  = (bytenot(Retail::KeyYs[7][13]) ^ hi_nibble(Retail::KeyYs[6][15])) - swapnibbles(Retail::KeyYs[2][1]) ^ Retail::KeyYs[1][6];
			Retail::NCCHKeys[1][8]  = (swapnibbles(Retail::KeyYs[6][9]) ^ bytenot(Retail::KeyNormals[7][6])) + lo_nibble(Retail::KeyXs[6][10]) ^ bytenot(Retail::KeyYs[3][4]);
			Retail::NCCHKeys[2][8]  = (swapnibbles(Retail::KeyYs[2][4]) ^ bytenot(Retail::KeyYs[6][12])) + lo_nibble(Retail::KeyYs[6][10]) ^ bytenot(Retail::KeyNormals[4][6]);
			Retail::NCCHKeys[0][9]  = (swapnibbles(Retail::KeyNormals[4][2]) ^ bytenot(Retail::KeyNormals[8][1])) + lo_nibble(Retail::KeyNormals[9][7]) ^ bytenot(Retail::KeyNormals[15][14]);
			Retail::NCCHKeys[1][9]  = bytenot(hi_nibble(Retail::KeyYs[3][6])) + swapnibbles(Retail::KeyNormals[4][11]) - bytenot(Retail::KeyNormals[17][2]) ^ hi_mask_nibble(bytenot(Retail::KeyXs[1][6]));
			Retail::NCCHKeys[2][9]  = swapnibbles(Retail::KeyNormals[7][1]) * bytenot(Retail::KeyYs[1][6]) + lo_nibble(Retail::KeyNormals[17][2]) ^ bytenot(Retail::KeyNormals[7][3]);
			Retail::NCCHKeys[0][10] = (swapnibbles(Retail::KeyXs[2][3]) ^ bytenot(Retail::KeyXs[7][2])) + lo_nibble(Retail::KeyXs[6][14]) ^ bytenot(Retail::KeyXs[7][8]);
			Retail::NCCHKeys[1][10] = (bytenot(Retail::KeyXs[4][6]) ^ hi_nibble(Retail::KeyYs[2][7])) - swapnibbles(Retail::KeyYs[4][14]) ^ Retail::KeyYs[0][15];
			Retail::NCCHKeys[2][10] = bytenot(hi_nibble(Retail::KeyXs[0][2])) + swapnibbles(Retail::KeyXs[7][13]) - bytenot(Retail::KeyYs[2][3]) ^ hi_mask_nibble(bytenot(Retail::KeyXs[2][7]));
			Retail::NCCHKeys[0][11] = (swapnibbles(Retail::KeyYs[3][8]) ^ bytenot(Retail::KeyYs[0][10])) + lo_nibble(Retail::KeyXs[6][12]) ^ bytenot(Retail::KeyXs[1][2]);
			Retail::NCCHKeys[1][11] = bytenot(Retail::KeyXs[2][14]) ^ hi_nibble(Retail::KeyXs[1][13]) ^ swapnibbles(Retail::KeyNormals[1][14]) ^ Retail::KeyXs[5][1];
			Retail::NCCHKeys[2][11] = (swapnibbles(Retail::KeyNormals[17][6]) ^ bytenot(Retail::KeyNormals[8][8])) + lo_nibble(Retail::KeyNormals[15][10]) ^ bytenot(Retail::KeyYs[5][3]);
			Retail::NCCHKeys[0][12] = (bytenot(Retail::KeyXs[4][13]) ^ hi_nibble(Retail::KeyYs[4][14])) - swapnibbles(Retail::KeyYs[5][11]) ^ Retail::KeyXs[7][8];
			Retail::NCCHKeys[1][12] = (swapnibbles(Retail::KeyNormals[18][14]) ^ bytenot(Retail::KeyXs[3][15])) + lo_nibble(Retail::KeyXs[5][4]) ^ bytenot(Retail::KeyXs[6][3]);
			Retail::NCCHKeys[2][12] = bytenot(Retail::KeyNormals[18][12]) ^ hi_nibble(Retail::KeyNormals[17][4]) ^ swapnibbles(Retail::KeyYs[5][9]) ^ Retail::KeyNormals[4][12];
			Retail::NCCHKeys[0][13] = (bytenot(Retail::KeyXs[3][10]) ^ hi_nibble(Retail::KeyXs[4][1])) - swapnibbles(Retail::KeyYs[4][12]) ^ Retail::KeyYs[3][5];
			Retail::NCCHKeys[1][13] = swapnibbles(Retail::KeyNormals[9][9]) * bytenot(Retail::KeyYs[2][3]) + lo_nibble(Retail::KeyYs[0][1]) ^ bytenot(Retail::KeyYs[2][4]);
			Retail::NCCHKeys[2][13] = bytenot(Retail::KeyNormals[14][6]) ^ hi_nibble(Retail::KeyYs[7][5]) ^ swapnibbles(Retail::KeyXs[3][14]) ^ Retail::KeyYs[4][5];
			Retail::NCCHKeys[0][14] = (bytenot(Retail::KeyNormals[6][8]) ^ hi_nibble(Retail::KeyXs[4][9])) - swapnibbles(Retail::KeyYs[0][4]) ^ Retail::KeyYs[1][15];
			Retail::NCCHKeys[1][14] = bytenot(hi_nibble(Retail::KeyNormals[19][1])) + swapnibbles(Retail::KeyXs[5][15]) - bytenot(Retail::KeyNormals[10][4]) ^ hi_mask_nibble(bytenot(Retail::KeyXs[7][6]));
			Retail::NCCHKeys[2][14] = swapnibbles(Retail::KeyNormals[18][12]) * bytenot(Retail::KeyYs[2][12]) + lo_nibble(Retail::KeyXs[6][1]) ^ bytenot(Retail::KeyYs[0][6]);
			Retail::NCCHKeys[0][15] = swapnibbles(Retail::KeyNormals[8][8]) * bytenot(Retail::KeyXs[4][10]) + lo_nibble(Retail::KeyYs[7][9]) ^ bytenot(Retail::KeyYs[4][15]);
			Retail::NCCHKeys[1][15] = swapnibbles(Retail::KeyXs[5][13]) * bytenot(Retail::KeyNormals[7][15]) + lo_nibble(Retail::KeyNormals[1][4]) ^ bytenot(Retail::KeyXs[2][4]);
			Retail::NCCHKeys[2][15] = bytenot(Retail::KeyYs[5][7]) ^ hi_nibble(Retail::KeyYs[1][8]) ^ swapnibbles(Retail::KeyYs[7][9]) ^ Retail::KeyYs[1][7];
			Dev::NCCHKeys[2][15]    = swapnibbles(Dev::KeyYs[3][13]) * bytenot(Dev::KeyNormals[11][4]) + lo_nibble(Dev::KeyXs[7][4]) ^ bytenot(Dev::KeyNormals[16][3]);
			Dev::NCCHKeys[1][15]    = bytenot(Dev::KeyXs[3][0]) ^ hi_nibble(Dev::KeyNormals[1][10]) ^ swapnibbles(Dev::KeyXs[5][11]) ^ Dev::KeyYs[5][12];
			Dev::NCCHKeys[0][15]    = (bytenot(Dev::KeyYs[4][9]) ^ hi_nibble(Dev::KeyYs[5][1])) - swapnibbles(Dev::KeyYs[7][1]) ^ Dev::KeyNormals[18][12];
			Dev::NCCHKeys[2][14]    = (swapnibbles(Dev::KeyYs[3][11]) ^ bytenot(Dev::KeyYs[2][14])) + lo_nibble(Dev::KeyXs[3][3]) ^ bytenot(Dev::KeyXs[7][8]);
			Dev::NCCHKeys[1][14]    = (bytenot(Dev::KeyXs[4][4]) ^ hi_nibble(Dev::KeyNormals[8][1])) - swapnibbles(Dev::KeyNormals[8][8]) ^ Dev::KeyXs[0][12];
			Dev::NCCHKeys[0][14]    = bytenot(hi_nibble(Dev::KeyNormals[3][6])) + swapnibbles(Dev::KeyXs[1][8]) - bytenot(Dev::KeyNormals[0][9]) ^ hi_mask_nibble(bytenot(Dev::KeyNormals[9][3]));
			Dev::NCCHKeys[2][13]    = bytenot(Dev::KeyXs[0][5]) ^ hi_nibble(Dev::KeyYs[3][14]) ^ swapnibbles(Dev::KeyYs[7][12]) ^ Dev::KeyYs[0][7];
			Dev::NCCHKeys[1][13]    = bytenot(hi_nibble(Dev::KeyXs[3][15])) + swapnibbles(Dev::KeyXs[2][1]) - bytenot(Dev::KeyYs[7][5]) ^ hi_mask_nibble(bytenot(Dev::KeyNormals[14][13]));
			Dev::NCCHKeys[0][13]    = (swapnibbles(Dev::KeyYs[0][10]) ^ bytenot(Dev::KeyYs[5][10])) + lo_nibble(Dev::KeyNormals[7][12]) ^ bytenot(Dev::KeyXs[3][2]);
			Dev::NCCHKeys[2][12]    = bytenot(hi_nibble(Dev::KeyYs[3][10])) + swapnibbles(Dev::KeyYs[5][14]) - bytenot(Dev::KeyYs[7][9]) ^ hi_mask_nibble(bytenot(Dev::KeyNormals[8][2]));
			Dev::NCCHKeys[1][12]    = bytenot(Dev::KeyYs[3][5]) ^ hi_nibble(Dev::KeyXs[2][9]) ^ swapnibbles(Dev::KeyYs[4][5]) ^ Dev::KeyNormals[13][4];
			Dev::NCCHKeys[0][12]    = swapnibbles(Dev::KeyYs[5][9]) * bytenot(Dev::KeyXs[3][13]) + lo_nibble(Dev::KeyXs[1][8]) ^ bytenot(Dev::KeyNormals[7][5]);
			Dev::NCCHKeys[2][11]    = (swapnibbles(Dev::KeyNormals[2][6]) ^ bytenot(Dev::KeyXs[5][9])) + lo_nibble(Dev::KeyYs[7][2]) ^ bytenot(Dev::KeyXs[6][6]);
			Dev::NCCHKeys[1][11]    = bytenot(Dev::KeyXs[7][12]) ^ hi_nibble(Dev::KeyNormals[4][8]) ^ swapnibbles(Dev::KeyNormals[14][9]) ^ Dev::KeyYs[1][15];
			Dev::NCCHKeys[0][11]    = bytenot(Dev::KeyXs[2][6]) ^ hi_nibble(Dev::KeyXs[1][14]) ^ swapnibbles(Dev::KeyYs[6][10]) ^ Dev::KeyXs[5][13];
			Dev::NCCHKeys[2][10]    = bytenot(hi_nibble(Dev::KeyXs[0][10])) + swapnibbles(Dev::KeyYs[0][10]) - bytenot(Dev::KeyYs[2][0]) ^ hi_mask_nibble(bytenot(Dev::KeyNormals[8][3]));
			Dev::NCCHKeys[1][10]    = bytenot(hi_nibble(Dev::KeyNormals[12][13])) + swapnibbles(Dev::KeyXs[7][7]) - bytenot(Dev::KeyYs[6][2]) ^ hi_mask_nibble(bytenot(Dev::KeyYs[3][3]));
			Dev::NCCHKeys[0][10]    = (swapnibbles(Dev::KeyYs[1][1]) ^ bytenot(Dev::KeyYs[3][4])) + lo_nibble(Dev::KeyNormals[9][14]) ^ bytenot(Dev::KeyXs[7][0]);
			Dev::NCCHKeys[2][9]     = (bytenot(Dev::KeyNormals[18][0]) ^ hi_nibble(Dev::KeyXs[5][15])) - swapnibbles(Dev::KeyYs[1][9]) ^ Dev::KeyXs[3][0];
			Dev::NCCHKeys[1][9]     = (swapnibbles(Dev::KeyXs[1][1]) ^ bytenot(Dev::KeyNormals[10][9])) + lo_nibble(Dev::KeyNormals[6][1]) ^ bytenot(Dev::KeyXs[7][9]);
			Dev::NCCHKeys[0][9]     = (swapnibbles(Dev::KeyNormals[15][2]) ^ bytenot(Dev::KeyXs[1][15])) + lo_nibble(Dev::KeyNormals[10][12]) ^ bytenot(Dev::KeyNormals[13][4]);
			Dev::NCCHKeys[2][8]     = bytenot(Dev::KeyNormals[3][13]) ^ hi_nibble(Dev::KeyNormals[10][1]) ^ swapnibbles(Dev::KeyYs[3][13]) ^ Dev::KeyYs[0][8];
			Dev::NCCHKeys[1][8]     = (bytenot(Dev::KeyXs[6][0]) ^ hi_nibble(Dev::KeyYs[2][9])) - swapnibbles(Dev::KeyNormals[14][3]) ^ Dev::KeyYs[3][2];
			Dev::NCCHKeys[0][8]     = bytenot(hi_nibble(Dev::KeyNormals[19][13])) + swapnibbles(Dev::KeyYs[6][10]) - bytenot(Dev::KeyNormals[3][2]) ^ hi_mask_nibble(bytenot(Dev::KeyYs[5][6]));
			Dev::NCCHKeys[2][7]     = bytenot(hi_nibble(Dev::KeyXs[7][2])) + swapnibbles(Dev::KeyXs[3][7]) - bytenot(Dev::KeyXs[6][10]) ^ hi_mask_nibble(bytenot(Dev::KeyNormals[7][1]));
			Dev::NCCHKeys[1][7]     = bytenot(hi_nibble(Dev::KeyYs[0][1])) + swapnibbles(Dev::KeyXs[5][14]) - bytenot(Dev::KeyYs[4][5]) ^ hi_mask_nibble(bytenot(Dev::KeyNormals[10][2]));
			Dev::NCCHKeys[0][7]     = swapnibbles(Dev::KeyNormals[16][5]) * bytenot(Dev::KeyXs[1][0]) + lo_nibble(Dev::KeyYs[2][6]) ^ bytenot(Dev::KeyXs[3][4]);
			Dev::NCCHKeys[2][6]     = bytenot(hi_nibble(Dev::KeyXs[2][12])) + swapnibbles(Dev::KeyNormals[5][5]) - bytenot(Dev::KeyYs[6][7]) ^ hi_mask_nibble(bytenot(Dev::KeyYs[7][12]));
			Dev::NCCHKeys[1][6]     = (bytenot(Dev::KeyXs[2][9]) ^ hi_nibble(Dev::KeyXs[0][14])) - swapnibbles(Dev::KeyXs[6][4]) ^ Dev::KeyNormals[1][2];
			Dev::NCCHKeys[0][6]     = (swapnibbles(Dev::KeyYs[3][13]) ^ bytenot(Dev::KeyNormals[15][10])) + lo_nibble(Dev::KeyYs[0][7]) ^ bytenot(Dev::KeyXs[0][2]);
			Dev::NCCHKeys[2][5]     = (bytenot(Dev::KeyXs[2][11]) ^ hi_nibble(Dev::KeyNormals[2][9])) - swapnibbles(Dev::KeyNormals[9][2]) ^ Dev::KeyYs[5][4];
			Dev::NCCHKeys[1][5]     = bytenot(Dev::KeyYs[7][8]) ^ hi_nibble(Dev::KeyYs[1][6]) ^ swapnibbles(Dev::KeyYs[0][13]) ^ Dev::KeyXs[4][10];
			Dev::NCCHKeys[0][5]     = bytenot(hi_nibble(Dev::KeyXs[1][3])) + swapnibbles(Dev::KeyNormals[8][13]) - bytenot(Dev::KeyXs[3][3]) ^ hi_mask_nibble(bytenot(Dev::KeyYs[1][8]));
			Dev::NCCHKeys[2][4]     = bytenot(Dev::KeyYs[7][1]) ^ hi_nibble(Dev::KeyXs[3][4]) ^ swapnibbles(Dev::KeyYs[3][6]) ^ Dev::KeyYs[6][14];
			Dev::NCCHKeys[1][4]     = (swapnibbles(Dev::KeyXs[6][11]) ^ bytenot(Dev::KeyYs[2][11])) + lo_nibble(Dev::KeyNormals[16][12]) ^ bytenot(Dev::KeyXs[3][9]);
			Dev::NCCHKeys[0][4]     = (bytenot(Dev::KeyYs[5][9]) ^ hi_nibble(Dev::KeyYs[4][7])) - swapnibbles(Dev::KeyXs[0][14]) ^ Dev::KeyNormals[13][13];
			Dev::NCCHKeys[2][3]     = swapnibbles(Dev::KeyYs[4][5]) * bytenot(Dev::KeyYs[4][14]) + lo_nibble(Dev::KeyYs[5][1]) ^ bytenot(Dev::KeyNormals[14][12]);
			Dev::NCCHKeys[1][3]     = bytenot(hi_nibble(Dev::KeyXs[0][12])) + swapnibbles(Dev::KeyXs[6][5]) - bytenot(Dev::KeyYs[7][14]) ^ hi_mask_nibble(bytenot(Dev::KeyYs[1][15]));
			Dev::NCCHKeys[0][3]     = (swapnibbles(Dev::KeyXs[0][11]) ^ bytenot(Dev::KeyNormals[15][2])) + lo_nibble(Dev::KeyXs[5][13]) ^ bytenot(Dev::KeyXs[2][3]);
			Dev::NCCHKeys[2][2]     = bytenot(Dev::KeyXs[5][1]) ^ hi_nibble(Dev::KeyYs[6][14]) ^ swapnibbles(Dev::KeyYs[6][15]) ^ Dev::KeyYs[4][12];
			Dev::NCCHKeys[1][2]     = swapnibbles(Dev::KeyNormals[5][13]) * bytenot(Dev::KeyYs[4][3]) + lo_nibble(Dev::KeyXs[5][11]) ^ bytenot(Dev::KeyNormals[5][11]);
			Dev::NCCHKeys[0][2]     = bytenot(hi_nibble(Dev::KeyNormals[12][14])) + swapnibbles(Dev::KeyXs[2][6]) - bytenot(Dev::KeyYs[2][10]) ^ hi_mask_nibble(bytenot(Dev::KeyNormals[15][12]));
			Dev::NCCHKeys[2][1]     = (swapnibbles(Dev::KeyYs[5][11]) ^ bytenot(Dev::KeyNormals[13][15])) + lo_nibble(Dev::KeyYs[3][0]) ^ bytenot(Dev::KeyXs[7][5]);
			Dev::NCCHKeys[1][1]     = (bytenot(Dev::KeyNormals[4][3]) ^ hi_nibble(Dev::KeyYs[3][8])) - swapnibbles(Dev::KeyYs[1][10]) ^ Dev::KeyYs[2][0];
			Dev::NCCHKeys[0][1]     = bytenot(Dev::KeyXs[5][13]) ^ hi_nibble(Dev::KeyNormals[16][14]) ^ swapnibbles(Dev::KeyXs[4][1]) ^ Dev::KeyXs[1][8];
			Dev::NCCHKeys[2][0]     = (bytenot(Dev::KeyNormals[12][11]) ^ hi_nibble(Dev::KeyYs[0][7])) - swapnibbles(Dev::KeyXs[4][14]) ^ Dev::KeyXs[2][15];
			Dev::NCCHKeys[1][0]     = bytenot(Dev::KeyYs[6][13]) ^ hi_nibble(Dev::KeyXs[6][4]) ^ swapnibbles(Dev::KeyXs[4][0]) ^ Dev::KeyNormals[16][7];
			Dev::NCCHKeys[0][0]     = (swapnibbles(Dev::KeyNormals[16][5]) ^ bytenot(Dev::KeyYs[4][12])) + lo_nibble(Dev::KeyYs[1][11]) ^ bytenot(Dev::KeyNormals[1][3]);

			#if defined __GNUC__
			#pragma GCC diagnostic pop
			#elif defined __clang__
			#pragma clang diagnostic pop
			#endif

			u8 shabuf[20];
			bool checkpass = true;
			for(int i = 0; checkpass && i < 8; i++) {
				SHA1(Retail::KeyXs[i], 16, shabuf);
				if(memcmp(shabuf, Retail::SHA1Checksums::KeyXs[i], 20)) {
					checkpass = false;
					break;
				}
				SHA1(Retail::KeyYs[i], 16, shabuf);
				if(memcmp(shabuf, Retail::SHA1Checksums::KeyYs[i], 20)) {
					checkpass = false;
					break;
				}
				SHA1(Dev::KeyXs[i], 16, shabuf);
				if(memcmp(shabuf, Dev::SHA1Checksums::KeyXs[i], 20)) {
					checkpass = false;
					break;
				}
				SHA1(Dev::KeyYs[i], 16, shabuf);
				if(memcmp(shabuf, Dev::SHA1Checksums::KeyYs[i], 20))
					checkpass = false;
			}
			for(int i = 0; checkpass && i < 20; i++) {
				SHA1(Retail::KeyNormals[i], 16, shabuf);
				if(memcmp(shabuf, Retail::SHA1Checksums::KeyNormals[i], 20)) {
					checkpass = false;
					break;
				}
				SHA1(Dev::KeyNormals[i], 16, shabuf);
				if(memcmp(shabuf, Dev::SHA1Checksums::KeyNormals[i], 20))
					checkpass = false;
			}
			for(int i = 0; checkpass && i < 3; i++) {
				SHA1(Retail::NCCHKeys[i], 16, shabuf);
				if(memcmp(shabuf, Retail::SHA1Checksums::NCCHKeys[i], 20)) {
					checkpass = false;
					break;
				}
				SHA1(Dev::NCCHKeys[i], 16, shabuf);
				if(memcmp(shabuf, Dev::SHA1Checksums::NCCHKeys[i], 20))
					checkpass = false;
			}
			for(int i = 0; checkpass && i < 5; i++) {
				SHA1(CommonKeys[i], 16, shabuf);
				if(memcmp(shabuf, SHA1Checksums::CommonKeys[i], 20))
					checkpass = false;
			}
			if(!checkpass) break;
			SHA1(Retail::CommonKey0, 16, shabuf);
			if(memcmp(shabuf, Retail::SHA1Checksums::CommonKey0, 20)) break;
			SHA1(Dev::CommonKey0, 16, shabuf);
			if(memcmp(shabuf, Dev::SHA1Checksums::CommonKey0, 20)) break;
			SHA1(Constant_C, 16, shabuf);
			if(memcmp(shabuf, SHA1Checksums::Constant_C, 20)) break;
			SHA1(TWLConstant, 16, shabuf);
			if(memcmp(shabuf, SHA1Checksums::TWLConstant, 20)) break;
			SHA1(FixedKey, 16, shabuf);
			if(memcmp(shabuf, SHA1Checksums::FixedKey, 20)) break;
			success = true;
		} while(0);
		fseek(fp, startoffset, SEEK_SET);
		return success;
	}
}

bool NintendoData::KeyUtils::Storage::ReloadStorage() {
	FILE* fp = NULL;
	try {
		readwritelock.lock();
	} catch(...) {return loaded;}
	if(loaded) {
		readwritelock.unlock();
		return loaded;
	}
	if(!NintendoData::SharedStorage::Load(fp, "boot9.bin")) {
		if(!fseek(fp, 0x8000, SEEK_SET))
			loaded = ::LoadBoot9Protected(fp);
		fclose(fp);
	}
	if(!loaded && !NintendoData::SharedStorage::Load(fp, "boot9_prot.bin")) {
		loaded = ::LoadBoot9Protected(fp);
		fclose(fp);
	}
	if(!loaded && !NintendoData::SharedStorage::Load(fp, "boot9_protected.bin")) {
		loaded = ::LoadBoot9Protected(fp);
		fclose(fp);
	}
	readwritelock.unlock();
	return loaded;
}

u8* NintendoData::KeyUtils::Storage::GetKey(u8* outkey, int keyslot, NintendoData::KeyUtils::Storage::KeyType type, bool retail) {
	if(!outkey) return NULL;
	if(type != KeyX && type != KeyY && type != KeyNormal) return NULL;
	else if(type == KeyX && (keyslot < 0x2C || keyslot > 0x3F) && keyslot != 0x18 && keyslot != 0x1B && keyslot != 0x25) return NULL;
	else if(type == KeyY && (keyslot < 0x4 || keyslot > 0xB)) return NULL;
	else if(keyslot < 0xC || keyslot > 0x3F) return NULL;
	if(!ReloadStorage()) return NULL;
	const u8* key = NULL;
	if(type == KeyY) {
		key = (retail ? Retail::KeyYs[keyslot-0x4] : Dev::KeyYs[keyslot-0x4]);
	} else if(type == KeyX && (keyslot == 0x18 || keyslot == 0x1B || keyslot == 0x25)) {
		int index = 0;
		switch(keyslot) {
		case 0x18:
			break;
		case 0x1B:
			index = 1;
			break;
		case 0x25:
			index = 2;
			break;
		default:
			break;
		}
		key = (retail ? Retail::NCCHKeys[index] : Dev::NCCHKeys[index]);
	} else if(type == KeyX) {
		int index;
		if(keyslot >= 0x2C && keyslot < 0x30) index = 0;
		else if(keyslot >= 0x30 && keyslot < 0x34) index = 1;
		else if(keyslot >= 0x34 && keyslot < 0x38) index = 2;
		else if(keyslot >= 0x38 && keyslot < 0x3C) index = 3;
		else index = keyslot - 0x38;
		key = (retail ? Retail::KeyXs[index] : Dev::KeyXs[index]);
	} else {
		int index;
		if(keyslot >= 0xC && keyslot < 0x10) index = 0;
		else if(keyslot >= 0x10 && keyslot < 0x14) index = 1;
		else if(keyslot >= 0x14 && keyslot < 0x18) index = keyslot - 0x12;
		else if(keyslot >= 0x18 && keyslot < 0x1C) index = 6;
		else if(keyslot >= 0x1C && keyslot < 0x20) index = 7;
		else if(keyslot >= 0x20 && keyslot < 0x24) index = 8;
		else if(keyslot >= 0x24 && keyslot < 0x29) index = 9;
		else if(keyslot >= 0x29 && keyslot < 0x2C) index = keyslot - 0x1F;
		else if(keyslot >= 0x2C && keyslot < 0x30) index = 13;
		else if(keyslot >= 0x30 && keyslot < 0x34) index = 14;
		else if(keyslot >= 0x34 && keyslot < 0x38) index = 15;
		else if(keyslot >= 0x38 && keyslot < 0x3D) index = 16;
		else index = keyslot - 0x2C;
		key = (retail ? Retail::KeyNormals[index] : Dev::KeyNormals[index]);
	}
	memcpy(outkey, key, 16);
	return outkey;
}

u8* NintendoData::KeyUtils::Storage::GetCommonKey(u8* outkey, int index, bool retail) {
	if(index < 0 || index > 5) return NULL;
	if(!ReloadStorage()) return NULL;
	const u8* key = NULL;
	if(index == 0) key = (retail ? Retail::CommonKey0 : Dev::CommonKey0);
	else key = CommonKeys[index-1];
	memcpy(outkey, key, 16);
	return outkey;
}

bool NintendoData::KeyUtils::TWLScrambler(u8* outnormal, const u8* keyX, const u8* keyY) {
	if(!outnormal || !keyX || !keyY) return false;
	if(!Storage::ReloadStorage()) return false;
	u8 xoredkeys[16];
	// xoring now without BN because it doesn't give me an XOR implementation
	for(int i = 0; i < 16; i++) {
		xoredkeys[i] = keyX[i] ^ keyY[i];
	}
	// keyX and keyY are taken in little endian
	BIGNUM* workkey1 = BN_lebin2bn(xoredkeys, 16, NULL);
	if(!workkey1) return false;
	BIGNUM* workkey2 = BN_bin2bn(TWLConstant, 16, NULL);
	if(!workkey2) {
		BN_clear_free(workkey1);
		return false;
	}
	bool success = false;
	do {
		if(!workkey1 || !workkey2) break;
		if(!BN_add(workkey1, workkey1, workkey2)) break;
		if(BN_num_bits(workkey1) > 128)
			BN_mask_bits(workkey1, 128);
		if(!BN_lshift(workkey2, workkey1, 42)) break;
		if(!BN_rshift(workkey1, workkey1, 86)) break;
		if(!BN_add(workkey1, workkey1, workkey2)) break;
		if(BN_bn2binpad(workkey1, outnormal, 16) != 16) break;
		success = true;
	} while(0);
	BN_clear_free(workkey1);
	BN_clear_free(workkey2);
	return success;
}

bool NintendoData::KeyUtils::CTRScrambler(u8* outnormal, const u8* keyX, const u8* keyY) {
	if(!outnormal || !keyX || !keyY) return false;
	if(!Storage::ReloadStorage()) return false;
	BIGNUM* workkey1 = BN_bin2bn(keyX, 16, NULL);
	if(!workkey1) return false;
	BIGNUM* workkey2 = BN_new();
	if(!workkey2) {
		BN_clear_free(workkey1);
		return false;
	}
	bool success = false;
	do {
		if(!workkey1 || !workkey2) break;
		if(!BN_lshift(workkey2, workkey1, 2)) break;
		if(BN_num_bits(workkey2) > 128)
			BN_mask_bits(workkey2, 128);
		if(!BN_rshift(workkey1, workkey1, 126)) break;
		if(!BN_add(workkey1, workkey1, workkey2)) break;
		u64 buffer[2][2];
		if(BN_bn2binpad(workkey1, (u8*)&buffer[0], 16) != 16) break;
		memcpy(&buffer[1], keyY, 16);
		buffer[0][0] ^= buffer[1][0];
		buffer[0][1] ^= buffer[1][1];
		if(!BN_bin2bn((u8*)&buffer[0], 16, workkey1)) break;
		if(!BN_bin2bn(Constant_C, 16, workkey2)) break;
		if(!BN_add(workkey1, workkey1, workkey2)) break;
		if(BN_num_bits(workkey1) > 128)
			BN_mask_bits(workkey1, 128);
		if(!BN_lshift(workkey2, workkey1, 87)) break;
		if(BN_num_bits(workkey2) > 128)
			BN_mask_bits(workkey2, 128);
		if(!BN_rshift(workkey1, workkey1, 41)) break;
		if(!BN_add(workkey1, workkey1, workkey2)) break;
		if(BN_bn2binpad(workkey1, outnormal, 16) != 16) break;
		success = true;
	} while(0);
	BN_clear_free(workkey1);
	BN_clear_free(workkey2);
	return success;
}

void NintendoData::KeyUtils::SeedKeyY(u8* keyY, const u8* seed) {
	u8 shabuf[32];
	u8 keyseed[32];
	memcpy(keyseed, keyY, 16);
	memcpy(keyseed+16, seed, 16);
	SHA256(keyseed, 32, shabuf);
	memcpy(keyY, shabuf, 16);
}

void NintendoData::AESEngine::CrypterContext::ResetIV(const u8* iv) {
	if(_mode == ECB) return;
	if(!iv)
		throw std::invalid_argument("Cipher expected IV.");
	if(!EVP_CIPHER_CTX_reset((EVP_CIPHER_CTX*)context))
		throw std::runtime_error("Unexpected error from context reset.");
	const EVP_CIPHER *(*ciphername)() = nullptr;
	switch(_mode) {
	case CTR:
		ciphername = &EVP_aes_128_ctr;
		break;
	case CBC:
		ciphername = &EVP_aes_128_cbc;
		break;
	default:
		break;
	}
	if(!EVP_CipherInit_ex((EVP_CIPHER_CTX*)context, ciphername(), NULL, _key, iv, (int)_encrypt))
		throw std::runtime_error("CrypterContext unable to init context and is now in invalid state.");
}

void NintendoData::AESEngine::CrypterContext::Cipher(u8* dataout, const u8* datain, int length) {
	if(length < 0)
		throw std::invalid_argument("CrypterContext got negative length.");
	if(length % 16)
		throw std::invalid_argument("CrypterContext expected length divisable by 16.");
	int outlength;
	if(!EVP_CipherUpdate((EVP_CIPHER_CTX*)context, dataout, &outlength, datain, length))
		throw std::runtime_error("CrypterContext cipher error.");
	if(outlength != length)
		throw std::runtime_error("CrypterContext only supports full chunks at a time, but unexpected length was returned.");
}

NintendoData::AESEngine::CrypterContext::CrypterContext(NintendoData::AESEngine::Modes mode, const u8* key, const u8* iv, bool encrypt) {
	const EVP_CIPHER *(*ciphername)() = nullptr;
	switch(mode) {
	case CTR:
		ciphername = &EVP_aes_128_ctr;
		break;
	case CBC:
		ciphername = &EVP_aes_128_cbc;
		break;
	case ECB:
		ciphername = &EVP_aes_128_ecb;
		break;
	}
	memcpy(_key, key, 16);
	_mode = mode;
	_encrypt = encrypt;
	EVP_CIPHER_CTX *_context = EVP_CIPHER_CTX_new();
	if(!context)
		throw std::runtime_error("CrypterContext unable to allocate context.");
	try {
		if(!EVP_CipherInit_ex(_context, ciphername(), NULL, key, iv, (int)encrypt))
			throw std::runtime_error("CrypterContext unable to init context.");
		if(EVP_CIPHER_CTX_key_length(_context) != 16)
			throw std::runtime_error("CrypterContext unexpected key length.");
		if(mode != ECB && EVP_CIPHER_CTX_iv_length(_context) != 16)
			throw std::runtime_error("CrypterContext unexpected iv length.");
		EVP_CIPHER_CTX_set_padding(_context, 0);
	} catch (...) {
		EVP_CIPHER_CTX_free(_context);
		throw;
	}
	context = (void*)_context;
}

NintendoData::AESEngine::CrypterContext::~CrypterContext() {
	EVP_CIPHER_CTX_free((EVP_CIPHER_CTX*)context);
}

template<const EVP_CIPHER *(*ciphername)(), bool has_iv, bool encrypt>
static inline bool cipher(u8* out, const u8* data, int length, const u8* key, const u8* iv) {
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	if(!ctx) return false;
    bool ret = false;
    do {
        if(!EVP_CipherInit_ex(ctx, ciphername(), NULL, key, has_iv ? iv : NULL, (int)encrypt)) break;
        if(EVP_CIPHER_CTX_key_length(ctx) != 16) break;
        if(has_iv && EVP_CIPHER_CTX_iv_length(ctx) != 16) break;
        EVP_CIPHER_CTX_set_padding(ctx, 0);
        int foo;
        if(!EVP_CipherUpdate(ctx, out, &foo, data, length)) break;
        if(!EVP_CipherFinal_ex(ctx, out + foo, &foo)) break;
        ret = true;
    } while(0);
    EVP_CIPHER_CTX_free(ctx);
	return ret;
}

#define CTR_Encrypt cipher<&EVP_aes_128_ctr, true, true>
#define CTR_Decrypt cipher<&EVP_aes_128_ctr, true, false>
#define CBC_Encrypt cipher<&EVP_aes_128_cbc, true, true>
#define CBC_Decrypt cipher<&EVP_aes_128_cbc, true, false>
#define ECB_Encrypt cipher<&EVP_aes_128_ecb, false, true>
#define ECB_Decrypt cipher<&EVP_aes_128_ecb, false, false>

NintendoData::AESEngine& NintendoData::AESEngine::operator=(NintendoData::AESEngine&& other) {
	if(this == &other) return *this;
	std::swap(this->keyslots, other.keyslots);
	this->retail = other.retail;
	memset(other.keyslots, 0, sizeof(*other.keyslots));
	other.ReloadFromKeyStorage();
	return *this;
}

NintendoData::AESEngine& NintendoData::AESEngine::operator=(const NintendoData::AESEngine& other) {
	if(this == &other) return *this;
	memcpy(this->keyslots, other.keyslots, sizeof(*keyslots));
	this->retail = other.retail;
	return *this;
}

void NintendoData::AESEngine::Cipher(NintendoData::AESEngine::Modes mode, int keyslot, const u8* iv, u8* out, const u8* data, int length, bool encrypt) {
	if(length < 0 || length & 0xF)
		throw std::invalid_argument("AESEngine encountered invalid data length.");
	if(!out || !data)
		throw std::invalid_argument("AESEngine encountered NULL data in or out pointer.");
	if(mode != ECB && !iv)
		throw std::invalid_argument("AESEngine cipher expected IV.");
	if(keyslot < 0 || keyslot >= 0x40)
		throw std::invalid_argument("AESEngine invalid keyslot.");
	u8 (&_keyslots)[3][64][16] = *keyslots;
	bool ret;
	switch(mode) {
	case CTR:
		ret = (encrypt ? CTR_Encrypt(out, data, length, _keyslots[2][keyslot], iv) : CTR_Decrypt(out, data, length, _keyslots[2][keyslot], iv));
		break;
	case CBC:
		ret = (encrypt ? CBC_Encrypt(out, data, length, _keyslots[2][keyslot], iv) : CBC_Decrypt(out, data, length, _keyslots[2][keyslot], iv));
		break;
	case ECB:
		ret = (encrypt ? ECB_Encrypt(out, data, length, _keyslots[2][keyslot], iv) : ECB_Decrypt(out, data, length, _keyslots[2][keyslot], iv));
		break;
	default:
		throw std::invalid_argument("AESEngine unknown engine.");
	}
	if(!ret)
		throw std::runtime_error("AESEngine cipher fail.");
}

NintendoData::AESEngine& NintendoData::AESEngine::SetKey(NintendoData::KeyUtils::Storage::KeyType type, int keyslot, const u8* key, const u8* seed) {
	if(type != KeyUtils::Storage::KeyX && type != KeyUtils::Storage::KeyY && type != KeyUtils::Storage::KeyNormal)
		throw std::invalid_argument("AESEngine invalid key type.");
	if(keyslot < 0 || keyslot >= 0x40)
		throw std::invalid_argument("AESEngine invalid keyslot.");
	if(!key)
		throw std::invalid_argument("AESEngine encountered NULL key pointer.");
	u8 keycopy[16];
	memcpy(keycopy, key, 16);
	if(type == KeyUtils::Storage::KeyY && seed)
		KeyUtils::SeedKeyY(keycopy, seed);
	memcpy((*keyslots)[type][keyslot], keycopy, 16);
	if(type != KeyUtils::Storage::KeyNormal) {
		bool ret;
		if(keyslot >= 4) ret = KeyUtils::CTRScrambler((*keyslots)[2][keyslot], (*keyslots)[0][keyslot], (*keyslots)[1][keyslot]);
		else ret = KeyUtils::TWLScrambler((*keyslots)[2][keyslot], (*keyslots)[0][keyslot], (*keyslots)[1][keyslot]);
		if(!ret)
			throw std::runtime_error("AESEngine Scrambler error.");
	}
	return *this;
}

NintendoData::AESEngine& NintendoData::AESEngine::SetCommon(int commonindex) {
	if(commonindex < 0 || commonindex > 5)
		throw std::invalid_argument("AESEngine invalid common index.");
	if(!KeyUtils::Storage::ReloadStorage())
		throw std::runtime_error("AESEngine couldn't get common key.");
	u8* key = KeyUtils::Storage::GetCommonKey((*keyslots)[1][0x3D], commonindex, retail);
	if(!key)
		throw std::runtime_error("AESEngine couldn't get common key.");
	if(KeyUtils::CTRScrambler((*keyslots)[2][0x3D], (*keyslots)[0][0x3D], (*keyslots)[1][0x3D]))
		throw std::runtime_error("AESEngine Scrambler error.");
	return *this;
}

NintendoData::AESEngine& NintendoData::AESEngine::SetFixedKey(int keyslot) {
	if(keyslot < 0 || keyslot >= 0x40)
		throw std::invalid_argument("AESEngine invalid keyslot.");
	if(!KeyUtils::Storage::ReloadStorage())
		throw std::runtime_error("AESEngine couldn't get fixed key.");
	memcpy((*keyslots)[2][keyslot], FixedKey, 16);
	return *this;
}

NintendoData::AESEngine& NintendoData::AESEngine::SetEncTitleKey(const u8* key, u64 titleid, int commonindex) {
	if(!key)
		throw std::invalid_argument("AESEngine encountered NULL key pointer.");
	u64 iv[2] = {Endian::Be(titleid), 0};
	SetCommon(commonindex);
	if(!CBC_Decrypt((*keyslots)[2][0x11], key, 16, (*keyslots)[2][0x3D], (u8*)&iv))
		throw std::runtime_error("AESEngine cipher fail.");
	return *this;
}

NintendoData::AESEngine::CrypterContext NintendoData::AESEngine::GetCrypterContext(NintendoData::AESEngine::Modes mode, int keyslot, const u8* iv, bool encrypt) {
	if(mode != CTR && mode != CBC && mode != ECB)
		throw std::invalid_argument("AESEngine unknown engine.");
	if(keyslot < 0 || keyslot >= 0x40)
		throw std::invalid_argument("AESEngine invalid keyslot.");
	if(mode != ECB && !iv)
		throw std::invalid_argument("AESEngine cipher expected IV.");
	return CrypterContext(mode, (*keyslots)[2][keyslot], iv, encrypt ? true : false);
}

bool NintendoData::AESEngine::ReloadFromKeyStorage() {
	if(!KeyUtils::Storage::ReloadStorage()) return false;
	u8 (&_keyslots)[3][64][16] = *keyslots;
	memcpy(_keyslots[1][4], retail ? Retail::KeyYs : Dev::KeyYs, sizeof(Retail::KeyYs));
	memcpy(_keyslots[0][0x18], retail ? Retail::NCCHKeys[0] : Dev::NCCHKeys[0], 16);
	memcpy(_keyslots[0][0x1B], retail ? Retail::NCCHKeys[1] : Dev::NCCHKeys[1], 16);
	memcpy(_keyslots[0][0x25], retail ? Retail::NCCHKeys[2] : Dev::NCCHKeys[2], 16);
	for(int i = 0; i < 4; i++) {
		for(int j = 0; j < 4; j++)
			memcpy(_keyslots[0][0x2C+i*4+j], retail ? Retail::KeyXs[i] : Dev::KeyXs[i], 16);
	}
	memcpy(_keyslots[0][0x3C], retail ? Retail::KeyXs[4] : Dev::KeyXs[4], 16*4);
	for(int i = 0; i < 2; i++) {
		for(int j = 0; j < 4; j++)
			memcpy(_keyslots[2][0xC+i*4+j], retail ? Retail::KeyNormals[i] : Dev::KeyNormals[i], 16);
	}
	memcpy(_keyslots[2][0x14], retail ? Retail::KeyNormals[2] : Dev::KeyNormals[2], 16*4);
	for(int i = 0; i < 4; i++) {
		for(int j = 0; j < 4; j++)
			memcpy(_keyslots[2][0x18+i*4+j], retail ? Retail::KeyNormals[6+i] : Dev::KeyNormals[6+i], 16);
	}
	memcpy(_keyslots[2][0x28], retail ? Retail::KeyNormals[9] : Dev::KeyNormals[9], 16*4);
	for(int i = 0; i < 4; i++) {
		for(int j = 0; j < 4; j++)
			memcpy(_keyslots[2][0x2C+i*4+j], retail ? Retail::KeyNormals[13+i] : Dev::KeyNormals[13+i], 16);
	}
	memcpy(_keyslots[2][0x3C], retail ? Retail::KeyNormals[16] : Dev::KeyNormals[16], 16*4);
	return true;
}

NintendoData::AESEngine::AESEngine(bool _retail, bool keysneeded) : keyslots(NULL), retail(_retail) {
	keyslots = (u8 (*)[3][64][16])calloc(sizeof(*keyslots), 1);
	if(!keyslots) throw std::bad_alloc();
	if(!ReloadFromKeyStorage() && keysneeded) {
		free(keyslots);
		throw std::runtime_error("AESEngine expected keys couldn't be loaded.");
	}
}

NintendoData::AESEngine::~AESEngine() {
	free(keyslots);
	keyslots = nullptr;
}
