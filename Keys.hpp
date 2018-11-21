#ifndef __KEYS_HPP__
#define __KEYS_HPP__
#include "types.h"

namespace NintendoData {
	namespace KeyUtils {
		namespace Storage {
			enum KeyType {
				KeyX,
				KeyY,
				KeyNormal
			};
			void ReloadStorage();
			const u8* GetKey(int keyslot, KeyType type = KeyX, bool retail = true);
			const u8* GetKeyX(int keyslot, bool retail = true) {return GetKey(keyslot, KeyX, retail);}
			const u8* GetKeyY(int keyslot, bool retail = true) {return GetKey(keyslot, KeyY, retail);}
			const u8* GetKeyNormal(int keyslot, bool retail = true) {return GetKey(keyslot, KeyNormal, retail);}
		}
		bool Scrambler(u8* outnormal, const u8* KeyX, const u8* KeyY);
		bool Scrambler(u8* outnormal, int keyslotX, const u8* keyY, bool retail = true) {
			return Scrambler(outnormal, Storage::GetKeyX(keyslotX, retail), keyY);
		}
		bool Scrambler(u8* outnormal, const u8* keyX, int keyslotY, bool retail = true) {
			return Scrambler(outnormal, keyX, Storage::GetKeyY(keyslotY, retail));
		}
		void SeedKeyY(u8* keyY, const u8* seed);
	}
}
#endif