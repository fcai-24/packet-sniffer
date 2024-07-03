#include "monitor.hpp"

namespace ps {
	bool is_ieee802_11_packet(const uint8_t *packet, size_t packet_length) {
		// Check if the packet is long enough to contain the frame control field
		if (packet_length < 2) { return false; }

		// Extract the frame control field (first 2 bytes)
		uint16_t frame_control = (packet[0] | (packet[1] << 8));

		// Check if the type and subtype fields indicate an IEEE 802.11 packet
		uint8_t type = (frame_control >> 2) & 0x3;
		uint8_t subtype = (frame_control >> 4) & 0xF;

		// IEEE 802.11 management frames have type 0, control frames have type 1, and data frames have
		// type 2
		if (type <= 2) { return true; }

		return false;
	}

	bool is_beacon(const uint8_t *packet, size_t packet_length, size_t *radiotap_length) {
		if (!packet || packet_length < 24 || !radiotap_length) { return false; }

		// Get Radiotap header length
		*radiotap_length = *(uint16_t *)(packet + 2);
		if (packet_length < *radiotap_length + 24) { return false; }

		// Check frame control field (at radiotap_length offset)
		uint8_t frame_control = packet[*radiotap_length];
		return ((frame_control & 0x0C) == 0x00 && (frame_control & 0xF0) == 0x80);
	}

	bool extract_ssid(
			const uint8_t *packet,
			size_t packet_length,
			size_t radiotap_length,
			char *ssid,
			size_t ssid_max_length) {
		if (!packet || !ssid || ssid_max_length == 0 || packet_length < radiotap_length + 36) {
			return false;
		}

		const uint8_t *pos = packet + radiotap_length + 36;		 // Skip to tags
		size_t remaining = packet_length - radiotap_length - 36;

		while (remaining >= 2) {
			uint8_t tag_number = *pos;
			uint8_t tag_length = *(pos + 1);

			if (tag_number == 0 && tag_length < remaining - 2) {
				if (tag_length == 0 || (tag_length == 1 && *(pos + 2) == 0)) {
					strncpy(ssid, "<hidden>", ssid_max_length - 1);
				} else {
					size_t copy_length =
							(tag_length < ssid_max_length - 1) ? tag_length : (ssid_max_length - 1);
					memcpy(ssid, pos + 2, copy_length);
					ssid[copy_length] = '\0';
				}
				return true;
			}

			if (remaining < 2 + tag_length) { break; }

			pos += 2 + tag_length;
			remaining -= 2 + tag_length;
		}

		strncpy(ssid, "<hidden>", ssid_max_length - 1);
		ssid[ssid_max_length - 1] = '\0';
		return true;
	}

	bool extract_bssid(
			const uint8_t *packet,
			size_t packet_length,
			size_t radiotap_length,
			char *bssid,
			size_t bssid_max_length) {
		if (!packet || !bssid || bssid_max_length < 18 || packet_length < radiotap_length + 24) {
			return false;
		}

		const uint8_t *bssid_pos = packet + radiotap_length + 16;		 // BSSID starts at this offset
		snprintf(
				bssid,
				bssid_max_length,
				"%02X:%02X:%02X:%02X:%02X:%02X",
				bssid_pos[0],
				bssid_pos[1],
				bssid_pos[2],
				bssid_pos[3],
				bssid_pos[4],
				bssid_pos[5]);
		return true;
	}

	bool extract_signal_strength(
			const uint8_t *packet, size_t packet_length, int8_t *signal_strength) {
		if (!packet || packet_length < 8 || !signal_strength) { return false; }

		uint16_t radiotap_length = *(uint16_t *)(packet + 2);
		uint32_t present_flags = *(uint32_t *)(packet + 4);

		if (packet_length < radiotap_length) { return false; }

		// Check if DBM_ANTSIGNAL flag is present (bit 5)
		if (!(present_flags & (1 << 5))) { return false; }

		// Count the number of set bits before DBM_ANTSIGNAL to determine its position
		int offset = 8;		 // Start after the presence flags
		for (int i = 0; i < 5; i++) {
			if (present_flags & (1 << i)) {
				switch (i) {
					case 0: offset += 8; break;		 // TSFT
					case 1: offset += 1; break;		 // Flags
					case 2: offset += 1; break;		 // Rate
					case 3: offset += 4; break;		 // Channel
					case 4: offset += 2; break;		 // FHSS
				}
			}
		}

		if (offset >= radiotap_length) { return false; }

		*signal_strength = (int8_t)packet[offset];
		return true;
	}

	bool extract_channel(const uint8_t *packet, size_t packet_length, uint16_t *channel) {
		if (!packet || packet_length < 8 || !channel) { return false; }

		uint16_t radiotap_length = *(uint16_t *)(packet + 2);
		uint32_t present_flags = *(uint32_t *)(packet + 4);

		if (packet_length < radiotap_length) { return false; }

		// Check if Channel flag is present (bit 3)
		if (!(present_flags & (1 << 3))) { return false; }

		// Count the number of set bits before Channel to determine its position
		int offset = 8;		 // Start after the presence flags
		for (int i = 0; i < 3; i++) {
			if (present_flags & (1 << i)) {
				switch (i) {
					case 0: offset += 8; break;		 // TSFT
					case 1: offset += 1; break;		 // Flags
					case 2: offset += 1; break;		 // Rate
				}
			}
		}

		if (offset + 4 > radiotap_length) { return false; }

		uint16_t frequency = *(uint16_t *)(packet + offset);

		// Convert frequency to channel
		if (frequency >= 2412 && frequency <= 2484) {
			*channel = (frequency - 2412) / 5 + 1;
		} else if (frequency >= 5170 && frequency <= 5825) {
			*channel = (frequency - 5170) / 5 + 34;
		} else {
			// Frequency out of known ranges
			return false;
		}

		return true;
	}

	bool extract_security_type(
			const uint8_t *packet, size_t packet_length, size_t radiotap_length, SecurityType *security) {
		if (!packet || packet_length < radiotap_length + 36 || !security) { return false; }

		*security = SECURITY_NONE;

		// Get to the capability info field (2 bytes)
		const uint8_t *cap_info = packet + radiotap_length + 34;
		uint16_t capability = (cap_info[1] << 8) | cap_info[0];

		// Check if Privacy bit is set
		if (capability & (1 << 4)) {
			*security = SECURITY_WEP;		 // Assume WEP initially if Privacy bit is set
		}

		// Move to the tagged parameters
		const uint8_t *pos = packet + radiotap_length + 36;
		size_t remaining = packet_length - (radiotap_length + 36);

		// Look for RSN (WPA2) or WPA IE
		while (remaining >= 2) {
			uint8_t tag_number = *pos;
			uint8_t tag_length = *(pos + 1);

			if (tag_number == 48 && tag_length >= 4) {		// RSN IE
				*security = SECURITY_WPA2;
				// Check for WPA3 (SAE Authentication)
				if (tag_length >= 8) {
					uint32_t akm_suites = *(uint32_t *)(pos + tag_length - 2);
					if (akm_suites == 0x000FAC08) {		 // SAE Authentication
						*security = SECURITY_WPA3;
					}
				}
				return true;
			} else if (tag_number == 221 && tag_length >= 8) {		// Vendor Specific IE
				if (memcmp(pos + 2, "\x00\x50\xF2\x01", 4) == 0) {		// Microsoft WPA IE
					*security = SECURITY_WPA;
					return true;
				}
			}

			if (remaining < 2 + tag_length) { break; }

			pos += 2 + tag_length;
			remaining -= 2 + tag_length;
		}

		return true;
	}

	const char *SecurityTypeToString(SecurityType type) {
		switch (type) {
			case SECURITY_NONE: return "None";
			case SECURITY_WEP: return "WEP";
			case SECURITY_WPA: return "WPA";
			case SECURITY_WPA2: return "WPA2";
			case SECURITY_WPA3: return "WPA3";
			default: return "Unknown";
		}
	}

}		 // namespace ps
