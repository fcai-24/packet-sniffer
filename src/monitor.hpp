#pragma once

#include <set>
#include <unordered_map>
#include "core/core.hpp"
#include "core/log.hpp"
#include "imgui.h"
#include "ImNodeFlow.h"

namespace ps {
	typedef enum {
		SECURITY_NONE,
		SECURITY_WEP,
		SECURITY_WPA,
		SECURITY_WPA2,
		SECURITY_WPA3,
		SECURITY_UNKNOWN
	} SecurityType;

	struct WifiNetwork {
		std::string ssid;
		std::string bssid;
		u16 channel = 0;
		i8 signal_strength = 0;
		SecurityType security = SECURITY_UNKNOWN;
	};

	const char* SecurityTypeToString(SecurityType type);
	bool is_ieee802_11_packet(const uint8_t *packet, size_t packet_length);
	// Function to check if the packet is a beacon
	bool is_beacon(const uint8_t *packet, size_t packet_length, size_t *radiotap_length);
	bool extract_ssid(
			const uint8_t *packet,
			size_t packet_length,
			size_t radiotap_length,
			char *ssid,
			size_t ssid_max_length);

	bool extract_bssid(
			const uint8_t *packet,
			size_t packet_length,
			size_t radiotap_length,
			char *bssid,
			size_t bssid_max_length);

	bool extract_signal_strength(
			const uint8_t *packet, size_t packet_length, int8_t *signal_strength);

	bool extract_channel(const uint8_t *packet, size_t packet_length, uint16_t *channel);

	bool extract_security_type(
			const uint8_t *packet, size_t packet_length, size_t radiotap_length, SecurityType *security);

	class MonitorMode {
	public:
		void parse_packet(const u8 *packet, size_t packet_length) {
			if (!is_ieee802_11_packet(packet, packet_length)) return;

			size_t radiotap_len;
			if (!is_beacon(packet, packet_length, &radiotap_len)) return;

			char ssid[33];
			char bssid[20];
			i8 signal;
			u16 channel;
			SecurityType security;

			extract_ssid(packet, packet_length, radiotap_len, ssid, 33);
			extract_bssid(packet, packet_length, radiotap_len, bssid, 20);
			extract_signal_strength(packet, packet_length, &signal);
			extract_channel(packet, packet_length, &channel);
			extract_security_type(packet, packet_length, radiotap_len, &security);

			WifiNetwork network{
					.ssid = ssid,
					.bssid = bssid,
					.channel = channel,
					.signal_strength = signal,
					.security = security,
			};

			networks[bssid] = network;
		}

		void draw() {
			ImGui::Begin("Monitor Mode");
			for (auto &pair : networks) {
				const WifiNetwork &network = pair.second;
				if (ImGui::CollapsingHeader((network.ssid + "##").c_str())) {
					ImGui::Indent();

					// Display BSSID
					ImGui::Text("BSSID: %s", network.bssid.c_str());

					// Display Signal Strength with a colored bar
					ImGui::Text("Signal Strength: %d dBm", network.signal_strength);
					float signalPercentage =
							(network.signal_strength + 100) / 100.0f;		 // Assuming range is -100 to 0 dBm
					ImGui::ProgressBar(signalPercentage, ImVec2(-1, 0), "");

					// Display Channel
					ImGui::Text("Channel: %d", network.channel);

					// Display Security Type
					ImGui::Text("Security: %s", SecurityTypeToString(network.security));

					ImGui::Unindent();
					ImGui::Separator();
				};
			}
			ImGui::End();
		}

	private:
		std::unordered_map<std::string, WifiNetwork> networks;
	};

}		 // namespace ps
