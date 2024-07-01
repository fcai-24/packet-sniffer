#include <mutex>
#include <optional>
#include <vector>
#include "Packet.h"
#include "ProtocolType.h"
#include "RawPacket.h"
#include "core/core.hpp"
#include "gui-context.hpp"
#include "imgui.h"
#include "PcapLiveDeviceList.h"
#include "gui/imgui_memory_editor.h"
#include <EthLayer.h>
#include <IPv4Layer.h>
#include <IPv6Layer.h>
#include <TcpLayer.h>
#include <UdpLayer.h>
#include <unordered_map>
#include <chrono>
#include <iostream>

#if _WIN32
	#define DEVICE_NAME(d) d->getDesc().c_str()
#else
	#define DEVICE_NAME(d) d->getName().c_str()
#endif

std::mutex packets_lock;

std::string header_str;		 // Declaration for header information
std::string payload_str;		// Declaration for payload information

// Structure to store performance metrics and intrusion detection
struct PerformanceMetrics {
	std::unordered_map<std::string, std::chrono::time_point<std::chrono::high_resolution_clock>>
			requestTimes;
	std::unordered_map<std::string, uint32_t> expectedSeq;
	std::unordered_map<std::string, uint64_t> byteCounts;
	std::chrono::time_point<std::chrono::high_resolution_clock> startTime;

	PerformanceMetrics() { startTime = std::chrono::high_resolution_clock::now(); }

	void recordLatency(
			const std::string& flowKey,
			const std::chrono::time_point<std::chrono::high_resolution_clock>& timePoint) {
		if (requestTimes.find(flowKey) != requestTimes.end()) {
			auto latency =
					std::chrono::duration_cast<std::chrono::milliseconds>(timePoint - requestTimes[flowKey])
							.count();
			std::cout << "Latency for " << flowKey << ": " << latency << " ms\n";
			requestTimes.erase(flowKey);
		} else {
			requestTimes[flowKey] = timePoint;
		}
	}

	void recordPacketLoss(const std::string& flowKey, uint32_t seq) {
		if (expectedSeq.find(flowKey) != expectedSeq.end() && seq > expectedSeq[flowKey]) {
			std::cout << "Packet loss detected in flow " << flowKey << "\n";
		}
		expectedSeq[flowKey] = seq;
	}

	void recordBandwidthUsage(const std::string& flowKey, uint64_t bytes) {
		byteCounts[flowKey] += bytes;
	}

	void reportBandwidthUsage() {
		auto currentTime = std::chrono::high_resolution_clock::now();
		auto elapsedTime =
				std::chrono::duration_cast<std::chrono::seconds>(currentTime - startTime).count();

		if (elapsedTime >= 1) {
			std::cout << "Bandwidth usage:\n";
			for (const auto& entry : byteCounts) {
				std::cout << entry.first << ": " << entry.second / elapsedTime << " bytes/sec\n";
			}
			byteCounts.clear();
			startTime = currentTime;
		}
	}

	// Intrusion Detection Example: Check for unusual bandwidth usage
	bool detectBandwidthAnomaly(const std::string& flowKey, uint64_t bytes) {
		// Example threshold: Detect if bandwidth usage exceeds 10 MB/sec
		constexpr uint64_t threshold = 10 * 1024 * 1024;		// 10 MB in bytes per second
		auto averageBytesPerSecond =
				byteCounts[flowKey] / std::chrono::duration_cast<std::chrono::seconds>(
																	std::chrono::high_resolution_clock::now() - startTime)
																	.count();

		return bytes > threshold;
	}
};

PerformanceMetrics metrics;

struct PacketStats {
	int ethPacketCount;
	int ipv4PacketCount;
	int ipv6PacketCount;
	int tcpPacketCount;
	int udpPacketCount;
	int dnsPacketCount;
	int httpPacketCount;
	int sslPacketCount;

	void clear() {
		ethPacketCount = 0;
		ipv4PacketCount = 0;
		ipv6PacketCount = 0;
		tcpPacketCount = 0;
		udpPacketCount = 0;
		dnsPacketCount = 0;
		httpPacketCount = 0;
		sslPacketCount = 0;
	}

	PacketStats() { clear(); }

	void consume_packet(pcpp::Packet& packet) {
		if (packet.isPacketOfType(pcpp::Ethernet)) ethPacketCount++;
		if (packet.isPacketOfType(pcpp::IPv4)) ipv4PacketCount++;
		if (packet.isPacketOfType(pcpp::IPv6)) ipv6PacketCount++;
		if (packet.isPacketOfType(pcpp::TCP)) tcpPacketCount++;
		if (packet.isPacketOfType(pcpp::UDP)) udpPacketCount++;
		if (packet.isPacketOfType(pcpp::DNS)) dnsPacketCount++;
		if (packet.isPacketOfType(pcpp::HTTP)) httpPacketCount++;
		if (packet.isPacketOfType(pcpp::SSL)) sslPacketCount++;
	}

	void draw() {
		ImGui::Text("Ethernet packet count: %i", ethPacketCount);
		ImGui::TextColored(ImVec4(0, 1, 0, 1), "IPv4 packet count:     %i", ipv4PacketCount);
		ImGui::TextColored(ImVec4(0, 1, 0, 1), "IPv6 packet count:     %i", ipv6PacketCount);
		ImGui::TextColored(ImVec4(0.92, 0.4, 0.92, 1), "TCP packet count:      %i", tcpPacketCount);
		ImGui::TextColored(ImVec4(0.92, 0.4, 0.92, 1), "UDP packet count:      %i", udpPacketCount);
		ImGui::TextColored(ImVec4(0.4, 0.92, 0.92, 1), "DNS packet count:      %i", dnsPacketCount);
		ImGui::TextColored(ImVec4(0.4, 0.92, 0.92, 1), "HTTP packet count:     %i", httpPacketCount);
		ImGui::TextColored(ImVec4(0.4, 0.92, 0.92, 1), "SSL packet count:      %i", sslPacketCount);
	}
};

struct PacketsData {
	std::vector<pcpp::Packet> packets;
	PacketStats stats;
};

void on_packet(pcpp::RawPacket* raw_packet, pcpp::PcapLiveDevice* device, void* data) {
	auto casted_data = static_cast<PacketsData*>(data);
	std::lock_guard<std::mutex> lock(packets_lock);
	auto packet = pcpp::Packet(raw_packet);
	casted_data->stats.consume_packet(packet);
	casted_data->packets.push_back(packet);

	// Check bandwidth anomaly
	metrics.recordBandwidthUsage("flow_key", packet.getRawPacket()->getRawDataLen());
	if (metrics.detectBandwidthAnomaly("flow_key", packet.getRawPacket()->getRawDataLen())) {
		std::cout << "Bandwidth anomaly detected for flow_key\n";
		// Trigger alert or take appropriate action
	}
}

std::string getDeviceName(pcpp::PcapLiveDevice* device) {
	return device->getName();
}

#if _WIN32
int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, PWSTR pCmdLine, int nCmdShow) {
#else
int main() {
#endif

	ps::Log::init();
	MemoryEditor memory_editor{};

	auto device_list = pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDevicesList();
	pcpp::PcapLiveDevice* active_device = nullptr;

	struct {
		std::optional<pcpp::Packet> active_packet;
		pcpp::Layer* active_layer = nullptr;
		uint64_t active_packet_index = -1;
	} state;

	PacketsData data;

	ps::GuiContext gui_context{1280, 720, "Packet Sniffer"};
	while (!gui_context.should_close()) {
		gui_context.start_frame();

		ImGui::BeginMainMenuBar();
		if (ImGui::BeginMenu("file")) {
			if (ImGui::MenuItem("close")) { gui_context.close_window(); }
			ImGui::EndMenu();
		}
		ImGui::EndMainMenuBar();

		ImGui::Begin("Devices");
		for (auto device : device_list) {
			if (ImGui::Selectable(DEVICE_NAME(device), device->isOpened())) {
				if (active_device && active_device->isOpened()) {
					active_device->stopCapture();
					active_device->close();
					active_device = nullptr;
				}

				bool res = device->open();
				if (res) {
					active_device = device;
					active_device->setFilter("ip");
					active_device->startCapture(on_packet, &data);
				}
			}
		}
		ImGui::End();

		ImGui::Begin("Stats");
		{
			std::lock_guard<std::mutex> lock(packets_lock);
			data.stats.draw();
		}
		ImGui::End();

		if (active_device) {
			ImGui::Begin("Packets");
			{
				std::lock_guard<std::mutex> lock(packets_lock);
				uint64_t i = 0;
				for (auto& packet : data.packets) {
					if (ImGui::GetScrollY() >= ImGui::GetScrollMaxY()) ImGui::SetScrollHereY(0.0f);
					std::string id = packet.getLastLayer()->toString() + "##" + std::to_string(i);

					auto layer = packet.getLastLayer()->getOsiModelLayer();
					ImVec4 color;
					switch (layer) {
						case pcpp::OsiModelNetworkLayer: color = ImVec4(0, 1, 0, 1); break;
						case pcpp::OsiModelTransportLayer: color = ImVec4(0.92, 0.4, 0.92, 1); break;
						case pcpp::OsiModelApplicationLayer: color = ImVec4(0.4, 0.92, 0.92, 1); break;
						default: color = ImVec4(1, 1, 1, 1); break;
					}

					ImGui::PushStyleColor(ImGuiCol_Text, color);

					if (ImGui::Selectable(id.c_str(), i == state.active_packet_index)) {
						state.active_packet = packet;
						state.active_packet_index = i;
					}

					ImGui::PopStyleColor();
					ImGui::Separator();
					i++;
				}
			}
			ImGui::End();
		}

		if (state.active_packet.has_value()) {
			ImGui::Begin("Packet Inspector");
			{
				auto& packet = state.active_packet.value();
				auto layer = packet.getFirstLayer();
				while (layer) {
					ImVec4 color;
					switch (layer->getOsiModelLayer()) {
						case pcpp::OsiModelNetworkLayer: color = ImVec4(0, 1, 0, 1); break;
						case pcpp::OsiModelTransportLayer: color = ImVec4(0.92, 0.4, 0.92, 1); break;
						case pcpp::OsiModelApplicationLayer: color = ImVec4(0.4, 0.92, 0.92, 1); break;
						default: color = ImVec4(1, 1, 1, 1); break;
					}
					ImGui::PushStyleColor(ImGuiCol_Text, color);

					// Display detailed layer information
					ImGui::Text("%s", layer->toString().c_str());

					// Additional details based on layer type
					switch (layer->getProtocol()) {
						case pcpp::Ethernet: {
							auto ethLayer = packet.getLayerOfType<pcpp::EthLayer>();
							if (ethLayer) {
								ImGui::Text("Source MAC: %s", ethLayer->getSourceMac().toString().c_str());
								ImGui::Text("Destination MAC: %s", ethLayer->getDestMac().toString().c_str());
							}
							break;
						}
						case pcpp::IPv4: {
							auto ipv4Layer = packet.getLayerOfType<pcpp::IPv4Layer>();
							if (ipv4Layer) {
								ImGui::Text("Header Length: %u", ipv4Layer->getHeaderLen());
								ImGui::Text("TTL: %u", ipv4Layer->getIPv4Header()->timeToLive);
							}
							break;
						}
						case pcpp::IPv6: {
							auto ipv6Layer = packet.getLayerOfType<pcpp::IPv6Layer>();
							if (ipv6Layer) {
								ImGui::Text("Header Length: %u", ipv6Layer->getHeaderLen());
								ImGui::Text("Hop Limit (TTL): %u", ipv6Layer->getIPv6Header()->hopLimit);
							}
							break;
						}
						case pcpp::TCP: {
							auto tcpLayer = packet.getLayerOfType<pcpp::TcpLayer>();
							if (tcpLayer) {
								ImGui::Text("Source Port: %d", tcpLayer->getSrcPort());
								ImGui::Text("Destination Port: %d", tcpLayer->getDstPort());
								ImGui::Text("Sequence Number: %u", tcpLayer->getTcpHeader()->sequenceNumber);
								ImGui::Text("Acknowledgment Number: %u", tcpLayer->getTcpHeader()->ackNumber);
								ImGui::Text("Flags:");
								if (tcpLayer->getTcpHeader()->synFlag) ImGui::Text("    SYN");
								if (tcpLayer->getTcpHeader()->ackFlag) ImGui::Text("    ACK");
								if (tcpLayer->getTcpHeader()->finFlag) ImGui::Text("    FIN");
							}
							break;
						}
						case pcpp::UDP: {
							auto udpLayer = packet.getLayerOfType<pcpp::UdpLayer>();
							if (udpLayer) {
								ImGui::Text("Source Port: %d", udpLayer->getSrcPort());
								ImGui::Text("Destination Port: %d", udpLayer->getDstPort());
							}
							break;
						}
					}

					ImGui::PopStyleColor();
					layer = layer->getNextLayer();
				}
			}
			ImGui::End();

			ImGui::Begin("Data");
			{
				ImGui::Text("Header:");
				ImGui::TextWrapped("%s", header_str.c_str());
				ImGui::Separator();

				gui_context.push_font_mono();
				memory_editor.DrawWindow(
						"Raw Data",
						(void*)state.active_packet.value().getRawPacket()->getRawData(),
						state.active_packet.value().getRawPacket()->getRawDataLen());
				gui_context.pull_font_mono();
			}
			ImGui::End();
		}

		gui_context.end_frame();
	}

	if (active_device) {
		active_device->stopCapture();
		active_device->close();
	}

#if _WIN32
	return 0;
#endif
}






		