#include <algorithm>
#include <iterator>
#include <mutex>
#include <vector>
#include <string_view>
#include "IpAddress.h"
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
#include <string>

#include "analyze.hpp"
#include "monitor.hpp"
#include "custom-protocols.hpp"

// this cuz windows and unix interpret
// name and description differently
#if _WIN32		// windows
	#define DEVICE_NAME(d) d->getDesc().c_str()
#else		 // unix
	#define DEVICE_NAME(d) d->getName().c_str()
#endif

#define BEACON_FRAME_SUBTYPE 8
#define SSID_ELEMENT_ID			 0

std::mutex packets_lock;
std::string header_str;		 // Declaration for header information
std::string payload_str;		// Declaration for payload information

// Structure to store performance metrics
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
		if (requestTimes.contains(flowKey)) {
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
		if (expectedSeq.contains(flowKey) && seq > expectedSeq[flowKey]) {
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

		// Adjust the reporting interval as needed, e.g., report every 5 seconds
		constexpr int reportingInterval = 5;		// seconds

		if (elapsedTime >= reportingInterval) {
			for (const auto& entry : byteCounts) {
				std::cout << "Bandwidth usage:\n"
									<< "Bandwidth usage:\n"
									<< entry.first << ": " << entry.second / elapsedTime << " bytes/sec\n";
			}
			byteCounts.clear();
			startTime = currentTime;		// Reset the start time for the next reporting interval
		}
	}

	// Example intrusion detection: Check for unusual bandwidth usage
	bool detectBandwidthAnomaly(const std::string& flowKey, uint64_t bytes) {
		// Example threshold: Detect if bandwidth usage exceeds 10 MB/sec
		constexpr uint64_t threshold = 10 * 1024 * 1024;		// 10 MB in bytes per second
		auto averageBytesPerSecond =
				byteCounts[flowKey] / std::chrono::duration_cast<std::chrono::seconds>(
																	std::chrono::high_resolution_clock::now() - startTime)
																	.count();

		bool anomalyDetected = bytes > threshold;
		if (anomalyDetected) {
			std::cout << "Bandwidth anomaly detected for " << flowKey << ": " << bytes / 1024 / 1024
								<< " MB/sec\n";
		}

		return anomalyDetected;
	}
};

PerformanceMetrics metrics;

struct PacketStats {
	int ethPacketCount{};
	int ipv4PacketCount{};
	int ipv6PacketCount{};
	int tcpPacketCount{};
	int udpPacketCount{};
	int dnsPacketCount{};
	int httpPacketCount{};
	int sslPacketCount{};

	void clear() {
		ethPacketCount = 0;
		ipv4PacketCount = 0;
		ipv6PacketCount = 0;
		tcpPacketCount = 0;
		udpPacketCount = 0;
		tcpPacketCount = 0;
		dnsPacketCount = 0;
		httpPacketCount = 0;
		sslPacketCount = 0;
	}

	PacketStats() { clear(); }

	void consume_packet(const pcpp::Packet& packet) {
		if (packet.isPacketOfType(pcpp::Ethernet)) ethPacketCount++;
		if (packet.isPacketOfType(pcpp::IPv4)) ipv4PacketCount++;
		if (packet.isPacketOfType(pcpp::IPv6)) ipv6PacketCount++;
		if (packet.isPacketOfType(pcpp::TCP)) tcpPacketCount++;
		if (packet.isPacketOfType(pcpp::UDP)) udpPacketCount++;
		if (packet.isPacketOfType(pcpp::DNS)) dnsPacketCount++;
		if (packet.isPacketOfType(pcpp::HTTP)) httpPacketCount++;
		if (packet.isPacketOfType(pcpp::SSL)) sslPacketCount++;
	}

	void draw() const {
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

struct WebsocketConnection {
	pcpp::IPv4Address srcIP, dstIP;
	u16 srcPort, dstPort;

	WebsocketConnection(
			const pcpp::IPv4Address srcIP,
			const pcpp::IPv4Address dstIP,
			const u16 srcPort,
			const u16 dstPort): srcIP(srcIP), dstIP(dstIP), srcPort(srcPort), dstPort(dstPort) {}
};

struct PacketsData {
	std::vector<pcpp::Packet> packets;
	std::vector<std::string> ssid;
	PacketStats stats;
	ps::AnalyticsWindow a;
	ps::MonitorMode monitor_mode;
	std::vector<WebsocketConnection> active_websocket_conns;
};

void print_active_sockets(const std::vector<WebsocketConnection>& sockets) {
	for (auto socket : sockets) {
		PS_INFO(
				"ACTIVE SOCKET: \n\tSRC: {}, PORT: {}\n\tDST: {}, PORT: {}",
				socket.srcIP.toString(),
				socket.srcPort,
				socket.dstIP.toString(),
				socket.dstPort);
	}
}

bool check_if_connection_exists(
		const WebsocketConnection& conn_to_find, const std::vector<WebsocketConnection>& active_conns) {
	const auto res = std::ranges::find_if(active_conns, [&](const WebsocketConnection& conn) {
		if (conn_to_find.srcIP == conn.srcIP && conn_to_find.srcPort == conn.srcPort &&
				conn_to_find.dstIP == conn.dstIP && conn_to_find.dstPort == conn.dstPort)
			return true;
		else if (
				conn_to_find.srcIP == conn.dstIP && conn_to_find.srcPort == conn.dstPort &&
				conn_to_find.dstIP == conn.srcIP && conn_to_find.dstPort == conn.srcPort)
			return true;
		return false;
	});
	if (res == active_conns.end()) return false;
	return true;
}

bool try_parse_websocket_handshake(const pcpp::Packet* packet, PacketsData* data) {
	const pcpp::Layer* lastLayer = packet->getLastLayer();
	if (lastLayer->getProtocol() != pcpp::GenericPayload && lastLayer->getProtocol() != pcpp::HTTP)
		return false;
	u8* payload = lastLayer->getData();
	std::string payload_str(payload, payload + lastLayer->getDataLen());
	std::string_view sv(std::begin(payload_str), std::end(payload_str));
	const size_t res1 = sv.find("Upgrade: websocket");
	const size_t res2 = sv.find("Connection: Upgrade");

	// Check if handshake response
	if (res1 != std::string_view::npos && res2 != std::string_view::npos) {
		const auto* ip = dynamic_cast<pcpp::IPv4Layer*>(packet->getLayerOfType(pcpp::IPv4));
		const auto* tcp = dynamic_cast<pcpp::TcpLayer*>(packet->getLayerOfType(pcpp::TCP));
		const pcpp::IPv4Address srcIP = ip->getSrcIPv4Address();
		const pcpp::IPv4Address dstIP = ip->getDstIPv4Address();
		const u16 srcPort = tcp->getSrcPort();
		const u16 dstPort = tcp->getDstPort();
		const WebsocketConnection connection(srcIP, dstIP, srcPort, dstPort);
		if (check_if_connection_exists(connection, data->active_websocket_conns)) return true;
		data->active_websocket_conns.push_back(connection);
		PS_INFO("Recognized websocket handshake");
		print_active_sockets(data->active_websocket_conns);
		return true;
	}
	return false;
};

void try_parse_websocket(pcpp::Packet* packet, const PacketsData* data) {
	pcpp::Layer* last = packet->getLastLayer();
	if (last->getProtocol() != pcpp::GenericPayload) return;
	const auto* tcp = dynamic_cast<pcpp::TcpLayer*>(packet->getLayerOfType(pcpp::TCP));
	if (tcp == nullptr) return;
	const auto* ip = dynamic_cast<pcpp::IPv4Layer*>(packet->getLayerOfType(pcpp::IPv4));
	const pcpp::IPv4Address srcIP = ip->getSrcIPv4Address();
	const pcpp::IPv4Address dstIP = ip->getDstIPv4Address();
	const u16 srcPort = tcp->getSrcPort();
	const u16 dstPort = tcp->getDstPort();
	if (!check_if_connection_exists({srcIP, dstIP, srcPort, dstPort}, data->active_websocket_conns))
		return;
	PS_INFO(
			"FOUND WEBSOCKET PACKET (BEFORE PARSE). size: {}, header: {}, payload: {}",
			last->getDataLen(),
			last->getHeaderLen(),
			last->getLayerPayloadSize());
	// ps::WebsocketLayer* ws = new ps::WebsocketLayer(last->getData(), last->getDataLen(),
	// last->getPrevLayer(), packet);
	auto* ws = new ps::WebsocketLayer(last);
	packet->removeLastLayer();
	packet->addLayer(ws, true);
	packet->computeCalculateFields();
	auto hdr = ws->getHeader();
	PS_INFO(
			"FIN: {}, RSV1: {}, RSV2: {}, RSV3: {}\nOPCODE: {}, MASK: {}, PAYLOAD_LEN: {}",
			(bool)hdr->fin,
			(bool)hdr->rsv1,
			(bool)hdr->rsv2,
			(bool)hdr->rsv3,
			(u8)hdr->opcode,
			(bool)hdr->mask,
			ws->getPayloadLen());
}

void on_packet(pcpp::RawPacket* raw_packet, pcpp::PcapLiveDevice* device, void* data) {
	if (!device) return;

	std::lock_guard<std::mutex> lock(packets_lock);
	auto casted_data = static_cast<PacketsData*>(data);
	// if (!ps::is_ieee802_11_packet(raw_packet->getRawData(), raw_packet->getRawDataLen())) {
		auto packet = pcpp::Packet(raw_packet);
		if (!try_parse_websocket_handshake(&packet, casted_data))
			try_parse_websocket(&packet, casted_data);
		casted_data->stats.consume_packet(packet);
		casted_data->a.consume(packet, device, casted_data->packets.size());
		casted_data->packets.push_back(packet);
	// } else {
	// 	casted_data->monitor_mode.parse_packet(raw_packet->getRawData(), raw_packet->getRawDataLen());
	// }

	// Example: Record latency for each packet
	metrics.recordLatency("flow_key", std::chrono::high_resolution_clock::now());

	// Example: Record packet loss
	uint32_t sequenceNumber = 0;		// Replace with actual sequence number retrieval
	metrics.recordPacketLoss("flow_key", sequenceNumber);

	// Example: Record bandwidth usage
	metrics.recordBandwidthUsage("flow_key", raw_packet->getRawDataLen());

	// Example intrusion detection: Check for bandwidth anomaly
	if (metrics.detectBandwidthAnomaly("flow_key", raw_packet->getRawDataLen())) {
		std::cout << "Bandwidth anomaly detected for flow_key\n";
		// Trigger alert or take appropriate action
	}
}

#if _WIN32
int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, PWSTR pCmdLine, int nCmdShow) {
	AllocConsole();
	freopen("CONOUT$", "w", stdout);
	freopen("CONOUT$", "w", stderr);
#else
int main() {
#endif

	// Initialize logging and GUI context
	ps::Log::init();
	MemoryEditor memory_editor{};

	// Obtain list of available devices
	auto device_list = pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDevicesList();
	pcpp::PcapLiveDevice* active_device = nullptr;

	// State for the active packet inspection
	struct {
		std::optional<pcpp::Packet> active_packet;
		pcpp::Layer* active_layer = nullptr;
		u64 active_packet_index = -1;
		std::string cur_filter;
		bool monitor_mode = false;
	} state;

	// Data structure to hold packets and statistics
	PacketsData data;

	bool graph = false;

	// this should always be the last variable before
	// the loop so it's the first to be cleaned
	// cuz we need the gui to disappear and then close other stuff
	// Initialize GUI context
	ps::GuiContext gui_context{1280, 720, "Packet Sniffer"};

	// Main GUI loop
	while (!gui_context.should_close()) {
		gui_context.start_frame();

		// Main menu bar
		ImGui::BeginMainMenuBar();
		if (ImGui::BeginMenu("File")) {
			if (ImGui::MenuItem("Toggle graph")) { graph = !graph; }
			if (ImGui::MenuItem("Toggle monitor")) { state.monitor_mode = !state.monitor_mode; }
			if (ImGui::MenuItem("Close")) { gui_context.close_window(); }
			ImGui::EndMenu();
		}
		ImGui::EndMainMenuBar();

		// Device selection window
		ImGui::Begin("Devices");
		ImGui::Text("Filter:");
		ImGui::SameLine();
		if (ImGui::InputText(
						"##filter", state.cur_filter.data(), 1000, ImGuiInputTextFlags_EnterReturnsTrue)) {
			state.cur_filter = state.cur_filter.data();		 // NOLINT(*-redundant-string-cstr)
			if (active_device) {
				// Set filter and print error to log if exists
				if (active_device->setFilter(state.cur_filter)) {
					PS_INFO("FILTER SET: " + state.cur_filter);
				} else {
					PS_ERROR("Cannot set filter: {}", state.cur_filter);
				}
			}
		}
		for (auto device : device_list) {
			if (ImGui::Selectable(DEVICE_NAME(device), device->isOpened())) {
				if (active_device && active_device->isOpened()) {
					active_device->stopCapture();
					active_device->close();
					active_device = nullptr;
				}

				// Open device and check for errors
				if (device->open()) {
					PS_INFO("Opened device: {}", DEVICE_NAME(device));
				} else {
					PS_ERROR("Cannot open device: {}", DEVICE_NAME(device));
				}
				active_device = device;
				// Set filter if exists
				if (state.cur_filter.empty())
					active_device->setFilter("ip");
				else
					active_device->setFilter(state.cur_filter);

				active_device->startCapture(on_packet, &data);
			};
		}
		ImGui::End();

		// Statistics display window
		ImGui::Begin("Stats");
		{
			std::lock_guard<std::mutex> lock(packets_lock);
			data.stats.draw();
		}
		ImGui::End();

		if (graph) {
			std::lock_guard<std::mutex> lock(packets_lock);
			data.a.draw();
		} else if (state.monitor_mode) {
			std::lock_guard<std::mutex> lock(packets_lock);
			data.monitor_mode.draw();
		} else {
			if (active_device) {
				ImGui::Begin("Packets");
				std::lock_guard<std::mutex> lock(packets_lock);
				u64 i = 0;
				for (auto& packet : data.packets) {
					if (ImGui::GetScrollY() >= ImGui::GetScrollMaxY()) ImGui::SetScrollHereY(0.0f);
					std::string id = packet.getLastLayer()->toString() + "##" + std::to_string(i);

					auto layer = packet.getLastLayer()->getOsiModelLayer();
					if (layer == pcpp::OsiModelNetworkLayer)
						ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0, 1, 0, 1));
					else if (layer == pcpp::OsiModelTransportLayer)
						ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.92, 0.4, 0.92, 1));
					else if (layer == pcpp::OsiModelApplicationLayer)
						ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.4, 0.92, 0.92, 1));
					else
						ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(1, 1, 1, 1));

					if (ImGui::Selectable(id.c_str(), i == state.active_packet_index)) {
						state.active_packet = packet;
						state.active_packet_index = i;
					};

					ImGui::PopStyleColor();
					ImGui::Separator();
					i++;
				}

				if (!data.ssid.empty()) {
					for (auto& ssid : data.ssid) {
						if (ImGui::GetScrollY() >= ImGui::GetScrollMaxY()) ImGui::SetScrollHereY(0.0f);

						ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.8, 0.7, 0.3, 1));
						ImGui::Selectable(ssid.c_str(), false);
						ImGui::PopStyleColor();
						ImGui::Separator();
					}
				}
				ImGui::End();
			}

			if (state.active_packet.has_value()) {
				ImGui::Begin("Packet Inspector");
				auto layer = state.active_packet->getFirstLayer();
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
						case pcpp::Ethernet:
							ImGui::Text(
									"Source MAC: %s",
									dynamic_cast<pcpp::EthLayer*>(layer)->getSourceMac().toString().c_str());
							ImGui::Text(
									"Destination MAC: %s",
									dynamic_cast<pcpp::EthLayer*>(layer)->getDestMac().toString().c_str());
							break;
						case pcpp::IPv4: {
							auto ipv4Layer = dynamic_cast<pcpp::IPv4Layer*>(layer);
							if (ipv4Layer) {
								ImGui::Text("Header Length: %zu", ipv4Layer->getHeaderLen());
								ImGui::Text("TTL: %u", ipv4Layer->getIPv4Header()->timeToLive);
							}
							break;
						}

						case pcpp::IPv6: {
							auto ipv6Layer = dynamic_cast<pcpp::IPv6Layer*>(layer);
							if (ipv6Layer) {
								ImGui::Text("Header Length: %zu", ipv6Layer->getHeaderLen());
								ImGui::Text("Hop Limit (TTL): %u", ipv6Layer->getIPv6Header()->hopLimit);
							}
							break;
						}

						case pcpp::TCP: {
							auto tcpLayer = dynamic_cast<pcpp::TcpLayer*>(layer);
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
							auto udpLayer = dynamic_cast<pcpp::UdpLayer*>(layer);
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
				ImGui::End();

				gui_context.push_font_mono();
				memory_editor.DrawWindow(
						"Raw Data",
						(void*)state.active_packet->getRawPacket()->getRawData(),
						state.active_packet->getRawPacket()->getRawDataLen());
				gui_context.pull_font_mono();
			}
		}

		// End frame for GUI context
		gui_context.end_frame();

		// Output performance metrics
		metrics.reportBandwidthUsage();
	}

	// Clean up: Stop capture and close device
	if (active_device) {
		active_device->stopCapture();
		active_device->close();
	}

	return 0;
}
