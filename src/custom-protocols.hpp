#pragma once
#include <sstream>
#include "Layer.h"
#include "ProtocolType.h"
#include "SystemUtils.h"
#include "core/core.hpp"
#ifdef __APPLE__
	#include <libkern/OSByteOrder.h>

	#define be16toh(x) OSSwapBigToHostInt16(x)
	#define be32toh(x) OSSwapBigToHostInt32(x)
	#define be64toh(x) OSSwapBigToHostInt64(x)
#endif

namespace ps {
	constexpr pcpp::ProtocolType Websocket = 0x80000000000000;

	enum WebsocketOpCode {
		CONTINUATION = 0x0,
		TEXT_FRAME = 0x1,
		BINARY_FRAME = 0x2,
		CONNECTION_CLOSE = 0x8,
		PING = 0x9,
		PONG = 0xA,
	};

	struct wshdr {
#if (__BYTE_ORDER__ == BIG_ENDIAN)
		bool fin : 1;
		bool rsv1 : 1;
		bool rsv2 : 1;
		bool rsv3 : 1;
		u8 opcode : 4;
		bool mask : 1;
		u8 payload_len : 7;
#else
		u8 opcode : 4;
		bool rsv3 : 1;
		bool rsv2 : 1;
		bool rsv1 : 1;
		bool fin : 1;

		u8 payload_len : 7;
		bool mask : 1;
#endif
	};

	class WebsocketLayer final: public pcpp::Layer {
	private:
		const u8* m_Payload = nullptr;
		u64 m_PayloadLen = 0;
		u64 m_ExtendedHeaderLen = 0;

	public:
		WebsocketLayer() { m_Protocol = Websocket; }
		WebsocketLayer(u8* data, const size_t dataLen, Layer* prevLayer, pcpp::Packet* packet):
				Layer(data, dataLen, prevLayer, packet) {
			m_Protocol = Websocket;
			parseHeader();
		}

		explicit WebsocketLayer(const Layer* layer) {
			m_DataLen = layer->getDataLen();
			m_Data = new u8[m_DataLen];
			layer->copyData(m_Data);
			// memcpy(m_Data, layer->getData(), m_DataLen);
			parseHeader();
			m_Protocol = Websocket;
			m_PrevLayer = layer->getPrevLayer();
			m_NextLayer = nullptr;
		}

		void parseHeader() {
			const wshdr* ws_header = (wshdr*)m_Data;

			const u8* current_ptr = m_Data + 2;
			u64 actual_length = ws_header->payload_len;
			if (ws_header->payload_len == 126) {
				u16 extended_payload_length;
				actual_length = pcpp::netToHost32(*current_ptr);
				current_ptr += 2;
			} else if (ws_header->payload_len == 127) {
				actual_length = be64toh(*current_ptr);
				current_ptr += 8;
			}

			u8 masking_key[4];
			if (ws_header->mask) {
				std::memcpy(masking_key, current_ptr, 4);
				current_ptr += 4;
			}

			m_ExtendedHeaderLen = current_ptr - m_Data;
			m_Payload = current_ptr;
			m_PayloadLen = actual_length;
		}

		wshdr* getHeader() const { return (wshdr*)m_Data; }

		void parseNextLayer() override { m_NextLayer = nullptr; }

		[[nodiscard]] size_t getHeaderLen() const override { return m_ExtendedHeaderLen; }
		size_t getPayloadLen() const { return m_PayloadLen; }

		void computeCalculateFields() override {}

		[[nodiscard]] std::string toString() const override {
			std::ostringstream text;
			switch (getHeader()->opcode) {
				case CONTINUATION: text << "Websocket [Continuation]"; break;
				case TEXT_FRAME:
					// std::string_view payload(m_Payload, m_PayloadLen);
					text << "Websocket [Text], Payload length: ";
					break;
				case BINARY_FRAME: text << "Websocket [Binary], Payload length: "; break;
				case CONNECTION_CLOSE: text << "Websocket [Connection Close], Payload length: "; break;
				case PING: text << "Websocket [Ping], Payload length: "; break;
				case PONG: text << "Websocket [Pong], Payload length: "; break;
				default: text << "Websocket, Payload length: "; break;
			}
			text << getPayloadLen() << " Bytes ";
			if (getHeader()->fin) text << "[FIN] ";
			if (getHeader()->mask) text << "[MASKED]";
			return text.str();
		}

		[[nodiscard]] pcpp::OsiModelLayer getOsiModelLayer() const override {
			return pcpp::OsiModelApplicationLayer;
		}
	};
}		 // namespace ps
