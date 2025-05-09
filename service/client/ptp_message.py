import sys
sys.path.append("build")

import ptp_protocol
import uuid

BUFFER_SIZE = 1500

class PtpMessage:
    def __init__(self, type, clock_id=uuid.getnode(), port=2, sequence_id=0):
        self.decoded = ptp_protocol.ffi.new("struct ptp_decoded_message *")

        if (type == "SIGNALING"):
            self.decoded.type = ptp_protocol.lib.PTP_MESSAGE_TYPE_SIGNALING
        else:
            raise RuntimeError("Invalid message type")

        self.decoded.sequence_id = sequence_id
        self.decoded.sdo_id = ptp_protocol.lib.ptp_sdo_id
        self.decoded.domain = ptp_protocol.lib.ptp_domain
        self.decoded.port_id.clock_id = clock_id.to_bytes(8, byteorder="big")
        self.decoded.port_id.port = port
        self.decoded.flags = ptp_protocol.lib.PTP_FLAG_UNICAST

    def get_payload(self):
        if (self.decoded.type == ptp_protocol.lib.PTP_MESSAGE_TYPE_SIGNALING):
            return self.decoded.payload.signaling
        
        return None

    def add_tlv(self, type):
        result = None
        tlv = self.decoded.tlvs[self.decoded.tlv_count]

        if (type == "REQUEST_UNICAST"):
            tlv.type = ptp_protocol.lib.PTP_TLV_TYPE_REQUEST_UNICAST_TRANSMISSION
            result = tlv.payload.request_unicast
        elif (type == "CANCEL_UNICAST"):
            tlv.type = ptp_protocol.lib.PTP_TLV_TYPE_CANCEL_UNICAST_TRANSMISSION
            result = tlv.payload.cancel_unicast
        else:
            raise RuntimeError("Invalid TLV type")

        self.decoded.tlv_count += 1

        return result

    def encode(self, buffer_size=BUFFER_SIZE):
        buffer = ptp_protocol.ffi.new("uint8_t [{}]".format(buffer_size))
        
        len = ptp_protocol.lib.ptp_encode_message(buffer, self.decoded, buffer_size)
        if (len < 0):
            raise RuntimeError("Failed to encode message")
        
        return ptp_protocol.ffi.buffer(buffer, len)[:]
