import sys
sys.path.append("build")

import ptp_protocol
import uuid

BUFFER_SIZE = 1500

class PtpMessage:
    def get_payload(self):
        if (self.decoded.type == ptp_protocol.lib.PTP_MESSAGE_TYPE_SIGNALING):
            return self.decoded.payload.signaling
        
        return None
    
    def get_tlvs(self):
        tlvs = []

        for i in range(self.decoded.tlv_count):
            tlv = self.decoded.tlvs[i]

            if (tlv.type == ptp_protocol.lib.PTP_TLV_TYPE_GRANT_UNICAST_TRANSMISSION):
                tlvs += [("GRANT_UNICAST", tlv.payload.grant_unicast)]
            elif (tlv.type == ptp_protocol.lib.PTP_TLV_TYPE_ACKNOWLEDGE_CANCEL_UNICAST_TRANSMISSION):
                tlvs += [("ACKNOWLEDGE_CANCEL_UNICAST", tlv.payload.acknowledge_cancel_unicast)]
            else:
                raise RuntimeError("Invalid TLV type")

        return tlvs

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
        
        ret = ptp_protocol.lib.ptp_encode_message(buffer, self.decoded, buffer_size)
        if (ret < 0):
            raise RuntimeError("Failed to encode message")
        
        return ptp_protocol.ffi.buffer(buffer, ret)[:]
    
def from_parameters(type: str, clock_id=uuid.getnode(), port=2, sequence_id=0):
    message = PtpMessage()
    message.decoded = ptp_protocol.ffi.new("struct ptp_decoded_message *")

    if (type == "SIGNALING"):
        message.decoded.type = ptp_protocol.lib.PTP_MESSAGE_TYPE_SIGNALING
    else:
        raise RuntimeError("Invalid message type")

    message.decoded.sequence_id = sequence_id
    message.decoded.sdo_id = ptp_protocol.lib.ptp_sdo_id
    message.decoded.domain = ptp_protocol.lib.ptp_domain
    message.decoded.port_id.clock_id = clock_id.to_bytes(8, byteorder="big")
    message.decoded.port_id.port = port
    message.decoded.flags = ptp_protocol.lib.PTP_FLAG_UNICAST

    return message

def from_buffer(buffer: bytes):
    message = PtpMessage()
    message.decoded = ptp_protocol.ffi.new("struct ptp_decoded_message *")

    ret = ptp_protocol.lib.ptp_decode_message(message.decoded, buffer, len(buffer))
    if (ret < 0):
        raise RuntimeError("Failed to decode message")
    
    return message
