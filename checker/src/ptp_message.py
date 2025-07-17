import os

import ptp_protocol

from enochecker3 import (
    MumbleException,
    InternalErrorException,
)

class PtpMessage:
    def get_payload(self):
        return self.decoded.payload
    
    def get_tlvs(self):
        return [self.decoded.tlvs[i] for i in range(self.decoded.tlv_count)]

    def add_tlv(self, type):
        tlv = self.decoded.tlvs[self.decoded.tlv_count]
        tlv.type = type

        self.decoded.tlv_count += 1

        return tlv

    def encode(self, buffer_size):
        pointer = ptp_protocol.ffi.new(f"uint8_t [{buffer_size}]")
        
        ret = ptp_protocol.lib.ptp_encode_message(pointer, self.decoded, buffer_size)
        if (ret < 0):
            raise InternalErrorException(f"Failed to encode PTP message: {os.strerror(-ret)}")
        
        return ptp_protocol.ffi.buffer(pointer, ret)[:], pointer
    
def from_parameters(type, clock_id, port, sequence_id):
    message = PtpMessage()
    message.decoded = ptp_protocol.ffi.new("struct ptp_decoded_message *")

    message.decoded.type = type
    message.decoded.sequence_id = sequence_id
    message.decoded.sdo_id = ptp_protocol.lib.ptp_sdo_id
    message.decoded.domain = ptp_protocol.lib.ptp_domain
    message.decoded.port_id.clock_id = clock_id
    message.decoded.port_id.port = port
    message.decoded.flags = ptp_protocol.lib.PTP_FLAG_UNICAST

    return message

def from_pointer(pointer, length):
    message = PtpMessage()
    message.decoded = ptp_protocol.ffi.new("struct ptp_decoded_message *")

    ret = ptp_protocol.lib.ptp_decode_message(message.decoded, pointer, length)
    if (ret < 0):
        raise MumbleException(f"Failed to decode PTP message: {os.strerror(-ret)}")
    
    return message

def from_buffer(buffer: bytes):
    pointer = ptp_protocol.ffi.new(f"uint8_t[{len(buffer)}]", buffer)
    
    return from_pointer(pointer, len(buffer)), pointer
