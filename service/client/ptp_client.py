import sys
sys.path.append("build")

import socket
import ptp_protocol
import uuid

SERVER_IP = "172.21.0.2"
SERVER_PORT = 320
BUFFER_SIZE = 1500

class PtpMessage:
    def __init__(self, type, sequence_id=0):
        self.decoded = ptp_protocol.ffi.new("struct ptp_decoded_message *")

        if (type == "SIGNALING"):
            self.decoded.type = ptp_protocol.lib.PTP_MESSAGE_TYPE_SIGNALING
        else:
            raise RuntimeError("Invalid message type")

        self.decoded.sequence_id = sequence_id
        self.decoded.sdo_id = ptp_protocol.lib.ptp_sdo_id
        self.decoded.domain = ptp_protocol.lib.ptp_domain
        self.decoded.port_id.clock_id = (uuid.getnode() + 1).to_bytes(8, byteorder="big")
        self.decoded.port_id.port = 6
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
        else:
            raise RuntimeError("Invalid TLV type")

        self.decoded.tlv_count += 1

        return result

    def encode(self):
        buffer = ptp_protocol.ffi.new("uint8_t [{}]".format(BUFFER_SIZE))
        
        len = ptp_protocol.lib.ptp_encode_message(buffer, self.decoded, BUFFER_SIZE)
        if (len < 0):
            raise RuntimeError("Failed to encode message")
        
        return ptp_protocol.ffi.buffer(buffer, len)[:]

def main():
    # Create UDP socket
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        message = PtpMessage("SIGNALING")

        payload = message.get_payload()
        payload.target_port_id.clock_id = (0x0200000000000000 + 42).to_bytes(8, byteorder="big")
        payload.target_port_id.port = 1

        tlv = message.add_tlv("REQUEST_UNICAST")
        tlv.type = ptp_protocol.lib.PTP_MESSAGE_TYPE_SYNC
        tlv.log_message_interval = 1 # 2sec
        tlv.duration = 60 # sec

        request = message.encode()

        # Send message to server
        sock.sendto(request, (SERVER_IP, SERVER_PORT))
        print(f"Sent: {request}")

        # Receive response from server
        response, server = sock.recvfrom(BUFFER_SIZE)
        print(f"Received from server: {response}")

if __name__ == "__main__":
    main()
