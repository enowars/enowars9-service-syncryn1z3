import sys
sys.path.append("build")

import socket
import ptp_protocol
import ptp_message
import uuid

class PtpConnection:
    SERVER_ADDRESS = "172.21.0.2"
    SERVER_PORT_EVENT = 319
    SERVER_PORT_GENERAL = 320
    BUFFER_SIZE = 1500

    def __init__(self, target_id, clock_id=uuid.getnode(), port=2):
        self.target_id = target_id

        self.clock_id = clock_id
        self.port = port

        self.sequence_number = 0

    def __enter__(self):
        # To be standard compliant we would need two sockets and bind to the assigned ports.
        # However this would lead to issues with the NAT.
        # Also the packets are still dissected by wireshark this way. 
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.settimeout(0.1)

        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.socket.close()

    def send(self, message, event=False):
        request = message.encode(self.BUFFER_SIZE)
        port = self.SERVER_PORT_EVENT if event else self.SERVER_PORT_GENERAL

        self.socket.sendto(request, (self.SERVER_ADDRESS, port))

    def receive(self):
        response, server = self.socket.recvfrom(self.BUFFER_SIZE)
        
        return ptp_message.from_buffer(response)
    
    def flush(self):
        self.socket.setblocking(False)

        while True:
            try:
                self.receive()
            except BlockingIOError:
                self.socket.setblocking(True)
                return

    def request_unicast_message(self, type, duration=60, log_message_interval=0):
        message = ptp_message.from_parameters(ptp_protocol.lib.PTP_MESSAGE_TYPE_SIGNALING, self.clock_id, self.port, self.sequence_number)
        self.sequence_number += 1

        payload = message.get_payload()
        payload.signaling.target_port_id.clock_id = (0x0200000000000000 + self.target_id).to_bytes(8, byteorder="big")
        payload.signaling.target_port_id.port = 1

        tlv = message.add_tlv(ptp_protocol.lib.PTP_TLV_TYPE_REQUEST_UNICAST_TRANSMISSION)
        tlv.payload.request_unicast.type = type
        tlv.payload.request_unicast.log_message_interval = log_message_interval
        tlv.payload.request_unicast.duration = duration
        
        self.flush()
        self.send(message)

        for i in range(10):
            try:
                response = self.receive()
            except TimeoutError:
                continue

            if any(tlv.type == ptp_protocol.lib.PTP_TLV_TYPE_GRANT_UNICAST_TRANSMISSION for tlv in response.get_tlvs()):
                return
            
        raise RuntimeError("No GRANT_UNICAST received")
