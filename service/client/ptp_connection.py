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

        self.sequence_number_general = 0

    def __enter__(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.settimeout(0.1)

        self.request_unicast_message("SYNC")
        self.request_unicast_message("ANNOUNCE")

    def __exit__(self, exc_type, exc_value, traceback):
        self.cancel_unicast_message("SYNC")
        self.cancel_unicast_message("ANNOUNCE")

        self.socket.close()

    def send(self, message, port_type):
        request = message.encode(self.BUFFER_SIZE)
        port = self.SERVER_PORT_EVENT if port_type == "EVENT" else self.SERVER_PORT_GENERAL

        self.socket.sendto(request, (self.SERVER_ADDRESS, port))

    def receive(self):
        response, server = self.socket.recvfrom(self.BUFFER_SIZE)
        
        return ptp_message.from_buffer(response)

    def request_unicast_message(self, type, duration=60, log_message_interval=0):
        message = ptp_message.from_parameters("SIGNALING", self.clock_id, self.port, self.sequence_number_general)
        self.sequence_number_general += 1

        payload = message.get_payload()
        payload.target_port_id.clock_id = (0x0200000000000000 + self.target_id).to_bytes(8, byteorder="big")
        payload.target_port_id.port = 1

        tlv = message.add_tlv("REQUEST_UNICAST")
        tlv.log_message_interval = log_message_interval
        tlv.duration = duration

        if (type == "SYNC"):
            tlv.type = ptp_protocol.lib.PTP_MESSAGE_TYPE_SYNC
        elif (type == "ANNOUNCE"):
            tlv.type = ptp_protocol.lib.PTP_MESSAGE_TYPE_ANNOUNCE
        else:
            raise RuntimeError("Invalid message type requested")

        self.send(message, "GENERAL")
        response = self.receive()

        if not any(type == "GRANT_UNICAST" for type, payload in response.get_tlvs()):
            raise RuntimeError("No GRANT_UNICAST received")

    def cancel_unicast_message(self, type):
        message = ptp_message.from_parameters("SIGNALING", self.clock_id, self.port, self.sequence_number_general)
        self.sequence_number_general += 1

        payload = message.get_payload()
        payload.target_port_id.clock_id = (0x0200000000000000 + self.target_id).to_bytes(8, byteorder="big")
        payload.target_port_id.port = 1

        tlv = message.add_tlv("CANCEL_UNICAST")
        
        if (type == "SYNC"):
            tlv.type = ptp_protocol.lib.PTP_MESSAGE_TYPE_SYNC
        elif (type == "ANNOUNCE"):
            tlv.type = ptp_protocol.lib.PTP_MESSAGE_TYPE_ANNOUNCE
        else:
            raise RuntimeError("Invalid message type requested")
        
        self.send(message, "GENERAL")
        response = self.receive()

        if not any(type == "ACKNOWLEDGE_CANCEL_UNICAST" for type, payload in response.get_tlvs()):
            raise RuntimeError("No ACKNOWLEDGE_CANCEL_UNICAST received")
        
