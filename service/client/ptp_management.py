import sys
sys.path.append("build")

import socket
import ptp_protocol
import ptp_message
import uuid

class PtpManagement:
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
    
    def get_user_description(self):
        message = ptp_message.from_parameters(ptp_protocol.lib.PTP_MESSAGE_TYPE_MANAGEMENT, self.clock_id, self.port, self.sequence_number)
        self.sequence_number += 1

        payload = message.get_payload()
        payload.management.target_port_id.clock_id = (0x0200000000000000 + self.target_id).to_bytes(8, byteorder="big")
        payload.management.target_port_id.port = 1
        payload.management.action = ptp_protocol.lib.PTP_MANAGEMENT_ACTION_GET
        payload.management.starting_boundary_hops = 0
        payload.management.boundary_hops = 0

        tlv = message.add_tlv(ptp_protocol.lib.PTP_TLV_TYPE_MANAGEMENT)
        tlv.payload.management.id = ptp_protocol.lib.PTP_MANAGEMENT_ID_USER_DESCRIPTION
        
        self.send(message)

    def set_user_description(self, description):
        description = description.encode('utf-8')
        if (len(description) > 128):
            raise ValueError("User description too large")

        message = ptp_message.from_parameters(ptp_protocol.lib.PTP_MESSAGE_TYPE_MANAGEMENT, self.clock_id, self.port, self.sequence_number)
        self.sequence_number += 1

        payload = message.get_payload()
        payload.management.target_port_id.clock_id = (0x0200000000000000 + self.target_id).to_bytes(8, byteorder="big")
        payload.management.target_port_id.port = 1
        payload.management.action = ptp_protocol.lib.PTP_MANAGEMENT_ACTION_SET
        payload.management.starting_boundary_hops = 0
        payload.management.boundary_hops = 0

        tlv = message.add_tlv(ptp_protocol.lib.PTP_TLV_TYPE_MANAGEMENT)
        tlv.payload.management.id = ptp_protocol.lib.PTP_MANAGEMENT_ID_USER_DESCRIPTION
        ptp_protocol.ffi.memmove(tlv.payload.management.payload.user_description, description + b'\0', len(description) + 1)
        
        self.send(message)

def main():
    with PtpManagement(42) as management:
        #management.set_user_description("test1234")
        management.get_user_description()
            
        try:
            while True:
                pass

        except KeyboardInterrupt:
            print("See you another time!")

if __name__ == "__main__":
    main()

