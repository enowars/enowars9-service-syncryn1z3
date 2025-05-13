import sys
sys.path.append("build")

import ptp_connection
import ptp_protocol
import ptp_message
import time

class PtpClient:
    def __init__(self, connection):
        self.connection = connection

        self.sequence_number = None
        self.t1 = None
        self.t2 = None
        self.t3 = None
        self.t4 = None

        self.offset = 0

    def handle_sync(self, sync):
        now = self.get_time_ns()

        self.sequence_number = sync.decoded.sequence_id
        self.t1 = sync.decoded.payload.event.timestamp
        self.t2 = now

        delay_request = ptp_message.from_parameters(ptp_protocol.lib.PTP_MESSAGE_TYPE_DELAY_REQUEST, self.connection.clock_id, self.connection.port, self.sequence_number)

        payload = delay_request.get_payload()
        payload.event.timestamp = now

        now = self.get_time_ns()
        self.connection.send(delay_request, event=True)

        self.t3 = now

    def handle_delay_response(self, delay_response):
        if self.sequence_number != delay_response.decoded.sequence_id:
            print("Mixup in sync process")

        self.t4 = delay_response.decoded.payload.event.timestamp
        self.offset += int(((self.t1 + self.t4) - (self.t2 + self.t3)) / 2)

        print("Time: {:.3f}, Offset: {:.3f}us".format(self.get_time_ns() / 1000000000, self.offset / 1000))

    def handle_announce(self, message):
        pass

    def get_time_ns(self):
        return time.clock_gettime_ns(time.CLOCK_MONOTONIC) + self.offset

    def run_sync(self):
        self.connection.request_unicast_message(ptp_protocol.lib.PTP_MESSAGE_TYPE_SYNC)

        message = self.connection.receive()

        if message.decoded.type != ptp_protocol.lib.PTP_MESSAGE_TYPE_SYNC:
            raise RuntimeError("Expected sync message")
        
        self.handle_sync(message)

        message = self.connection.receive()

        if message.decoded.type != ptp_protocol.lib.PTP_MESSAGE_TYPE_DELAY_RESPONSE:
            raise RuntimeError("Expected delay response message")
        
        self.handle_delay_response(message)

    def run_announce(self):
        self.connection.request_unicast_message(ptp_protocol.lib.PTP_MESSAGE_TYPE_ANNOUNCE)

        message = self.connection.receive()
        
        if message.decoded.type != ptp_protocol.lib.PTP_MESSAGE_TYPE_ANNOUNCE:
            raise RuntimeError("Expected announce message")

        self.handle_announce(message)

def main():
    with ptp_connection.PtpConnection(42) as connection:
        client = PtpClient(connection)
        
        try:
            while True:
                client.run_announce()
                client.run_sync()

                time.sleep(1)

        except KeyboardInterrupt:
            print("See you another time!")

if __name__ == "__main__":
    main()
