import asyncio
import random
import time
import hmac
import hashlib
import argparse
import math
import datetime

import ptp_protocol
import ptp_message


LOCAL_PORT = 2000
EVENT_PORT = 319
GENERAL_PORT = 320

"""
Utility classes
"""

class PtpException(Exception):
    pass

class UdpClientProtocol(asyncio.DatagramProtocol):
    def __init__(self, remote_address):
        self.remote_address = remote_address

        self.transport = None
        self.queue = asyncio.Queue()

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, address):
        try:
            self.queue.put_nowait(data)
        except Exception as e:
            raise PtpException(f"Transport exception: {e}")

    def error_received(self, e):
        raise PtpException(f"Received error: {e}")

class Connection:
    BUFFER_SIZE = 1472

    def __init__(self, remote_address, protocol):
        self.remote_address = remote_address
        self.protocol = protocol

    def send_raw(self, request, port):
        self.protocol.transport.sendto(request, (self.remote_address, port))
        
    async def receive_raw(self, port):
        try:
            return await asyncio.wait_for(self.protocol.queue.get(), 1.0)
        except asyncio.TimeoutError:
            raise PtpException("Timeout waiting for response")

    def send(self, message, port):
        request = message.encode(self.BUFFER_SIZE)
        self.send_raw(request, port)

    async def receive(self, port):
        response = await self.receive_raw(port)
        message = ptp_message.from_buffer(response)

        return message

"""
Utility functions
"""

def get_time_ns():
    return time.clock_gettime_ns(time.CLOCK_MONOTONIC)

def generate_port_id():
    clock_id = random.randint(0x0200000000000001, 0x02ffffffffffffff)
    port = random.randint(0x1, 0xfffe)

    return clock_id, port

def add_auth_tlv(message):
    tlv = message.add_tlv(ptp_protocol.lib.PTP_TLV_TYPE_AUTHENTICATION)
    tlv.payload.authentication.policy = ptp_protocol.lib.PTP_AUTHENTICATION_POLICY_HMAC_128
    tlv.payload.authentication.parameter_indicator = 0
    tlv.payload.authentication.key_id = 0
    tlv.payload.authentication.icv_length = 16
    
def finalize_auth_tlv(tlv, request, secret=b""):
    if tlv.type != ptp_protocol.lib.PTP_TLV_TYPE_AUTHENTICATION:
        return

    buffer_address = ptp_protocol.ffi.cast("uint8_t *", ptp_protocol.ffi.addressof(ptp_protocol.ffi.from_buffer(request)))
    icv_address = tlv.payload.authentication.icv
    icv = hmac.new(secret, bytearray(request)[:icv_address - buffer_address], hashlib.sha256).digest()

    ptp_protocol.ffi.memmove(icv_address, icv[:tlv.payload.authentication.icv_length], tlv.payload.authentication.icv_length)

def finalize_auth_tlvs(request, secret=b""):
    message = ptp_message.from_buffer(request)

    for tlv in message.get_tlvs():
        finalize_auth_tlv(tlv, request, secret)

async def get_user_description(connection: Connection, clock_id: int, port: int, secret: str):
    secret = secret.encode("utf-8")
    secret = secret + b'\x00' * (100 - len(secret))

    local_clock_id, local_port = generate_port_id()
    message = ptp_message.from_parameters(ptp_protocol.lib.PTP_MESSAGE_TYPE_MANAGEMENT, local_clock_id, local_port, 0)

    payload = message.get_payload()
    payload.management.target_port_id.clock_id = clock_id
    payload.management.target_port_id.port = port
    payload.management.action = ptp_protocol.lib.PTP_MANAGEMENT_ACTION_GET

    tlv = message.add_tlv(ptp_protocol.lib.PTP_TLV_TYPE_MANAGEMENT)
    tlv.payload.management.id = ptp_protocol.lib.PTP_MANAGEMENT_ID_USER_DESCRIPTION

    add_auth_tlv(message)
    request = message.encode(connection.BUFFER_SIZE)
    finalize_auth_tlvs(request, secret=secret)

    connection.send_raw(request, GENERAL_PORT)
    response = await connection.receive(GENERAL_PORT)

    for tlv in response.get_tlvs():
        if tlv.type == ptp_protocol.lib.PTP_TLV_TYPE_MANAGEMENT:
            if tlv.payload.management.id == ptp_protocol.lib.PTP_MANAGEMENT_ID_USER_DESCRIPTION:
                return ptp_protocol.ffi.string(tlv.payload.management.payload.user_description).decode()
        if tlv.type == ptp_protocol.lib.PTP_TLV_TYPE_MANAGEMENT_ERROR_STATUS:
            raise PtpException(f"Received error from server: {ptp_protocol.ffi.string(tlv.payload.management_error_status.display_data).decode()}")

    raise PtpException("Received no description")

async def request_unicast_message(connection: Connection, clock_id: int, port: int, secret: str, type: int):
    secret = secret.encode("utf-8")
    secret = secret + b'\x00' * (100 - len(secret))

    local_clock_id, local_port = generate_port_id()
    message = ptp_message.from_parameters(ptp_protocol.lib.PTP_MESSAGE_TYPE_SIGNALING, local_clock_id, local_port, 0)

    payload = message.get_payload()
    payload.signaling.target_port_id.clock_id = clock_id
    payload.signaling.target_port_id.port = port

    tlv = message.add_tlv(ptp_protocol.lib.PTP_TLV_TYPE_REQUEST_UNICAST_TRANSMISSION)
    tlv.payload.request_unicast.type = type
    tlv.payload.request_unicast.log_message_interval = 0
    tlv.payload.request_unicast.duration = 0

    add_auth_tlv(message)
    request = message.encode(connection.BUFFER_SIZE)
    finalize_auth_tlvs(request, secret=secret)

    connection.send_raw(request, EVENT_PORT)
    response = await connection.receive(EVENT_PORT)

    for tlv in response.get_tlvs():
        if tlv.type == ptp_protocol.lib.PTP_TLV_TYPE_GRANT_UNICAST_TRANSMISSION:
            return
        if tlv.type == ptp_protocol.lib.PTP_TLV_TYPE_MANAGEMENT_ERROR_STATUS:
            raise PtpException(f"Received error from server: {ptp_protocol.ffi.string(tlv.payload.management_error_status.display_data).decode()}")

    raise PtpException("Received no unicast transmission grant")

async def get_offset(connection: Connection, clock_id: int, port: int, secret: str):
    await request_unicast_message(connection, clock_id, port, secret, ptp_protocol.lib.PTP_MESSAGE_TYPE_ANNOUNCE)

    announce = await connection.receive(EVENT_PORT)

    if announce.decoded.type != ptp_protocol.lib.PTP_MESSAGE_TYPE_ANNOUNCE:
        raise PtpException("Expected announce message")
    
    offset_tlv = announce.get_tlvs()[0]
    if offset_tlv.type != ptp_protocol.lib.PTP_TLV_TYPE_ALTERNATE_TIME_OFFSET_INDICATOR:
        raise PtpException("Expected alternate time offset indicator tlv")
    
    return offset_tlv.payload.alternate_time_offset_indicator.current_offset * 1000000000

async def run_synchronization(connection: Connection, clock_id: int, port: int, secret: str):
    await request_unicast_message(connection, clock_id, port, secret, ptp_protocol.lib.PTP_MESSAGE_TYPE_SYNC)

    sync = await connection.receive(EVENT_PORT)

    if sync.decoded.type != ptp_protocol.lib.PTP_MESSAGE_TYPE_SYNC:
        raise PtpException("Expected sync message")
    
    t1 = sync.decoded.payload.event.timestamp
    t2 = get_time_ns()

    local_clock_id, local_port = generate_port_id()
    delay_request = ptp_message.from_parameters(ptp_protocol.lib.PTP_MESSAGE_TYPE_DELAY_REQUEST, local_clock_id, local_port, 0)

    payload = delay_request.get_payload()
    payload.event.timestamp = t2

    t3 = get_time_ns()
    connection.send(delay_request, EVENT_PORT)
    delay_response = await connection.receive(EVENT_PORT)

    if delay_response.decoded.type != ptp_protocol.lib.PTP_MESSAGE_TYPE_DELAY_RESPONSE:
        raise PtpException("Expected delay response message")
    
    t4 = delay_response.decoded.payload.event.timestamp

    return int(((t1 + t4) - (t2 + t3)) / 2)

def parse_args():
    def hex_int(x):
        return int(x, 16)

    parser = argparse.ArgumentParser(description="syncryn1z3 ptp client")

    parser.add_argument("address", type=str, help="IP address of the server")
    parser.add_argument("clock_id", type=hex_int, help="Clock ID registered in the server")
    parser.add_argument("port", type=hex_int, help="Port registered in the server")
    parser.add_argument("--secret", type=str, default="", help="Password to secure the remote port")
    parser.add_argument("--description", type=str, default="", help="Description of the remote port")
    parser.add_argument("--syncs", type=int, default=5, help="Number of syncs to perform")
    parser.add_argument("--interval", type=float, default=1, help="Interval in sec between syncs")

    args = parser.parse_args()

    if args.clock_id < 0x1 or args.clock_id > 0xfffffffffffffffe:
        raise PtpException("Clock ID out of range")
    if args.port < 1 or args.port >= 0xffff:
        raise PtpException("Port out of range")
    
    return args

async def create_connections(args):
    transport, protocol = await asyncio.get_running_loop().create_datagram_endpoint(lambda: UdpClientProtocol(args.address), local_addr=("0.0.0.0", LOCAL_PORT))

    return Connection(args.address, protocol)

async def main():
    args = parse_args()

    connection = await create_connections(args)

    description = await get_user_description(connection, args.clock_id, args.port, args.secret)
    print(f"Connected to clock: {args.clock_id:x}/{args.port:x}")
    print(f"Description: {description}")

    offset = await get_offset(connection, args.clock_id, args.port, args.secret)

    for _ in range(args.syncs):
        error = await run_synchronization(connection, args.clock_id, args.port, args.secret)

        current_time_ns = get_time_ns() + error + offset
        timestamp_seconds = math.floor(current_time_ns / 1000000000)
        timestamp_nanoseconds = current_time_ns % 1000000000

        print("Time: {}:{:09d}".format(datetime.datetime.fromtimestamp(timestamp_seconds, datetime.timezone.utc).strftime("%d.%m.%Y / %H:%M:%S"), timestamp_nanoseconds))

        await asyncio.sleep(args.interval)

    print("Exiting")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except PtpException as e:
        print(e)
        exit(1)
