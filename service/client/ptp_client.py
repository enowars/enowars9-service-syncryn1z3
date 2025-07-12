import asyncio
import curses
import random
import time
import hmac
import hashlib
import argparse
import math
import datetime
import zlib

import ptp_protocol
import ptp_message


LOCAL_PORT = 2000
EVENT_PORT = 319
GENERAL_PORT = 320


"""
PTP utility classes
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
    
class AuthInfo:
    def __init__(self, clock_id: int, port: int, secret: str, policy = "hmac"):
        self.clock_id = clock_id
        self.port = port
        self.secret = secret
        self.policy = policy


"""
PTP utility functions
"""

def get_time_ns():
    return time.clock_gettime_ns(time.CLOCK_MONOTONIC)

def generate_port_id():
    clock_id = random.randint(0x0200000000000001, 0x02ffffffffffffff)
    port = random.randint(0x1, 0xfffe)

    return clock_id, port

def policy_to_int(policy: str):
    if policy == "hmac":
        return ptp_protocol.lib.PTP_AUTHENTICATION_POLICY_HMAC_128
    elif policy == "plain":
        return ptp_protocol.lib.PTP_AUTHENTICATION_POLICY_PLAIN

def add_auth_tlv(message, auth_info: AuthInfo):
    tlv = message.add_tlv(ptp_protocol.lib.PTP_TLV_TYPE_AUTHENTICATION)
    tlv.payload.authentication.policy = policy_to_int(auth_info.policy)
    tlv.payload.authentication.parameter_indicator = 0
    tlv.payload.authentication.key_id = 0

    if auth_info.policy == "hmac":
        tlv.payload.authentication.icv_length = 16
    elif auth_info.policy == "plain":
        tlv.payload.authentication.icv_length = 64
    
def finalize_auth_tlv(tlv, request, auth_info: AuthInfo):
    if tlv.type != ptp_protocol.lib.PTP_TLV_TYPE_AUTHENTICATION:
        return

    buffer_address = ptp_protocol.ffi.cast("uint8_t *", ptp_protocol.ffi.addressof(ptp_protocol.ffi.from_buffer(request)))
    icv_address = tlv.payload.authentication.icv
    
    if tlv.payload.authentication.policy == policy_to_int("hmac"):
        icv = hmac.new(auth_info.secret.encode("ascii"), bytearray(request)[:icv_address - buffer_address], hashlib.sha256).digest()
    elif tlv.payload.authentication.policy == policy_to_int("plain"):
        icv = auth_info.secret.encode("ascii") + b'\0'

    ptp_protocol.ffi.memmove(icv_address, icv[:tlv.payload.authentication.icv_length], tlv.payload.authentication.icv_length)

def finalize_auth_tlvs(request, auth_info: AuthInfo):
    message = ptp_message.from_buffer(request)

    for tlv in message.get_tlvs():
        finalize_auth_tlv(tlv, request, auth_info)

async def get_user_description(connection: Connection, auth_info: AuthInfo):
    local_clock_id, local_port = generate_port_id()
    message = ptp_message.from_parameters(ptp_protocol.lib.PTP_MESSAGE_TYPE_MANAGEMENT, local_clock_id, local_port, 0)

    payload = message.get_payload()
    payload.management.target_port_id.clock_id = auth_info.clock_id
    payload.management.target_port_id.port = auth_info.port
    payload.management.action = ptp_protocol.lib.PTP_MANAGEMENT_ACTION_GET

    tlv = message.add_tlv(ptp_protocol.lib.PTP_TLV_TYPE_MANAGEMENT)
    tlv.payload.management.id = ptp_protocol.lib.PTP_MANAGEMENT_ID_USER_DESCRIPTION

    add_auth_tlv(message, auth_info)
    request = message.encode(connection.BUFFER_SIZE)
    finalize_auth_tlvs(request, auth_info)

    connection.send_raw(request, GENERAL_PORT)
    response = await connection.receive(GENERAL_PORT)

    buffer = None

    for tlv in response.get_tlvs():
        if tlv.type == ptp_protocol.lib.PTP_TLV_TYPE_MANAGEMENT:
            if tlv.payload.management.id == ptp_protocol.lib.PTP_MANAGEMENT_ID_USER_DESCRIPTION:
                buffer = ptp_protocol.ffi.buffer(tlv.payload.management.payload.user_description.data, tlv.payload.management.payload.user_description.length)[:]
        if tlv.type == ptp_protocol.lib.PTP_TLV_TYPE_MANAGEMENT_ERROR_STATUS:
            raise PtpException(f"Received error from server: {ptp_protocol.ffi.string(tlv.payload.management_error_status.display_data).decode()}")
        
    if buffer is None:
        raise PtpException("Received no description")
    
    # Decode compressed description
    if buffer.startswith(b"zlib"):
        try:
            return zlib.decompress(buffer[4:]).decode()
        except zlib.error:
            pass

    return buffer.decode()

async def request_unicast_message(connection: Connection, auth_info: AuthInfo, type: int):
    local_clock_id, local_port = generate_port_id()
    message = ptp_message.from_parameters(ptp_protocol.lib.PTP_MESSAGE_TYPE_SIGNALING, local_clock_id, local_port, 0)

    payload = message.get_payload()
    payload.signaling.target_port_id.clock_id = auth_info.clock_id
    payload.signaling.target_port_id.port = auth_info.port

    tlv = message.add_tlv(ptp_protocol.lib.PTP_TLV_TYPE_REQUEST_UNICAST_TRANSMISSION)
    tlv.payload.request_unicast.type = type
    tlv.payload.request_unicast.log_message_interval = 0
    tlv.payload.request_unicast.duration = 0

    add_auth_tlv(message, auth_info)
    request = message.encode(connection.BUFFER_SIZE)
    finalize_auth_tlvs(request, auth_info)

    connection.send_raw(request, EVENT_PORT)
    response = await connection.receive(EVENT_PORT)

    for tlv in response.get_tlvs():
        if tlv.type == ptp_protocol.lib.PTP_TLV_TYPE_GRANT_UNICAST_TRANSMISSION:
            return
        if tlv.type == ptp_protocol.lib.PTP_TLV_TYPE_MANAGEMENT_ERROR_STATUS:
            raise PtpException(f"Received error from server: {ptp_protocol.ffi.string(tlv.payload.management_error_status.display_data).decode()}")

    raise PtpException("Received no unicast transmission grant")

async def get_offset(connection: Connection, auth_info: AuthInfo):
    await request_unicast_message(connection, auth_info, ptp_protocol.lib.PTP_MESSAGE_TYPE_ANNOUNCE)

    announce = await connection.receive(EVENT_PORT)

    if announce.decoded.type != ptp_protocol.lib.PTP_MESSAGE_TYPE_ANNOUNCE:
        raise PtpException("Expected announce message")
    
    offset_tlv = announce.get_tlvs()[0]
    if offset_tlv.type != ptp_protocol.lib.PTP_TLV_TYPE_ALTERNATE_TIME_OFFSET_INDICATOR:
        raise PtpException("Expected alternate time offset indicator tlv")
    
    return offset_tlv.payload.alternate_time_offset_indicator.current_offset * 1000000000

async def run_synchronization(connection: Connection, auth_info: AuthInfo):
    await request_unicast_message(connection, auth_info, ptp_protocol.lib.PTP_MESSAGE_TYPE_SYNC)

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

async def create_connections(args):
    transport, protocol = await asyncio.get_running_loop().create_datagram_endpoint(lambda: UdpClientProtocol(args.address), local_addr=("0.0.0.0", LOCAL_PORT))

    return Connection(args.address, protocol)


"""
CLI utility functions
"""

def parse_args():
    def hex_int(x):
        return int(x, 16)

    parser = argparse.ArgumentParser(description="syncryn1z3 ptp client")

    parser.add_argument("address", type=str, help="IP address of the server")
    parser.add_argument("clock_id", type=hex_int, help="Clock ID registered in the server")
    parser.add_argument("port", type=hex_int, help="Port registered in the server")
    parser.add_argument("--secret", type=str, default="", help="Password to secure the remote port")
    parser.add_argument("--description", type=str, default="", help="Description of the remote port")
    parser.add_argument("--syncs", type=int, default=100, help="Number of syncs to perform")
    parser.add_argument("--interval", type=float, default=0.1, help="Interval in sec between syncs")

    args = parser.parse_args()

    if args.clock_id < 0x1 or args.clock_id > 0xfffffffffffffffe:
        raise PtpException("Clock ID out of range")
    if args.port < 1 or args.port >= 0xffff:
        raise PtpException("Port out of range")
    
    return args

def draw_graph(stdscr, data, start_y, start_x, height, width):
    for i in range(height):
        y = start_y + i
        stdscr.addstr(y, start_x, '|')
        stdscr.addstr(y, start_x + width, '|')

    stdscr.addstr(start_y + height, start_x, '+' + '-' * (width - 1) + '+')

    if len(data) == 0:
        return

    max_val = max(data)
    min_val = min(data)
    scale = (height - 2) / (max_val - min_val) if max_val != min_val else 1

    stdscr.addstr(start_y, start_x + width + 2, f"{round(max_val)} ppm")
    stdscr.addstr(start_y + height, start_x + width + 2, f"{round(min_val)} ppm")

    for i, val in enumerate(data[-min(width - 1, len(data)):]):
        y = int(scale * (val - min_val))
        y = start_y + height - 1 - y
        if 0 <= y < curses.LINES:
            stdscr.addstr(y, start_x + i + 1, '*')

def wait_for_exit(stdscr):
    try:
        key = stdscr.getch()
        if key == ord('q'):
            return True
    except curses.error:
        return False

async def loop(stdscr, args):
    curses.curs_set(0)
    curses.start_color()
    curses.use_default_colors()
    stdscr.nodelay(True)

    connection = await create_connections(args)

    auth_info = AuthInfo(args.clock_id, args.port, args.secret)

    try:
        description = await get_user_description(connection, auth_info)
    except PtpException:
        # Retry with legacy auth policy
        auth_info.policy = "plain"
        description = await get_user_description(connection, auth_info)

    offset = await get_offset(connection, auth_info)
    last_time_ns = get_time_ns() + offset
    drift = []

    for i in range(args.syncs):
        rows, cols = stdscr.getmaxyx()
        if rows < 20 or cols < 60:
            raise PtpException("Minimal terminal size: 20x60")

        stdscr.erase()
        stdscr.addstr(0, 0, "Welcome to the syncryn1z3 network clock inspector!")
        stdscr.addstr(2, 0, f"Connected to clock: {args.clock_id:x}/{args.port:x}")
        stdscr.addstr(3, 0, f"Description: {description}")

        error = await run_synchronization(connection, auth_info)

        current_time_ns = get_time_ns() + error + offset
        timestamp_seconds = math.floor(current_time_ns / 1000000000)
        timestamp_nanoseconds = current_time_ns % 1000000000

        if i > 0:
            drift.append(1000000 * error / (current_time_ns - last_time_ns))
            drift = drift[-40:]

        stdscr.addstr(5, 0, "Drift:")
        draw_graph(stdscr, drift, 6, 0, 10, 40)
        
        stdscr.addstr(18, 0, "Time: {}:{:09}".format(datetime.datetime.fromtimestamp(timestamp_seconds, datetime.timezone.utc).strftime("%d.%m.%Y / %H:%M:%S"), timestamp_nanoseconds))
        stdscr.addstr(19, 0, "Press 'q' to quit.")
        stdscr.refresh()

        last_time_ns = current_time_ns

        if wait_for_exit(stdscr):
            return

        await asyncio.sleep(args.interval)

    stdscr.nodelay(False)
    wait_for_exit(stdscr)

def main():
    try:
        args = parse_args()
        curses.wrapper(lambda stdscr: asyncio.run(loop(stdscr, args)))
    except Exception as e:
        print(e)
        exit(1)

if __name__ == "__main__":
    main()
