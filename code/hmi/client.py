#!/usr/bin/env python3
"""Pymodbus asynchronous client example.

An example of a single threaded synchronous client.

usage: simple_client_async.py

All options must be adapted in the code
The corresponding server must be started before e.g. as:
    python3 server_sync.py
"""
import asyncio
from pymodbus.transaction import (
    ModbusAsciiFramer,
    ModbusBinaryFramer,
    ModbusRtuFramer,
    ModbusSocketFramer,
    ModbusTlsFramer,
)
from pymodbus import pymodbus_apply_logging_config
from pymodbus.client import (
    AsyncModbusSerialClient,
    AsyncModbusTcpClient,
    AsyncModbusTlsClient,
    AsyncModbusUdpClient,
)
from pymodbus.exceptions import ModbusException
from pymodbus.pdu import ExceptionResponse

import argparse


async def run_async_simple_client(comm, host, port, framer=ModbusSocketFramer):
    """Run async client."""
    # activate debugging
    pymodbus_apply_logging_config("DEBUG")

    print("get client")
    if comm == "tcp":
        client = AsyncModbusTcpClient(
            host,
            port=port,
            framer=framer,
            # timeout=10,
            # retries=3,
            # retry_on_empty=False,
            # close_comm_on_error=False,
            # strict=True,
            # source_address=("localhost", 0),
        )
    elif comm == "udp":
        client = AsyncModbusUdpClient(
            host,
            port=port,
            framer=framer,
            # timeout=10,
            # retries=3,
            # retry_on_empty=False,
            # close_comm_on_error=False,
            # strict=True,
            # source_address=None,
        )
    elif comm == "serial":
        client = AsyncModbusSerialClient(
            port,
            framer=framer,
            # timeout=10,
            # retries=3,
            # retry_on_empty=False,
            # close_comm_on_error=False,
            # strict=True,
            baudrate=9600,
            bytesize=8,
            parity="N",
            stopbits=1,
            # handle_local_echo=False,
        )
    elif comm == "tls":
        client = AsyncModbusTlsClient(
            host,
            port=port,
            framer=ModbusTlsFramer,
            # timeout=10,
            # retries=3,
            # retry_on_empty=False,
            # close_comm_on_error=False,
            # strict=True,
            # sslctx=sslctx,
            certfile="../examples/certificates/pymodbus.crt",
            keyfile="../examples/certificates/pymodbus.key",
            # password="none",
            server_hostname="localhost",
        )
    else:  # pragma no cover
        print(f"Unknown client {comm} selected")
        return

    print("connect to server")
    await client.connect()
    # test client is connected
    assert client.connected

    print("get and verify data")
    try:
        # See all calls in client_calls.py
        rr = await client.read_coils(1, 1, slave=1)
    except ModbusException as exc:  # pragma no cover
        print(f"Received ModbusException({exc}) from library")
        client.close()
        return
    if rr.isError():  # pragma no cover
        print(f"Received Modbus library error({rr})")
        client.close()
        return
    if isinstance(rr, ExceptionResponse):  # pragma no cover
        print(f"Received Modbus library exception ({rr})")
        # THIS IS NOT A PYTHON EXCEPTION, but a valid modbus message
        client.close()

    print("close connection")
    client.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(prog="Wrapper", 
                                     description='Wrapper that acts as a transparent proxy. Intercepts packets from the client \
                                        processes them and forwards them to the correct destination where they will be \
                                        intercepted again by the corresponding wrapper'
                                    )
    parser.add_argument('-c', '--comm', default='tcp',
                    help='{tcp,udp,serial,tls} set communication, default: tcp')
                
    parser.add_argument('--host', default = "127.0.0.1", 
                    help='the remote host\'s IP. Deafult: 127.0.0.1')

    parser.add_argument('-p', '--port', type=int, default = 502, 
                    help='the port the remote server is listening on. Deafult: 502')
    args = parser.parse_args()

    comm = args.comm
    host = args.host
    port = args.port

    asyncio.run(
        run_async_simple_client(comm, host, port), debug=True
    )  # pragma: no cover