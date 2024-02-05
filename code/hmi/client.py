#!/usr/bin/env python3
"""Pymodbus asynchronous client example.

An example of a single threaded synchronous client.

usage: simple_client_async.py

All options must be adapted in the code
The corresponding server must be started before e.g. as:
    python3 server_sync.py
"""
import asyncio
import argparse
import logging
import ast

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

_logger = logging.getLogger(__file__)
_logger.setLevel("INFO")

async def run_async_simple_client(args, framer=ModbusSocketFramer):
    comm = args.comm
    host = args.host
    port = args.port
    subcommand = args.subcommand
    slave_id = args.id

    """Run async client."""
    # activate debugging
    pymodbus_apply_logging_config("INFO")

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

    try:
        read_list = None
        if subcommand == "rc":
            _logger.info("Reading Coils")
            start = args.start
            quantity = args.quantity
            result = await client.read_coils(start, quantity, slave=slave_id)
            read_list = result.bits
        elif subcommand == "rdi":
            start = args.start
            quantity = args.quantity
            result = await client.read_discrete_inputs(start, quantity, slave=slave_id)
            read_list = result.bits
        elif subcommand == "rhr":
            start = args.start
            quantity = args.quantity
            result = await client.read_holding_registers(start, quantity, slave=slave_id)
            read_list = result.registers
        elif subcommand == "rir":
            start = args.start
            quantity = args.quantity
            result = await client.read_input_registers(start, quantity, slave=slave_id)
            read_list = result.registers
        elif subcommand == "wc":
            index = args.index
            value = ast.literal_eval(args.value)
            result = await client.write_coil(index, value, slave=slave_id)
        elif subcommand == "wr":
            index = args.index
            value = args.value
            result = await client.write_register(index, value, slave=slave_id)
        elif subcommand == "wmc":
            start_address = args.start_address
            values = [ast.literal_eval(x.strip()) for x in args.values.split(',')]
            result = await client.write_coils(start_address, values, slave=slave_id)
        elif subcommand == "wmr":
            start_address = args.start_address
            values = [int(x.strip()) for x in args.values.split(',')]
            result = await client.write_registers(start_address, values, slave=slave_id)
        elif subcommand == "rwr":
            start = args.read_start
            write_start = args.write_start
            quantity = args.quantity
            values = [int(x.strip()) for x in args.values.split(',')]
            result = await client.readwrite_registers(start, quantity, write_start, values, slave=slave_id)  
            read_list = result.registers         

    except ModbusException as exc:  # pragma no cover
        print(f"Received ModbusException({exc}) from library")
        client.close()
        return
    if result.isError():  # pragma no cover
        print(f"Received Modbus library error({result})")
        client.close()
        return
    if isinstance(result, ExceptionResponse):  # pragma no cover
        print(f"Received Modbus library exception ({result})")
        # THIS IS NOT A PYTHON EXCEPTION, but a valid modbus message
        client.close()

    if read_list:
        [print(hex(start + i) + ": " + str(read_list[i])) for i in range(len(read_list))]

    print("close connection")
    client.close()


if __name__ == "__main__":

    # Create the argument parser
    parser = argparse.ArgumentParser(prog="Modbus Client", 
                                    description="Simple Modbus client")

    # Add the arguments
    parser.add_argument("--host", default = "127.0.0.1",
                        help="The remote server's IP. Deafult: 127.0.0.1")
    parser.add_argument("-p", "--port", type=int, default=502,
                        help="The port the remote Modbus server is listening on. Deafult: 502")
    parser.add_argument("-i", "--id", type=int, default=0,
                        help="The Modbus slave ID")
    parser.add_argument("-c", "--comm", choices=["udp", "tcp", "serial", "tls"], default='tcp',
                        help='{tcp,udp,serial,tls} set communication, default: tcp')

    # Create subparsers for subcommands
    subparsers = parser.add_subparsers(dest="subcommand", title="Subcommands")

    # Subparser for "rc" command
    rc_parser = subparsers.add_parser("rc", help="Read coils")
    rc_parser.add_argument("-s", "--start", type=int, required=True, help="Starting address")
    rc_parser.add_argument("-q", "--quantity", type=int, default=1, help="Quantity of coils")

    # Subparser for "rdi" command
    rdi_parser = subparsers.add_parser("rdi", help="Read discrete inputs")
    rdi_parser.add_argument("-s", "--start", type=int, required=True, help="Starting address")
    rdi_parser.add_argument("-q", "--quantity", type=int, default=1, help="Quantity of discrete inputs")

    # Subparser for "rhr" command
    rhr_parser = subparsers.add_parser("rhr", help="Read holding registers")
    rhr_parser.add_argument("-s", "--start", type=int, required=True, help="Starting address")
    rhr_parser.add_argument("-q", "--quantity", type=int, default=1, help="Quantity of holding registers")

    # Subparser for "rir" command
    rir_parser = subparsers.add_parser("rir", help="Read input registers")
    rir_parser.add_argument("-s", "--start", type=int, required=True, help="Starting address")
    rir_parser.add_argument("-q", "--quantity", type=int, default=1, help="Quantity of input registers")

    # Subparser for "wsc" command
    wsc_parser = subparsers.add_parser("wc", help="Write single coil")
    wsc_parser.add_argument("-i", "--index", type=int, required=True, help="Index of the coil")
    wsc_parser.add_argument("-v", "--value", choices=["True", "False"], required=True, help="Value of the coil")

    # Subparser for "wsr" command
    wsr_parser = subparsers.add_parser("wr", help="Write single register")
    wsr_parser.add_argument("-i", "--index", type=int, required=True, help="Index of the register")
    wsr_parser.add_argument("-v", "--value", type=int, required=True, help="Value of the register")

    # Subparser for "wmc" command
    wmc_parser = subparsers.add_parser("wmc", help="Write multiple coils")
    wmc_parser.add_argument("-s", "--start_address", type=int, required=True, help="Starting address")
    wmc_parser.add_argument("-v", "--values", type=str, required=True, help="List of booleans to write")

    # Subparser for "wmr" command
    wmr_parser = subparsers.add_parser("wmr", help="Write multiple registers")
    wmr_parser.add_argument("-s", "--start_address", type=int, required=True, help="Starting address")
    wmr_parser.add_argument("-v", "--values", type=str, required=True, help="List of values to write, as a comma separated list")

    # Subparser for "rwr" command
    rwr_parser = subparsers.add_parser("rwr", help="Read-write registers")
    rwr_parser.add_argument("-rs", "--read_start", type=int, required=True, help="The address to start reading from")
    rwr_parser.add_argument("-q", "--quantity", type=int, required=True, help="Quantity of registers to read")
    rwr_parser.add_argument("-ws", "--write_start", type=int, required=True, help="The address to start writing to")
    rwr_parser.add_argument("-v", "--values", type=str, required=True, help="List of values to write, as a comma separated list")

    # Parse the command-line arguments
    args = parser.parse_args()

    asyncio.run(
        run_async_simple_client(args), debug=True
    )  # pragma: no cover