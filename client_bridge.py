import asyncio
import json
import socket
import os
import hashlib
from bleak import BleakClient, BleakScanner

SERVICE_UUID = "12345678-1234-1234-1234-1234567890ab"
CHAR_UUID_RX = "12345678-1234-1234-1234-1234567890ac"  # write
CHAR_UUID_TX = "12345678-1234-1234-1234-1234567890ad"  # notify

HOST = "127.0.0.1"
PORT = 9000


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


async def find_device():
    print("Scanning for ESP32...")
    devices = await BleakScanner.discover(timeout=5.0)
    for d in devices:
        print(d)
    addr = input("Enter ESP32 BLE address from list above: ").strip()
    return addr


async def run_client():
    addr = await find_device()

    # TCP connection to server
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.connect((HOST, PORT))
    print("Connected to server")

    Id_c = os.urandom(16)
    # For demo, define Id_c_prime as hash of Id_c
    Id_c_prime = sha256(Id_c)

    # Notification handler
    queue = asyncio.Queue()

    def notification_handler(sender, data: bytearray):
        msg = data.decode()
        print("Notification from ESP32:", msg)
        asyncio.create_task(queue.put(msg))

    async with BleakClient(addr) as client:
        print("Connected to ESP32 over BLE")
        await client.start_notify(CHAR_UUID_TX, notification_handler)

        # Step 1: send CLIENT_HELLO with Id_c
        msg = {
            "type": "CLIENT_HELLO",
            "Id_c": Id_c.hex(),
        }
        await client.write_gatt_char(CHAR_UUID_RX, json.dumps(msg).encode())

        # Wait for BLE_HELLO_RESP
        resp_str = await queue.get()
        resp = json.loads(resp_str)
        assert resp["type"] == "BLE_HELLO_RESP"
        Id_p_hex = resp["Id_p"]
        Id_p = bytes.fromhex(Id_p_hex)

        print("Got BLE_HELLO_RESP")

        # Send HELLO_FROM_CLIENT to server with Id_p, Id_c and Id_c_prime
        hello = {
            "type": "HELLO_FROM_CLIENT",
            "Id_p": Id_p_hex,
            "Id_c": Id_c.hex(),
            "Id_c_prime": Id_c_prime.hex(),
        }
        server_sock.sendall(json.dumps(hello).encode())

        # Receive SERVER_DATA_TO_CLIENT from server
        sdata = json.loads(server_sock.recv(4096).decode())
        assert sdata["type"] == "SERVER_DATA_TO_CLIENT"

        # Forward to ESP32 as SERVER_DATA
        fwd = {
            "type": "SERVER_DATA",
            "M1": sdata["M1"],
            "M2": sdata["M2"],
            "M3": sdata["M3"],
            "M4": sdata["M4"],
            "Cp": sdata["Cp"],
        }
        await client.write_gatt_char(CHAR_UUID_RX, json.dumps(fwd).encode())

        # Wait for two messages: BLE_TO_SERVER_1 and BLE_TO_SERVER_2
        part1 = json.loads(await queue.get())
        print("Got from ESP32:", part1)
        part2 = json.loads(await queue.get())
        print("Got from ESP32:", part2)

        assert part1["type"] == "BLE_TO_SERVER_1"
        assert part2["type"] == "BLE_TO_SERVER_2"

        M5 = part1["M5"]
        M6 = part1["M6"]
        M7 = part2["M7"]
        M8 = part2["M8"]

        send_server = {
            "type": "BLE_TO_SERVER",
            "Id_p": Id_p_hex,
            "M5": M5,
            "M6": M6,
            "M7": M7,
            "M8": M8,
        }
        server_sock.sendall(json.dumps(send_server).encode())

        # Receive SERVER_M9_TO_CLIENT
        sm9 = json.loads(server_sock.recv(4096).decode())
        assert sm9["type"] == "SERVER_M9_TO_CLIENT"
        M9 = bytes.fromhex(sm9["M9"])

        # Compute Nc, M10, M11
        Nc = os.urandom(32)
        M10 = bytes(a ^ b for a, b in zip(Nc, M9))
        M11 = sha256(M10 + M9)

        msg_nonce = {
            "type": "SERVER_M9",  # first tell ESP32 what M9 is
            "M9": M9.hex(),
        }
        await client.write_gatt_char(CHAR_UUID_RX, json.dumps(msg_nonce).encode())

        msg_client_nonce = {
            "type": "CLIENT_NONCE",
            "M10": M10.hex(),
            "M11": M11.hex(),
        }
        await client.write_gatt_char(CHAR_UUID_RX, json.dumps(msg_client_nonce).encode())

        # Wait for two messages: BLE_FINAL_1 and BLE_FINAL_2
        final1 = json.loads(await queue.get())
        print("Got from ESP32:", final1)
        final2 = json.loads(await queue.get())
        print("Got from ESP32:", final2)

        assert final1["type"] == "BLE_FINAL_1"
        assert final2["type"] == "BLE_FINAL_2"

        M12 = bytes.fromhex(final1["M12"])
        M13 = bytes.fromhex(final1["M13"])
        elapsed_us = final2["elapsed_us"]
        SK_ble = bytes.fromhex(final2["SK"])

        # Client side recovery of Np and verification
        Np = bytes(a ^ b for a, b in zip(M12, Nc))
        check_M13 = sha256(M12 + Nc)
        if check_M13 != M13:
            print("Client: M13 verification failed")
        else:
            print("Client: M13 verified")

        # Compute client side session key
        SK_client = sha256(Nc + Np + Id_c_prime + Id_p)

        print("ESP32 session key:", SK_ble.hex())
        print("Client session key:", SK_client.hex())
        print("Keys match:", SK_ble == SK_client)
        print("ESP32 reported elapsed time (microseconds):", elapsed_us)

        await client.stop_notify(CHAR_UUID_TX)
        server_sock.close()


if __name__ == "__main__":
    asyncio.run(run_client())
