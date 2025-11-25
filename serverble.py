import socket
import json
import os
import hashlib

HOST = "127.0.0.1"
PORT = 9000

def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()

# Must match ESP32 PUF_SECRET
PUF_SECRET = bytes([
    0x10,0x20,0x30,0x40,0x50,0x60,0x70,0x80,
    0x90,0xA0,0xB0,0xC0,0xD0,0xE0,0xF0,0x00
])

def puf_eval(chal: bytes) -> bytes:
    # same as ESP32: SHA256(challenge || PUF_SECRET) truncated to 16 bytes
    return sha256(chal + PUF_SECRET)[:16]

# Database: Id_p_hex -> dict with Cp, Rp, Id_c_prime, T1, T2
db = {}

def main():
    print("Server listening on", HOST, PORT)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen(1)
        conn, addr = s.accept()
        with conn:
            print("Server connected by", addr)
            while True:
                data = conn.recv(4096)
                if not data:
                    break
                msg = json.loads(data.decode())
                mtype = msg.get("type")

                if mtype == "HELLO_FROM_CLIENT":
                    id_p_hex = msg["Id_p"]
                    id_c_hex = msg["Id_c"]
                    idc_prime_hex = msg["Id_c_prime"]
                    Id_c_prime = bytes.fromhex(idc_prime_hex)

                    # If no CRP stored, create Cp and derive Rp via PUF
                    if id_p_hex not in db:
                        Cp = os.urandom(16)
                        Rp = puf_eval(Cp)
                        db[id_p_hex] = {
                            "Cp": Cp,
                            "Rp": Rp,
                            "Id_c_prime": Id_c_prime,
                            "T1": None,
                            "T2": None,
                        }
                        print("Created initial CRP for", id_p_hex)
                    else:
                        # just update Id_c_prime, keep Cp and Rp
                        db[id_p_hex]["Id_c_prime"] = Id_c_prime

                    entry = db[id_p_hex]
                    Cp = entry["Cp"]
                    Rp = entry["Rp"]

                    # Generate T1, T2 and M1..M4
                    T1 = os.urandom(16)
                    T2 = os.urandom(16)
                    entry["T1"] = T1
                    entry["T2"] = T2

                    M1 = bytes(a ^ b for a, b in zip(T1, Rp))
                    M2 = bytes(a ^ b for a, b in zip(T1, T2))
                    hT = sha256(T1 + T2)
                    M3 = bytes(a ^ b for a, b in zip(hT, Id_c_prime))
                    M4 = sha256(T1 + T2 + Rp + Cp + Id_c_prime)

                    resp = {
                        "type": "SERVER_DATA_TO_CLIENT",
                        "M1": M1.hex(),
                        "M2": M2.hex(),
                        "M3": M3.hex(),
                        "M4": M4.hex(),
                        "Cp": Cp.hex(),
                    }
                    conn.sendall(json.dumps(resp).encode())

                elif mtype == "BLE_TO_SERVER":
                    # M5..M8 from BLE
                    id_p_hex = msg["Id_p"]
                    entry = db[id_p_hex]
                    Cp = entry["Cp"]
                    Rp = entry["Rp"]
                    Id_c_prime = entry["Id_c_prime"]
                    T2 = entry["T2"]

                    M5 = bytes.fromhex(msg["M5"])
                    M6 = bytes.fromhex(msg["M6"])
                    M7 = bytes.fromhex(msg["M7"])
                    M8 = bytes.fromhex(msg["M8"])

                    H_Rp = sha256(Rp)
                    H_Rp_trunc = H_Rp[:16]

                    Cp_new = bytes(a ^ b for a, b in zip(M5, H_Rp_trunc))
                    check_M6 = sha256(M5 + H_Rp)
                    if check_M6 != M6:
                        print("M6 verification failed")
                        continue

                    Rp_new = bytes(a ^ b for a, b in zip(M7, T2))
                    check_M8 = sha256(M7 + T2)
                    if check_M8 != M8:
                        print("M8 verification failed")
                        continue

                    # Update CRP
                    entry["Cp"] = Cp_new
                    entry["Rp"] = Rp_new
                    db[id_p_hex] = entry

                    M9 = sha256(Cp_new + Rp_new)
                    resp = {
                        "type": "SERVER_M9_TO_CLIENT",
                        "M9": M9.hex(),
                    }
                    conn.sendall(json.dumps(resp).encode())

                else:
                    print("Unknown server message type", mtype)


if __name__ == "__main__":
    main()
