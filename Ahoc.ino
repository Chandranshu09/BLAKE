#include <Arduino.h>
#include <BLEDevice.h>
#include <BLEServer.h>
#include <BLEUtils.h>
#include <BLE2902.h>
#include <ArduinoJson.h>
#include "mbedtls/sha256.h"

// --------------------------------------------------------
// Configuration
// --------------------------------------------------------

static const char *BLE_DEVICE_NAME = "BLAKE_ESP32";

// One service and two characteristics: RX (write), TX (notify)
static const char *SERVICE_UUID = "12345678-1234-1234-1234-1234567890ab";
static const char *CHAR_UUID_RX = "12345678-1234-1234-1234-1234567890ac";
static const char *CHAR_UUID_TX = "12345678-1234-1234-1234-1234567890ad";

// Identifier of BLE device (16 bytes = 128 bits)
uint8_t ID_P[16] = {
  0xDE,0xAD,0xBE,0xEF,0x00,0x11,0x22,0x33,
  0x44,0x55,0x66,0x77,0x88,0x99,0xAA,0xBB
};

// Session variables
static uint8_t g_Id_c[16];        // received from client
static uint8_t g_Id_c_prime[32];  // recovered in Step 3
static uint8_t g_Cp[16];
static uint8_t g_Rp[16];
static uint8_t g_Cp_new[16];
static uint8_t g_Rp_new[16];
static uint8_t g_T1[16];
static uint8_t g_T2[16];
static uint8_t g_M9[32];          // H(Cp_new || Rp_new)
static uint8_t g_Nc[32];
static uint8_t g_Np[32];
static uint8_t g_SK[32];

static uint64_t g_t_start = 0;
static uint64_t g_t_end   = 0;

// BLE globals
BLECharacteristic *pTxCharacteristic = nullptr;
bool deviceConnected = false;

// --------------------------------------------------------
// Utility functions
// --------------------------------------------------------

void xorBytes(const uint8_t *a, const uint8_t *b, uint8_t *out, size_t len) {
  for (size_t i = 0; i < len; ++i) {
    out[i] = a[i] ^ b[i];
  }
}

void sha256_init(mbedtls_sha256_context *ctx) {
  mbedtls_sha256_init(ctx);
  // 0 means SHA-256 (not SHA-224)
  mbedtls_sha256_starts(ctx, 0);
}

void sha256_update(mbedtls_sha256_context *ctx, const uint8_t *data, size_t len) {
  mbedtls_sha256_update(ctx, data, len);
}

void sha256_final(mbedtls_sha256_context *ctx, uint8_t out[32]) {
  mbedtls_sha256_finish(ctx, out);
  mbedtls_sha256_free(ctx);
}

void hash_single(const uint8_t *in, size_t inLen, uint8_t out[32]) {
  mbedtls_sha256_context ctx;
  sha256_init(&ctx);
  sha256_update(&ctx, in, inLen);
  sha256_final(&ctx, out);
}

void hash_concat3(const uint8_t *a, size_t al,
                  const uint8_t *b, size_t bl,
                  const uint8_t *c, size_t cl,
                  uint8_t out[32]) {
  mbedtls_sha256_context ctx;
  sha256_init(&ctx);
  if (a && al > 0) sha256_update(&ctx, a, al);
  if (b && bl > 0) sha256_update(&ctx, b, bl);
  if (c && cl > 0) sha256_update(&ctx, c, cl);
  sha256_final(&ctx, out);
}

void hash_concat5(const uint8_t *a, size_t al,
                  const uint8_t *b, size_t bl,
                  const uint8_t *c, size_t cl,
                  const uint8_t *d, size_t dl,
                  const uint8_t *e, size_t el,
                  uint8_t out[32]) {
  mbedtls_sha256_context ctx;
  sha256_init(&ctx);
  if (a && al > 0) sha256_update(&ctx, a, al);
  if (b && bl > 0) sha256_update(&ctx, b, bl);
  if (c && cl > 0) sha256_update(&ctx, c, cl);
  if (d && dl > 0) sha256_update(&ctx, d, dl);
  if (e && el > 0) sha256_update(&ctx, e, el);
  sha256_final(&ctx, out);
}

// Convert byte array to hex string
String bytesToHex(const uint8_t *data, size_t len) {
  const char hexmap[] = "0123456789abcdef";
  String s;
  s.reserve(len * 2);
  for (size_t i = 0; i < len; ++i) {
    uint8_t v = data[i];
    s += hexmap[v >> 4];
    s += hexmap[v & 0x0F];
  }
  return s;
}

// Convert hex string to byte array
bool hexToBytes(const String &hex, uint8_t *out, size_t outLen) {
  if (hex.length() != outLen * 2) return false;
  for (size_t i = 0; i < outLen; ++i) {
    char c1 = hex[2 * i];
    char c2 = hex[2 * i + 1];
    uint8_t v1 = (c1 >= '0' && c1 <= '9') ? c1 - '0' :
                 (c1 >= 'a' && c1 <= 'f') ? c1 - 'a' + 10 :
                 (c1 >= 'A' && c1 <= 'F') ? c1 - 'A' + 10 : 0;
    uint8_t v2 = (c2 >= '0' && c2 <= '9') ? c2 - '0' :
                 (c2 >= 'a' && c2 <= 'f') ? c2 - 'a' + 10 :
                 (c2 >= 'A' && c2 <= 'F') ? c2 - 'A' + 10 : 0;
    out[i] = (v1 << 4) | v2;
  }
  return true;
}

// --------------------------------------------------------
// PUF stub and challenge generation
// --------------------------------------------------------

// Replace with your real SRAM PUF evaluation.
const uint8_t PUF_SECRET[16] = {
  0x10,0x20,0x30,0x40,0x50,0x60,0x70,0x80,
  0x90,0xA0,0xB0,0xC0,0xD0,0xE0,0xF0,0x00
};

void evalPUF(const uint8_t *challenge, size_t chalLen, uint8_t response[16]) {
  uint8_t buf[32];
  mbedtls_sha256_context ctx;
  sha256_init(&ctx);
  sha256_update(&ctx, challenge, chalLen);
  sha256_update(&ctx, PUF_SECRET, sizeof(PUF_SECRET));
  sha256_final(&ctx, buf);
  memcpy(response, buf, 16); // 128-bit response
}

void generateNewChallenge(uint8_t out[16]) {
  for (int i = 0; i < 16; ++i) {
    out[i] = (uint8_t)(esp_random() & 0xFF);
  }
}

void generateNonce32(uint8_t out[32]) {
  for (int i = 0; i < 32; ++i) {
    out[i] = (uint8_t)(esp_random() & 0xFF);
  }
}

// --------------------------------------------------------
// Protocol logic
// --------------------------------------------------------

// Handle "CLIENT_HELLO": Step 1
void handleClientHello(JsonDocument &doc) {
  const char *idc_hex = doc["Id_c"];
  if (!idc_hex) {
    Serial.println("CLIENT_HELLO missing Id_c");
    return;
  }
  if (!hexToBytes(String(idc_hex), g_Id_c, 16)) {
    Serial.println("Id_c hex length mismatch");
    return;
  }

  g_t_start = esp_timer_get_time(); // start timing

  StaticJsonDocument<256> out;
  out["type"] = "BLE_HELLO_RESP";
  out["Id_p"] = bytesToHex(ID_P, 16);
  out["Id_c"] = bytesToHex(g_Id_c, 16);
  String s;
  serializeJson(out, s);
  pTxCharacteristic->setValue((uint8_t *)s.c_str(), s.length());
  pTxCharacteristic->notify();

  Serial.println("Sent BLE_HELLO_RESP");
}

// Handle "SERVER_DATA": Step 3
void handleServerData(JsonDocument &doc) {
  const char *m1_hex = doc["M1"];
  const char *m2_hex = doc["M2"];
  const char *m3_hex = doc["M3"];
  const char *m4_hex = doc["M4"];
  const char *cp_hex = doc["Cp"];

  if (!m1_hex || !m2_hex || !m3_hex || !m4_hex || !cp_hex) {
    Serial.println("SERVER_DATA missing fields");
    return;
  }

  uint8_t M1[16], M2[16], M3[32], M4[32];
  hexToBytes(String(m1_hex), M1, 16);
  hexToBytes(String(m2_hex), M2, 16);
  hexToBytes(String(m3_hex), M3, 32);
  hexToBytes(String(m4_hex), M4, 32);
  hexToBytes(String(cp_hex), g_Cp, 16);

  // Rp = PUF(Cp)
  evalPUF(g_Cp, 16, g_Rp);

  // T1 = M1 XOR Rp
  xorBytes(M1, g_Rp, g_T1, 16);

  // T2 = M2 XOR T1
  xorBytes(M2, g_T1, g_T2, 16);

  // Id_c' = M3 XOR H(T1||T2)
  uint8_t hT[32];
  hash_concat3(g_T1, 16, g_T2, 16, nullptr, 0, hT);
  xorBytes(M3, hT, g_Id_c_prime, 32);

  // Verify M4 == H(T1||T2||Rp||Cp||Id_c')
  uint8_t check[32];
  hash_concat5(g_T1, 16, g_T2, 16, g_Rp, 16, g_Cp, 16, g_Id_c_prime, 32, check);

  if (memcmp(check, M4, 32) != 0) {
    Serial.println("M4 verification failed, aborting");
    return;
  }
  Serial.println("Step 3 verification succeeded");

  // Step 4: generate Cp_new, M5..M8
  generateNewChallenge(g_Cp_new);
  uint8_t H_Rp[32];
  hash_single(g_Rp, 16, H_Rp);

  uint8_t H_Rp_trunc[16];
  memcpy(H_Rp_trunc, H_Rp, 16);

  uint8_t M5[16];
  xorBytes(g_Cp_new, H_Rp_trunc, M5, 16);

  // M6 = H(M5 || H(Rp))
  uint8_t M6[32];
  mbedtls_sha256_context ctx2;
  sha256_init(&ctx2);
  sha256_update(&ctx2, M5, 16);
  sha256_update(&ctx2, H_Rp, 32);
  sha256_final(&ctx2, M6);

  // Rp_new = PUF(Cp_new)
  evalPUF(g_Cp_new, 16, g_Rp_new);

  // M7 = T2 XOR Rp_new
  uint8_t M7[16];
  xorBytes(g_T2, g_Rp_new, M7, 16);

  // M8 = H(M7 || T2)
  uint8_t M8[32];
  hash_concat3(M7, 16, g_T2, 16, nullptr, 0, M8);

  // -------- send in two smaller JSON notifications --------

  // Part 1: M5, M6
  {
    StaticJsonDocument<256> out1;
    out1["type"] = "BLE_TO_SERVER_1";
    out1["M5"] = bytesToHex(M5, 16);
    out1["M6"] = bytesToHex(M6, 32);
    String s1;
    serializeJson(out1, s1);
    pTxCharacteristic->setValue((uint8_t *)s1.c_str(), s1.length());
    pTxCharacteristic->notify();
    Serial.println("Sent BLE_TO_SERVER_1 (M5,M6)");
  }

  // Part 2: M7, M8
  {
    StaticJsonDocument<256> out2;
    out2["type"] = "BLE_TO_SERVER_2";
    out2["M7"] = bytesToHex(M7, 16);
    out2["M8"] = bytesToHex(M8, 32);
    String s2;
    serializeJson(out2, s2);
    pTxCharacteristic->setValue((uint8_t *)s2.c_str(), s2.length());
    pTxCharacteristic->notify();
    Serial.println("Sent BLE_TO_SERVER_2 (M7,M8)");
  }
}


// Handle "SERVER_M9": store M9
void handleServerM9(JsonDocument &doc) {
  const char *m9_hex = doc["M9"];
  if (!m9_hex) {
    Serial.println("SERVER_M9 missing M9");
    return;
  }
  hexToBytes(String(m9_hex), g_M9, 32);
  Serial.println("Received M9 from server (via client)");
}

// Handle "CLIENT_NONCE": Step 7
void handleClientNonce(JsonDocument &doc) {
  const char *m10_hex = doc["M10"];
  const char *m11_hex = doc["M11"];
  if (!m10_hex || !m11_hex) {
    Serial.println("CLIENT_NONCE missing fields");
    return;
  }
  uint8_t M10[32], M11[32];
  hexToBytes(String(m10_hex), M10, 32);
  hexToBytes(String(m11_hex), M11, 32);

  // Nc = M10 XOR M9
  xorBytes(M10, g_M9, g_Nc, 32);

  // Verify M11 == H(M10 || M9)
  uint8_t check[32];
  hash_concat3(M10, 32, g_M9, 32, nullptr, 0, check);
  if (memcmp(check, M11, 32) != 0) {
    Serial.println("M11 verification failed");
    return;
  }
  Serial.println("M11 verified, generating Np");

  // Generate Np and create M12, M13
  generateNonce32(g_Np);
  uint8_t M12[32];
  xorBytes(g_Np, g_Nc, M12, 32);

  uint8_t M13[32];
  hash_concat3(M12, 32, g_Nc, 32, nullptr, 0, M13);

  // Session key SK = H(Nc || Np || Id_c' || Id_p)
  mbedtls_sha256_context ctx;
  sha256_init(&ctx);
  sha256_update(&ctx, g_Nc, 32);
  sha256_update(&ctx, g_Np, 32);
  sha256_update(&ctx, g_Id_c_prime, 32);
  sha256_update(&ctx, ID_P, 16);
  sha256_final(&ctx, g_SK);

  g_t_end = esp_timer_get_time();
  uint64_t elapsed_us = g_t_end - g_t_start;

  Serial.print("Protocol completed, elapsed time (microseconds): ");
  Serial.println((unsigned long)elapsed_us);

  // Part 1: M12, M13
  {
    StaticJsonDocument<256> out1;
    out1["type"] = "BLE_FINAL_1";
    out1["M12"] = bytesToHex(M12, 32);
    out1["M13"] = bytesToHex(M13, 32);
    String s1;
    serializeJson(out1, s1);
    pTxCharacteristic->setValue((uint8_t *)s1.c_str(), s1.length());
    pTxCharacteristic->notify();
    Serial.println("Sent BLE_FINAL_1 (M12,M13)");
  }

  // Part 2: elapsed_us, SK
  {
    StaticJsonDocument<256> out2;
    out2["type"] = "BLE_FINAL_2";
    out2["elapsed_us"] = elapsed_us;
    out2["SK"] = bytesToHex(g_SK, 32);
    String s2;
    serializeJson(out2, s2);
    pTxCharacteristic->setValue((uint8_t *)s2.c_str(), s2.length());
    pTxCharacteristic->notify();
    Serial.println("Sent BLE_FINAL_2 (elapsed_us, SK)");
  }
}


// --------------------------------------------------------
// BLE callbacks
// --------------------------------------------------------

class MyServerCallbacks : public BLEServerCallbacks {
  void onConnect(BLEServer *pServer) override {
    deviceConnected = true;
    Serial.println("BLE client connected");
  }
  void onDisconnect(BLEServer *pServer) override {
    deviceConnected = false;
    Serial.println("BLE client disconnected");
    pServer->getAdvertising()->start();
  }
};

class MyRxCallbacks : public BLECharacteristicCallbacks {
  void onWrite(BLECharacteristic *pChar) override {
    // On your core getValue() returns Arduino String
    String rxValue = pChar->getValue();
    if (rxValue.length() == 0) return;

    String jsonStr = rxValue;
    Serial.print("Received over BLE: ");
    Serial.println(jsonStr);

    StaticJsonDocument<1024> doc;
    DeserializationError err = deserializeJson(doc, jsonStr);
    if (err) {
      Serial.print("JSON parse error: ");
      Serial.println(err.c_str());
      return;
    }

    const char *type = doc["type"];
    if (!type) {
      Serial.println("Missing type field");
      return;
    }

    String t = String(type);
    if (t == "CLIENT_HELLO") {
      handleClientHello(doc);
    } else if (t == "SERVER_DATA") {
      handleServerData(doc);
    } else if (t == "SERVER_M9") {
      handleServerM9(doc);
    } else if (t == "CLIENT_NONCE") {
      handleClientNonce(doc);
    } else {
      Serial.println("Unknown message type");
    }
  }
};

// --------------------------------------------------------
// Setup and loop
// --------------------------------------------------------

void setup() {
  Serial.begin(115200);
  delay(1000);
  Serial.println("Starting PLAKE-like ESP32 BLE device");

  BLEDevice::init(BLE_DEVICE_NAME);
  BLEDevice::setMTU(247);

  BLEServer *pServer = BLEDevice::createServer();
  pServer->setCallbacks(new MyServerCallbacks());

  BLEService *pService = pServer->createService(SERVICE_UUID);

  // TX characteristic (notify)
  pTxCharacteristic = pService->createCharacteristic(
      CHAR_UUID_TX,
      BLECharacteristic::PROPERTY_NOTIFY
  );
  pTxCharacteristic->addDescriptor(new BLE2902());

  // RX characteristic (write)
  BLECharacteristic *pRxCharacteristic = pService->createCharacteristic(
      CHAR_UUID_RX,
      BLECharacteristic::PROPERTY_WRITE
  );
  pRxCharacteristic->setCallbacks(new MyRxCallbacks());

  pService->start();

  BLEAdvertising *pAdvertising = BLEDevice::getAdvertising();
  pAdvertising->addServiceUUID(SERVICE_UUID);
  pAdvertising->setScanResponse(true);
  pAdvertising->setMinPreferred(0x06);
  pAdvertising->setMaxPreferred(0x12);
  BLEDevice::startAdvertising();

  Serial.println("BLE advertising started");
}

void loop() {
  delay(1000);
}
