# Files in this snippet
# 1) VotingWithBlockchain.ino  – your upgraded Arduino sketch with a tamper‑evident (hash‑chained) vote log stored in EEPROM
# 2) .github/workflows/arduino.yml – GitHub Actions workflow to build the sketch on each push/PR and upload the HEX as an artifact
# 3) README.md – quick instructions


==========================
VotingWithBlockchain.ino
==========================

#include <Keypad.h>
#include <EEPROM.h>

// -------- KEYPAD SETUP --------
const byte ROWS = 4; 
const byte COLS = 4;
char keys[ROWS][COLS] = {
  {'1','2','3','A'},
  {'4','5','6','B'},
  {'7','8','9','C'},
  {'*','0','#','D'}
};
byte rowPins[ROWS] = {A0, A1, A2, A3};
byte colPins[COLS] = {A4, A5, 2, 8};
Keypad keypad = Keypad(makeKeymap(keys), rowPins, colPins, ROWS, COLS);

// -------- VOTING SETUP --------
const int buttonPins[4] = {3, 4, 5, 6};
const int resultButton = 7;
const int ledPins[4] = {9, 10, 11, 12};
const int buzzerPin = 13;

int votes[4] = {0, 0, 0, 0};

// -------- PASSWORD STRUCTURE --------
struct PasswordEntry {
  const char* password;
  bool used;
};

PasswordEntry validPasswords[70] = {
  {"1234", false}, {"4321", false}, {"1111", false}, {"0000", false}, {"2468", false},
  {"1357", false}, {"9999", false}, {"2580", false}, {"9876", false}, {"1010", false},
  {"1001", false}, {"1002", false}, {"1003", false}, {"1004", false}, {"1005", false},
  {"1006", false}, {"1007", false}, {"1008", false}, {"1009", false}, {"1011", false},
  {"1012", false}, {"1013", false}, {"1014", false}, {"1015", false}, {"1016", false},
  {"1017", false}, {"1018", false}, {"1019", false}, {"1020", false}, {"1021", false},
  {"1022", false}, {"1023", false}, {"1024", false}, {"1025", false}, {"1026", false},
  {"1027", false}, {"1028", false}, {"1029", false}, {"1030", false}, {"2001", false},
  {"2002", false}, {"2003", false}, {"2004", false}, {"2005", false}, {"2006", false},
  {"2007", false}, {"2008", false}, {"2009", false}, {"2010", false}, {"2011", false},
  {"2012", false}, {"2013", false}, {"2014", false}, {"2015", false}, {"2016", false},
  {"2017", false}, {"2018", false}, {"2019", false}, {"2020", false}, {"2021", false},
  {"2022", false}, {"2023", false}, {"2024", false}, {"2025", false}, {"2026", false},
  {"2027", false}, {"2028", false}, {"2029", false}, {"2030", false}, {"9990", false}
};

String inputPassword = "";
bool accessGranted = false;
bool voteCasted = false;
int lastPasswordIndex = -1; // remember which password unlocked the current vote

// ================================
//         MINI BLOCKCHAIN
// ================================
// We implement a tamper‑evident append‑only log (hash chain) in EEPROM.
// Each vote creates a "block" whose hash depends on: prevHash, candidate, passwordIndex, timestamp.
// If any stored block is edited, verification will fail.

// FNV‑1a 32‑bit hash (fast + tiny)
static uint32_t fnv1a(const uint8_t* data, size_t len) {
  uint32_t hash = 0x811C9DC5UL; // offset basis
  for (size_t i = 0; i < len; i++) {
    hash ^= data[i];
    hash *= 16777619UL; // FNV prime
  }
  return hash;
}

// Compact block stored in EEPROM (14 bytes per block)
// Layout: [prevHash(4)][candidate(1)][pwdIdx(1)][timestamp(4)][hash(4)]
struct VoteBlock {
  uint32_t prevHash;
  uint8_t  candidate;
  uint8_t  pwdIdx;
  uint32_t timestamp;
  uint32_t hash;
};

// EEPROM layout
// [0..1]  -> uint16_t blockCount
// [2..]   -> VoteBlock records (each 14 bytes)
const int EE_ADDR_COUNT = 0;
const int EE_ADDR_BLOCKS = 2;
const int BLOCK_SIZE = 14; // sizeof(VoteBlock) packed

uint16_t eeReadU16(int addr) {
  uint16_t v = EEPROM.read(addr) | (uint16_t(EEPROM.read(addr+1)) << 8);
  return v;
}

void eeWriteU16(int addr, uint16_t v) {
  EEPROM.update(addr,   uint8_t(v & 0xFF));
  EEPROM.update(addr+1, uint8_t((v >> 8) & 0xFF));
}

void eeWriteBlock(int addr, const VoteBlock& b) {
  // write in the same order/size as layout
  EEPROM.put(addr, b.prevHash);         // 4
  EEPROM.update(addr+4, b.candidate);   // 1
  EEPROM.update(addr+5, b.pwdIdx);      // 1
  EEPROM.put(addr+6, b.timestamp);      // 4
  EEPROM.put(addr+10, b.hash);          // 4
}

void eeReadBlock(int addr, VoteBlock& b) {
  EEPROM.get(addr, b.prevHash);
  b.candidate = EEPROM.read(addr+4);
  b.pwdIdx    = EEPROM.read(addr+5);
  EEPROM.get(addr+6, b.timestamp);
  EEPROM.get(addr+10, b.hash);
}

uint16_t getBlockCount() {
  return eeReadU16(EE_ADDR_COUNT);
}

void setBlockCount(uint16_t c) {
  eeWriteU16(EE_ADDR_COUNT, c);
}

int blockAddr(uint16_t index) {
  return EE_ADDR_BLOCKS + int(index) * BLOCK_SIZE;
}

uint32_t computeBlockHash(uint32_t prevHash, uint8_t candidate, uint8_t pwdIdx, uint32_t timestamp) {
  uint8_t buf[10];
  // Pack into buffer: prevHash(4), candidate(1), pwdIdx(1), timestamp(4)
  buf[0] = uint8_t(prevHash & 0xFF);
  buf[1] = uint8_t((prevHash >> 8) & 0xFF);
  buf[2] = uint8_t((prevHash >> 16) & 0xFF);
  buf[3] = uint8_t((prevHash >> 24) & 0xFF);
  buf[4] = candidate;
  buf[5] = pwdIdx;
  buf[6] = uint8_t(timestamp & 0xFF);
  buf[7] = uint8_t((timestamp >> 8) & 0xFF);
  buf[8] = uint8_t((timestamp >> 16) & 0xFF);
  buf[9] = uint8_t((timestamp >> 24) & 0xFF);
  return fnv1a(buf, sizeof(buf));
}

uint32_t getLastHash() {
  uint16_t n = getBlockCount();
  if (n == 0) return 0; // genesis prevHash
  VoteBlock b; eeReadBlock(blockAddr(n - 1), b);
  return b.hash;
}

bool appendVoteToChain(uint8_t candidate, uint8_t pwdIdx) {
  uint16_t n = getBlockCount();
  int addr = blockAddr(n);

  // Ensure EEPROM capacity (UNO has 1024 bytes)
  if (addr + BLOCK_SIZE > EEPROM.length()) {
    Serial.println("[BLOCKCHAIN] EEPROM full – cannot append more votes.");
    return false;
  }

  VoteBlock b;
  b.prevHash = getLastHash();
  b.candidate = candidate;
  b.pwdIdx = pwdIdx;
  b.timestamp = millis();
  b.hash = computeBlockHash(b.prevHash, b.candidate, b.pwdIdx, b.timestamp);

  eeWriteBlock(addr, b);
  setBlockCount(n + 1);

  Serial.print("[BLOCKCHAIN] Appended block #"); Serial.print(n);
  Serial.print("  candidate="); Serial.print(candidate+1);
  Serial.print("  pwdIdx="); Serial.print(pwdIdx);
  Serial.print("  prevHash=0x"); Serial.print(b.prevHash, HEX);
  Serial.print("  hash=0x"); Serial.println(b.hash, HEX);
  return true;
}

bool verifyChain(bool verbose=true) {
  uint16_t n = getBlockCount();
  uint32_t prev = 0;
  for (uint16_t i = 0; i < n; i++) {
    VoteBlock b; eeReadBlock(blockAddr(i), b);
    uint32_t expect = computeBlockHash(prev, b.candidate, b.pwdIdx, b.timestamp);
    if (verbose) {
      Serial.print("[VERIFY] #"); Serial.print(i);
      Serial.print(" cand="); Serial.print(b.candidate+1);
      Serial.print(" pwdIdx="); Serial.print(b.pwdIdx);
      Serial.print(" prev=0x"); Serial.print(prev, HEX);
      Serial.print(" hash=0x"); Serial.print(b.hash, HEX);
      Serial.print(" expect=0x"); Serial.println(expect, HEX);
    }
    if (b.hash != expect) return false;
    prev = b.hash;
  }
  return true;
}

void printChainSummary() {
  uint16_t n = getBlockCount();
  Serial.print("[BLOCKCHAIN] Blocks: "); Serial.println(n);
  bool ok = verifyChain(false);
  Serial.print("[BLOCKCHAIN] Integrity: "); Serial.println(ok ? "OK" : "BROKEN");
  if (!ok) {
    Serial.println("Run detailed verify via menu to see which block fails.");
  }
}

void clearChainAndVotes() {
  // Wipe header + all used bytes
  uint16_t n = getBlockCount();
  int used = blockAddr(n);
  for (int i = 0; i < used; i++) EEPROM.update(i, 0x00);
  setBlockCount(0);
  for (int i=0;i<4;i++) votes[i]=0;
  for (int i=0;i<70;i++) validPasswords[i].used = false;
  Serial.println("[BLOCKCHAIN] Cleared all votes and chain.");
}

// Long‑press (>=5s) on result button will clear chain + votes
bool maybeHandleLongPressToClear() {
  if (digitalRead(resultButton) == HIGH) {
    unsigned long t0 = millis();
    while (digitalRead(resultButton) == HIGH) {
      if (millis() - t0 >= 5000UL) {
        clearChainAndVotes();
        return true;
      }
    }
  }
  return false;
}

// -------- BUZZER --------
void playSuccessTone() {
  tone(buzzerPin, 1000, 300);
  delay(350);
  tone(buzzerPin, 1500, 300);
  delay(350);
  noTone(buzzerPin);
}

void playFailureTone() {
  tone(buzzerPin, 400, 500);
  delay(600);
  noTone(buzzerPin);
}

// -------- FORWARD DECLS --------
void declareWinner();

// ================================
//             SETUP
// ================================
void setup() {
  Serial.begin(9600);

  for (int i = 0; i < 4; i++) {
    pinMode(buttonPins[i], INPUT);
    pinMode(ledPins[i], OUTPUT);
    digitalWrite(ledPins[i], LOW);
  }

  pinMode(resultButton, INPUT);
  pinMode(buzzerPin, OUTPUT);

  Serial.println("Enter password to start voting:");
  printChainSummary();
}

// ================================
//              LOOP
// ================================
void loop() {
  // Allow long‑press clear anytime
  if (maybeHandleLongPressToClear()) {
    delay(500); // debounce cool‑off
  }

  // -------- PASSWORD ENTRY --------
  if (!accessGranted) {
    char key = keypad.getKey();
    if (key) {
      Serial.print("Key pressed: ");
      Serial.println(key);

      if (key == '#') {
        int matchedIndex = -1;
        for (int i = 0; i < 70; i++) {
          if (inputPassword.equals(validPasswords[i].password)) {
            matchedIndex = i;
            break;
          }
        }

        if (matchedIndex != -1) {
          if (!validPasswords[matchedIndex].used) {
            validPasswords[matchedIndex].used = true;
            Serial.println("Access Granted! You may now vote.");
            playSuccessTone();
            accessGranted = true;
            voteCasted = false;
            lastPasswordIndex = matchedIndex; // remember for blockchain
          } else {
            Serial.println("This password has already been used. Try another.");
            playFailureTone();
          }
        } else {
          Serial.println("Wrong Password. Try again.");
          playFailureTone();
        }

        inputPassword = ""; // Reset input
      }
      else if (key == '*') {
        inputPassword = "";
        Serial.println("Input cleared.");
      }
      else if (key == 'D') {
        // Quick menu via keypad: press D then # to print full chain verify
        Serial.println("[MENU] Press # to verify full chain...");
      }
      else {
        inputPassword += key;
      }
    }
  }

  // If D then # pressed, run detailed verification
  if (keypad.getState() == PRESSED) {
    char k = keypad.getKey();
    if (k == '#') {
      // small trick: when user saw "[MENU] Press #..." this will trigger next
      Serial.println("[VERIFY] Running detailed verification...");
      bool ok = verifyChain(true);
      Serial.print("[VERIFY] Result: "); Serial.println(ok?"OK":"BROKEN");
    }
  }

  // -------- VOTING PROCESS (One vote per access) --------
  if (accessGranted && !voteCasted) {
    for (int i = 0; i < 4; i++) {
      if (digitalRead(buttonPins[i]) == HIGH) {
        votes[i]++;
        Serial.print("Vote for Candidate ");
        Serial.print(i + 1);
        Serial.println(" counted!");
        delay(300); // Debounce

        // Append to blockchain
        if (!appendVoteToChain((uint8_t)i, (uint8_t)lastPasswordIndex)) {
          Serial.println("[BLOCKCHAIN] Failed to log vote (EEPROM full).");
        }

        voteCasted = true;
        accessGranted = false;
        Serial.println("Your vote is registered. Next person, please enter your password.");
        break;
      }
    }
  }

  // -------- RESULT CHECK (Always allowed) --------
  if (digitalRead(resultButton) == HIGH) {
    delay(500); // Debounce
    declareWinner();
    printChainSummary();
  }
}

// -------- DECLARE WINNER --------
void declareWinner() {
  int maxVotes = 0;
  int winnerIndex = -1;

  for (int i = 0; i < 4; i++) {
    if (votes[i] > maxVotes) {
      maxVotes = votes[i];
      winnerIndex = i;
    }
  }

  for (int i = 0; i < 4; i++) {
    digitalWrite(ledPins[i], LOW); // Turn off all LEDs
  }

  if (maxVotes == 0) {
    Serial.println("No votes were cast. No winner.");
  } else {
    Serial.print("Voting Ended! Winner is Candidate ");
    Serial.print(winnerIndex + 1);
    Serial.print(" with ");
    Serial.print(maxVotes);
    Serial.println(" votes!");
    digitalWrite(ledPins[winnerIndex], HIGH); // Show winner
  }

  Serial.println("System will restart when RESET button is pressed.");
}


// ===========================
// End VotingWithBlockchain.ino
// ===========================



=================================
.github/workflows/arduino.yml
=================================

name: Arduino CI

on:
  push:
  pull_request:

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: Set up Arduino CLI
        uses: arduino/setup-arduino-cli@v1

      - name: Install AVR core
        run: |
          arduino-cli core update-index
          arduino-cli core install arduino:avr

      - name: Compile sketch for Arduino Uno
        run: |
          arduino-cli compile --fqbn arduino:avr:uno ./

      - name: Upload compiled HEX artifact
        uses: actions/upload-artifact@v4
        with:
          name: firmware-uno
          path: ./build/arduino.avr.uno/*.hex



=============
README.md
=============

# Arduino Voting – Tamper‑Evident Log (On‑Device "Blockchain")

This upgrade adds a tiny, self‑contained blockchain (hash‑chained log) stored in EEPROM. Every vote becomes a block that includes:

- previous block hash
- candidate index
- password index (which valid password unlocked this vote)
- timestamp (millis since power‑on)
- computed FNV‑1a 32‑bit hash of the above

Any change to a past block breaks verification.

## How to use
1. Upload `VotingWithBlockchain.ino` to your Arduino Uno.
2. Start Serial Monitor at 9600 baud – it will show chain summary on boot.
3. Normal voting flow remains the same (password → press candidate button).
4. After each vote, a new block is appended and printed with its hash.
5. Press the **Result** button to see the winner and a quick chain summary.
6. To run a detailed verification: press `D` then `#` on the keypad.
7. **Wipe all votes + chain**: hold the **Result** button for ≥5 seconds.

> **Note (EEPROM limits):** UNO has 1024 bytes. Each block uses 14 bytes → ~73 blocks max minus header; system will stop logging when full. Votes still count in RAM, but won’t be appended to the chain once EEPROM fills.

## GitHub Actions (CI)
- Push this repo to GitHub with both files in place.
- The workflow builds the sketch for Arduino Uno on every push/PR and publishes the compiled HEX as an artifact (`firmware-uno`).
- Download the artifact from the Actions run if you want the prebuilt firmware.

## Exporting the log
Open Serial Monitor and trigger detailed verification (`D` then `#`). Copy the printed blocks to a file. You (or anyone) can re‑compute the FNV‑1a across each block to verify integrity.

## Optional: Networked chain
This example is fully offline. If you later add an ESP8266/ESP32 or a gateway PC/Raspberry Pi, you can forward each block’s hash to a public blockchain or a server for anchoring.
