#include <array>
#include <chrono>
#include <format>
#include <fstream>
#include <iostream>
#include <iterator>
#include <print>
#include <random>
#include <string>

enum {
  AES_BLOCKLEN = 16, // Block length in bytes AES is 128b block only
  AES_keyExpSize = 240
};

struct AES_ctx {
  std::array<uint8_t, AES_keyExpSize> RoundKey{};
};

enum {
  Nb = 4, // The number of columns comprising a state in AES
  Nk = 8,
  Nr = 14
};

// state - array holding the intermediate results during decryption.
using state_t = std::array<std::array<uint8_t, 4>, 4>;

const std::array<uint8_t, 256> sbox = {
    // 0     1     2     3     4     5     6     7     8     9     A     B     C
    // D     E     F
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b,
    0xfe, 0xd7, 0xab, 0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
    0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26,
    0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2,
    0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
    0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed,
    0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f,
    0x50, 0x3c, 0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
    0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec,
    0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14,
    0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
    0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d,
    0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f,
    0x4b, 0xbd, 0x8b, 0x8a, 0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
    0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 0xe1, 0xf8, 0x98, 0x11,
    0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f,
    0xb0, 0x54, 0xbb, 0x16};

const std::array<uint8_t, 256> rsbox = {
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e,
    0x81, 0xf3, 0xd7, 0xfb, 0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87,
    0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb, 0x54, 0x7b, 0x94, 0x32,
    0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49,
    0x6d, 0x8b, 0xd1, 0x25, 0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16,
    0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92, 0x6c, 0x70, 0x48, 0x50,
    0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05,
    0xb8, 0xb3, 0x45, 0x06, 0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02,
    0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b, 0x3a, 0x91, 0x11, 0x41,
    0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8,
    0x1c, 0x75, 0xdf, 0x6e, 0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89,
    0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b, 0xfc, 0x56, 0x3e, 0x4b,
    0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59,
    0x27, 0x80, 0xec, 0x5f, 0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d,
    0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef, 0xa0, 0xe0, 0x3b, 0x4d,
    0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63,
    0x55, 0x21, 0x0c, 0x7d};

const std::array<uint8_t, 8> Rcon = {0x8d, 0x01, 0x02, 0x04,
                                     0x08, 0x10, 0x20, 0x40};

uint8_t getSBoxValue(uint8_t num) { return sbox.at(num); }

uint8_t getSBoxInvert(uint8_t num) { return rsbox.at(num); }

// This function produces Nb(Nr+1) round keys. The round keys are used in each
// round to decrypt the states.
void KeyExpansion(auto &RoundKey, const auto &Key) {
  unsigned first = 0;
  unsigned second = 0;
  unsigned third = 0;
  std::array<uint8_t, 4> tempa{}; // Used for the column/row operations

  // The first round key is the key itself.
  for (first = 0; first < Nk; first++) {
    RoundKey.at((first * 4) + 0) = Key.at((first * 4) + 0);
    RoundKey.at((first * 4) + 1) = Key.at((first * 4) + 1);
    RoundKey.at((first * 4) + 2) = Key.at((first * 4) + 2);
    RoundKey.at((first * 4) + 3) = Key.at((first * 4) + 3);
  }

  // All other round keys are found from the previous round keys.
  for (first = Nk; first < Nb * (Nr + 1); first++) {
    third = (first - 1) * 4;
    tempa.at(0) = RoundKey.at(third + 0);
    tempa.at(1) = RoundKey.at(third + 1);
    tempa.at(2) = RoundKey.at(third + 2);
    tempa.at(3) = RoundKey.at(third + 3);

    if (first % Nk == 0) {
      // This function shifts the 4 bytes in a word to the left once.
      // [a0,a1,a2,a3] becomes [a1,a2,a3,a0]
      const uint8_t u8tmp = tempa[0];
      tempa[0] = tempa[1];
      tempa[1] = tempa[2];
      tempa[2] = tempa[3];
      tempa[3] = u8tmp;

      // This is a function that takes a four-byte input word and
      // applies the S-box to each of the four bytes to produce an output word.
      tempa[0] = getSBoxValue(tempa[0]);
      tempa[1] = getSBoxValue(tempa[1]);
      tempa[2] = getSBoxValue(tempa[2]);
      tempa[3] = getSBoxValue(tempa[3]);

      tempa.at(0) = tempa.at(0) ^ Rcon.at(first / Nk);
    }

    if (first % Nk == 4) {
      tempa[0] = getSBoxValue(tempa[0]);
      tempa[1] = getSBoxValue(tempa[1]);
      tempa[2] = getSBoxValue(tempa[2]);
      tempa[3] = getSBoxValue(tempa[3]);
    }

    second = first * 4;
    third = (first - Nk) * 4;
    RoundKey.at(second + 0) = RoundKey.at(third + 0) ^ tempa.at(0);
    RoundKey.at(second + 1) = RoundKey.at(third + 1) ^ tempa.at(1);
    RoundKey.at(second + 2) = RoundKey.at(third + 2) ^ tempa.at(2);
    RoundKey.at(second + 3) = RoundKey.at(third + 3) ^ tempa.at(3);
  }
}

void AES_init_ctx(AES_ctx &ctx, const auto &key) {
  KeyExpansion(ctx.RoundKey, key);
}

// This function adds the round key to state.
// The round key is added to the state by an XOR function.
void AddRoundKey(uint8_t round, state_t &state, const auto &RoundKey) {
  for (uint8_t i = 0; i < 4; i++) {
    for (uint8_t j = 0; j < 4; j++) {
      state.at(i).at(j) ^= RoundKey.at((round * Nb * 4) + (i * Nb) + j);
    }
  }
}

// The SubBytes Function Substitutes the values in the
// state matrix with values in an S-box.
void SubBytes(state_t &state) {
  for (uint8_t i = 0; i < 4; i++) {
    for (uint8_t j = 0; j < 4; j++) {
      state.at(j).at(i) = getSBoxValue(state.at(j).at(i));
    }
  }
}

// The ShiftRows() function shifts the rows in the state to the left.
// Each row is shifted with different offset.
// Offset = Row number. So the first row is not shifted.
void ShiftRows(state_t &state) {
  // Rotate first row 1 columns to left
  uint8_t temp = state[0][1];
  state[0][1] = state[1][1];
  state[1][1] = state[2][1];
  state[2][1] = state[3][1];
  state[3][1] = temp;

  // Rotate second row 2 columns to left
  temp = state[0][2];
  state[0][2] = state[2][2];
  state[2][2] = temp;
  temp = state[1][2];
  state[1][2] = state[3][2];
  state[3][2] = temp;

  // Rotate third row 3 columns to left
  temp = state[0][3];
  state[0][3] = state[3][3];
  state[3][3] = state[2][3];
  state[2][3] = state[1][3];
  state[1][3] = temp;
}

uint8_t xtime(uint8_t x) { return ((x << 1) ^ (((x >> 7) & 1) * 0x1b)); }

// MixColumns function mixes the columns of the state matrix
void MixColumns(state_t &state) {
  uint8_t Tmp = 0;
  uint8_t Tm = 0;
  uint8_t t = 0;
  for (uint8_t i = 0; i < 4; i++) {
    t = state.at(i).at(0);
    Tmp = state.at(i).at(0) ^ state.at(i).at(1) ^ state.at(i).at(2) ^
          state.at(i).at(3);
    Tm = state.at(i).at(0) ^ state.at(i).at(1);
    Tm = xtime(Tm);
    state.at(i).at(0) ^= Tm ^ Tmp;
    Tm = state.at(i).at(1) ^ state.at(i).at(2);
    Tm = xtime(Tm);
    state.at(i).at(1) ^= Tm ^ Tmp;
    Tm = state.at(i).at(2) ^ state.at(i).at(3);
    Tm = xtime(Tm);
    state.at(i).at(2) ^= Tm ^ Tmp;
    Tm = state.at(i).at(3) ^ t;
    Tm = xtime(Tm);
    state.at(i).at(3) ^= Tm ^ Tmp;
  }
}

uint8_t Multiply(uint8_t x, uint8_t y) {
  return (((y & 1) * x) ^ ((y >> 1 & 1) * xtime(x)) ^
          ((y >> 2 & 1) * xtime(xtime(x))) ^
          ((y >> 3 & 1) * xtime(xtime(xtime(x)))) ^
          ((y >> 4 & 1) * xtime(xtime(xtime(xtime(x))))));
}

void InvMixColumns(state_t &state) {
  uint8_t first = 0;
  uint8_t second = 0;
  uint8_t third = 0;
  uint8_t fourth = 0;
  for (int i = 0; i < 4; i++) {
    first = state.at(i).at(0);
    second = state.at(i).at(1);
    third = state.at(i).at(2);
    fourth = state.at(i).at(3);

    state.at(i).at(0) = Multiply(first, 0x0e) ^ Multiply(second, 0x0b) ^
                        Multiply(third, 0x0d) ^ Multiply(fourth, 0x09);
    state.at(i).at(1) = Multiply(first, 0x09) ^ Multiply(second, 0x0e) ^
                        Multiply(third, 0x0b) ^ Multiply(fourth, 0x0d);
    state.at(i).at(2) = Multiply(first, 0x0d) ^ Multiply(second, 0x09) ^
                        Multiply(third, 0x0e) ^ Multiply(fourth, 0x0b);
    state.at(i).at(3) = Multiply(first, 0x0b) ^ Multiply(second, 0x0d) ^
                        Multiply(third, 0x09) ^ Multiply(fourth, 0x0e);
  }
}

void InvSubBytes(state_t &state) {
  for (uint8_t i = 0; i < 4; i++) {
    for (uint8_t j = 0; j < 4; j++) {
      state.at(j).at(i) = getSBoxInvert(state.at(j).at(i));
    }
  }
}

void InvShiftRows(state_t &state) {
  // Rotate first row 1 columns to right
  uint8_t temp = state[3][1];
  state[3][1] = state[2][1];
  state[2][1] = state[1][1];
  state[1][1] = state[0][1];
  state[0][1] = temp;

  // Rotate second row 2 columns to right
  temp = state[0][2];
  state[0][2] = state[2][2];
  state[2][2] = temp;

  temp = state[1][2];
  state[1][2] = state[3][2];
  state[3][2] = temp;

  // Rotate third row 3 columns to right
  temp = state[0][3];
  state[0][3] = state[1][3];
  state[1][3] = state[2][3];
  state[2][3] = state[3][3];
  state[3][3] = temp;
}

// Cipher is the main function that encrypts the PlainText.
void Cipher(state_t &state, auto &RoundKey) {
  // Add the First round key to the state before starting the rounds.
  AddRoundKey(0, state, RoundKey);

  // There will be Nr rounds.
  // The first Nr-1 rounds are identical.
  // These Nr-1 rounds are executed in the loop below.
  for (uint8_t round = 1; round < Nr; round++) {
    SubBytes(state);
    ShiftRows(state);
    MixColumns(state);
    AddRoundKey(round, state, RoundKey);
  }

  // The last round is given below.
  // The MixColumns function is not here in the last round.
  SubBytes(state);
  ShiftRows(state);
  AddRoundKey(Nr, state, RoundKey);
}

void InvCipher(state_t &state, auto &RoundKey) {
  // Add the First round key to the state before starting the rounds.
  AddRoundKey(Nr, state, RoundKey);

  // There will be Nr rounds.
  // The first Nr-1 rounds are identical.
  // These Nr-1 rounds are executed in the loop below.
  for (uint8_t round = (Nr - 1); round > 0; --round) {
    InvShiftRows(state);
    InvSubBytes(state);
    AddRoundKey(round, state, RoundKey);
    InvMixColumns(state);
  }

  // The last round is given below.
  // The MixColumns function is not here in the last round.
  InvShiftRows(state);
  InvSubBytes(state);
  AddRoundKey(0, state, RoundKey);
}

void AES_ECB_encrypt(AES_ctx &ctx, auto &buf) {
  // The next function call encrypts the PlainText with the Key using AES
  // algorithm.
  Cipher(buf, ctx.RoundKey);
}

void AES_ECB_decrypt(AES_ctx &ctx, auto &buf) {
  // The next function call decrypts the PlainText with the Key using AES
  // algorithm.
  InvCipher(buf, ctx.RoundKey);
}

void AES_encrypt(const auto &key, auto &data) {
  AES_ctx ctx{};
  state_t array{};

  AES_init_ctx(ctx, key);
  for (uint32_t i = 0; i < data.size() / AES_BLOCKLEN; i++) {
    auto offset = i * AES_BLOCKLEN;
    auto start_read_iterator = data.begin();
    auto start_write_iterator = data.begin();
    const uint8_t maxextent{4};
    std::advance(start_read_iterator, offset);
    std::advance(start_write_iterator, offset);

    // copy to temporary array
    for (unsigned counter{0};
         counter < AES_BLOCKLEN && start_read_iterator != data.end();
         ++counter, std::advance(start_read_iterator, 1)) {
      array.at(counter / maxextent).at(counter % maxextent) =
          *start_read_iterator;
    }
    AES_ECB_encrypt(ctx, array);

    // copy back to vector
    for (unsigned counter{0};
         counter < AES_BLOCKLEN && start_write_iterator != data.end();
         ++counter, std::advance(start_write_iterator, 1)) {
      *start_write_iterator =
          array.at(counter / maxextent).at(counter % maxextent);
    }
  }
}

void AES_decrypt(const auto &key, auto &data) {
  AES_ctx ctx{};
  state_t array{};

  AES_init_ctx(ctx, key);
  for (uint32_t i = 0; i < data.size() / AES_BLOCKLEN; i++) {
    auto offset = i * AES_BLOCKLEN;
    auto start_read_iterator = data.begin();
    auto start_write_iterator = data.begin();
    const uint8_t maxextent{4};
    std::advance(start_read_iterator, offset);
    std::advance(start_write_iterator, offset);

    // copy to temporary array
    for (unsigned counter{0};
         counter < AES_BLOCKLEN && start_read_iterator != data.end();
         ++counter, std::advance(start_read_iterator, 1)) {
      array.at(counter / maxextent).at(counter % maxextent) =
          *start_read_iterator;
    }
    AES_ECB_decrypt(ctx, array);

    // copy back to vector
    for (unsigned counter{0};
         counter < AES_BLOCKLEN && start_write_iterator != data.end();
         ++counter, std::advance(start_write_iterator, 1)) {
      *start_write_iterator =
          array.at(counter / maxextent).at(counter % maxextent);
    }
  }
}

void PrintHex(const auto &str, uint8_t len) {
  for (uint8_t i = 0; i < len; i++) {
    if (i > 0 && i % AES_BLOCKLEN == 0) {
      std::println("");
    }
    std::cout << std::format("{0:2x}", str.at(i));
  }
  std::println("");
}

int ctoh(char character) {
  std::string str = {character, '\0'};
  return std::stoi(str);
}

uint8_t chartohex(uint8_t character) {
  uint8_t res = std::numeric_limits<unsigned char>::max();
  if (character >= '0' && character <= '9') {
    res = character - '0';
  } else if (character >= 'a' && character <= 'f') {
    res = character - 'a' + 10;
  } else { // if (c >= 'A' && c <= 'F')
    res = character - 'A' + 10;
  }
  return res;
}

void prompt() {

  std::cout << "This program encrypts/decrypts files\n";
  std::println("using AES256 encryption with ECB mode of operation");
  std::println("and ANSI X9.23 padding method\n");

  std::println("The maximum supported file size is 4GB");
  std::println("Enough RAM is required to load the file");
  std::println(
      "Encrypted files are 1 to 16 bytes larger than the original ones");

  std::print("\nChoose an option:");
  std::print("\n\t1) Generate random key");
  std::print("\n\t2) Load key from file");
  std::println("\n\t3) Type key");
}

int main() {
  uint32_t opt = 0;
  prompt();
  std::cin >> opt;
  if (opt != 1 && opt != 2 && opt != 3) {
    std::terminate();
  }
  std::println("");
  const uint8_t keysize{32};
  std::array<uint8_t, keysize> key{};

  if (opt == 1) {
    std::print("Loading Source of Entropy\t");
    std::random_device randomdevice{};
    std::mt19937 generator(randomdevice());
    const unsigned char maxchar{255};
    std::uniform_int_distribution<uint8_t> distribution(1, maxchar);
    std::println("COMPLETE");
    std::print("Generating Keys\t\t\t");
    for (unsigned char &character : key) {
      character = distribution(generator);
    }
    std::println("COMPLETE");
  } else if (opt == 2) {

    std::string keyfilename;
    std::println("Enter the name of the binary file containing the key");
    std::cin >> keyfilename;
    std::ifstream keyfile{keyfilename};
    unsigned counter{};
    for (auto &byte : key) {
      keyfile >> byte;
      counter++;
    }
    const auto ksize = counter;
    //    assert(keyfile.eof() == true);
    keyfile.seekg(0);
    std::println("key file size => {}", static_cast<int>(ksize));

    std::println("Key loaded from file {}", keyfilename);
  } else {
    char digit1 = 0;
    char digit2 = 0;

    std::println("Enter the key (64 hexadecimal digits):");
    for (unsigned char &character : key) {
      std::cin >> digit1;
      std::cin >> digit2;
      character = chartohex(digit1) * AES_BLOCKLEN + chartohex(digit2);
    }
    std::println("Key Read");
  }

  std::println("Key:");
  PrintHex(key, keysize);
  std::println("");

  std::ofstream keyoutput("key.bin");
  for (const auto byte : key) {
    keyoutput << byte;
  }

  std::println(
      "Key has been stored in the file key.bin\nEnter name of the file to "
      "Encrypt/Decrypt\nWARNING: The file will be overwritten");

  std::string datafilename;
  std::cin >> datafilename;

  std::ifstream datafile{datafilename};

  auto data = std::vector<uint8_t>{};
  std::copy(std::istream_iterator<uint8_t>(datafile),
            std::istream_iterator<uint8_t>(), std::back_inserter(data));

  unsigned size = data.size();

  std::print("\nChoose an option:");
  std::print("\n\t1) Encrypt");
  std::print("\n\t2) Decrypt");
  std::println("");

  std::cin >> opt;
  if (opt != 1 && opt != 2) {
    std::cerr << "Invalid Option\n";
    std::terminate();
  }
  std::println("");

  if (opt == 1) {
    auto const len =
        static_cast<unsigned>(AES_BLOCKLEN - (size % AES_BLOCKLEN));
    std::vector<uint8_t> pad(len);
    // ANSI X9.23
    pad.assign(len, 0x00);

    pad.at(len - 1) = static_cast<uint8_t>(len);

    for (const auto byte : pad) {
      data.push_back(byte);
    }
    // PKCS#7
    //    for (uint8_t i = 0; i < len; i++)
    //      pad[i] = len;
    std::println("{} bytes have been added to the file to encrypt it",
                 pad.size());
  }

  const auto start = std::chrono::system_clock::now();

  if (opt == 1) {
    const auto five_seconds{50000000};
    std::println("Estimated Encryption time: {} seconds", size / five_seconds);
    AES_encrypt(key, data);
    std::println("Encrypted!");
  } else {
    const auto two_seconds{20000000};
    std::println("Estimated Decryption time: {} seconds", size / two_seconds);
    AES_decrypt(key, data);
    std::println("Decrypted!");
  }

  const auto end = std::chrono::system_clock::now();

  const auto diff = end - start;
  std::println("{} bytes have been encrypted / decrypted in {}", size, diff);

  if (opt == 2) {
    uint32_t const del = data.at(size - 1);
    size -= del;
    auto beginpoint = data.begin();
    std::advance(beginpoint, size);
    data.erase(beginpoint, data.end());
    std::println("{} bytes have been removed from the decrypted file", del);
  }

  std::ofstream outputfile{datafilename};

  for (const auto byte : data) {
    outputfile << byte;
  }

  std::println("File saved on disk");
  return 0;
}
