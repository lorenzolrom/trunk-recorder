/*
 * Standalone DES known-answer test for the OP25-derived P25 DES primitive.
 *
 * Build from the repository root with:
 *   c++ -std=c++17 -Ilib/op25_repeater/lib tests/des_known_answer.cc \
 *     lib/op25_repeater/lib/p25_crypt_des.cc -o /tmp/des_known_answer
 *
 * Then run:
 *   /tmp/des_known_answer
 */

#include <iostream>
#include <string>
#include <vector>

#define private public
#include "p25_crypt_des.h"
#undef private

static std::vector<std::string> build_round_keys(p25_crypt_des& des, const std::string& hex_key)
{
    std::string key = des.hex2bin(hex_key);

    int keyp[56] = { 57, 49, 41, 33, 25, 17, 9,
                    1, 58, 50, 42, 34, 26, 18,
                    10, 2, 59, 51, 43, 35, 27,
                    19, 11, 3, 60, 52, 44, 36,
                    63, 55, 47, 39, 31, 23, 15,
                    7, 62, 54, 46, 38, 30, 22,
                    14, 6, 61, 53, 45, 37, 29,
                    21, 13, 5, 28, 20, 12, 4 };

    int shift_table[16] = { 1, 1, 2, 2,
                            2, 2, 2, 2,
                            1, 2, 2, 2,
                            2, 2, 2, 1 };

    int key_comp[48] = { 14, 17, 11, 24, 1, 5,
                        3, 28, 15, 6, 21, 10,
                        23, 19, 12, 4, 26, 8,
                        16, 7, 27, 20, 13, 2,
                        41, 52, 31, 37, 47, 55,
                        30, 40, 51, 45, 33, 48,
                        44, 49, 39, 56, 34, 53,
                        46, 42, 50, 36, 29, 32 };

    key = des.permute(key, keyp, 56);
    std::string left = key.substr(0, 28);
    std::string right = key.substr(28, 28);
    std::vector<std::string> round_keys;
    round_keys.reserve(16);

    for (int i = 0; i < 16; i++) {
        left = des.shift_left(left, shift_table[i]);
        right = des.shift_left(right, shift_table[i]);
        round_keys.push_back(des.permute(left + right, key_comp, 48));
    }

    return round_keys;
}

int main()
{
    log_ts logger;
    p25_crypt_des des(logger, 0, 0);

    const std::string key = "133457799BBCDFF1";
    const std::string plaintext = "0123456789ABCDEF";
    const std::string expected_ciphertext = "85E813540F0AB405";

    std::vector<std::string> round_keys = build_round_keys(des, key);
    std::vector<std::string> round_keys_hex;
    round_keys_hex.reserve(round_keys.size());
    for (const auto& round_key : round_keys) {
        round_keys_hex.push_back(des.bin2hex(round_key));
    }

    const std::string actual_ciphertext = des.encrypt(plaintext, round_keys, round_keys_hex);
    if (actual_ciphertext != expected_ciphertext) {
        std::cerr << "DES known-answer test failed: expected "
                  << expected_ciphertext << ", got " << actual_ciphertext << "\n";
        return 1;
    }

    std::cout << "DES known-answer test passed\n";
    return 0;
}
