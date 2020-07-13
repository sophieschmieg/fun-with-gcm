#include <algorithm>
#include <array>
#include <iomanip>
#include <iostream>
#include <vector>

#include "gauss.h"
#include "gf2_128_polyval.h"
#include "openssl/evp.h"
#include "openssl/rand.h"

constexpr int kNonceSize = 12;
constexpr int kTagSize = 16;
constexpr int kKeySize = 16;

template <class T>
void PrintHex(const T& data) {
  for (int i = 0; i < data.size(); i++) {
    std::cout << std::hex << std::setw(2) << std::setfill('0')
              << static_cast<int>(data[i]);
  }
  std::cout << std::endl;
}

class ManualAesGcmSiv {
 public:
  std::array<uint8_t, kBlockSize> EncryptBlock(
      std::array<uint8_t, kKeySize> key,
      std::array<uint8_t, kBlockSize> block) {
    bssl::UniquePtr<EVP_CIPHER_CTX> ctx(EVP_CIPHER_CTX_new());
    EVP_EncryptInit_ex(ctx.get(), cipher, nullptr, key.data(), nullptr);
    int len;
    std::array<uint8_t, kBlockSize> out;
    if (EVP_EncryptUpdate(ctx.get(), out.data(), &len, block.data(),
                          block.size()) != 1 ||
        len != kBlockSize) {
      std::cerr << "Block encryption failed" << std::endl;
      std::abort();
    }
    return out;
  }

  std::array<uint8_t, kBlockSize> DecryptBlock(
      std::array<uint8_t, kKeySize> key,
      std::array<uint8_t, kBlockSize> block) {
    bssl::UniquePtr<EVP_CIPHER_CTX> ctx(EVP_CIPHER_CTX_new());
    EVP_DecryptInit_ex(ctx.get(), cipher, nullptr, key.data(), nullptr);
    EVP_CIPHER_CTX_set_padding(ctx.get(), 0);
    int len;
    std::array<uint8_t, kBlockSize> out;
    if (EVP_DecryptUpdate(ctx.get(), out.data(), &len, block.data(),
                          block.size()) != 1 ||
        len != kBlockSize) {
      std::cerr << "Block decryption failed" << std::endl;
      std::abort();
    }
    return out;
  }

  std::array<uint8_t, kBlockSize> LengthBlock(int additional_data_size,
                                              int plaintext_size) {
    std::array<uint8_t, kBlockSize> lb;
    additional_data_size *= 8;
    for (int i = 0; i < 8; i++) {
      lb[i] = additional_data_size % 256;
      additional_data_size /= 256;
    }
    plaintext_size *= 8;
    for (int i = 8; i < kBlockSize; i++) {
      lb[i] = plaintext_size % 256;
      plaintext_size /= 256;
    }
    return lb;
  }

  GF2_128_polyval AuthConstant(
      const std::array<uint8_t, kBlockSize>& auth_key) {
    std::array<uint8_t, kBlockSize> constant;
    constant.fill(0x00);
    constant[15] = 0x92;
    constant[14] = 0x04;
    constant[0] = 0x01;
    GF2_128_polyval auth_constant(constant);
    auth_constant *= auth_key;
    return auth_constant;
  }

  GF2_128_polyval Polyval(const std::array<uint8_t, kBlockSize>& auth_key,
                          const std::vector<uint8_t>& additional_data,
                          const std::vector<uint8_t>& plaintext) {
    std::array<uint8_t, kBlockSize> last_ad_block;
    last_ad_block.fill(0x00);
    int aligned_ad_size = kBlockSize * (additional_data.size() / kBlockSize);
    memcpy(last_ad_block.data(), additional_data.data() + aligned_ad_size,
           additional_data.size() - aligned_ad_size);
    std::array<uint8_t, kBlockSize> last_block;
    last_block.fill(0x00);
    int aligned_size = kBlockSize * (plaintext.size() / kBlockSize);
    memcpy(last_block.data(), plaintext.data() + aligned_size,
           plaintext.size() - aligned_size);
    GF2_128_polyval auth_constant = AuthConstant(auth_key);
    GF2_128_polyval result(0);
    for (int i = 0; i < aligned_ad_size; i += kBlockSize) {
      result += GF2_128_polyval(additional_data.data() + i);
      result *= auth_constant;
    }
    if (additional_data.size() % kBlockSize != 0) {
      result += last_ad_block;
      result *= auth_constant;
    }
    for (int i = 0; i < aligned_size; i += kBlockSize) {
      result += GF2_128_polyval(plaintext.data() + i);
      result *= auth_constant;
    }
    if (plaintext.size() % kBlockSize != 0) {
      result += last_block;
      result *= auth_constant;
    }
    result += LengthBlock(additional_data.size(), plaintext.size());
    result *= auth_constant;
    return result;
  }

  std::array<uint8_t, kBlockSize> CounterBlock(
      const std::array<uint8_t, kBlockSize>& initial, uint32_t counter) {
    std::array<uint8_t, kBlockSize> in = initial;
    uint32_t in_ctr = 0;
    for (int i = 3; i >= 0; i--) {
      in_ctr *= 256;
      in_ctr += initial[i];
    }
    counter += in_ctr;
    for (int i = 0; i < 4; i++) {
      in[i] = counter % 256;
      counter /= 256;
    }
    return in;
  }

  std::pair<std::array<uint8_t, kBlockSize>, std::array<uint8_t, kKeySize>>
  GenerateKeys(const std::array<uint8_t, kKeySize>& key,
               const std::array<uint8_t, kNonceSize>& nonce) {
    std::array<uint8_t, kBlockSize> input;
    input.fill(0x00);
    std::array<uint8_t, kBlockSize> output;
    std::array<uint8_t, kBlockSize> auth_key;
    std::array<uint8_t, kKeySize> enc_key;
    memcpy(input.data() + 4, nonce.data(), kNonceSize);
    output = EncryptBlock(key, input);
    memcpy(auth_key.data(), output.data(), 8);
    input[0] = 0x01;
    output = EncryptBlock(key, input);
    memcpy(auth_key.data() + 8, output.data(), 8);
    input[0] = 0x02;
    output = EncryptBlock(key, input);
    memcpy(enc_key.data(), output.data(), 8);
    input[0] = 0x03;
    output = EncryptBlock(key, input);
    memcpy(enc_key.data() + 8, output.data(), 8);
    if (kKeySize == 32) {
      input[0] = 0x04;
      output = EncryptBlock(key, input);
      memcpy(enc_key.data() + 16, output.data(), 8);
      input[0] = 0x05;
      output = EncryptBlock(key, input);
      memcpy(enc_key.data() + 24, output.data(), 8);
    }
    return make_pair(auth_key, enc_key);
  }

  std::array<uint8_t, kBlockSize> CounterForTag(
      const std::array<uint8_t, kBlockSize>& tag) {
    std::array<uint8_t, kBlockSize> counter = tag;
    counter[15] |= 0x80;
    return counter;
  }

  std::array<uint8_t, kBlockSize> TagForPolyvalResult(
      const std::array<uint8_t, kKeySize>& enc_key,
      const std::array<uint8_t, kNonceSize>& nonce,
      const GF2_128_polyval& result) {
    std::array<uint8_t, kBlockSize> s = result.get();
    for (int i = 0; i < kNonceSize; i++) {
      s[i] ^= nonce[i];
    }
    s[15] &= 0x7f;
    return EncryptBlock(enc_key, s);
  }

  GF2_128_polyval PolyvalResultForTag(
      const std::array<uint8_t, kKeySize>& enc_key,
      const std::array<uint8_t, kNonceSize>& nonce,
      const std::array<uint8_t, kBlockSize>& tag, bool* ok) {
    std::array<uint8_t, kBlockSize> s = DecryptBlock(enc_key, tag);
    *ok = (s[15] & 0x80) == 0;
    for (int i = 0; i < kNonceSize; i++) {
      s[i] ^= nonce[i];
    }
    return s;
  }

  std::pair<std::vector<std::vector<GF2_128_polyval>>,
            std::vector<GF2_128_polyval>>
  SystemOfEquations(const GF2_128_polyval& auth_constant1,
                    const GF2_128_polyval& polyval_result1,
                    const std::vector<GF2_128_polyval>& key_stream1,
                    const GF2_128_polyval& auth_constant2,
                    const GF2_128_polyval& polyval_result2,
                    const std::vector<GF2_128_polyval>& key_stream2,
                    int num_blocks) {
    std::vector<std::vector<GF2_128_polyval>> matrix(
        num_blocks + 2, std::vector<GF2_128_polyval>(2 * num_blocks, 0));
    std::vector<GF2_128_polyval> rhs(num_blocks + 2);
    // X11 * H1^3 + X12 * H1^2 = S1 + LB1 * H1
    // X21 * H2^3 + X22 * H2^2 = S2 + LB2 * H2
    // X11 + KS11 = X21 + KS21
    // X12 + KS12 = X22 + KS22
    rhs[0] = polyval_result1 +
             auth_constant1 * LengthBlock(0, kBlockSize * num_blocks);
    rhs[1] = polyval_result2 +
             auth_constant2 * LengthBlock(0, kBlockSize * num_blocks);
    GF2_128_polyval h1 = auth_constant1;
    GF2_128_polyval h2 = auth_constant2;
    for (int i = 0; i < num_blocks; i++) {
      h1 *= auth_constant1;
      h2 *= auth_constant2;
      int index = num_blocks - i - 1;
      matrix[0][index] = h1;
      matrix[1][num_blocks + index] = h2;
      matrix[i + 2][i] = 1;
      matrix[i + 2][num_blocks + i] = 1;
      rhs[i + 2] = key_stream1[i] + key_stream2[i];
    }
    return std::make_pair(matrix, rhs);
  }

  std::vector<uint8_t> MakeFragileCiphertext(
      const std::array<uint8_t, kKeySize>& key1,
      const std::array<uint8_t, kKeySize>& key2) {
    int num_blocks = 2;
    std::vector<uint8_t> ciphertext(kNonceSize + num_blocks * kBlockSize +
                                    kBlockSize);
    std::array<uint8_t, kNonceSize> nonce;
    std::array<uint8_t, kBlockSize> auth_key1;
    std::array<uint8_t, kKeySize> enc_key1;
    std::array<uint8_t, kBlockSize> auth_key2;
    std::array<uint8_t, kKeySize> enc_key2;
    RAND_bytes(nonce.data(), kNonceSize);
    for (int i = 0; i < nonce.size(); i++) {
      ciphertext[i] = nonce[i];
    }
    std::tie(auth_key1, enc_key1) = GenerateKeys(key1, nonce);
    std::tie(auth_key2, enc_key2) = GenerateKeys(key2, nonce);
    bool ok1 = false;
    bool ok2 = false;
    GF2_128_polyval polyval_result1;
    GF2_128_polyval polyval_result2;
    std::array<uint8_t, kBlockSize> tag;
    while (!(ok1 && ok2)) {
      RAND_bytes(tag.data(), kBlockSize);
      std::cout << "Tag:\n";
      PrintHex(tag);
      polyval_result1 = PolyvalResultForTag(enc_key1, nonce, tag, &ok1);
      polyval_result2 = PolyvalResultForTag(enc_key2, nonce, tag, &ok2);
    }
    auto counter = CounterForTag(tag);
    std::vector<GF2_128_polyval> key_stream1(num_blocks);
    std::vector<GF2_128_polyval> key_stream2(num_blocks);
    for (int i = 0; i < num_blocks; i++) {
      key_stream1[i] = EncryptBlock(enc_key1, CounterBlock(counter, i));
      key_stream2[i] = EncryptBlock(enc_key2, CounterBlock(counter, i));
    }
    std::vector<std::vector<GF2_128_polyval>> matrix;
    std::vector<GF2_128_polyval> rhs;
    std::tie(matrix, rhs) = SystemOfEquations(
        AuthConstant(auth_key1), polyval_result1, key_stream1,
        AuthConstant(auth_key2), polyval_result2, key_stream2, num_blocks);
    std::vector<GF2_128_polyval> result;
    std::vector<std::vector<GF2_128_polyval>> homogenous;
    std::tie(result, homogenous) = solve(matrix, rhs);
    if (result.size() != 2 * num_blocks) {
      std::cout << "Matrix rank too small" << std::endl;
      return MakeFragileCiphertext(key1, key2);
    }
    std::vector<uint8_t> plaintext1(kBlockSize * num_blocks);
    std::vector<uint8_t> plaintext2(kBlockSize * num_blocks);
    for (int i = 0; i < num_blocks; i++) {
      std::cout << "Plaintext1 Fragment " << i << std::endl;
      PrintHex(result[i].get());
      std::cout << "Plaintext2 Fragment " << i << std::endl;
      PrintHex(result[num_blocks + i].get());
      auto ciphertext_fragment = key_stream1[i] + result[i];
      std::cout << "Ciphertext Fragment " << i << std::endl;
      PrintHex(ciphertext_fragment.get());
      ciphertext_fragment = key_stream2[i] + result[num_blocks + i];
      std::cout << "Ciphertext Fragment " << i << std::endl;
      PrintHex(ciphertext_fragment.get());
      for (int j = 0; j < ciphertext_fragment.get().size(); j++) {
        plaintext1[kBlockSize * i + j] = result[i].get()[j];
        plaintext2[kBlockSize * i + j] = result[num_blocks + i].get()[j];
        ciphertext[kNonceSize + kBlockSize * i + j] =
            ciphertext_fragment.get()[j];
      }
    }
    std::vector<uint8_t> additional_data;
    std::cout << "Expected Polyval Result 1:\n";
    PrintHex(polyval_result1.get());
    std::cout << "Actual Polyval Result 1:\n";
    PrintHex(Polyval(auth_key1, additional_data, plaintext1).get());
    std::cout << "Expected Polyval Result 2:\n";
    PrintHex(polyval_result2.get());
    std::cout << "Actual Polyval Result 2:\n";
    PrintHex(Polyval(auth_key2, additional_data, plaintext2).get());
    for (int i = 0; i < tag.size(); i++) {
      ciphertext[kNonceSize + kBlockSize * num_blocks + i] = tag[i];
    }
    return ciphertext;
  }

  std::vector<uint8_t> Encrypt(const std::array<uint8_t, kKeySize>& key,
                               const std::array<uint8_t, kNonceSize>& nonce,
                               const std::vector<uint8_t>& additional_data,
                               const std::vector<uint8_t>& plaintext) {
    std::vector<uint8_t> ciphertext(kNonceSize);
    memcpy(ciphertext.data(), nonce.data(), nonce.size());
    auto keys = GenerateKeys(key, nonce);
    auto tag = TagForPolyvalResult(
        keys.second, nonce, Polyval(keys.first, additional_data, plaintext));
    std::array<uint8_t, kBlockSize> counter = CounterForTag(tag);
    std::array<uint8_t, kBlockSize> keystream;
    for (int i = 0; i < plaintext.size(); i++) {
      if (i % kBlockSize == 0) {
        keystream = EncryptBlock(keys.second, CounterBlock(counter, i / 16));
      }
      ciphertext.push_back(keystream[i % kBlockSize] ^ plaintext[i]);
    }
    for (int i = 0; i < tag.size(); i++) {
      ciphertext.push_back(tag[i]);
    }
    return ciphertext;
  }

 private:
  const EVP_CIPHER* cipher =
      kKeySize == 16 ? EVP_aes_128_ecb() : EVP_aes_256_ecb();
};

std::vector<uint8_t> DecryptBoringSSL(std::array<uint8_t, kKeySize> key,
                                      std::vector<uint8_t> additional_data,
                                      std::vector<uint8_t> ciphertext) {
  const EVP_AEAD* aead = EVP_aead_aes_128_gcm_siv();
  bssl::UniquePtr<EVP_AEAD_CTX> ctx(
      EVP_AEAD_CTX_new(aead, key.data(), key.size(), kTagSize));
  size_t len;
  std::vector<uint8_t> decrypted(ciphertext.size() - kNonceSize - kTagSize);
  if (EVP_AEAD_CTX_open(ctx.get(), decrypted.data(), &len, decrypted.size(),
                        ciphertext.data(), kNonceSize,
                        ciphertext.data() + kNonceSize,
                        ciphertext.size() - kNonceSize, additional_data.data(),
                        additional_data.size()) != 1 ||
      len != decrypted.size()) {
    std::cerr << "Decryption failed!" << std::endl;
    std::abort();
  }
  std::cout << "Decryption successful:\n";
  PrintHex(decrypted);
  return decrypted;
}

int main(int argc, char** argv) {
  std::array<uint8_t, kKeySize> key;
  RAND_bytes(key.data(), key.size());
  std::array<uint8_t, kNonceSize> nonce;
  RAND_bytes(nonce.data(), nonce.size());
  std::vector<uint8_t> plaintext(6);
  plaintext[0] = 'H';
  plaintext[1] = 'e';
  plaintext[2] = 'l';
  plaintext[3] = 'l';
  plaintext[4] = 'o';
  plaintext[5] = 0x00;

  std::vector<uint8_t> additional_data;
  std::vector<uint8_t> ciphertext(kNonceSize + kTagSize + plaintext.size());
  memcpy(ciphertext.data(), nonce.data(), nonce.size());
  const EVP_AEAD* aead = EVP_aead_aes_128_gcm_siv();
  bssl::UniquePtr<EVP_AEAD_CTX> ctx(
      EVP_AEAD_CTX_new(aead, key.data(), key.size(), kTagSize));
  size_t len;
  if (EVP_AEAD_CTX_seal(ctx.get(), ciphertext.data() + kNonceSize, &len,
                        ciphertext.size() - kNonceSize, nonce.data(),
                        nonce.size(), plaintext.data(), plaintext.size(),
                        additional_data.data(), additional_data.size()) != 1 ||
      len != ciphertext.size() - kNonceSize) {
    std::cerr << "Encryption failed!" << std::endl;
    return 1;
  }
  std::cout << "Encryption successful:" << std::endl;
  PrintHex(ciphertext);
  DecryptBoringSSL(key, additional_data, ciphertext);
  ManualAesGcmSiv manual;
  ciphertext = manual.Encrypt(key, nonce, additional_data, plaintext);
  std::cout << "Manual Encryption successful:" << std::endl;
  PrintHex(ciphertext);
  DecryptBoringSSL(key, additional_data, ciphertext);
  std::array<uint8_t, kKeySize> key2;
  RAND_bytes(key2.data(), key2.size());
  ciphertext = manual.MakeFragileCiphertext(key, key2);
  std::cout << "Created fragile ciphertext:" << std::endl;
  PrintHex(ciphertext);
  DecryptBoringSSL(key, additional_data, ciphertext);
  DecryptBoringSSL(key2, additional_data, ciphertext);
  return 0;
}
