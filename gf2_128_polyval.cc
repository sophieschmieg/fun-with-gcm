#include "gf2_128_polyval.h"

#include <cstdlib>
#include <iomanip>

GF2_128_polyval::GF2_128_polyval(int val) : val_() {
  for (int i = 0; i < kBlockSize; i++) {
    val_[i] = val % 256;
    val /= 256;
  }
}

GF2_128_polyval::GF2_128_polyval(const uint8_t* val) : val_() {
  for (int i = 0; i < kBlockSize; i++) {
    val_[i] = val[i];
  }
}

bool operator==(const GF2_128_polyval& lhs, const GF2_128_polyval& rhs) {
  for (int i = 0; i < kBlockSize; i++) {
    if (lhs.val_[i] != rhs.val_[i]) {
      return false;
    }
  }
  return true;
}

GF2_128_polyval GF2_128_polyval::inv() const {
  int deg = degree();
  if (deg < 0) {
    std::cerr << "Division by zero!" << std::endl;
    std::abort();
  }
  if (deg == 0) {
    return *this;
  }
  GF2_128_polyval a(*this);
  GF2_128_polyval b;
  b.power_of_x_assign(128 - deg);
  b *= a;
  GF2_128_polyval x;
  x.power_of_x_assign(0);
  GF2_128_polyval y;
  y.power_of_x_assign(128 - deg);
  while (deg > 0) {
    int degb = b.degree();
    if (deg > degb) {
      std::swap(a, b);
      std::swap(x, y);
      std::swap(deg, degb);
    }
    GF2_128_polyval q;
    q.power_of_x_assign(degb - deg);
    b += a * q;
    y += x * q;
  }
  return x;
}

int GF2_128_polyval::degree() const {
  for (int i = kBlockSize - 1; i >= 0; i--) {
    for (int j = 7; j >= 0; j--) {
      if (val_[i] & (0x01 << j)) {
        return i * 8 + j;
      }
    }
  }
  return -1;
}

void GF2_128_polyval::power_of_x_assign(int exp) {
  for (int i = 0; i < kBlockSize; i++) {
    val_[i] = 0x00;
  }
  val_[exp / 8] = 0x01 << (exp % 8);
}

void GF2_128_polyval::mul_x_assign() {
  uint8_t carry = val_[kBlockSize - 1] >> 7;
  for (int i = kBlockSize - 1; i >= 1; i--) {
    val_[i] = (val_[i] << 1) | (val_[i - 1] >> 7);
  }
  val_[0] <<= 1;
  if (carry != 0) {
    val_[kBlockSize - 1] ^= 0xc2;
    val_[0] ^= 0x01;
  }
}

GF2_128_polyval& GF2_128_polyval::operator*=(const GF2_128_polyval& rhs) {
  GF2_128_polyval mul_by_x(0);
  std::swap(val_, mul_by_x.val_);
  for (int i = 0; i < kBlockSize; i++) {
    uint8_t work = rhs.val_[i];
    for (int j = 0; j < 8; j++) {
      if (work & 0x01) {
        *this += mul_by_x;
      }
      work >>= 1;
      mul_by_x.mul_x_assign();
    }
  }
  return *this;
}
GF2_128_polyval& GF2_128_polyval::operator+=(const GF2_128_polyval& rhs) {
  for (int i = 0; i < kBlockSize; i++) {
    val_[i] ^= rhs.val_[i];
  }
  return *this;
}

std::ostream& operator<<(std::ostream& os, const GF2_128_polyval& rhs) {
  char fill = os.fill('0');
  auto flags = os.flags();
  os.setf(std::ios_base::hex, std::ios_base::basefield);
  for (int i = kBlockSize - 1; i >= 0; i--) {
    os << std::setw(2) << static_cast<int>(rhs.val_[i]);
  }
  os.fill(fill);
  os.flags(flags);
  return os;
}
