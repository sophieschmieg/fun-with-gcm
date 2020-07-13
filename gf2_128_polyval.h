#ifndef GF2_128_POLYVAL_H_
#define GF2_128_POLYVAL_H_

#include <array>
#include <iostream>

constexpr int kBlockSize = 16;

class GF2_128_polyval {
 public:
  GF2_128_polyval() : val_() {}
  GF2_128_polyval(int val);
  GF2_128_polyval(const uint8_t* val);
  GF2_128_polyval(const std::array<uint8_t, 16>& val) : val_(val) {}
  GF2_128_polyval(std::array<uint8_t, 16>&& val) : val_(std::move(val)) {}
  GF2_128_polyval(const GF2_128_polyval& rhs) : val_(rhs.val_) {}
  GF2_128_polyval(GF2_128_polyval&& rhs) : val_(std::move(rhs.val_)) {}

  const std::array<uint8_t, kBlockSize>& get() const { return val_; }

  GF2_128_polyval& operator=(GF2_128_polyval rhs) noexcept {
    std::swap(val_, rhs.val_);
    return *this;
  }

  friend bool operator==(const GF2_128_polyval& lhs,
                         const GF2_128_polyval& rhs);

  friend bool operator!=(const GF2_128_polyval& lhs,
                         const GF2_128_polyval& rhs) {
    return !(lhs == rhs);
  }

  friend std::ostream& operator<<(std::ostream& os, const GF2_128_polyval& rhs);

  GF2_128_polyval& operator+=(const GF2_128_polyval& rhs);
  friend GF2_128_polyval operator+(GF2_128_polyval lhs,
                                   const GF2_128_polyval& rhs) {
    lhs += rhs;
    return lhs;
  }

  GF2_128_polyval& operator-=(const GF2_128_polyval& rhs) {
    return *this += rhs;
  }
  friend GF2_128_polyval operator-(GF2_128_polyval lhs,
                                   const GF2_128_polyval& rhs) {
    lhs -= rhs;
    return lhs;
  }

  GF2_128_polyval& operator*=(const GF2_128_polyval& rhs);
  friend GF2_128_polyval operator*(GF2_128_polyval lhs,
                                   const GF2_128_polyval& rhs) {
    lhs *= rhs;
    return lhs;
  }

  GF2_128_polyval& operator/=(const GF2_128_polyval& rhs) {
    return *this *= rhs.inv();
  }

  friend GF2_128_polyval operator/(GF2_128_polyval lhs,
                                   const GF2_128_polyval& rhs) {
    lhs /= rhs;
    return lhs;
  }

 private:
  GF2_128_polyval inv() const;
  int degree() const;

  void power_of_x_assign(int exp);
  void mul_x_assign();

  std::array<uint8_t, 16> val_;
};

#endif  // GF2_128_POLYVAL_H_
