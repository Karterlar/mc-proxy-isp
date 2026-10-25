// Copyright 2026 MC Proxy contributors.
// SPDX-License-Identifier: MIT
// Shared by the native readback and encoding paths; never modifies source data.
#ifndef MC_PROXY_NATIVE_CANVAS_NOISE_H_
#define MC_PROXY_NATIVE_CANVAS_NOISE_H_

#include <array>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <cmath>
#include <limits>
#include <span>

namespace mc_proxy::canvas {

enum class PixelFormat { kRgba8888, kRgbaF16, kRgbaF32 };

constexpr size_t BytesPerPixel(PixelFormat format) {
  switch (format) {
    case PixelFormat::kRgba8888: return 4;
    case PixelFormat::kRgbaF16: return 8;
    case PixelFormat::kRgbaF32: return 16;
  }
  return 0;
}

// Unsigned arithmetic is deliberately fixed-width, endian-independent, and has
// no process/thread PRNG state. Projection depends on color content, not pixel
// position: translating an unread source must not expose independent noise
// samples that a page can majority-vote away. Crops still agree without a full
// canvas readback. Coordinates remain accepted/validated for the shared API.
constexpr uint64_t Mix(uint64_t value) {
  value ^= value >> 30;
  value *= UINT64_C(0xbf58476d1ce4e5b9);
  value ^= value >> 27;
  value *= UINT64_C(0x94d049bb133111eb);
  return value ^ (value >> 31);
}

constexpr uint64_t PixelKey(uint32_t seed, int64_t /*x*/, int64_t /*y*/) {
  return Mix((static_cast<uint64_t>(seed) << 32) ^ UINT64_C(0xd1b54a32d192ed03));
}

// A many-to-one projection, not a reversible XOR mask. Both values in a
// selected adjacent pair map to the same low bit, so writing an observed image
// back and reading it again cannot undo the protection. Only immutable high
// bits participate in the key: re-reads and integer translations are idempotent.
// All adjacent pairs are projected; sparse position-dependent selection leaks
// independent clean samples. High bits remain observable: arbitrary chosen
// color transforms are an explicit limitation, not a cryptographic guarantee.
constexpr uint32_t ProjectLowBit(uint64_t pixel_key, uint32_t channel,
                                 uint32_t value) {
  const uint64_t field = Mix(pixel_key ^
      (static_cast<uint64_t>(channel + 1) * UINT64_C(0x9e3779b97f4a7c15)) ^
      (value & 0xfffffffeu));
  return (value & 0xfffffffeu) | static_cast<uint32_t>(field & 1u);
}

inline float HalfToFloat(uint16_t value) {
  const uint32_t sign = static_cast<uint32_t>(value & 0x8000u) << 16;
  const uint32_t exponent = (value >> 10) & 31u;
  const uint32_t mantissa = value & 1023u;
  if (!exponent) {
    const float magnitude = std::ldexp(static_cast<float>(mantissa), -24);
    return sign ? -magnitude : magnitude;
  }
  return std::bit_cast<float>(sign | ((exponent + 112u) << 23) |
                              (mantissa << 13));
}

// Only used for changed, finite, normalized [0,1] channels. Preserve all other
// half encodings verbatim, including HDR, NaN and infinity.
inline uint16_t UnitFloatToHalf(float value) {
  if (value <= 0) return 0;
  const uint32_t bits = std::bit_cast<uint32_t>(value);
  const uint32_t exponent = (bits >> 23) & 255u;
  if (exponent < 113u) {
    if (exponent < 102u) return 0;
    const uint32_t mantissa = (bits & 0x7fffffu) | 0x800000u;
    const uint32_t shift = 126u - exponent;
    const uint32_t rounded = mantissa + ((1u << (shift - 1u)) - 1u) +
                              ((mantissa >> shift) & 1u);
    return static_cast<uint16_t>(rounded >> shift);
  }
  const uint32_t rounded = bits + 0xfffu + ((bits >> 13) & 1u);
  return static_cast<uint16_t>((rounded - 0x38000000u) >> 13);
}

inline uint32_t UnitByte(float value) {
  return static_cast<uint32_t>(std::floor(static_cast<double>(value) * 255 + .5));
}

inline float ProjectUnitFloat(uint64_t key, uint32_t channel, float value) {
  const uint32_t code = UnitByte(value);
  const uint32_t projected = ProjectLowBit(key, channel, code);
  if (projected == code) return value;
  // Move by one observable 8-bit code and retain the original sub-code residual.
  // This closes float16 -> uint8 conversion stripping sub-ULP-only noise.
  const float shifted = value +
      static_cast<float>(static_cast<int>(projected) - static_cast<int>(code)) /
          255.0f;
  return std::fmax(0.0f, std::fmin(1.0f, shifted));
}

// Mutates only a *fresh, caller-owned, unpremultiplied* destination. In Blink:
// - getImageData's newly allocated destination is already caller-owned;
// - encoding first readPixels() into private SkData and then calls this helper.
// Never pass a borrowed SkPixmap or any source canvas resource to this function.
// Rows may be padded. Padding, alpha, and fully transparent pixel RGB stay exact.
// 8-bit RGB changes by at most one integer code point. Normalized F16/F32 use
// the SAME observable 8-bit projection, retaining residual precision rather
// than adding a mantissa ULP that disappears on uint8 conversion. Values outside
// [0,1] retain their range/sign/exponent with a low-mantissa projection. No claim
// is made that arbitrary color conversion or lossy encoding retains a low bit.
inline bool ApplyToOwnedUnpremul(std::span<uint8_t> bytes,
                                size_t width, size_t height,
                                size_t row_bytes, PixelFormat format,
                                int64_t origin_x, int64_t origin_y,
                                uint32_t seed) {
  const size_t bpp = BytesPerPixel(format);
  if (!bpp || width > std::numeric_limits<size_t>::max() / bpp) return false;
  const size_t packed_row = width * bpp;
  if (row_bytes < packed_row) return false;
  if (!width || !height) return true;
  if (height - 1 > (std::numeric_limits<size_t>::max() - packed_row) /
                       row_bytes) return false;
  if ((height - 1) * row_bytes + packed_row > bytes.size()) return false;
  if (width - 1 > static_cast<uint64_t>(std::numeric_limits<int64_t>::max()) ||
      height - 1 > static_cast<uint64_t>(std::numeric_limits<int64_t>::max()) ||
      origin_x > std::numeric_limits<int64_t>::max() -
                     static_cast<int64_t>(width - 1) ||
      origin_y > std::numeric_limits<int64_t>::max() -
                     static_cast<int64_t>(height - 1)) return false;
  if (!seed) return true;

  for (size_t y = 0; y < height; ++y) {
    auto row = bytes.subspan(y * row_bytes, packed_row);
    for (size_t x = 0; x < width; ++x) {
      auto pixel = row.subspan(x * bpp, bpp);
      const uint64_t key = PixelKey(seed, origin_x + static_cast<int64_t>(x),
                                   origin_y + static_cast<int64_t>(y));
      if (format == PixelFormat::kRgba8888) {
        if (pixel[3] == 0) continue;
        for (uint32_t channel = 0; channel < 3; ++channel)
          pixel[channel] = static_cast<uint8_t>(
              ProjectLowBit(key, channel, pixel[channel]));
      } else if (format == PixelFormat::kRgbaF16) {
        const uint16_t alpha = std::bit_cast<uint16_t>(
            std::array<uint8_t, 2>{pixel[6], pixel[7]});
        if ((alpha & 0x7fffu) == 0 || (alpha & 0x7c00u) == 0x7c00u) continue;
        for (uint32_t channel = 0; channel < 3; ++channel) {
          const size_t at = channel * 2;
          uint16_t value = std::bit_cast<uint16_t>(
              std::array<uint8_t, 2>{pixel[at], pixel[at + 1]});
          if ((value & 0x7c00u) != 0x7c00u) {
            const float number = HalfToFloat(value);
            if (number >= 0 && number <= 1) {
              const float projected = ProjectUnitFloat(key, channel, number);
              if (projected == number) continue;
              value = UnitFloatToHalf(projected);
              const uint32_t target = ProjectLowBit(key, channel, UnitByte(number));
              // Half rounding at an 8-bit bucket edge can cross back. Fall back
              // to the bucket center; do not silently discard the projection.
              if (UnitByte(HalfToFloat(value)) != target)
                value = UnitFloatToHalf(static_cast<float>(target) / 255.0f);
            } else {
              value = static_cast<uint16_t>(ProjectLowBit(key, channel, value));
            }
            const auto encoded = std::bit_cast<std::array<uint8_t, 2>>(value);
            pixel[at] = encoded[0];
            pixel[at + 1] = encoded[1];
          }
        }
      } else {
        const uint32_t alpha = std::bit_cast<uint32_t>(
            std::array<uint8_t, 4>{pixel[12], pixel[13], pixel[14], pixel[15]});
        if ((alpha & 0x7fffffffu) == 0 ||
            (alpha & 0x7f800000u) == 0x7f800000u) continue;
        for (uint32_t channel = 0; channel < 3; ++channel) {
          const size_t at = channel * 4;
          uint32_t value = std::bit_cast<uint32_t>(
              std::array<uint8_t, 4>{pixel[at], pixel[at + 1],
                                     pixel[at + 2], pixel[at + 3]});
          if ((value & 0x7f800000u) != 0x7f800000u) {
            const float number = std::bit_cast<float>(value);
            if (number >= 0 && number <= 1) {
              float projected = ProjectUnitFloat(key, channel, number);
              if (projected == number) continue;
              const uint32_t target = ProjectLowBit(key, channel, UnitByte(number));
              if (UnitByte(projected) != target)
                projected = static_cast<float>(target) / 255.0f;
              value = std::bit_cast<uint32_t>(projected);
            } else {
              value = ProjectLowBit(key, channel, value);
            }
            const auto encoded = std::bit_cast<std::array<uint8_t, 4>>(value);
            for (size_t index = 0; index < encoded.size(); ++index)
              pixel[at + index] = encoded[index];
          }
        }
      }
    }
  }
  return true;
}

}  // namespace mc_proxy::canvas

#endif  // MC_PROXY_NATIVE_CANVAS_NOISE_H_
