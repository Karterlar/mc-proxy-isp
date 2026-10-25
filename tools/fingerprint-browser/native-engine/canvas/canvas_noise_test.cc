// Copyright 2026 MC Proxy contributors.
// SPDX-License-Identifier: MIT
// Standalone algorithm check: c++ -std=c++20 -O2 canvas_noise_test.cc -o test.
// This does not replace compiling Blink or testing a newly built native browser.
#include "canvas_noise.h"

#include <algorithm>
#include <array>
#include <cassert>
#include <iostream>
#include <vector>

using mc_proxy::canvas::ApplyToOwnedUnpremul;
using mc_proxy::canvas::PixelFormat;

int main() {
  constexpr size_t width = 280, height = 100, row_bytes = width * 4 + 9;
  std::vector<uint8_t> source(row_bytes * height, 0xa7);
  for (size_t y = 0; y < height; ++y) for (size_t x = 0; x < width; ++x) {
    const size_t at = y * row_bytes + x * 4;
    source[at] = (x * 7 + y * 3) & 255;
    source[at + 1] = (x * 11 + y * 5) & 255;
    source[at + 2] = (x * 13 + y * 17) & 255;
    source[at + 3] = std::array<uint8_t, 5>{0, 64, 128, 192, 255}[(x + y) % 5];
  }
  const auto original = source;
  std::vector<std::vector<uint8_t>> protected_by_seed;
  for (uint32_t seed : {1u, 3324349380u, 4294967295u}) {
    auto owned = source;
    assert(ApplyToOwnedUnpremul(owned, width, height, row_bytes,
                              PixelFormat::kRgba8888, 0, 0, seed));
    assert(owned != source && source == original);
    // Regression F01: putting the observed pixels into a new same-sized canvas
    // and reading again must NOT reconstruct the original pixels.
    auto written_back = owned;
    assert(ApplyToOwnedUnpremul(written_back, width, height, row_bytes,
                              PixelFormat::kRgba8888, 0, 0, seed));
    assert(written_back == owned && written_back != original);
    // Every adjacent pair intentionally loses its original low bit. This
    // is a projection, not a reversible two-element permutation.
    size_t collapsed_pairs = 0;
    for (uint32_t code = 0; code < 256; code += 2) {
      const auto key = mc_proxy::canvas::PixelKey(seed, code, 17);
      for (uint32_t c = 0; c < 3; ++c)
        if (mc_proxy::canvas::ProjectLowBit(key, c, code) ==
            mc_proxy::canvas::ProjectLowBit(key, c, code + 1))
          ++collapsed_pairs;
    }
    assert(collapsed_pairs == 128 * 3);
    // Draw an UNREAD source at sixteen integer offsets, realign, then majority
    // vote. A coordinate-dependent sparse field offered mostly clean samples
    // and reconstructed the original exactly; color-only projection must not.
    std::vector<uint8_t> votes(source.size(), 0);
    for (int translation = 0; translation < 16; ++translation) {
      auto translated = source;
      assert(ApplyToOwnedUnpremul(translated, width, height, row_bytes,
                                PixelFormat::kRgba8888, translation * 131, 0, seed));
      assert(translated == owned);
      for (size_t at = 0; at < translated.size(); ++at)
        votes[at] += translated[at] & 1u;
    }
    auto majority = owned;
    for (size_t at = 0; at < majority.size(); ++at)
      majority[at] = static_cast<uint8_t>((majority[at] & 0xfeu) | (votes[at] > 8 ? 1 : 0));
    assert(majority == owned && majority != original);
    for (size_t y = 0; y < height; ++y) {
      for (size_t x = 0; x < width; ++x) {
        const size_t at = y * row_bytes + x * 4;
        assert(owned[at + 3] == source[at + 3]);
        for (size_t c = 0; c < 3; ++c) {
          const auto distance = static_cast<int>(owned[at + c]) - source[at + c];
          assert(distance >= -1 && distance <= 1);
          if (!source[at + 3]) assert(owned[at + c] == source[at + c]);
        }
      }
      assert(std::equal(owned.begin() + y * row_bytes + width * 4,
                        owned.begin() + (y + 1) * row_bytes,
                        source.begin() + y * row_bytes + width * 4));
    }
    // Independent copies and independent API/context callers get the same bytes.
    for (int repeat = 0; repeat < 100; ++repeat) {
      auto repeated = source;
      assert(ApplyToOwnedUnpremul(repeated, width, height, row_bytes,
                                PixelFormat::kRgba8888, 0, 0, seed));
      assert(repeated == owned);
    }
    // Crops use absolute canvas coordinates and don't need to read the rest.
    constexpr size_t left = 31, top = 7, crop_w = 17, crop_h = 13;
    std::vector<uint8_t> crop(crop_w * crop_h * 4);
    for (size_t y = 0; y < crop_h; ++y)
      std::copy_n(source.begin() + (y + top) * row_bytes + left * 4,
                  crop_w * 4, crop.begin() + y * crop_w * 4);
    assert(ApplyToOwnedUnpremul(crop, crop_w, crop_h, crop_w * 4,
                              PixelFormat::kRgba8888, left, top, seed));
    for (size_t y = 0; y < crop_h; ++y)
      assert(std::equal(crop.begin() + y * crop_w * 4,
                        crop.begin() + (y + 1) * crop_w * 4,
                        owned.begin() + (y + top) * row_bytes + left * 4));
    // Negative read coordinates produce transparent out-of-bounds padding;
    // valid pixels must still match their positions in the full readback.
    std::vector<uint8_t> padded(7 * 13 * 4, 0);
    for (size_t y = 2; y < 13; ++y)
      std::copy_n(source.begin() + (y - 2) * row_bytes, 4 * 4,
                  padded.begin() + (y * 7 + 3) * 4);
    assert(ApplyToOwnedUnpremul(padded, 7, 13, 7 * 4,
                              PixelFormat::kRgba8888, -3, -2, seed));
    for (size_t y = 0; y < 13; ++y) for (size_t x = 0; x < 7; ++x) {
      const size_t at = (y * 7 + x) * 4;
      if (y < 2 || x < 3)
        assert(std::all_of(padded.begin() + at, padded.begin() + at + 4,
                           [](uint8_t value) { return value == 0; }));
      else
        assert(std::equal(padded.begin() + at, padded.begin() + at + 4,
                          owned.begin() + (y - 2) * row_bytes + (x - 3) * 4));
    }
    auto changed = source; changed[row_bytes * 9 + 17 * 4] ^= 32;
    assert(ApplyToOwnedUnpremul(changed, width, height, row_bytes,
                              PixelFormat::kRgba8888, 0, 0, seed));
    assert(changed != owned);  // New drawing has no stale cached export.
    auto restored = source;
    assert(ApplyToOwnedUnpremul(restored, width, height, row_bytes,
                              PixelFormat::kRgba8888, 0, 0, seed));
    assert(restored == owned);
    protected_by_seed.push_back(std::move(owned));
  }
  assert(protected_by_seed[0] != protected_by_seed[1] &&
         protected_by_seed[0] != protected_by_seed[2] &&
         protected_by_seed[1] != protected_by_seed[2]);
  auto disabled = source;
  assert(ApplyToOwnedUnpremul(disabled, width, height, row_bytes,
                            PixelFormat::kRgba8888, 0, 0, 0));
  assert(disabled == source);
  auto bad = source;
  assert(!ApplyToOwnedUnpremul(bad, width, height, width * 4 - 1,
                             PixelFormat::kRgba8888, 0, 0, 1));
  assert(!ApplyToOwnedUnpremul(std::span<uint8_t>(bad).first(3), 1, 1, 4,
                             PixelFormat::kRgba8888, 0, 0, 1));
  assert(!ApplyToOwnedUnpremul(bad, width, height, row_bytes,
                             PixelFormat::kRgba8888,
                             std::numeric_limits<int64_t>::max(), 0, 1));
  assert(ApplyToOwnedUnpremul({}, 0, 0, 0, PixelFormat::kRgba8888, 0, 0, 1));
  assert(bad == source);

  // Typed F16/F32 retain format, alpha, NaN/Inf and transparent pixels. Normal
  // SDR values must retain exactly the same perturbation after uint8 rounding.
  std::vector<uint16_t> half(128 * 4);
  std::vector<uint32_t> single(128 * 4);
  for (size_t x = 0; x < 128; ++x) {
    half[x * 4] = mc_proxy::canvas::UnitFloatToHalf(static_cast<float>(x) / 127.0f);
    half[x * 4 + 1] = 0x7c00;  // +Inf
    half[x * 4 + 2] = 0x7e01;  // NaN payload
    half[x * 4 + 3] = x % 3 ? 0x3c00 : 0;
    single[x * 4] = std::bit_cast<uint32_t>(static_cast<float>(x) / 127.0f);
    single[x * 4 + 1] = 0x7f800000u;
    single[x * 4 + 2] = 0x7fc00001u;
    single[x * 4 + 3] = x % 3 ? 0x3f800000u : 0;
  }
  const auto original_half = half; const auto original_single = single;
  auto as_bytes = [](auto& values) { return std::span<uint8_t>(
      reinterpret_cast<uint8_t*>(values.data()), values.size() * sizeof(values[0])); };
  assert(ApplyToOwnedUnpremul(as_bytes(half), 128, 1, 128 * 8,
                            PixelFormat::kRgbaF16, 0, 0, 3324349380u));
  assert(ApplyToOwnedUnpremul(as_bytes(single), 128, 1, 128 * 16,
                            PixelFormat::kRgbaF32, 0, 0, 3324349380u));
  assert(half != original_half && single != original_single);
  for (size_t x = 0; x < 128; ++x) for (size_t c = 0; c < 4; ++c) {
    const size_t at = x * 4 + c;
    if (c != 0 || x % 3 == 0) {
      assert(half[at] == original_half[at]);
      assert(single[at] == original_single[at]);
    } else {
      assert(std::abs(mc_proxy::canvas::HalfToFloat(half[at]) -
                      mc_proxy::canvas::HalfToFloat(original_half[at])) < .0042f);
      assert(std::abs(std::bit_cast<float>(single[at]) -
                      std::bit_cast<float>(original_single[at])) < .0042f);
    }
  }
  // F02: every possible SDR byte value, three seeds and all RGB channels. A
  // float16 read followed by JS Math.round(channel*255) must agree with RGBA8;
  // the old sub-ULP transform restored every original byte in this operation.
  for (uint32_t seed : {123456789u, 987654321u, 3324349380u}) {
    std::vector<uint8_t> rgba(256 * 4);
    std::vector<uint16_t> f16(256 * 4);
    std::vector<uint32_t> f32(256 * 4);
    for (uint32_t x = 0; x < 256; ++x) {
      for (size_t c = 0; c < 3; ++c) {
        rgba[x * 4 + c] = static_cast<uint8_t>(x);
        f16[x * 4 + c] = mc_proxy::canvas::UnitFloatToHalf(x / 255.0f);
        f32[x * 4 + c] = std::bit_cast<uint32_t>(x / 255.0f);
      }
      rgba[x * 4 + 3] = 255; f16[x * 4 + 3] = 0x3c00;
      f32[x * 4 + 3] = 0x3f800000u;
    }
    assert(ApplyToOwnedUnpremul(rgba, 256, 1, 256 * 4,
                              PixelFormat::kRgba8888, 0, 0, seed));
    assert(ApplyToOwnedUnpremul(as_bytes(f16), 256, 1, 256 * 8,
                              PixelFormat::kRgbaF16, 0, 0, seed));
    assert(ApplyToOwnedUnpremul(as_bytes(f32), 256, 1, 256 * 16,
                              PixelFormat::kRgbaF32, 0, 0, seed));
    size_t differences = 0;
    for (uint32_t x = 0; x < 256; ++x) for (size_t c = 0; c < 3; ++c) {
      const size_t at = x * 4 + c;
      assert(mc_proxy::canvas::UnitByte(mc_proxy::canvas::HalfToFloat(f16[at])) == rgba[at]);
      assert(mc_proxy::canvas::UnitByte(std::bit_cast<float>(f32[at])) == rgba[at]);
      if (rgba[at] != x) ++differences;
    }
    assert(differences > 0);
    const auto once_half = f16; const auto once_single = f32;
    for (size_t repeat = 0; repeat < 20; ++repeat) {
      assert(ApplyToOwnedUnpremul(as_bytes(f16), 256, 1, 256 * 8,
                                PixelFormat::kRgbaF16, 0, 0, seed));
      assert(ApplyToOwnedUnpremul(as_bytes(f32), 256, 1, 256 * 16,
                                PixelFormat::kRgbaF32, 0, 0, seed));
      assert(f16 == once_half && f32 == once_single);
    }
  }
  // All representable normalized half values survive conversion when no change
  // is requested. The projector must not silently collapse float precision.
  for (uint16_t value = 0; value <= 0x3c00; ++value)
    assert(mc_proxy::canvas::UnitFloatToHalf(mc_proxy::canvas::HalfToFloat(value)) == value);
  // HDR values outside [0,1] retain sign/exponent and native finite precision.
  std::vector<uint16_t> hdr_half(512 * 4);
  std::vector<uint32_t> hdr_single(512 * 4);
  for (size_t x = 0; x < 512; ++x) {
    hdr_half[x * 4] = static_cast<uint16_t>(0x4000 + x);
    hdr_half[x * 4 + 1] = static_cast<uint16_t>(0xc000 + x);
    hdr_half[x * 4 + 2] = 0x7e01; hdr_half[x * 4 + 3] = 0x3c00;
    hdr_single[x * 4] = 0x40000000u + static_cast<uint32_t>(x);
    hdr_single[x * 4 + 1] = 0xc0000000u + static_cast<uint32_t>(x);
    hdr_single[x * 4 + 2] = 0x7fc00001u; hdr_single[x * 4 + 3] = 0x3f800000u;
  }
  const auto original_hdr_half = hdr_half; const auto original_hdr_single = hdr_single;
  assert(ApplyToOwnedUnpremul(as_bytes(hdr_half), 512, 1, 512 * 8,
                            PixelFormat::kRgbaF16, 0, 0, 123456789u));
  assert(ApplyToOwnedUnpremul(as_bytes(hdr_single), 512, 1, 512 * 16,
                            PixelFormat::kRgbaF32, 0, 0, 123456789u));
  for (size_t at = 0; at < hdr_half.size(); ++at) {
    assert((hdr_half[at] & 0xfffeu) == (original_hdr_half[at] & 0xfffeu));
    assert((hdr_single[at] & 0xfffffffeu) == (original_hdr_single[at] & 0xfffffffeu));
    if (at % 4 >= 2) {
      assert(hdr_half[at] == original_hdr_half[at]);
      assert(hdr_single[at] == original_hdr_single[at]);
    }
  }
  std::cout << "Canvas algorithm: deterministic copies, 300 readbacks, crop, "
               "alpha, padding, input bounds, writeback non-inversion, integer "
               "translation majority resistance, all 256 "
               "SDR codes across float formats, HDR and half precision passed.\n";
}
