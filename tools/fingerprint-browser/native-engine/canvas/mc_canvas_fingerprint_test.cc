// Copyright 2026 MC Proxy contributors.
// SPDX-License-Identifier: MIT
// Native Blink tests; run against the newly compiled component after each edit.
#include "third_party/blink/renderer/platform/graphics/mc_canvas_fingerprint.h"

#include <algorithm>
#include <array>
#include <span>
#include <vector>

#include "base/test/scoped_command_line.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/platform/graphics/image_data_buffer.h"
#include "third_party/blink/renderer/platform/graphics/unaccelerated_static_bitmap_image.h"
#include "third_party/blink/renderer/platform/image-encoders/image_encoder.h"
#include "third_party/skia/include/core/SkBitmap.h"
#include "third_party/skia/include/core/SkColorSpace.h"
#include "third_party/skia/include/core/SkImage.h"

namespace blink {
namespace {

scoped_refptr<StaticBitmapImage> Fixture(SkColorType type) {
  const SkImageInfo info = SkImageInfo::Make(280, 100, type,
                                           kUnpremul_SkAlphaType,
                                           SkColorSpace::MakeSRGB());
  SkBitmap bitmap;
  if (!bitmap.tryAllocPixels(info)) return nullptr;
  // Draw through a separate 8-bit source conversion to populate every supported
  // destination with the same nonuniform semantic colors and transparent alpha.
  std::vector<uint8_t> bytes(280 * 100 * 4);
  for (size_t y = 0; y < 100; ++y) for (size_t x = 0; x < 280; ++x) {
    const size_t at = (y * 280 + x) * 4;
    bytes[at] = (x * 7 + y * 3) & 255;
    bytes[at + 1] = (x * 11 + y * 5) & 255;
    bytes[at + 2] = (x * 13 + y * 17) & 255;
    bytes[at + 3] = std::array<uint8_t, 5>{0, 64, 128, 192, 255}[(x + y) % 5];
  }
  const SkPixmap source(info.makeColorType(kRGBA_8888_SkColorType),
                        bytes.data(), 280 * 4);
  if (!bitmap.writePixels(source)) return nullptr;
  return UnacceleratedStaticBitmapImage::Create(SkImages::RasterFromBitmap(bitmap));
}

std::vector<uint8_t> Read(scoped_refptr<StaticBitmapImage> image) {
  if (!image) return {};
  PaintImage paint = image->PaintImageForCurrentFrame();
  const SkImageInfo info = paint.GetSkImageInfo();
  const size_t size = info.computeByteSize(info.minRowBytes());
  if (SkImageInfo::ByteSizeOverflowed(size)) return {};
  std::vector<uint8_t> bytes(size);
  if (!paint.readPixels(info, bytes.data(), info.minRowBytes(), 0, 0)) return {};
  return bytes;
}

std::vector<uint8_t> ReadRgba8(scoped_refptr<StaticBitmapImage> image) {
  if (!image) return {};
  PaintImage paint = image->PaintImageForCurrentFrame();
  const SkImageInfo info = paint.GetSkImageInfo().makeColorType(kRGBA_8888_SkColorType);
  std::vector<uint8_t> bytes(info.computeByteSize(info.minRowBytes()));
  if (!paint.readPixels(info, bytes.data(), info.minRowBytes(), 0, 0)) return {};
  return bytes;
}

scoped_refptr<StaticBitmapImage> AllSdrCodes(SkColorType type) {
  const SkImageInfo info = SkImageInfo::Make(256, 1, type,
                                           kUnpremul_SkAlphaType,
                                           SkColorSpace::MakeSRGB());
  SkBitmap bitmap;
  if (!bitmap.tryAllocPixels(info)) return nullptr;
  std::vector<uint8_t> bytes(256 * 4);
  for (size_t x = 0; x < 256; ++x) {
    for (size_t c = 0; c < 3; ++c) bytes[x * 4 + c] = static_cast<uint8_t>(x);
    bytes[x * 4 + 3] = 255;
  }
  const SkPixmap source(info.makeColorType(kRGBA_8888_SkColorType),
                        bytes.data(), 256 * 4);
  if (!bitmap.writePixels(source)) return nullptr;
  return UnacceleratedStaticBitmapImage::Create(SkImages::RasterFromBitmap(bitmap));
}

TEST(McCanvasFingerprintTest, StrictSeedAndExactDisableToken) {
  base::test::ScopedCommandLine command;
  auto* args = command.GetProcessCommandLine();
  args->AppendSwitchASCII("fingerprint", "4294967295");
  EXPECT_EQ(CanvasFingerprintSeed(), 4294967295u);
  args->AppendSwitchASCII("disable-spoofing", "font,audio,canvas2,gpu");
  EXPECT_EQ(CanvasFingerprintSeed(), 4294967295u);
  args->AppendSwitchASCII("disable-spoofing", "font, canvas ,gpu");
  EXPECT_EQ(CanvasFingerprintSeed(), 0u);
  args->RemoveSwitch("disable-spoofing");
  for (const char* invalid : {"0", "-1", "+1", " 1", "1 ", "4294967296", "1.0"}) {
    args->AppendSwitchASCII("fingerprint", invalid);
    EXPECT_EQ(CanvasFingerprintSeed(), 0u) << invalid;
  }
}

TEST(McCanvasFingerprintTest, StablePrivateSdrCopyPreservesOriginalAndAlpha) {
  auto source = Fixture(kRGBA_8888_SkColorType);
  ASSERT_TRUE(source);
  const auto original = Read(source);
  ASSERT_FALSE(original.empty());
  auto first = MakeCanvasFingerprintCopy(source, 3324349380u);
  ASSERT_TRUE(first);
  const auto expected = Read(first);
  ASSERT_NE(expected, original);
  EXPECT_EQ(Read(source), original);
  EXPECT_NE(Read(MakeCanvasFingerprintCopy(source, 1)), expected);
  for (int repeat = 0; repeat < 100; ++repeat)
    EXPECT_EQ(Read(MakeCanvasFingerprintCopy(source, 3324349380u)), expected);
  for (size_t at = 0; at < expected.size(); at += 4) {
    EXPECT_EQ(expected[at + 3], original[at + 3]);
    if (!original[at + 3])
      EXPECT_TRUE(std::ranges::equal(std::span(expected).subspan(at, 4),
                                    std::span(original).subspan(at, 4)));
  }
  EXPECT_EQ(MakeCanvasFingerprintCopy(source, 0).get(), source.get());
  EXPECT_EQ(Read(source), original);
}

TEST(McCanvasFingerprintTest, FloatPrecisionAndNativeEncoderSupportAreRetained) {
  for (SkColorType type : {kRGBA_F16_SkColorType, kRGBA_F32_SkColorType}) {
    auto source = Fixture(type);
    ASSERT_TRUE(source);
    const auto original = Read(source);
    auto protected_copy = MakeCanvasFingerprintCopy(source, 3324349380u);
    ASSERT_TRUE(protected_copy);
    EXPECT_EQ(protected_copy->PaintImageForCurrentFrame().GetSkImageInfo().colorType(), type);
    EXPECT_EQ(Read(source), original);
    const auto actual = Read(protected_copy);
    ASSERT_EQ(actual.size(), original.size());
    const size_t channel_bytes = type == kRGBA_F16_SkColorType ? 2 : 4;
    for (size_t at = 0; at < actual.size(); at += channel_bytes * 4)
      EXPECT_TRUE(std::ranges::equal(
          std::span(actual).subspan(at + channel_bytes * 3, channel_bytes),
          std::span(original).subspan(at + channel_bytes * 3, channel_bytes)));
    // This guard compares against the same stock encoder and format. Existing
    // unsupported formats remain unsupported; the patch must not turn every HDR
    // export into EncodingError. A successful export alone is not proof that a
    // lossy or color-converting encoder retains the protected low bits.
    for (ImageEncodingMimeType mime : {kMimeTypePng, kMimeTypeJpeg, kMimeTypeWebp}) {
      auto original_buffer = ImageDataBuffer::Create(source);
      auto protected_buffer = ImageDataBuffer::Create(protected_copy);
      ASSERT_TRUE(original_buffer); ASSERT_TRUE(protected_buffer);
      Vector<unsigned char> native_bytes, protected_bytes;
      const bool native_ok = original_buffer->EncodeImage(mime, .9, &native_bytes);
      const bool protected_ok = protected_buffer->EncodeImage(mime, .9, &protected_bytes);
      EXPECT_EQ(protected_ok, native_ok);
      if (native_ok) EXPECT_FALSE(protected_bytes.empty());
    }
  }
}

TEST(McCanvasFingerprintTest, WritebackCannotUndoReadbackProjection) {
  for (SkColorType type : {kRGBA_8888_SkColorType, kRGBA_F16_SkColorType,
                           kRGBA_F32_SkColorType}) {
    auto source = AllSdrCodes(type);
    ASSERT_TRUE(source);
    const auto original = Read(source);
    for (uint32_t seed : {123456789u, 987654321u, 3324349380u}) {
      auto first = MakeCanvasFingerprintCopy(source, seed);
      ASSERT_TRUE(first);
      const auto observed = Read(first);
      ASSERT_NE(observed, original);
      for (int repeat = 0; repeat < 20; ++repeat) {
        first = MakeCanvasFingerprintCopy(std::move(first), seed);
        ASSERT_TRUE(first);
        EXPECT_EQ(Read(first), observed);
        EXPECT_NE(Read(first), original);
      }
      EXPECT_EQ(Read(source), original);
    }
  }
}

TEST(McCanvasFingerprintTest, FloatToRgba8RetainsSameObservableProjection) {
  auto sdr_source = AllSdrCodes(kRGBA_8888_SkColorType);
  ASSERT_TRUE(sdr_source);
  for (uint32_t seed : {123456789u, 987654321u, 3324349380u}) {
    auto byte_copy = MakeCanvasFingerprintCopy(sdr_source, seed);
    ASSERT_TRUE(byte_copy);
    const auto expected = ReadRgba8(byte_copy);
    ASSERT_NE(expected, ReadRgba8(sdr_source));
    for (SkColorType type : {kRGBA_F16_SkColorType, kRGBA_F32_SkColorType}) {
      auto float_source = AllSdrCodes(type);
      ASSERT_TRUE(float_source);
      EXPECT_EQ(ReadRgba8(float_source), ReadRgba8(sdr_source));
      auto float_copy = MakeCanvasFingerprintCopy(float_source, seed);
      ASSERT_TRUE(float_copy);
      EXPECT_EQ(ReadRgba8(float_copy), expected);
      EXPECT_EQ(float_copy->PaintImageForCurrentFrame().GetSkImageInfo().colorType(), type);
    }
  }
}

TEST(McCanvasFingerprintTest, IntegerTranslationCannotCollectCleanSamples) {
  auto source = AllSdrCodes(kRGBA_8888_SkColorType);
  ASSERT_TRUE(source);
  const auto original = ReadRgba8(source);
  const SkImageInfo info = SkImageInfo::Make(256, 1, kRGBA_8888_SkColorType,
                                           kUnpremul_SkAlphaType,
                                           SkColorSpace::MakeSRGB());
  for (uint32_t seed : {123456789u, 987654321u}) {
    auto expected = original;
    ASSERT_TRUE(ProtectCanvasOwnedPixmap(
        SkPixmap(info, expected.data(), 256 * 4), 0, 0, seed));
    ASSERT_NE(expected, original);
    std::vector<uint8_t> low_bit_votes(original.size(), 0);
    for (int translation = 0; translation < 16; ++translation) {
      auto translated = original;
      ASSERT_TRUE(ProtectCanvasOwnedPixmap(
          SkPixmap(info, translated.data(), 256 * 4), translation * 131, 0, seed));
      EXPECT_EQ(translated, expected);
      for (size_t at = 0; at < translated.size(); ++at)
        low_bit_votes[at] += translated[at] & 1u;
    }
    auto majority = expected;
    for (size_t at = 0; at < majority.size(); ++at)
      majority[at] = static_cast<uint8_t>((majority[at] & 0xfeu) |
                                         (low_bit_votes[at] > 8 ? 1 : 0));
    EXPECT_EQ(majority, expected);
    EXPECT_NE(majority, original);
  }
}

}  // namespace
}  // namespace blink
