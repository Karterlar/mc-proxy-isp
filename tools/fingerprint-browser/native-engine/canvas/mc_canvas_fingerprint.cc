// Copyright 2026 MC Proxy contributors.
// SPDX-License-Identifier: MIT
#include "third_party/blink/renderer/platform/graphics/mc_canvas_fingerprint.h"

#include <optional>
#include <span>
#include <string>
#include <utility>

#include "base/command_line.h"
#include "base/compiler_specific.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/string_split.h"
#include "third_party/blink/renderer/platform/graphics/mc_canvas_noise.h"
#include "third_party/blink/renderer/platform/graphics/unaccelerated_static_bitmap_image.h"
#include "third_party/skia/include/core/SkData.h"
#include "third_party/skia/include/core/SkImage.h"

namespace blink {
namespace {

std::optional<mc_proxy::canvas::PixelFormat> Format(SkColorType type) {
  switch (type) {
    case kRGBA_8888_SkColorType:
      return mc_proxy::canvas::PixelFormat::kRgba8888;
    case kRGBA_F16Norm_SkColorType:
    case kRGBA_F16_SkColorType:
      return mc_proxy::canvas::PixelFormat::kRgbaF16;
    case kRGBA_F32_SkColorType:
      return mc_proxy::canvas::PixelFormat::kRgbaF32;
    default:
      return std::nullopt;
  }
}

}  // namespace

uint32_t CanvasFingerprintSeed() {
  const base::CommandLine* command = base::CommandLine::ForCurrentProcess();
  const std::string disabled = command->GetSwitchValueASCII("disable-spoofing");
  for (const auto part : base::SplitStringPiece(
           disabled, ",", base::TRIM_WHITESPACE, base::SPLIT_WANT_NONEMPTY)) {
    if (part == "canvas") return 0;
  }
  const std::string input = command->GetSwitchValueASCII("fingerprint");
  if (input.empty()) return 0;
  for (const char digit : input) if (digit < '0' || digit > '9') return 0;
  uint32_t seed = 0;
  if (!base::StringToUint(input, &seed)) return 0;
  return seed;
}

bool ProtectCanvasOwnedPixmap(const SkPixmap& destination,
                              int64_t origin_x, int64_t origin_y,
                              uint32_t seed) {
  if (!seed) return true;
  const auto format = Format(destination.colorType());
  const size_t size = destination.computeByteSize();
  if (!format || destination.width() < 0 || destination.height() < 0 ||
      destination.alphaType() == kPremul_SkAlphaType ||
      SkImageInfo::ByteSizeOverflowed(size) || (!destination.addr() && size)) {
    return false;
  }
  // SAFETY: Callers pass a newly allocated ImageData or private SkData pixmap.
  // Skia computes its byte extent from the validated format, dimensions and
  // rowBytes; the overflow/null guards above reject invalid extents. Only this
  // external Skia pointer-to-bounded-view bridge needs an unsafe annotation.
  const auto bytes = UNSAFE_BUFFERS(std::span<uint8_t>(
      static_cast<uint8_t*>(destination.writable_addr()), size));
  return mc_proxy::canvas::ApplyToOwnedUnpremul(
      bytes,
      static_cast<size_t>(destination.width()),
      static_cast<size_t>(destination.height()), destination.rowBytes(),
      *format, origin_x, origin_y, seed);
}

scoped_refptr<StaticBitmapImage> MakeCanvasFingerprintCopy(
    scoped_refptr<StaticBitmapImage> source, uint32_t seed) {
  if (!source || !seed) return source;
  PaintImage paint = source->PaintImageForCurrentFrame();
  if (!paint || paint.IsPaintWorklet()) return nullptr;
  SkImageInfo info = paint.GetSkImageInfo();
  if (info.isEmpty()) return nullptr;
  // Default SDR snapshot: canonical RGBA byte order, unpremultiplied, original
  // colorspace. Do not assume N32 == RGBA (Windows N32 commonly means BGRA).
  // Floating sources retain native channel precision and HDR/color metadata.
  const auto native_format = Format(info.colorType());
  if (!native_format || *native_format == mc_proxy::canvas::PixelFormat::kRgba8888)
    info = info.makeColorType(kRGBA_8888_SkColorType);
  info = info.makeAlphaType(kUnpremul_SkAlphaType);
  const size_t row_bytes = info.minRowBytes();
  const size_t size = info.computeByteSize(row_bytes);
  if (SkImageInfo::ByteSizeOverflowed(size)) return nullptr;
  sk_sp<SkData> owned = SkData::MakeUninitialized(size);
  if (!owned || !paint.readPixels(info, owned->writable_data(), row_bytes, 0, 0))
    return nullptr;
  const SkPixmap destination(info, owned->writable_data(), row_bytes);
  if (!ProtectCanvasOwnedPixmap(destination, 0, 0, seed)) return nullptr;
  sk_sp<SkImage> image = SkImages::RasterFromData(info, std::move(owned), row_bytes);
  if (!image) return nullptr;
  auto result = UnacceleratedStaticBitmapImage::Create(
      std::move(image), source->Orientation(), source->GetHdrMetadata());
  if (result) result->SetOriginClean(source->OriginClean());
  return result;
}

}  // namespace blink
