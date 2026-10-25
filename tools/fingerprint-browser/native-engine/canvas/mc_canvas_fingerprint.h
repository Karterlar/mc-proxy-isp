// Copyright 2026 MC Proxy contributors.
// SPDX-License-Identifier: MIT
#ifndef THIRD_PARTY_BLINK_RENDERER_PLATFORM_GRAPHICS_MC_CANVAS_FINGERPRINT_H_
#define THIRD_PARTY_BLINK_RENDERER_PLATFORM_GRAPHICS_MC_CANVAS_FINGERPRINT_H_

#include <cstdint>

#include "base/memory/scoped_refptr.h"
#include "third_party/blink/renderer/platform/graphics/static_bitmap_image.h"
#include "third_party/blink/renderer/platform/platform_export.h"
#include "third_party/skia/include/core/SkPixmap.h"

namespace blink {

// Zero means disabled. Strict nonzero uint32 --fingerprint and exact comma-list
// --disable-spoofing=canvas compatibility, in both Window and worker renderers.
PLATFORM_EXPORT uint32_t CanvasFingerprintSeed();

// Only call with the newly allocated getImageData destination, after Chromium
// has performed its own validation, clipping, colorspace/format conversion and
// readPixels. Never call with a source canvas's borrowed backing pixmap.
PLATFORM_EXPORT bool ProtectCanvasOwnedPixmap(const SkPixmap& destination,
                                            int64_t origin_x,
                                            int64_t origin_y,
                                            uint32_t seed);

// Makes a separate unpremultiplied, CPU-owned snapshot for encoding. No mutation
// of any source PaintImage/SkPixmap; the result retains its private SkData until
// both idle main-thread and worker encoders finish. nullptr signals a normal
// allocation/readback failure, as Chromium's existing encoding paths expect.
PLATFORM_EXPORT scoped_refptr<StaticBitmapImage> MakeCanvasFingerprintCopy(
    scoped_refptr<StaticBitmapImage> source, uint32_t seed);

}  // namespace blink

#endif
