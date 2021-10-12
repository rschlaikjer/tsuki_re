#include <stdint.h>
#include <stdio.h>
#include <unistd.h>

#include <vector>

struct IpsEntry {
  IpsEntry(uint32_t offset_, std::vector<uint8_t> data_)
      : offset(offset_), data(data_) {}

  const uint32_t offset;
  const std::vector<uint8_t> data;
};

int main(int argc, char **argv) {
  static const std::vector<uint8_t> svc_0x27 = {0xe1, 0x04, 0x00, 0xd4};
  static const std::vector<uint8_t> svc_0xaa = {0x41, 0x15, 0x00, 0xd4};
  static const std::vector<uint8_t> nop = {0x1f, 0x20, 0x03, 0xd5};

  // Text section offset
  static const int text_offset = 0x100;

  // V1.0.1 offsets
  std::vector<IpsEntry> entries = {
      // IpsEntry(0x142784, svc_0x27),

      // 1.0.2
      // Replace calls to disable recording with enable recording
      IpsEntry(0xfbf54, {0x73, 0x5e, 0x01, 0x14}), // Recording
      IpsEntry(0xfbf68, {0x76, 0x5e, 0x01, 0x14}), // Screenshot

      // Initial nn::fontll::ScalableFontEngine::SetFont call
      // If nopped, text doesn't render
      // IpsEntry(0x142740, svc_0xaa),

      // Finalize OtfKerning
      // IpsEntry(0x1428d8, svc_0xaa),

      // Check glyph
      // IpsEntry(0x142f64, svc_0xaa), // 9400448b
      // IpsEntry(0x143168, svc_0xaa), // 9400440a

      // Set scale
      //  IpsEntry(0x143188, svc_0xaa), // 94004406

      // Get glyph map
      // IpsEntry(0x1431c4, svc_0xaa), // 940043fb
      // IpsEntry(0x1431c8, svc_0xaa), // aa0003f4

      // Get advance
      // IpsEntry(0x14353c, svc_0xaa), // 94004325
      // IpsEntry(0x143540, svc_0xaa), // 79c09be9

      // 2 calls to bl FontEngine::GetAdvance
      // IpsEntry{0x14353c, svc_0x27},
      // IpsEntry{0x14405c, svc_0x27},

      // Immediately after first getadvance call
      // IpsEntry{0x143540, svc_0x27},
      // IpsEntry{0x144060, svc_0x27},

      // After GetKerning
      // IpsEntry{0x1444b0, svc_0x27},

      // After OtfKerningFirst
      // IpsEntry{0x14436c, svc_0x27},

      // After OtfKerningLast
      // IpsEntry{0x1443e8, svc_0x27},

      // After AcqOtfKerning
      // IpsEntry{0x144464, svc_0x27},
  };

  // Header
  write(STDOUT_FILENO, "PATCH", 5);

  // Patch records
  for (auto &entry : entries) {
    // Address is 24-bit BE
    uint8_t offset_buf[3];
    const uint32_t nso_offset = text_offset + entry.offset;
    offset_buf[0] = (nso_offset >> 16) & 0xFF;
    offset_buf[1] = (nso_offset >> 8) & 0xFF;
    offset_buf[2] = (nso_offset >> 0) & 0xFF;
    write(STDOUT_FILENO, offset_buf, 3);

    // Size, 16-bit BE
    uint8_t size_buf[2];
    size_buf[0] = (entry.data.size() >> 8) & 0xFF;
    size_buf[1] = (entry.data.size() >> 0) & 0xFF;
    write(STDOUT_FILENO, size_buf, 2);

    // Data
    write(STDOUT_FILENO, entry.data.data(), entry.data.size());
  }

  write(STDOUT_FILENO, "EOF", 3);

  return 0;
}
