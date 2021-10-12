#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <util.hpp>

#include <string>
#include <vector>

#include <lz4.h>
#include <openssl/sha.h>

struct __attribute__((__packed__)) SegmentHeader {
  uint32_t file_offset;
  uint32_t memory_offset;
  uint32_t decompressed_size;
};

struct __attribute__((__packed__)) SegmentHeaderRelative {
  uint32_t offset;
  uint32_t size;
};

struct __attribute__((__packed__)) NSOHeader {
  uint8_t magic[4];
  uint32_t version;
  uint8_t reserved_0x8[4];
  uint32_t flags;
  SegmentHeader text_segment_header;
  uint32_t module_name_offset;
  SegmentHeader rodata_segment_header;
  uint32_t module_name_size;
  SegmentHeader data_segment_header;
  uint32_t bss_size;
  uint8_t module_id[0x20];
  uint32_t text_size_compressed;
  uint32_t rodata_size_compressed;
  uint32_t data_size_compressed;
  uint8_t reserved_0x6c[0x1C];

  SegmentHeaderRelative rel_api_info;
  SegmentHeaderRelative rel_dynstr;
  SegmentHeaderRelative rel_dynsym;

  uint8_t text_hash[0x20];
  uint8_t rodata_hash[0x20];
  uint8_t data_hash[0x20];
};

// Sanity check bit packing
static_assert(sizeof(NSOHeader) == 0x100);

struct PatchEntry {
  PatchEntry(uint32_t offset_, std::vector<uint8_t> data_)
      : offset(offset_), data(data_) {}

  const uint32_t offset;
  const std::vector<uint8_t> data;
};

int main(int argc, char **argv) {
  if (argc != 3) {
    fprintf(stderr, "%s in_nso out_nso\n", argv[0]);
    return -1;
  }

  const char *input_file = argv[1];
  const char *output_file = argv[2];

  // Instructions to patch
  static const std::vector<uint8_t> nop = {0x1f, 0x20, 0x03, 0xd5};
  static const std::vector<uint8_t> svc_0x27 = {0xe1, 0x04, 0x00, 0xd4};
  static const std::vector<uint8_t> mov_x0_0x0 = {0x00, 0x00, 0x80, 0xd2};
  static const std::vector<uint8_t> mov_w0_0x0 = {0x00, 0x00, 0x80, 0x52};
  static const std::vector<uint8_t> mov_w1_0x0 = {0x01, 0x00, 0x80, 0x52};
  static const std::vector<uint8_t> mov_w1_0x1 = {0x21, 0x00, 0x80, 0x52};

  /*
  std::vector<PatchEntry> patch_entries = {
      PatchEntry(0x142780, mov_w1_0x0),
      PatchEntry(0x1436c8, mov_w1_0x0),
      PatchEntry(0x144178, mov_w1_0x0),
  };
  */

  std::vector<PatchEntry> patch_entries = {
      // PatchEntry(0x142784, svc_0x27),
      PatchEntry(0x142784, nop),
  };

  // Map the NSO
  auto original_nso = MappedData::open(input_file);

  // Pun the header on the the first 0x100 bytes and print some info
  const NSOHeader *nso_header =
      reinterpret_cast<const NSOHeader *>(original_nso->_data);
  fprintf(stderr, "Version: %08x\n", nso_header->version);
  fprintf(stderr, "Flags:   %08x\n", nso_header->flags);
  fprintf(stderr, "Text Segment:\n");
  fprintf(stderr, "    File offset: %08x\n",
          nso_header->text_segment_header.file_offset);
  fprintf(stderr, "    Mem offset:  %08x\n",
          nso_header->text_segment_header.memory_offset);
  fprintf(stderr, "    Full size:   %08x\n",
          nso_header->text_segment_header.decompressed_size);
  fprintf(stderr, "    Sha256:      %s\n",
          bytes_to_hex(
              std::string(reinterpret_cast<const char *>(nso_header->text_hash),
                          sizeof(nso_header->text_hash)))
              .c_str());

  // Print the total data uncompressed size
  const int uncompressed_total =
      nso_header->text_segment_header.decompressed_size +
      nso_header->rodata_segment_header.decompressed_size +
      nso_header->data_segment_header.decompressed_size +
      nso_header->rel_api_info.size + nso_header->rel_dynstr.size +
      nso_header->rel_dynsym.size;
  fprintf(stderr, "Total expanded size: %d\n", uncompressed_total);

  // Extract the text segment
  std::string decompressed_text;
  decompressed_text.resize(nso_header->text_segment_header.decompressed_size);
  const int decompress_ok = LZ4_decompress_safe(
      /* src */ reinterpret_cast<const char *>(
          &original_nso->_data[nso_header->text_segment_header.file_offset]),
      /* dst */ decompressed_text.data(),
      /* compressedSize */ nso_header->text_size_compressed,
      /* dstCapacity */ decompressed_text.size());
  if (decompress_ok != (int)nso_header->text_segment_header.decompressed_size) {
    fprintf(stderr, "Failed to fully decompress text section\n");
    return -1;
  }
  fprintf(stderr, "Decompressed %u -> %d bytes of .text\n",
          nso_header->text_size_compressed, decompress_ok);

  // Verify sha256
  uint8_t decompressed_sha256[SHA256_DIGEST_LENGTH];
  SHA256(reinterpret_cast<const uint8_t *>(decompressed_text.data()),
         decompressed_text.size(), decompressed_sha256);
  if (memcmp(decompressed_sha256, nso_header->text_hash,
             SHA256_DIGEST_LENGTH) != 0) {
    fprintf(stderr,
            "Decompressed data has bad SHA256:\n"
            "Expected: %s\n"
            "Received: %s\n",
            bytes_to_hex(std::string(reinterpret_cast<const char *>(
                                         nso_header->text_hash),
                                     sizeof(nso_header->text_hash)))
                .c_str(),
            bytes_to_hex(
                std::string(reinterpret_cast<const char *>(decompressed_sha256),
                            SHA256_DIGEST_LENGTH))
                .c_str());
    return -1;
  }

  // Locate and patch our target instructions
  for (auto &entry : patch_entries) {
    // Print some info
    std::string old_text{&decompressed_text[entry.offset], entry.data.size()};
    std::string new_text{reinterpret_cast<const char *>(entry.data.data()),
                         entry.data.size()};
    fprintf(stderr,
            "Patching offset %08x:\n"
            "    Was: %s\n"
            "    Now: %s\n",
            entry.offset, bytes_to_hex(old_text).c_str(),
            bytes_to_hex(new_text).c_str());

    // Overwrite the data
    memcpy(&decompressed_text[entry.offset], entry.data.data(),
           entry.data.size());
  }

  // Recalculate text section SHA
  uint8_t new_decompressed_sha256[SHA256_DIGEST_LENGTH];
  SHA256(reinterpret_cast<const uint8_t *>(decompressed_text.data()),
         decompressed_text.size(), new_decompressed_sha256);
  fprintf(stderr, "New .text SHA256: %s\n",
          bytes_to_hex(std::string(reinterpret_cast<const char *>(
                                       new_decompressed_sha256),
                                   SHA256_DIGEST_LENGTH))
              .c_str());

  // Recompress the data
  std::string recompressed_text;
  recompressed_text.resize(
      decompressed_text.size()); // The compressed data _surely_ can't be bigger
                                 // than the decompressed data
  const int recompressed_size =
      LZ4_compress_default(decompressed_text.data(), recompressed_text.data(),
                           decompressed_text.size(), recompressed_text.size());
  const int size_delta = recompressed_size - nso_header->text_size_compressed;

  fprintf(stderr, "Recompressed .text size: %d (delta: %d bytes)\n",
          recompressed_size, size_delta);

  // Duplicate the old NSO header and update the affected fields
  NSOHeader new_header = *nso_header;
  memcpy(new_header.text_hash, new_decompressed_sha256, SHA256_DIGEST_LENGTH);

  // Text compressed size may be different
  new_header.text_size_compressed += size_delta;

  // Ro/Data segment offsets may have changed
  new_header.rodata_segment_header.file_offset += size_delta;
  new_header.data_segment_header.file_offset += size_delta;

  // Open our output file
  int output_fd = ::open(output_file, O_RDWR | O_CREAT, 0644);
  if (output_fd < 0) {
    fprintf(stderr, "Failed to open %s: %d: %s\n", output_file, errno,
            strerror(errno));
    return -1;
  }
  std::shared_ptr<void> _defer_close_fd(nullptr,
                                        [=](...) { ::close(output_fd); });

  // Write the header
  int file_offset = write(output_fd, &new_header, sizeof(new_header));
  printf("Wrote header, file offfset now %d\n", file_offset);

  // Write any data from the old file that comes after the header and before
  // the compressed .text
  const int post_header_pre_text_data_len =
      new_header.text_segment_header.file_offset - sizeof(new_header);
  file_offset += write(output_fd, &original_nso->_data[file_offset],
                       post_header_pre_text_data_len);
  printf("Wrote pre- .text, file offfset now %d\n", file_offset);

  // Write the edited .text
  file_offset += write(output_fd, recompressed_text.data(), recompressed_size);
  printf("Wrote new .text, file offfset now %d\n", file_offset);

  // Now, write all of the data from the old file that came _after_ the
  // text section
  const int old_nso_compressed_text_end_offset =
      nso_header->text_segment_header.file_offset +
      nso_header->text_size_compressed;
  const uint8_t *old_nso_compressed_text_end =
      &original_nso->_data[old_nso_compressed_text_end_offset];
  file_offset +=
      write(output_fd, old_nso_compressed_text_end,
            original_nso->_size - old_nso_compressed_text_end_offset);
}
