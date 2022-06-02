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

std::vector<PatchEntry> parse_nso_as_patch_entries(const MappedData &ips) {
  std::vector<PatchEntry> ret;

  // IPS format:
  // Repeated:
  //   24-bit offset (BE)
  //   16-bit size (BE)
  //   SIZE bytes of data
  static const int TEXT_OFFSET = 0x100;

  if (memcmp("PATCH", ips._data, 5) != 0) {
    fprintf(stderr, "Invalid .ips file\n");
    asm volatile("ud2");
  }

  ssize_t ips_read_offset = 5;
  while (ips_read_offset + 5 < ips._size) {
    // Extract offset
    uint32_t offset = ((ips._data[ips_read_offset + 0] << 16) |
                       (ips._data[ips_read_offset + 1] << 8) |
                       (ips._data[ips_read_offset + 2] << 0));
    offset -= TEXT_OFFSET;
    ips_read_offset += 3;

    // Extract size
    uint16_t size = ((ips._data[ips_read_offset + 0] << 8) |
                     (ips._data[ips_read_offset + 1] << 0));
    ips_read_offset += 2;

    // Append new patch entry
    const uint8_t *data_begin = &ips._data[ips_read_offset];
    const uint8_t *data_end = &ips._data[ips_read_offset + size];
    ret.emplace_back(
        PatchEntry(offset, std::vector<uint8_t>(data_begin, data_end)));

    ips_read_offset += size;
  }

  return ret;
}

int main(int argc, char **argv) {
  if (argc != 4) {
    fprintf(stderr, "%s in_nso out_nso in_ips\n", argv[0]);
    return -1;
  }

  const char *input_nso = argv[1];
  const char *output_nso = argv[2];
  const char *input_ips = argv[3];

  // Load IPS and parse into a series of patch entries
  auto mapped_ips = MappedData::open(input_ips);
  std::vector<PatchEntry> patch_entries =
      parse_nso_as_patch_entries(*mapped_ips);

  // 1.0.2
  // Replace calls to disable recording with enable recording
  //   patch_entries.emplace_back(
  //       PatchEntry(0xfbf54, {0x73, 0x5e, 0x01, 0x14})); // Recording
  //   patch_entries.emplace_back(
  //       PatchEntry(0xfbf68, {0x76, 0x5e, 0x01, 0x14})); // Screenshot

  // Map the NSO
  auto original_nso = MappedData::open(input_nso);

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
            "Patching offset %08x + %ld:\n"
            "    Was: %s\n"
            "    Now: %s\n",
            entry.offset, entry.data.size(), bytes_to_hex(old_text).c_str(),
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
  int output_fd = ::open(output_nso, O_RDWR | O_CREAT, 0644);
  if (output_fd < 0) {
    fprintf(stderr, "Failed to open %s: %d: %s\n", output_nso, errno,
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
