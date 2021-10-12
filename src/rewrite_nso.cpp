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

struct __attribute__((__packed__)) NsoHeader {
  uint8_t magic[4] = {'N', 'S', 'O', '0'};
  uint32_t version = 0;
  uint8_t reserved_0x8[4] = {0};
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
  uint8_t reserved_0x6c[0x1C] = {0};

  SegmentHeaderRelative rel_api_info;
  SegmentHeaderRelative rel_dynstr;
  SegmentHeaderRelative rel_dynsym;

  uint8_t text_hash[0x20];
  uint8_t rodata_hash[0x20];
  uint8_t data_hash[0x20];
};
// Sanity check bit packing
static_assert(sizeof(NsoHeader) == 0x100);

struct NsoObject {
  NsoHeader original_header;

  // Uncompressed
  std::string text_segment;
  std::string rodata_segment;
  std::string data_segment;

  // Relative
  std::string api_info;
  std::string dynstr;
  std::string dynsym;

  // Special
  std::string module_name;

  static NsoObject from_file(const char *path) {
    // Map input file
    auto original_nso = MappedData::open(path);

    // Copy header
    NsoObject ret;
    ret.original_header =
        *reinterpret_cast<const NsoHeader *>(original_nso->_data);

    // Helper fun to uncompress
    auto decompress_section = [&](const SegmentHeader &hdr,
                                  int compressed_size) -> std::string {
      std::string decompressed;
      decompressed.resize(hdr.decompressed_size);
      const int decompressed_bytes = LZ4_decompress_safe(
          /* src */ reinterpret_cast<const char *>(
              &original_nso->_data[hdr.file_offset]),
          /* dst */ decompressed.data(),
          /* compressedSize */ compressed_size,
          /* dstCapacity */ decompressed.size());
      if (decompressed_bytes != (int)hdr.decompressed_size) {
        fprintf(stderr, "Failed to fully decompress section\n");
        return "";
      }
      return decompressed;
    };

    // Extract main sections
    ret.text_segment =
        decompress_section(ret.original_header.text_segment_header,
                           ret.original_header.text_size_compressed);
    ret.rodata_segment =
        decompress_section(ret.original_header.rodata_segment_header,
                           ret.original_header.rodata_size_compressed);
    ret.data_segment =
        decompress_section(ret.original_header.data_segment_header,
                           ret.original_header.data_size_compressed);

    // Extract relative sections
    // Offsets are relative to .rodata start
    const int rodata_start =
        ret.original_header.rodata_segment_header.file_offset;
    auto extract_rel_section =
        [&](const SegmentHeaderRelative &hdr) -> std::string {
      /* src */
      return std::string(reinterpret_cast<const char *>(
                             &original_nso->_data[rodata_start + hdr.offset]),
                         hdr.size);
    };
    ret.api_info = extract_rel_section(ret.original_header.rel_api_info);

    // Extract module name
    ret.module_name = std::string(
        reinterpret_cast<const char *>(
            &original_nso->_data[ret.original_header.module_name_offset]),
        ret.original_header.module_name_size);

    return ret;
  }

  int to_file(const char *output_file) {
    // Helper fun to LZ data
    auto compress_section = [](const std::string &uncompressed) -> std::string {
      std::string compressed;
      compressed.resize(uncompressed.size());

      const int compressed_size =
          LZ4_compress_default(uncompressed.data(), compressed.data(),
                               uncompressed.size(), compressed.size());
      compressed.resize(compressed_size);
      return compressed;
    };

    // Helper to generate SHA256 of a section
    auto calculate_sha = [](const std::string &data, uint8_t *sha_out) {
      SHA256(reinterpret_cast<const uint8_t *>(data.data()), data.size(),
             sha_out);
    };

    // Compress the main sections
    const std::string lz_text = compress_section(text_segment);
    const std::string lz_rodata = compress_section(rodata_segment);
    const std::string lz_data = compress_section(data_segment);

    // Create a header for our output
    NsoHeader output_header;
    output_header.flags = 0x0000003f; // Compressed

    // Running output offset counter
    int output_offset = sizeof(NsoHeader);

    // Module name
    output_header.module_name_offset = output_offset;
    output_header.module_name_size = module_name.size();
    output_offset += module_name.size();

    // Start .text after header
    output_header.text_segment_header.file_offset = output_offset;
    output_header.text_segment_header.memory_offset =
        original_header.text_segment_header.memory_offset;
    output_header.text_segment_header.decompressed_size = text_segment.size();
    output_header.text_size_compressed = lz_text.size();
    calculate_sha(lz_text, output_header.text_hash);
    output_offset += output_header.text_size_compressed;

    // .rodata
    output_header.rodata_segment_header.file_offset = output_offset;
    output_header.rodata_segment_header.memory_offset =
        original_header.rodata_segment_header.memory_offset;
    output_header.rodata_segment_header.decompressed_size =
        rodata_segment.size();
    output_header.rodata_size_compressed = lz_rodata.size();
    calculate_sha(lz_rodata, output_header.rodata_hash);
    output_offset += output_header.rodata_size_compressed;

    // .data
    output_header.data_segment_header.file_offset = output_offset;
    output_header.data_segment_header.memory_offset =
        original_header.data_segment_header.memory_offset;
    output_header.data_segment_header.decompressed_size = data_segment.size();
    output_header.data_size_compressed = lz_data.size();
    calculate_sha(lz_data, output_header.data_hash);
    output_offset += output_header.data_size_compressed;

    // Relative sections
    // Offsets are relative to the .rodata section
    output_header.rel_api_info.offset =
        output_offset - output_header.rodata_segment_header.file_offset;
    output_header.rel_api_info.size = api_info.size();
    output_offset += api_info.size();

    // .dynstr
    output_header.rel_dynstr.offset =
        output_offset - output_header.rodata_segment_header.file_offset;
    output_header.rel_dynstr.size = dynstr.size();
    output_offset += dynstr.size();

    // .dynsym
    output_header.rel_dynsym.offset =
        output_offset - output_header.rodata_segment_header.file_offset;
    output_header.rel_dynsym.size = dynsym.size();
    output_offset += dynstr.size();

    // BSS unchanged
    output_header.bss_size = original_header.bss_size;

    // Module ID unchanged
    memcpy(output_header.module_id, original_header.module_id,
           sizeof(output_header.module_id));

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
    write(output_fd, &output_header, sizeof(NsoHeader));

    // Module name
    write(output_fd, module_name.data(), module_name.size());

    // Compressed sections
    write(output_fd, lz_text.data(), lz_text.size());
    write(output_fd, lz_rodata.data(), lz_rodata.size());
    write(output_fd, lz_data.data(), lz_data.size());

    // Relative sections
    write(output_fd, api_info.data(), api_info.size());
    write(output_fd, dynstr.data(), dynstr.size());
    write(output_fd, dynsym.data(), dynsym.size());

    return 0;
  }
};

int main(int argc, char **argv) {
  if (argc != 4) {
    fprintf(stderr, "%s in_nso inject_asm out_nso\n", argv[0]);
    return -1;
  }

  const char *input_file = argv[1];
  const char *injection_asm_file = argv[2];
  const char *output_file = argv[3];

  // Load the base NSO
  NsoObject nso = NsoObject::from_file(input_file);

  // At what .text offset are we injecting our custom code
  static const int injected_code_org = 0x00160000;

  // Load in the injected code asm
  auto injection_asm = MappedData::open(injection_asm_file);
  if (injection_asm == nullptr) {
    return -1;
  }

  // Expand the NSO text section to fit the code we are about to insert
  const int new_text_segment_size = injected_code_org + injection_asm->_size;
  nso.text_segment.resize(new_text_segment_size);

  // Memcpy in our new functions
  memcpy(&nso.text_segment.data()[injected_code_org], injection_asm->_data,
         injection_asm->_size);

  // Emit the new NSO
  nso.to_file(output_file);

  return 0;
}
