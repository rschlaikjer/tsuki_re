#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <vector>

#include <util.hpp>

struct IpsEntry {
  IpsEntry(uint32_t offset_, std::vector<uint8_t> data_)
      : offset(offset_), data(data_) {}

  const uint32_t offset;
  const std::vector<uint8_t> data;
};

int main(int argc, char **argv) {
  if (argc != 4) {
    fprintf(stderr, "%s base patched out_ips\n", argv[0]);
    return -1;
  }

  // Load input files
  auto base_nso = MappedData::open(argv[1]);
  auto modded_nso = MappedData::open(argv[2]);
  const char *output_file = argv[3];

  // Accumulate patch entries
  std::vector<IpsEntry> entries;
  bool in_diff_section = false;
  uint32_t current_diff_start;
  std::vector<uint8_t> current_diff_data;
  for (ssize_t i = 0; i < modded_nso->_size; i++) {
    // Do the files match at this offset
    // If we are off the end of the base nso, count that as a non-match
    if (i < base_nso->_size && base_nso->_data[i] == modded_nso->_data[i]) {
      // If we aren't currently generating a patch, just continue
      if (!in_diff_section) {
        continue;
      }

      // If we _were_ generating a patch, then we can finalize it and add to the
      // list of entries
      entries.emplace_back(current_diff_start, current_diff_data);
      in_diff_section = false;
    } else {
      // Files do _not_ match at this offset
      if (!in_diff_section) {
        // If this is a start of a new diff, mark the offset and zero the diff
        // data
        in_diff_section = true;
        current_diff_start = i;
        current_diff_data = {};
      }
      current_diff_data.emplace_back(modded_nso->_data[i]);
    }
  }

  // If we were mid-patch when we hit eof, finalize it now
  if (in_diff_section) {
    entries.emplace_back(current_diff_start, current_diff_data);
  }

  // Open our output file
  int output_fd = ::open(output_file, O_RDWR | O_CREAT, 0644);
  if (output_fd < 0) {
    fprintf(stderr, "Failed to open %s: %d: %s\n", output_file, errno,
            strerror(errno));
    return -1;
  }
  std::shared_ptr<void> _defer_close_fd(nullptr,
                                        [=](...) { ::close(output_fd); });

  // Emit patch file, starting with header
  write(output_fd, "PATCH", 5);

  // Patch records
  for (auto &entry : entries) {
    fprintf(stderr, "Patch @ %08x: %s\n", entry.offset,
            bytes_to_hex(
                std::string(reinterpret_cast<const char *>(entry.data.data()),
                            entry.data.size()))
                .c_str());

    // Address is 24-bit BE
    uint8_t offset_buf[3];
    offset_buf[0] = (entry.offset >> 16) & 0xFF;
    offset_buf[1] = (entry.offset >> 8) & 0xFF;
    offset_buf[2] = (entry.offset >> 0) & 0xFF;
    write(output_fd, offset_buf, 3);

    // Size, 16-bit BE
    uint8_t size_buf[2];
    size_buf[0] = (entry.data.size() >> 8) & 0xFF;
    size_buf[1] = (entry.data.size() >> 0) & 0xFF;
    write(output_fd, size_buf, 2);

    // Data
    write(output_fd, entry.data.data(), entry.data.size());
  }

  write(output_fd, "EOF", 3);

  return 0;
}
