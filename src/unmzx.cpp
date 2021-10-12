#include <stdio.h>
#include <string.h>

#include <vector>

#include <util.hpp>

struct __attribute__((__packed__)) MszHeader {
  uint8_t magic[4];
  uint32_t uncompressed_size;
};

static const uint8_t CMD_RLE = 0;
static const uint8_t CMD_BACKREF = 1;
static const uint8_t CMD_RINGBUF = 2;
static const uint8_t CMD_LITERAL = 3;

int main(int argc, char **argv) {

  if (argc != 2) {
    fprintf(stderr, "%s in.mzx", argv[0]);
    return -1;
  }

  auto input = MappedData::open(argv[1]);

  // Do we have enough data for header
  if (input->_size < 8) {
    fprintf(stderr, "Missing header\n");
    return -1;
  }

  // Check header
  const MszHeader *header = (const MszHeader *)input->_data;
  if (memcmp(header->magic, "MZX0", sizeof(header->magic)) != 0) {
    fprintf(stderr, "Invalid magic\n");
    return -1;
  }

  ssize_t read_offset = sizeof(MszHeader);
  uint8_t last[2] = {0xFF, 0xFF};

  std::vector<uint8_t> decompressed;
  decompressed.resize(header->uncompressed_size);
  unsigned decompress_offset = 0;
  int clear_count = 0;
  while (read_offset < input->_size) {
    // Get type / len
    const uint8_t len_cmd = input->_data[read_offset++];
    const uint8_t cmd = len_cmd & 0b11;
    const uint8_t len = len_cmd >> 2;

    // Reset counter
    if (clear_count <= 0) {
      clear_count = 0x1000;
      last[0] = 0xFF;
      last[1] = 0xFF;
    }

    switch (cmd) {

    case CMD_RLE: {
      // Repeat last two bytes len + 1 times
      for (unsigned i = 0; i <= len; i++) {
        decompressed[decompress_offset++] = last[0];
        decompressed[decompress_offset++] = last[1];
      }
    } break;

    case CMD_BACKREF: {
      const int lookback = 2 * (input->_data[read_offset++] + 1);
      for (unsigned i = 0; i <= len; i++) {
      }

    } break;

    case CMD_RINGBUF: {
    } break;

    case CMD_LITERAL: {
    } break;
    }
  }
}

