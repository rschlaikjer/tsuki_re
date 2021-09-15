#pragma once
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <memory>
#include <string>

template <typename... Args>
std::string string_format(const std::string &format, Args... args) {
  size_t size = snprintf(nullptr, 0, format.c_str(), args...) + 1;
  std::string ret;
  ret.resize(size);
  snprintf(&ret[0], size, format.c_str(), args...);
  ret.resize(size - 1);
  return ret;
}

struct MappedData {
  MappedData(const uint8_t *data, ssize_t size) : _data(data), _size(size) {}
  ~MappedData() { munmap(const_cast<uint8_t *>(_data), _size); }
  MappedData(const MappedData &other) = delete;
  MappedData &operator=(const MappedData &other) = delete;
  const uint8_t *const _data;
  const ssize_t _size;

  static std::unique_ptr<MappedData> open(const char *filename) {
    int file_fd = ::open(filename, O_RDONLY);
    if (file_fd < 0) {
      return nullptr;
    }

    std::shared_ptr<void> _defer_close_fd(nullptr,
                                          [=](...) { ::close(file_fd); });

    const off_t file_size = ::lseek(file_fd, 0, SEEK_END);
    if (file_size < 0) {
      return nullptr;
    }
    if (lseek(file_fd, 0, SEEK_SET) < 0) {
      return nullptr;
    }

    void *mmapped_data =
        mmap(nullptr, file_size, PROT_READ, MAP_PRIVATE, file_fd, 0);

    if (mmapped_data == nullptr) {
      return nullptr;
    }

    return std::make_unique<MappedData>(
        reinterpret_cast<uint8_t *>(mmapped_data), file_size);
  }
};

[[maybe_unused]] static const std::string
bytes_to_hex(const std::string &bytes) {
  std::string ret;
  ret.resize(bytes.size() * 2);
  auto nibble_to_hex = [](uint8_t nibble) -> char {
    nibble &= 0xF;
    if (nibble < 10)
      return '0' + nibble;
    return 'A' + (nibble - 10);
  };

  for (std::string::size_type i = 0; i < bytes.size(); i++) {
    uint8_t byte = bytes[i];
    ret[i * 2] = nibble_to_hex(byte >> 4);
    ret[i * 2 + 1] = nibble_to_hex(byte);
  }

  return ret;
}

