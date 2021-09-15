#include <cxxabi.h>
#include <string>

std::string cxa_demangle(const char *mangled) {
  int status;
  char *demangled = abi::__cxa_demangle(mangled, nullptr, nullptr, &status);
  if (status != 0) {
    return mangled;
  }
  std::string ret(demangled);
  free(demangled);
  return ret;
}

int main(int argc, char **argv) {
  for (int i = 1; i < argc; i++) {
    printf("%s\n", cxa_demangle(argv[i]).c_str());
  }
}
