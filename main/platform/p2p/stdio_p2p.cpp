#include "stdio_p2p.h"

StdioSerial::StdioSerial(FILE* handle_) : handle(handle_) { }

size_t StdioSerial::read_nonblock(void* dst, size_t size) {
    return fread(dst, 1, size, handle);
}

void StdioSerial::write(const void* data, size_t size) {
    fwrite(data, 1, size, handle);
}
