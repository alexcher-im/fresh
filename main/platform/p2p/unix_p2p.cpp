#include <cstdio>
#include "unix_p2p.h"


UnixSerial::UnixSerial(const char* name, uint baud) {
    fd = open(name, O_RDWR | O_NOCTTY | O_NONBLOCK);

    if (fd < 0) {
        printf("Error: opening port: %s", name);
        return;
    }

    struct termios serial;

    if (tcgetattr(fd, &serial) < 0) {
        printf("Error: getting configuration\n");
        return;
    }

    serial_old = serial;

    // SERIAL CONFIGURATION
    /* Set Baud Rate */
    cfsetospeed(&serial, baud);
    cfsetispeed(&serial, baud);

    // Todo: make read from uart more purify (exclude from current reader trash from uart)

    // Setting other Port Stuff
    serial.c_cflag = 4146;
    serial.c_iflag = 0;
    serial.c_oflag = 0;
    serial.c_lflag = 0;
    serial.c_cc[VMIN] = 1;
    serial.c_cc[VTIME] = 1;

    // Make raw
    //cfmakeraw(&serial);

    // Flush Port, then applies attributes
    tcflush(fd, TCIFLUSH);

    // Set attributes to port
    if (tcsetattr(fd, TCSANOW, &serial) < 0) {
        printf("Error: set attributes\n");
        return;
    }

    printf("Port opened\n");
}

void UnixSerial::read_block(void* dst, size_t size) {
    uint written = 0;
    while (written != size)
        written += read_nonblock((ubyte *) dst + written, size - written);
}

size_t UnixSerial::read_nonblock(void* dst, size_t size) {
    auto bytes = read(fd, dst, size);
    if(bytes == -1)
        return 0;

    return bytes;
}

void UnixSerial::write(const void* data, size_t size) {
    //attempt to send
    if (::write(fd, data, size) < 0) {
        perror("serial write");
    }
}

UnixSerial::~UnixSerial() {
    tcsetattr(fd, TCSANOW, &serial_old); // Set old settings
    close(fd);
}
