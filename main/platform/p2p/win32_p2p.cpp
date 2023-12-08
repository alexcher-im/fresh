#include "win32_p2p.h"

#include <cstdio>
#include <windows.h>


Win32Serial::Win32Serial(const char* name, uint baudrate) {
    // this function is a copy-pasted serial example in winapi

    auto file = CreateFile(name,                         // Name of the Port to be Opened
                           GENERIC_READ | GENERIC_WRITE, // Read/Write Access
                           0,                            // No Sharing, ports cant be shared
                           NULL,                         // No Security
                           OPEN_EXISTING,                // Open existing port only
                           0,                            // Non Overlapped I/O
                           NULL);                        // Null for Comm Devices

    if (file == INVALID_HANDLE_VALUE)
        printf("\n   Error! - Port %s can't be opened", name);
    else
        printf("\n   Port %s Opened\n ", name);


    /*------------------------------- Setting the Parameters for the SerialPort ------------------------------*/

    DCB dcbSerialParams = {0}; // Initializing DCB structure
    dcbSerialParams.DCBlength = sizeof(dcbSerialParams);

    auto Status = GetCommState(file, &dcbSerialParams); //retreives  the current settings

    if (Status == FALSE)
        printf("\n   Error! in GetCommState()");

    dcbSerialParams.BaudRate = baudrate;   //CBR_9600;   // Setting BaudRate = 9600
    dcbSerialParams.ByteSize = 8;          // Setting ByteSize = 8
    dcbSerialParams.StopBits = ONESTOPBIT; // Setting StopBits = 1
    dcbSerialParams.Parity = NOPARITY;     // Setting Parity = None

    Status = SetCommState(file, &dcbSerialParams); //Configuring the port according to settings in DCB

    if (Status == FALSE)
    {
        printf("\n   Error! in Setting DCB Structure");
    }
    else
    {
        printf("\n   Setting DCB Structure Successfull\n");
        printf("\n       Baudrate = %d", dcbSerialParams.BaudRate);
        printf("\n       ByteSize = %d", dcbSerialParams.ByteSize);
        printf("\n       StopBits = %d", dcbSerialParams.StopBits);
        printf("\n       Parity   = %d", dcbSerialParams.Parity);
    }

    /*------------------------------------ Setting Timeouts --------------------------------------------------*/

    COMMTIMEOUTS timeouts = {0};

    timeouts.ReadIntervalTimeout = 50000;
    timeouts.ReadTotalTimeoutConstant = 50;
    timeouts.ReadTotalTimeoutMultiplier = 0;
    timeouts.WriteTotalTimeoutConstant = 50;
    timeouts.WriteTotalTimeoutMultiplier = 1;

    if (SetCommTimeouts(file, &timeouts) == FALSE)
        printf("\n   Error! in Setting Time Outs");
    else
        printf("\n\n   Setting Serial Port Timeouts Successfull\n");

    handle = (ubyte*) file;
}

size_t Win32Serial::read_nonblock(void* dst, size_t size) {
    DWORD n_read;
    ReadFile((HANDLE) handle, dst, size, &n_read, nullptr);
    if (n_read) {
        //printf("read %d bytes\n", n_read);
        //fflush(stdout);
    }
    return n_read;
}

void Win32Serial::write(const void* data, size_t size) {
    DWORD n_written = 0;
    while (size) {
        auto status = WriteFile((HANDLE) handle, data, size, &n_written, NULL);
        if (status != TRUE)
            return; // todo handle error somehow
        size -= n_written;
    }
}
