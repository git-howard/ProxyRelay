// Precompiled header - ensure proper include order
#pragma once

// WinSock must be included before Windows.h
#include <winsock2.h>
#include <ws2tcpip.h>

// Do NOT define WIN32_LEAN_AND_MEAN because GDI+ needs the full Windows headers
// Including OLE headers for IStream which is required by GDI+

#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <windows.h>
#include <objidl.h>  // For IStream, required by GDI+
