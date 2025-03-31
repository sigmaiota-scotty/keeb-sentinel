#define UNICODE
#define _UNICODE

// keystroke_defense_client - Proof of Concept
// Windows 10 | C++ | No GUI | Uses Windows Crypto API for signature verification

#include <windows.h>
#include <wincrypt.h>
#include <setupapi.h>
#include <hidsdi.h>
#include <initguid.h>
#include <dbt.h>
#include <vector>
#include <string>
#include <fstream>
#include <chrono>
#include <thread>
#include <mutex>
#include <regex>
#include <nlohmann/json.hpp> // JSON parsing (header-only)

#pragma comment(linker, "/SUBSYSTEM:CONSOLE")
#pragma comment(lib, "setupapi.lib")
#pragma comment(lib, "hid.lib")
#pragma comment(lib, "crypt32.lib")

using json = nlohmann::json;

DEFINE_GUID(GUID_DEVINTERFACE_HID, 
    0x4D1E55B2, 0xF16F, 0x11CF,
    0x88, 0xCB, 0x00, 0x11,
    0x11, 0x00, 0x00, 0x30);

// --- Global Configuration ---
const std::string WHITELIST_PATH = "C:\\ProgramData\\HIDWatcher\\whitelist.json";
const std::wstring EVENT_SOURCE = L"HID Keystroke Monitor";
constexpr int MAX_EVENTS = 20;
constexpr double INTERVAL_THRESHOLD_MS = 10.0;
constexpr double VARIANCE_THRESHOLD = 2.0;

std::vector<DWORD> intervals;
LARGE_INTEGER lastTimestamp;
LARGE_INTEGER freq;
bool shouldBlock = false;
std::mutex hookMutex;
json whitelistCache;
bool debugMode = false;

// --- Function Declarations ---
bool LoadAndVerifyWhitelist(json& whitelist);
void MonitorHIDDevices(const json& whitelist);
void StartKeystrokeHook();
void LogSecurityEvent(const std::wstring& message);
LRESULT CALLBACK LowLevelKeyboardProc(int nCode, WPARAM wParam, LPARAM lParam);

// --- Main Service Loop ---
int wmain(int argc, wchar_t* argv[]) {
    if (argc > 1 && wcscmp(argv[1], L"--debug") == 0) {
        debugMode = true;
    }

    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&lastTimestamp);

    if (!LoadAndVerifyWhitelist(whitelistCache)) {
        LogSecurityEvent(L"Whitelist verification failed. Exiting.");
        return 1;
    }

    std::thread deviceMonitor([&]() { MonitorHIDDevices(whitelistCache); });
    std::thread keyboardHook(StartKeystrokeHook);

    deviceMonitor.join();
    keyboardHook.join();
    return 0;
}

bool LoadAndVerifyWhitelist(json& whitelist) {
    std::ifstream file(WHITELIST_PATH);
    if (!file.is_open()) {
        LogSecurityEvent(L"Failed to open whitelist file.");
        return false;
    }

    try {
        file >> whitelist;
        file.close();

        if (!debugMode) {
            // TODO: Add digital signature verification using Windows Crypto API
            LogSecurityEvent(L"Whitelist loaded in production mode but not yet verified.");
        } else {
            LogSecurityEvent(L"Whitelist loaded in debug mode. Signature not verified.");
        }
    } catch (...) {
        LogSecurityEvent(L"Whitelist parsing failed.");
        return false;
    }

    return true;
}

void MonitorHIDDevices(const json& whitelist) {
    HDEVINFO deviceInfoSet = SetupDiGetClassDevs(&GUID_DEVINTERFACE_HID, NULL, NULL, DIGCF_PRESENT | DIGCF_DEVICEINTERFACE);
    if (deviceInfoSet == INVALID_HANDLE_VALUE) return;

    SP_DEVICE_INTERFACE_DATA deviceInterfaceData;
    deviceInterfaceData.cbSize = sizeof(SP_DEVICE_INTERFACE_DATA);

    DWORD index = 0;
    while (SetupDiEnumDeviceInterfaces(deviceInfoSet, NULL, &GUID_DEVINTERFACE_HID, index++, &deviceInterfaceData)) {
        DWORD requiredSize = 0;
        SetupDiGetDeviceInterfaceDetail(deviceInfoSet, &deviceInterfaceData, NULL, 0, &requiredSize, NULL);
        std::vector<BYTE> detailDataBuffer(requiredSize);
        auto* detailData = reinterpret_cast<PSP_DEVICE_INTERFACE_DETAIL_DATA_A>(detailDataBuffer.data());
        detailData->cbSize = sizeof(SP_DEVICE_INTERFACE_DETAIL_DATA_A);

        if (SetupDiGetDeviceInterfaceDetailA(deviceInfoSet, &deviceInterfaceData, detailData, requiredSize, NULL, NULL)) {
            std::string devicePath(detailData->DevicePath);
            std::smatch match;
            std::regex re("VID_([0-9A-Fa-f]{4})&PID_([0-9A-Fa-f]{4})");

            if (std::regex_search(devicePath, match, re)) {
                std::string key = match[1].str() + ":" + match[2].str();

                if (!whitelist.contains(key)) {
                    LogSecurityEvent(L"Unapproved HID Device Detected: " + std::wstring(key.begin(), key.end()));
                }
            }
        }
    }
    SetupDiDestroyDeviceInfoList(deviceInfoSet);
}

void StartKeystrokeHook() {
    HHOOK hook = SetWindowsHookEx(WH_KEYBOARD_LL, LowLevelKeyboardProc, NULL, 0);
    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    UnhookWindowsHookEx(hook);
}

LRESULT CALLBACK LowLevelKeyboardProc(int nCode, WPARAM wParam, LPARAM lParam) {
    if (nCode == HC_ACTION && wParam == WM_KEYDOWN) {
        LARGE_INTEGER now;
        QueryPerformanceCounter(&now);

        std::lock_guard<std::mutex> lock(hookMutex);
        if (lastTimestamp.QuadPart != 0) {
            DWORD delta = (DWORD)((now.QuadPart - lastTimestamp.QuadPart) * 1000 / freq.QuadPart);
            intervals.push_back(delta);
            if (intervals.size() > MAX_EVENTS) intervals.erase(intervals.begin());

            if (intervals.size() == MAX_EVENTS) {
                double mean = 0, variance = 0;
                for (DWORD d : intervals) mean += d;
                mean /= MAX_EVENTS;
                for (DWORD d : intervals) variance += pow(d - mean, 2);
                variance /= MAX_EVENTS;

                if (mean < INTERVAL_THRESHOLD_MS && variance < VARIANCE_THRESHOLD) {
                    shouldBlock = true;
                    std::this_thread::sleep_for(std::chrono::milliseconds(500));
                    intervals.clear();
                    shouldBlock = false;
                }
            }
        }
        lastTimestamp = now;

        if (shouldBlock) return 1;
    }
    return CallNextHookEx(NULL, nCode, wParam, lParam);
}

void LogSecurityEvent(const std::wstring& message) {
    HANDLE hEventLog = RegisterEventSourceW(NULL, EVENT_SOURCE.c_str());
    if (hEventLog) {
        LPCWSTR strings[1] = { message.c_str() };
        ReportEventW(hEventLog, EVENTLOG_WARNING_TYPE, 0, 0, NULL, 1, 0, strings, NULL);
        DeregisterEventSource(hEventLog);
    }
}
