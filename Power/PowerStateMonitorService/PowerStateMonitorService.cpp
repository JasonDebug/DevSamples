#include <windows.h>
#include <tchar.h>
#include <fstream>
#include <iomanip>
#include <powrprof.h>
#include <initguid.h>
#include <winevt.h>
#include <mutex>

#pragma comment(lib, "wevtapi.lib")
#pragma comment(lib, "PowrProf.lib")

#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)

HPOWERNOTIFY g_PowerNotify = NULL;  // RegisterSuspendResumeNotification (hidden window)
HPOWERNOTIFY g_PowerNotify2 = NULL; // RegisterSuspendResumeNotification (callback)
HPOWERNOTIFY g_PowerNotify3 = NULL; // RegisterPowerSettingNotification (GUID_CONSOLE_DISPLAY_STATE)
SERVICE_STATUS g_ServiceStatus = { 0 };
SERVICE_STATUS_HANDLE g_StatusHandle = NULL;
HANDLE g_ServiceStopEvent = INVALID_HANDLE_VALUE;
HWND g_HiddenWindow = NULL;

std::mutex logMutex;

const TCHAR* g_ServiceName = _T("PowerStateMonitorService");
const TCHAR* g_WindowClassName = _T("PowerStateMonitor");

std::ofstream logFile("C:\\PowerStateMonitorService\\PowerStateMonitorService.log", std::ios::app);

void LogEvent(const char* message, DWORD errorCode = 0)
{
    std::lock_guard<std::mutex> guard(logMutex);
    if (logFile.is_open())
    {
        SYSTEMTIME st = { 0 };
        GetLocalTime(&st);

        // Really either method works I guess, but ugh I hate string conversions and passing the buffer to the log is a pain
        //int bufferSize = GetTimeFormatEx(LOCALE_NAME_USER_DEFAULT, TIME_FORCE24HOURFORMAT, &st, L"yyyy-MM-dd HH:mm:ss", NULL, 0);
		//WCHAR* buffer = new WCHAR[bufferSize];
        //GetTimeFormatEx(LOCALE_NAME_USER_DEFAULT, 0, &st, L"yyyy-MM-dd HH:mm:ss", buffer, bufferSize);

        GetLocalTime(&st);
        logFile << "[" << std::setfill('0') << st.wYear << "-"
            << std::setw(2) << st.wMonth << "-"
            << std::setw(2) << st.wDay << " "
            << std::setw(2) << st.wHour << ":"
            << std::setw(2) << st.wMinute << ":"
            << std::setw(2) << st.wSecond << "] "
            << message;
        
        if (errorCode > 0)
        {
            logFile << errorCode;
        }

        logFile << std::endl;
        logFile.flush();

        //delete[] buffer;
    }
}

void ReportServiceStatus(DWORD dwCurrentState, DWORD dwWin32ExitCode, DWORD dwWaitHint) {
    g_ServiceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    g_ServiceStatus.dwCurrentState = dwCurrentState;
    g_ServiceStatus.dwControlsAccepted = (dwCurrentState == SERVICE_RUNNING)
        ? SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_POWEREVENT | SERVICE_ACCEPT_SESSIONCHANGE
        : 0;
    g_ServiceStatus.dwWin32ExitCode = dwWin32ExitCode;
    g_ServiceStatus.dwWaitHint = dwWaitHint;

    SetServiceStatus(g_StatusHandle, &g_ServiceStatus);
}

LRESULT CALLBACK HiddenWindowProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    switch (msg)
    {
    case WM_POWERBROADCAST:
		LogEvent("[HiddenWindowProc] Power event received.");

        switch (wParam)
        {
            case PBT_APMQUERYSUSPEND:
                LogEvent("-[HiddenWindowProc] System is about to enter sleep mode.");
                break;
            case PBT_APMSUSPEND:
                LogEvent("-[HiddenWindowProc] System is entering sleep mode.");
                break;
            case PBT_APMRESUMESUSPEND:
                LogEvent("-[HiddenWindowProc] System has resumed from sleep mode.");
                break;
            case PBT_APMBATTERYLOW:
                LogEvent("-[HiddenWindowProc] Battery is running low.");
                break;
            case PBT_APMPOWERSTATUSCHANGE:
                LogEvent("-[HiddenWindowProc] Power status has changed.");
                break;
            case PBT_APMOEMEVENT:
                LogEvent("-[HiddenWindowProc] OEM-defined event occurred.");
                break;
            case PBT_APMRESUMECRITICAL:
                LogEvent("-[HiddenWindowProc] System has resumed from a critical sleep mode.");
                break;
            case PBT_APMRESUMEAUTOMATIC:
                LogEvent("-[HiddenWindowProc] System has resumed automatically.");
                break;
            case PBT_POWERSETTINGCHANGE:
            {
                LogEvent("-[HiddenWindowProc] PBT_POWERSETTINGCHANGE: Power setting has changed.");

                POWERBROADCAST_SETTING* pSetting = reinterpret_cast<POWERBROADCAST_SETTING*>(lParam);
                if (IsEqualGUID(pSetting->PowerSetting, GUID_CONSOLE_DISPLAY_STATE))
                {
                    DWORD displayState = *reinterpret_cast<DWORD*>(pSetting->Data);
                    switch (displayState)
                    {
                    case 0:
                        LogEvent("-[HiddenWindowProc] PBT_POWERSETTINGCHANGE: Display Off");
                        break;
                    case 1:
                        LogEvent("-[HiddenWindowProc] PBT_POWERSETTINGCHANGE: Display On");
                        break;
                    case 2:
                        LogEvent("-[HiddenWindowProc] PBT_POWERSETTINGCHANGE: Display Dimmed");
                        break;
                    default:
                        LogEvent("-[HiddenWindowProc] PBT_POWERSETTINGCHANGE: Unknown display state.");
                        break;
                    }
                }
                break;
            }
            default:
                LogEvent("-[HiddenWindowProc] Unknown power event.");
                break;
        }
        return TRUE;
    case WM_CLOSE:
        PostQuitMessage(0);
        return 0;
    default:
        return DefWindowProc(hwnd, msg, wParam, lParam);
    }
}

ULONG CALLBACK DeviceNotifyCallbackRoutine(
    PVOID Context,
    ULONG Type,
    PVOID Setting
)
{
    LogEvent("[RegisterSuspendResumeNotification][CALLBACK] Power event received.");

    switch (Type)
    {
        case PBT_APMQUERYSUSPEND:
            LogEvent("-[RegisterSuspendResumeNotification][CALLBACK] PBT_APMQUERYSUSPEND: System is about to enter sleep mode.");
            break;
        case PBT_APMSUSPEND:
            LogEvent("-[RegisterSuspendResumeNotification][CALLBACK] PBT_APMSUSPEND: System is entering sleep mode.");
            break;
        case PBT_APMRESUMESUSPEND:
            LogEvent("-[RegisterSuspendResumeNotification][CALLBACK] PBT_APMRESUMESUSPEND: System has resumed from sleep mode.");
            break;
        case PBT_APMBATTERYLOW:
            LogEvent("-[RegisterSuspendResumeNotification][CALLBACK] PBT_APMBATTERYLOW: Battery is running low.");
            break;
        case PBT_APMPOWERSTATUSCHANGE:
            LogEvent("-[RegisterSuspendResumeNotification][CALLBACK] PBT_APMPOWERSTATUSCHANGE: Power status has changed.");
            break;
        case PBT_APMOEMEVENT:
            LogEvent("-[RegisterSuspendResumeNotification][CALLBACK] PBT_APMOEMEVENT: OEM-defined event occurred.");
            break;
        case PBT_APMRESUMECRITICAL:
            LogEvent("-[RegisterSuspendResumeNotification][CALLBACK] PBT_APMRESUMECRITICAL: System has resumed from a critical sleep mode.");
            break;
        case PBT_APMRESUMEAUTOMATIC:
            LogEvent("-[RegisterSuspendResumeNotification][CALLBACK] PBT_APMRESUMEAUTOMATIC: System has resumed automatically.");
            break;
        case PBT_POWERSETTINGCHANGE:
            LogEvent("-[RegisterSuspendResumeNotification][CALLBACK] PBT_POWERSETTINGCHANGE: Power setting has changed.");
            break;
        default:
            LogEvent("-[RegisterSuspendResumeNotification][CALLBACK] Unknown power event.");
            break;
    }

    return TRUE;
}

void CALLBACK EventCallback(EVT_SUBSCRIBE_NOTIFY_ACTION action, PVOID context, EVT_HANDLE hEvent)
{
    if (action != EvtSubscribeActionDeliver)
        return;

    LogEvent("[EventCallback] Kernel-Power event detected");

    DWORD status = ERROR_SUCCESS;
    DWORD dwBufferSize = 0;
    DWORD dwBufferUsed = 0;
    DWORD dwPropertyCount = 0;
    EVT_VARIANT* pRenderedValues = NULL;

    LPCWSTR properties[] = { L"Event/System/EventID", L"Event/System/TimeCreated/@SystemTime" };
    EVT_HANDLE hContext = EvtCreateRenderContext(2, properties, EvtRenderContextValues);

    if (!hContext)
    {
        LogEvent("EvtCreateRenderContext failed with error: ", GetLastError());
        return;
    }

    // Get required buffer size
    if (!EvtRender(hContext, hEvent, EvtRenderEventValues, 0, NULL, &dwBufferSize, &dwPropertyCount))
    {
        if (GetLastError() != ERROR_INSUFFICIENT_BUFFER)
        {
            LogEvent("EvtRender (size check) failed with error: ", GetLastError());
            goto cleanup;
        }
    }

    pRenderedValues = (EVT_VARIANT*)malloc(dwBufferSize);
    if (!pRenderedValues)
    {
        LogEvent("Memory allocation failed!");
        goto cleanup;
    }

    // Extract the event values
    if (EvtRender(hContext, hEvent, EvtRenderEventValues, dwBufferSize, pRenderedValues, &dwBufferUsed, &dwPropertyCount))
    {
        // Extract Event ID
        if (dwPropertyCount > 0 && pRenderedValues[0].Type == EvtVarTypeUInt16)
        {
            LogEvent("-[EventCallback] Event ID: ", pRenderedValues[0].UInt16Val);
            switch (pRenderedValues[0].UInt16Val)
            {
                case 42:
                case 506:
                    LogEvent("-[EventCallback] Entering standby / sleep / hibernation");
                    break;
                case 107:
                case 507:
                    LogEvent("-[EventCallback] Exiting standby / sleep / hibernation");
                    break;
            }
        }

        // Extract TimeCreated
        if (dwPropertyCount > 1 && pRenderedValues[1].Type == EvtVarTypeFileTime)
        {
            FILETIME ft;
            ft.dwLowDateTime = (DWORD)(pRenderedValues[1].FileTimeVal & 0xFFFFFFFF);
            ft.dwHighDateTime = (DWORD)(pRenderedValues[1].FileTimeVal >> 32);

            SYSTEMTIME utcTime, localTime;
            if (FileTimeToSystemTime(&ft, &utcTime))
            {
                // Convert UTC time to local time
                SystemTimeToTzSpecificLocalTime(NULL, &utcTime, &localTime);

                char timestamp[64];
                sprintf_s(timestamp, "-[EventCallback] TimeCreated: %04d-%02d-%02dT%02d:%02d:%02d.%03d",
                    localTime.wYear, localTime.wMonth, localTime.wDay,
                    localTime.wHour, localTime.wMinute, localTime.wSecond,
                    localTime.wMilliseconds);

                LogEvent(timestamp);
            }
        }
    }
    else
    {
        LogEvent("-[EventCallback] EvtRender failed with error:", GetLastError());
    }

cleanup:
    if (pRenderedValues) free(pRenderedValues);
    if (hContext) EvtClose(hContext);
}

DWORD WINAPI ServiceWorkerThread(LPVOID lpParam)
{
    EVT_HANDLE hSubscription = EvtSubscribe(
        NULL,
        NULL,
        L"System",
        L"*[System[Provider[@Name='Microsoft-Windows-Kernel-Power'] and ((EventID=42) or (EventID=107) or (EventID=506) or (EventID=507))]]",
        NULL,
        NULL,
        (EVT_SUBSCRIBE_CALLBACK)EventCallback,
        EvtSubscribeToFutureEvents
    );

    if (!hSubscription)
    {
        LogEvent("EvtSubscribe failed with error: ", GetLastError());
        return 1;
    }
    LogEvent("Monitoring System\\Microsoft-Windows-Kernel-Power for EventIDs 42, 107, 506, and 507");

    // Register a window class
    WNDCLASS wc = { 0 };
    wc.lpfnWndProc = HiddenWindowProc;
    wc.hInstance = GetModuleHandle(NULL);
    wc.lpszClassName = g_WindowClassName;

    if (!RegisterClass(&wc))
    {
        LogEvent("Failed to register window class.");
        return 1;
    }

    // Create a hidden window
    g_HiddenWindow = CreateWindow(
        g_WindowClassName,
        _T("Hidden Window"),
        0,
        0, 0, 0, 0,
        NULL, NULL, GetModuleHandle(NULL), NULL);

    if (!g_HiddenWindow)
    {
        LogEvent("Failed to create hidden window.");
        return 1;
    }

    LogEvent("Hidden window created successfully.");

    g_PowerNotify = RegisterSuspendResumeNotification(g_HiddenWindow, DEVICE_NOTIFY_WINDOW_HANDLE);

    if (g_PowerNotify == nullptr)
    {
		LogEvent("Failed to register suspend/resume notification: ", GetLastError());
        return -1;
    }

	g_PowerNotify2 = RegisterSuspendResumeNotification(
        DeviceNotifyCallbackRoutine,
		DEVICE_NOTIFY_CALLBACK
	);
    if (g_PowerNotify2 == nullptr)
    {
        LogEvent("Failed to register suspend/resume notification (CALLBACK): ", GetLastError());
        return -1;
    }

    g_PowerNotify3 = RegisterPowerSettingNotification(
        g_HiddenWindow,
        &GUID_CONSOLE_DISPLAY_STATE,
        DEVICE_NOTIFY_WINDOW_HANDLE
    );
    if (g_PowerNotify3 == nullptr) {
        LogEvent("Failed to register for GUID_CONSOLE_DISPLAY_STATE notifications: ", GetLastError());
    }

    MSG msg;
    BOOL bRet;

    while ((bRet = GetMessage(&msg, NULL, 0, 0)) != 0)
    {
        if (bRet == -1)
        {
            // handle the error and possibly exit
			LogEvent("Error in GetMessage.");
        }
        else
        {
            LogEvent("Message received.");
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }
    }
	LogEvent("Exiting worker thread.");

    EvtClose(hSubscription);
    if (g_PowerNotify)
    {
        UnregisterSuspendResumeNotification(g_PowerNotify);
        g_PowerNotify = NULL;
        LogEvent("Unregistered power notifications.");
    }
    if (g_PowerNotify2)
    {
		UnregisterSuspendResumeNotification(g_PowerNotify2);
		g_PowerNotify2 = NULL;
		LogEvent("Unregistered power notifications (CALLBACK).");
    }
    if (g_PowerNotify3)
    {
        UnregisterSuspendResumeNotification(g_PowerNotify3);
        g_PowerNotify3 = nullptr;
        LogEvent("Unregistered GUID_CONSOLE_DISPLAY_STATE notifications.");
    }


    return 0;
}

DWORD WINAPI ServiceControlHandler(
    DWORD ControlCode,
    DWORD EventType,
    PVOID EventData,
    PVOID Context
)
{
    DWORD win32status = NO_ERROR;

    switch (ControlCode)
    {
        case SERVICE_CONTROL_STOP:
            LogEvent("Service stopping.");
            ReportServiceStatus(SERVICE_STOP_PENDING, NO_ERROR, 0);

            SetEvent(g_ServiceStopEvent);

            if (logFile.is_open())
            {
                logFile.close();
            }

            ReportServiceStatus(SERVICE_STOPPED, NO_ERROR, 0);
            break;
        case SERVICE_CONTROL_POWEREVENT:
            LogEvent("[RegisterServiceCtrlHandlerEx] SERVICE_CONTROL_POWEREVENT received.");

            switch (EventType)
            {
                case PBT_APMQUERYSUSPEND:
                    LogEvent("-[RegisterServiceCtrlHandlerEx] PBT_APMQUERYSUSPEND: System is about to enter sleep mode.");
                    break;
                case PBT_APMSUSPEND:
                    LogEvent("-[RegisterServiceCtrlHandlerEx] PBT_APMSUSPEND: System is entering sleep mode.");
                    break;
                case PBT_APMRESUMESUSPEND:
                    LogEvent("-[RegisterServiceCtrlHandlerEx] PBT_APMRESUMESUSPEND: System has resumed from sleep mode.");
                    break;
                case PBT_APMBATTERYLOW:
                    LogEvent("-[RegisterServiceCtrlHandlerEx] PBT_APMBATTERYLOW: Battery is running low.");
                    break;
                case PBT_APMPOWERSTATUSCHANGE:
                    LogEvent("-[RegisterServiceCtrlHandlerEx] PBT_APMPOWERSTATUSCHANGE: Power status has changed.");
                    break;
                case PBT_APMOEMEVENT:
                    LogEvent("-[RegisterServiceCtrlHandlerEx] PBT_APMOEMEVENT: OEM-defined event occurred.");
                    break;
                case PBT_APMRESUMECRITICAL:
                    LogEvent("-[RegisterServiceCtrlHandlerEx] PBT_APMRESUMECRITICAL: System has resumed from a critical sleep mode.");
                    break;
                case PBT_APMRESUMEAUTOMATIC:
                    LogEvent("-[RegisterServiceCtrlHandlerEx] PBT_APMRESUMEAUTOMATIC: System has resumed automatically.");
                    break;
                case PBT_POWERSETTINGCHANGE:
                {
                    // This is the typical way of determining standby state
                    LogEvent("-[RegisterServiceCtrlHandlerEx] PBT_POWERSETTINGCHANGE: Power setting has changed.");
                    
                    POWERBROADCAST_SETTING* pSetting = static_cast<POWERBROADCAST_SETTING*>(EventData);
                    if (IsEqualGUID(pSetting->PowerSetting, GUID_CONSOLE_DISPLAY_STATE))
                    {
                        DWORD displayState = *reinterpret_cast<DWORD*>(pSetting->Data);
                        switch (displayState)
                        {
                        case 0:
                            LogEvent("-[RegisterServiceCtrlHandlerEx] PBT_POWERSETTINGCHANGE: Display Off");
                            break;
                        case 1:
                            LogEvent("-[RegisterServiceCtrlHandlerEx] PBT_POWERSETTINGCHANGE: Display On");
                            break;
                        case 2:
                            LogEvent("-[RegisterServiceCtrlHandlerEx] PBT_POWERSETTINGCHANGE: Display Dimmed");
                            break;
                        default:
                            LogEvent("-[RegisterServiceCtrlHandlerEx] PBT_POWERSETTINGCHANGE: Unknown display state.");
                            break;
                        }
                    }
                    break;
                }
                default:
                    LogEvent("-[RegisterServiceCtrlHandlerEx] Unknown power event.");
                    break;
            }
            break;
        case SERVICE_CONTROL_SESSIONCHANGE:
        {
            LogEvent("[RegisterServiceCtrlHandlerEx] SERVICE_CONTROL_SESSIONCHANGE received.");

            WTSSESSION_NOTIFICATION* pSessionNotification = static_cast<WTSSESSION_NOTIFICATION*>(EventData);
            LogEvent("-[RegisterServiceCtrlHandlerEx] Session ID: ", pSessionNotification->dwSessionId);

            switch (EventType)
            {
                case WTS_CONSOLE_CONNECT:
                    LogEvent("-[RegisterServiceCtrlHandlerEx] WTS_CONSOLE_CONNECT");
                    break;
                case WTS_CONSOLE_DISCONNECT:
                    LogEvent("-[RegisterServiceCtrlHandlerEx] WTS_CONSOLE_DISCONNECT");
                    break;
                case WTS_REMOTE_CONNECT:
                    LogEvent("-[RegisterServiceCtrlHandlerEx] WTS_REMOTE_CONNECT");
                    break;
                case WTS_REMOTE_DISCONNECT:
                    LogEvent("-[RegisterServiceCtrlHandlerEx] WTS_REMOTE_DISCONNECT");
                    break;
                case WTS_SESSION_LOGON:
                    LogEvent("-[RegisterServiceCtrlHandlerEx] WTS_SESSION_LOGON");
                    break;
                case WTS_SESSION_LOGOFF:
                    LogEvent("-[RegisterServiceCtrlHandlerEx] WTS_SESSION_LOGOFF");
                    break;
                case WTS_SESSION_LOCK:
                    LogEvent("-[RegisterServiceCtrlHandlerEx] WTS_SESSION_LOCK");
                    break;
                case WTS_SESSION_UNLOCK:
                    LogEvent("-[RegisterServiceCtrlHandlerEx] WTS_SESSION_UNLOCK");
                    break;
                case WTS_SESSION_REMOTE_CONTROL:
                    LogEvent("-[RegisterServiceCtrlHandlerEx] WTS_SESSION_REMOTE_CONTROL");
                    break;
                case WTS_SESSION_CREATE:
                    LogEvent("-[RegisterServiceCtrlHandlerEx] WTS_SESSION_CREATE");
                    break;
                case WTS_SESSION_TERMINATE:
                    LogEvent("-[RegisterServiceCtrlHandlerEx] WTS_SESSION_TERMINATE");
                    break;
            }
            break;
        }
        default:
            LogEvent("[RegisterServiceCtrlHandlerEx] Unknown ControlCode: ", ControlCode);
            win32status = ERROR_CALL_NOT_IMPLEMENTED;
            break;
    }

    return win32status;
}

void WINAPI ServiceMain(DWORD argc, LPTSTR* argv)
{
    g_StatusHandle = RegisterServiceCtrlHandlerEx(
        g_ServiceName,
        ServiceControlHandler,
        NULL
    );

    if (!g_StatusHandle)
    {
        return;
    }

    ReportServiceStatus(SERVICE_START_PENDING, NO_ERROR, 3000);

    g_ServiceStopEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (g_ServiceStopEvent == NULL)
    {
        ReportServiceStatus(SERVICE_STOPPED, NO_ERROR, 0);
        return;
    }

    LogEvent("Service started.");
    ReportServiceStatus(SERVICE_RUNNING, NO_ERROR, 0);

    HANDLE hThread = CreateThread(NULL, 0, ServiceWorkerThread, NULL, 0, NULL);
    if (!hThread)
    {
        CloseHandle(g_ServiceStopEvent);
		LogEvent("Unable to create worker thread.");
        ReportServiceStatus(SERVICE_STOPPED, NO_ERROR, 0);
        return;
    }

    WaitForSingleObject(g_ServiceStopEvent, INFINITE);

    PostMessage(g_HiddenWindow, WM_CLOSE, 0, 0);
    WaitForSingleObject(hThread, INFINITE);

    CloseHandle(g_ServiceStopEvent);
    CloseHandle(hThread);
    logFile.close();

    ReportServiceStatus(SERVICE_STOPPED, NO_ERROR, 0);
}

int main()
{
    LogEvent("Starting service...");

    SERVICE_TABLE_ENTRY ServiceTable[] = {
        { (LPWSTR)g_ServiceName, (LPSERVICE_MAIN_FUNCTION)ServiceMain },
        { NULL, NULL }
    };

    if (!StartServiceCtrlDispatcher(ServiceTable))
    {
        LogEvent("Failed to start service control dispatcher. Error: ", GetLastError());
        return GetLastError();
    }

    return 0;
}
