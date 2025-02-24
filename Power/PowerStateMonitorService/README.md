PowerStateMonitorService is a sample to log and track sleep/wake events using various methods.

#### Installation:
From an administrative command prompt, install the service with:
  sc create PowerStateMonitorService binPath= C:\PowerStateMonitorService\PowerStateMonitorService.exe

#### Uninstall:
From an administrative command prompt, delete the service with:
  sc delete PowerStateMonitorService

The service will log to C:\PowerStateMonitorService\PowerStateMonitorService.log. The path is hard-coded, but you can of course change it to whatever meets your needs.

When running, the service will try to log sleep/wake events using 4 methods:
- Register for power events with RegisterServiceCtrlHandlerEx, listening for SERVICE_CONTROL_POWEREVENT codes
- Subscribe to System\Microsoft-Windows-Kernel-Power event IDs 42 and 506 (Sleep), and 107 and 507 (Wake) with EvtSubscribe
- Create a new hidden window, and register it for power events with RegisterSuspendResumeNotification(hWnd, DEVICE_NOTIFY_WINDOW_HANDLE)
- Register for power events with RegisterSuspendResumeNotification(DeviceNotifyCallbackRoutine, DEVICE_NOTIFY_CALLBACK)
- Register for power setting events with RegisterPowerSettingNotification(hWnd, &GUID_CONSOLE_DISPLAY_STATE, DEVICE_NOTIFY_WINDOW_HANDLE)
