### EtwMonitor

This sample illustrates the use of ETW real-time tracing to monitor for Microsoft-Kernel-Power events to detect sleep / wake events. The sample has a hardcoded local EtwMonitor.log file, but also logs to console.

It mostly just merges samples from the pages below, with some extra work done to be real-time and filtered.


#### References:

- [Consuming Events (Event Tracing)](https://learn.microsoft.com/en-us/windows/win32/etw/consuming-events)
- [ETW Consumer sample](https://learn.microsoft.com/en-us/samples/microsoft/windows-classic-samples/etw-consumer-sample/)
- [Retrieving Event Metadata](https://learn.microsoft.com/en-us/windows/win32/etw/retrieving-event-metadata)
- [Using TdhFormatProperty to Consume Event Data](https://learn.microsoft.com/en-us/windows/win32/etw/using-tdhformatproperty-to-consume-event-data)
