/*
Sample for decoding ETW events using TdhFormatProperty.

This sample demonstrates the following:

- How to process events from ETL files using OpenTrace and ProcessTrace.
- How to get TRACE_EVENT_INFO data for an event using TdhGetEventInformation.
- How to format a WPP message using TdhGetProperty.
- How to extract property values from non-WPP events.
- How to format property values from non-WPP events using TdhFormatProperty.
*/

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN 1 // Exclude rarely-used APIs from <windows.h>
#endif

#include <windows.h>
#include <fstream>
#include <thread>

#define INITGUID // Ensure that EventTraceGuid is defined.
#include <evntrace.h>
#undef INITGUID

#include <tdh.h>
#include <vector>

#include <wchar.h> // wprintf
#include <cstdarg> // for va_list, va_start, etc.
#include <unordered_set>

#pragma comment(lib, "tdh.lib") // Link against TDH.dll

// Support building this sample using older versions of the Windows SDK:
#define EventNameOffset        ActivityIDNameOffset
#define EventAttributesOffset  RelatedActivityIDNameOffset

/* GUID of Microsoft-Windows-Kernel-Power
 * Name:                 Microsoft-Windows-Kernel-Power
 * Provider Guid:        {331C3B3A-2005-44C2-AC5E-77220C37D6B4}
 */

static const GUID ProviderGuid =
{ 0x331c3b3a, 0x2005, 0x44c2, {0xac, 0x5e, 0x77, 0x22, 0x0c, 0x37, 0xd6, 0xb4} };
static const GUID GUID_NULL =
{ 0x00000000, 0x0000, 0x0000, { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } };

static constexpr LPCWSTR SESSION_NAME = L"MyProviderSession";
std::wofstream g_LogFile("ETWEventMonitor.log", std::wios::app);
static TRACEHANDLE g_SessionHandle = 0;
static bool g_SessionCreated = false;
static bool g_Exit = false;
static bool g_isSleepEvent = false;

// Mutually exclusive. If include has items, skip will not be used.
static const std::unordered_set<USHORT> includeEventIds = {
    //179,
    //180,
    //536,
    //539,
    //561,
    564     // PowerAggregatorPdcSleepTransition, probably all you need really
};
static const std::unordered_set<USHORT> skipEventIds = {
    63,     // SystemTimeResolutionChange
    95,     // SystemTimeResolutionUpdate
    181,    // DeepSleepSetConstraint
    182,    // DeepSleepClearConstraint
    557     // SystemTimeResolutionKernelChangeInternal
};

void LogPrintf(const wchar_t* format, ...)
{
    va_list args;
    va_start(args, format);

    // Print to stdout
    vwprintf(format, args);
    fflush(stdout); // ensure it's flushed immediately

    // Print to g_LogFile
    if (g_LogFile.is_open()) {
        // Format into buffer first
        wchar_t buffer[2048];
        vswprintf_s(buffer, sizeof(buffer) / sizeof(wchar_t), format, args);
        g_LogFile << buffer;
        g_LogFile.flush(); // Optional, but good for real-time logs
    }

    va_end(args);
}

void PrintFileTime(FILETIME const& ft)
{
    SYSTEMTIME st = {};
    FileTimeToSystemTime(&ft, &st);
    LogPrintf(L"%04u-%02u-%02uT%02u:%02u:%02u.%03uZ",
        st.wYear,
        st.wMonth,
        st.wDay,
        st.wHour,
        st.wMinute,
        st.wSecond,
        st.wMilliseconds);
}

/*
Decodes event data using TdhGetEventInformation and TdhFormatProperty. Prints
the event information to stdout.

We use a context object so we can reuse buffers instead of allocating new
buffers and freeing them for each event.
*/
class DecoderContext
{
public:

    /*
    Initialize the decoder context.
    Sets up the TDH_CONTEXT array that will be used for decoding.
    */
    explicit DecoderContext()
    {
        TDH_CONTEXT* p = m_tdhContext;

        m_tdhContextCount = static_cast<BYTE>(p - m_tdhContext);
    }

    /*
    Decode and print the data for an event.
    Might throw an exception for out-of-memory conditions. Caller should catch
    the exception before returning from the ProcessTrace callback.
    */
    void PrintEventRecord(
        _In_ EVENT_RECORD* pEventRecord)
    {
        g_isSleepEvent = FALSE;

        if (pEventRecord->EventHeader.EventDescriptor.Opcode == EVENT_TRACE_TYPE_INFO &&
            pEventRecord->EventHeader.ProviderId == EventTraceGuid)
        {
            /*
            The first event in every ETL file contains the data from the file header.
            This is the same data as was returned in the EVENT_TRACE_LOGFILEW by
            OpenTrace. Since we've already seen this information, we'll skip this
            event.
            */
            return;
        }

        // Reset state to process a new event.
        m_indentLevel = 1;
        m_pEvent = pEventRecord;
        m_pbData = static_cast<BYTE const*>(m_pEvent->UserData);
        m_pbDataEnd = m_pbData + m_pEvent->UserDataLength;
        m_pointerSize =
            m_pEvent->EventHeader.Flags & EVENT_HEADER_FLAG_32_BIT_HEADER
            ? 4
            : m_pEvent->EventHeader.Flags & EVENT_HEADER_FLAG_64_BIT_HEADER
            ? 8
            : sizeof(void*); // Ambiguous, assume size of the decoder's pointer.

        // There is a lot of information available in the event even without decoding,
        // including timestamp, PID, TID, provider ID, activity ID, and the raw data.

        // Show the event timestamp.
        PrintFileTime(reinterpret_cast<FILETIME const&>(m_pEvent->EventHeader.TimeStamp));

        if (IsWppEvent())
        {
            PrintWppEvent();
        }
        else
        {
            PrintNonWppEvent();
        }
    }

private:

    /*
    Print the primary properties for a WPP event.
    */
    void PrintWppEvent()
    {
        /*
        TDH supports a set of known properties for WPP events:
        - "Version": UINT32 (usually 0)
        - "TraceGuid": GUID
        - "GuidName": UNICODESTRING (module name)
        - "GuidTypeName": UNICODESTRING (source file name and line number)
        - "ThreadId": UINT32
        - "SystemTime": SYSTEMTIME
        - "UserTime": UINT32
        - "KernelTime": UINT32
        - "SequenceNum": UINT32
        - "ProcessId": UINT32
        - "CpuNumber": UINT32
        - "Indent": UINT32
        - "FlagsName": UNICODESTRING
        - "LevelName": UNICODESTRING
        - "FunctionName": UNICODESTRING
        - "ComponentName": UNICODESTRING
        - "SubComponentName": UNICODESTRING
        - "FormattedString": UNICODESTRING
        - "RawSystemTime": FILETIME
        - "ProviderGuid": GUID (usually 0)
        */

        // Use TdhGetProperty to get the properties we need.
        wprintf(L" ");
        PrintWppStringProperty(L"GuidName"); // Module name (WPP's "CurrentDir" variable)
        wprintf(L" ");
        PrintWppStringProperty(L"GuidTypeName"); // Source code file name + line number
        wprintf(L" ");
        PrintWppStringProperty(L"FunctionName");
        wprintf(L"\n");
        PrintIndent();
        PrintWppStringProperty(L"FormattedString");
        wprintf(L"\n");
    }

    /*
    Print the value of the given UNICODESTRING property.
    */
    void PrintWppStringProperty(_In_z_ LPCWSTR szPropertyName)
    {
        PROPERTY_DATA_DESCRIPTOR pdd = { reinterpret_cast<UINT_PTR>(szPropertyName) };

        ULONG status;
        ULONG cb = 0;
        status = TdhGetPropertySize(
            m_pEvent,
            m_tdhContextCount,
            m_tdhContextCount ? m_tdhContext : nullptr,
            1,
            &pdd,
            &cb);
        if (status == ERROR_SUCCESS)
        {
            if (m_propertyBuffer.size() < cb / 2)
            {
                m_propertyBuffer.resize(cb / 2);
            }

            status = TdhGetProperty(
                m_pEvent,
                m_tdhContextCount,
                m_tdhContextCount ? m_tdhContext : nullptr,
                1,
                &pdd,
                cb,
                reinterpret_cast<BYTE*>(m_propertyBuffer.data()));
        }

        if (status != ERROR_SUCCESS)
        {
            wprintf(L"[TdhGetProperty(%ls) error %u]", szPropertyName, status);
        }
        else
        {
            // Print the FormattedString property data (nul-terminated
            // wchar_t string).
            wprintf(L"%ls", m_propertyBuffer.data());
        }
    }

    /*
    Use TdhGetEventInformation to obtain information about this event
    (including the names and types of the event's properties). Print some
    basic information about the event (provider name, event name), then print
    each property (using TdhFormatProperty to format each property value).
    */
    void PrintNonWppEvent()
    {
        ULONG status;
        ULONG cb;

        // Try to get event decoding information from TDH.
        cb = static_cast<ULONG>(m_teiBuffer.size());
        status = TdhGetEventInformation(
            m_pEvent,
            m_tdhContextCount,
            m_tdhContextCount ? m_tdhContext : nullptr,
            reinterpret_cast<TRACE_EVENT_INFO*>(m_teiBuffer.data()),
            &cb);
        if (status == ERROR_INSUFFICIENT_BUFFER)
        {
            m_teiBuffer.resize(cb);
            status = TdhGetEventInformation(
                m_pEvent,
                m_tdhContextCount,
                m_tdhContextCount ? m_tdhContext : nullptr,
                reinterpret_cast<TRACE_EVENT_INFO*>(m_teiBuffer.data()),
                &cb);
        }

        if (status != ERROR_SUCCESS)
        {
            // TdhGetEventInformation failed so there isn't a lot we can do.
            // The provider ID might be helpful in tracking down the right
            // manifest or TMF path.
            LogPrintf(L" ");
            PrintGuid(m_pEvent->EventHeader.ProviderId);
            LogPrintf(L"\n");
        }
        else
        {
            // TDH found decoding information. Print some basic info about the event,
            // then format the event contents.

            TRACE_EVENT_INFO const* const pTei =
                reinterpret_cast<TRACE_EVENT_INFO const*>(m_teiBuffer.data());

            if (pTei->ProviderNameOffset != 0)
            {
                // Event has a provider name -- show it.
                LogPrintf(L" %ls", TeiString(pTei->ProviderNameOffset));
            }
            else
            {
                // No provider name so print the provider ID.
                LogPrintf(L" ");
                PrintGuid(m_pEvent->EventHeader.ProviderId);
            }

            if (pTei->ProviderGuid != GUID_NULL)
            {
                LogPrintf(L" ");
                PrintGuid(pTei->ProviderGuid);
            }
            LogPrintf(L"\n");

            // Show core important event properties - try to show some kind of "event name".
            if (pTei->DecodingSource == DecodingSourceWbem ||
                pTei->DecodingSource == DecodingSourceWPP)
            {
                // OpcodeName is usually the best "event name" property for WBEM/WPP events.
                if (pTei->OpcodeNameOffset != 0)
                {
                    LogPrintf(L" %ls", TeiString(pTei->OpcodeNameOffset));
                }

                LogPrintf(L"\n");
            }
            else
            {
                LogPrintf(L"  Event ID: %hu\n", pTei->EventDescriptor.Id);

                if (pTei->EventNameOffset != 0)
                {
                    // Event has an EventName, so print it.
                    LogPrintf(L"  EventName: %ls", TeiString(pTei->EventNameOffset));
                }
                else if (pTei->TaskNameOffset != 0)
                {
                    // EventName is a recent addition, so not all events have it.
                    // Many events use TaskName as an event identifier, so print it if present.
                    LogPrintf(L"  TaskName: %ls", TeiString(pTei->TaskNameOffset));
                    //if (L"PowerAggregatorPdcSleepTransition" == TeiString(pTei->TaskNameOffset))
                    if (_wcsicmp(L"PowerAggregatorPdcSleepTransition", TeiString(pTei->TaskNameOffset)) == 0)
                    {
                        LogPrintf(L"  ***** Sleep / Wake Event *****");
                    }
                }

                LogPrintf(L"\n");

                // Show EventAttributes if available.
                if (pTei->EventAttributesOffset != 0)
                {
                    PrintIndent();
                    LogPrintf(L"EventAttributes: %ls\n", TeiString(pTei->EventAttributesOffset));
                }
            }

            if (IsStringEvent())
            {
                // The event was written using EventWriteString.
                // We'll handle it later.
            }
            else
            {
                // The event is a MOF, manifest, or TraceLogging event.

                // To help resolve PropertyParamCount and PropertyParamLength,
                // we will record the values of all integer properties as we
                // reach them. Before we start, clear out any old values and
                // resize the vector with room for the new values.
                m_integerValues.clear();
                m_integerValues.resize(pTei->PropertyCount);

                // Recursively print the event's properties.
                PrintProperties(0, pTei->TopLevelPropertyCount);
            }
        }

        if (IsStringEvent())
        {
            // The event was written using EventWriteString.
            // We can print it whether or not we have decoding information.
            LPCWSTR pchData = static_cast<LPCWSTR>(m_pEvent->UserData);
            unsigned cchData = m_pEvent->UserDataLength / 2;
            PrintIndent();

            // It's probably nul-terminated, but just in case, limit to cchData chars.
            LogPrintf(L"%.*ls\n", cchData, pchData);
            //if (pchData == L"IsSleepEnter")
            if (_wcsicmp(L"IsSleepEnter", pchData) == 0)
            {
                LogPrintf(L"  ***** Sleep Enter / Exit *****");
            }
        }
    }

    /*
    Prints out the values of properties from begin..end.
    Called by PrintEventRecord for the top-level properties.
    If there are structures, this will be called recursively for the child
    properties.
    */
    void PrintProperties(unsigned propBegin, unsigned propEnd)
    {
        TRACE_EVENT_INFO const* const pTei =
            reinterpret_cast<TRACE_EVENT_INFO const*>(m_teiBuffer.data());

        for (unsigned propIndex = propBegin; propIndex != propEnd; propIndex += 1)
        {
            EVENT_PROPERTY_INFO const& epi = pTei->EventPropertyInfoArray[propIndex];

            // If this property is a scalar integer, remember the value in case it
            // is needed for a subsequent property's length or count.
            if (0 == (epi.Flags & (PropertyStruct | PropertyParamCount)) &&
                epi.count == 1)
            {
                switch (epi.nonStructType.InType)
                {
                case TDH_INTYPE_INT8:
                case TDH_INTYPE_UINT8:
                    if ((m_pbDataEnd - m_pbData) >= 1)
                    {
                        m_integerValues[propIndex] = *m_pbData;
                    }
                    break;
                case TDH_INTYPE_INT16:
                case TDH_INTYPE_UINT16:
                    if ((m_pbDataEnd - m_pbData) >= 2)
                    {
                        m_integerValues[propIndex] = *reinterpret_cast<UINT16 const UNALIGNED*>(m_pbData);
                    }
                    break;
                case TDH_INTYPE_INT32:
                case TDH_INTYPE_UINT32:
                case TDH_INTYPE_HEXINT32:
                    if ((m_pbDataEnd - m_pbData) >= 4)
                    {
                        auto val = *reinterpret_cast<UINT32 const UNALIGNED*>(m_pbData);
                        m_integerValues[propIndex] = static_cast<USHORT>(val > 0xffffu ? 0xffffu : val);
                    }
                    break;
                }
            }

            PrintIndent();

            // Print the property's name.
            LogPrintf(L"%ls:", epi.NameOffset ? TeiString(epi.NameOffset) : L"(noname)");

            if (_wcsicmp(L"IsSleepEnter", TeiString(epi.NameOffset)) == 0)
            {
                g_isSleepEvent = TRUE;
            }

            m_indentLevel += 1;

            // We recorded the values of all previous integer properties just
            // in case we need to determine the property length or count.
            USHORT const propLength =
                epi.nonStructType.OutType == TDH_OUTTYPE_IPV6 &&
                epi.nonStructType.InType == TDH_INTYPE_BINARY &&
                epi.length == 0 &&
                (epi.Flags & (PropertyParamLength | PropertyParamFixedLength)) == 0
                ? 16 // special case for incorrectly-defined IPV6 addresses
                : (epi.Flags & PropertyParamLength)
                ? m_integerValues[epi.lengthPropertyIndex] // Look up the value of a previous property
                : epi.length;
            USHORT const arrayCount =
                (epi.Flags & PropertyParamCount)
                ? m_integerValues[epi.countPropertyIndex] // Look up the value of a previous property
                : epi.count;

            // Note that PropertyParamFixedCount is a new flag and is ignored
            // by many decoders. Without the PropertyParamFixedCount flag,
            // decoders will assume that a property is an array if it has
            // either a count parameter or a fixed count other than 1. The
            // PropertyParamFixedCount flag allows for fixed-count arrays with
            // one element to be propertly decoded as arrays.
            bool isArray =
                1 != arrayCount ||
                0 != (epi.Flags & (PropertyParamCount | PropertyParamFixedCount));
            if (isArray)
            {
                LogPrintf(L" Array[%u]\n", arrayCount);
            }

            PEVENT_MAP_INFO pMapInfo = nullptr;

            // Treat non-array properties as arrays with one element.
            for (unsigned arrayIndex = 0; arrayIndex != arrayCount; arrayIndex += 1)
            {
                if (isArray)
                {
                    // Print a name for the array element.
                    PrintIndent();
                    LogPrintf(L"%ls[%lu]:",
                        epi.NameOffset ? TeiString(epi.NameOffset) : L"(noname)",
                        arrayIndex);
                }

                if (epi.Flags & PropertyStruct)
                {
                    // If this property is a struct, recurse and print the child
                    // properties.
                    LogPrintf(L"\n");
                    PrintProperties(
                        epi.structType.StructStartIndex,
                        epi.structType.StructStartIndex + epi.structType.NumOfStructMembers);
                    continue;
                }

                // If the property has an associated map (i.e. an enumerated type),
                // try to look up the map data. (If this is an array, we only need
                // to do the lookup on the first iteration.)
                if (epi.nonStructType.MapNameOffset != 0 && arrayIndex == 0)
                {
                    switch (epi.nonStructType.InType)
                    {
                    case TDH_INTYPE_UINT8:
                    case TDH_INTYPE_UINT16:
                    case TDH_INTYPE_UINT32:
                    case TDH_INTYPE_HEXINT32:
                        if (m_mapBuffer.size() == 0)
                        {
                            m_mapBuffer.resize(sizeof(EVENT_MAP_INFO));
                        }

                        for (;;)
                        {
                            ULONG cbBuffer = static_cast<ULONG>(m_mapBuffer.size());
                            ULONG status = TdhGetEventMapInformation(
                                m_pEvent,
                                const_cast<LPWSTR>(TeiString(epi.nonStructType.MapNameOffset)),
                                reinterpret_cast<PEVENT_MAP_INFO>(m_mapBuffer.data()),
                                &cbBuffer);

                            if (status == ERROR_INSUFFICIENT_BUFFER &&
                                m_mapBuffer.size() < cbBuffer)
                            {
                                m_mapBuffer.resize(cbBuffer);
                                continue;
                            }
                            else if (status == ERROR_SUCCESS)
                            {
                                pMapInfo = reinterpret_cast<PEVENT_MAP_INFO>(m_mapBuffer.data());
                            }

                            break;
                        }
                        break;
                    }
                }

                bool useMap = pMapInfo != nullptr;

                // Loop because we may need to retry the call to TdhFormatProperty.
                for (;;)
                {
                    ULONG cbBuffer = static_cast<ULONG>(m_propertyBuffer.size() * 2);
                    USHORT cbUsed = 0;
                    ULONG status;

                    if (0 == propLength &&
                        epi.nonStructType.InType == TDH_INTYPE_NULL)
                    {
                        // TdhFormatProperty doesn't handle INTYPE_NULL.
                        if (m_propertyBuffer.empty())
                        {
                            m_propertyBuffer.push_back(0);
                        }
                        m_propertyBuffer[0] = 0;
                        status = ERROR_SUCCESS;
                    }
                    else if (
                        0 == propLength &&
                        0 != (epi.Flags & (PropertyParamLength | PropertyParamFixedLength)) &&
                        (epi.nonStructType.InType == TDH_INTYPE_UNICODESTRING ||
                            epi.nonStructType.InType == TDH_INTYPE_ANSISTRING))
                    {
                        // TdhFormatProperty doesn't handle zero-length counted strings.
                        if (m_propertyBuffer.empty())
                        {
                            m_propertyBuffer.push_back(0);
                        }
                        m_propertyBuffer[0] = 0;
                        status = ERROR_SUCCESS;
                    }
                    else
                    {
                        status = TdhFormatProperty(
                            const_cast<TRACE_EVENT_INFO*>(pTei),
                            useMap ? pMapInfo : nullptr,
                            m_pointerSize,
                            epi.nonStructType.InType,
                            static_cast<USHORT>(
                                epi.nonStructType.OutType == TDH_OUTTYPE_NOPRINT
                                ? TDH_OUTTYPE_NULL
                                : epi.nonStructType.OutType),
                            propLength,
                            static_cast<USHORT>(m_pbDataEnd - m_pbData),
                            const_cast<PBYTE>(m_pbData),
                            &cbBuffer,
                            m_propertyBuffer.data(),
                            &cbUsed);

                        if (cbUsed > 0 && g_isSleepEvent)
                        {
                            std::wstring cleanStrValue(m_propertyBuffer.data()); // safely constructs up to the first \0

                            if (_wcsicmp(L"true", cleanStrValue.c_str()) == 0)
                            {
                                LogPrintf(L"  ***** Going to sleep *****");
                            }
                            else
                            {
                                LogPrintf(L"  ***** Waking from sleep *****");
                            }
                            g_isSleepEvent = FALSE;
                        }
                    }

                    if (status == ERROR_INSUFFICIENT_BUFFER &&
                        m_propertyBuffer.size() < cbBuffer / 2)
                    {
                        // Try again with a bigger buffer.
                        m_propertyBuffer.resize(cbBuffer / 2);
                        continue;
                    }
                    else if (status == ERROR_EVT_INVALID_EVENT_DATA && useMap)
                    {
                        // If the value isn't in the map, TdhFormatProperty treats it
                        // as an error instead of just putting the number in. We'll
                        // try again with no map.
                        useMap = false;
                        continue;
                    }
                    else if (status != ERROR_SUCCESS)
                    {
                        LogPrintf(L" [ERROR:TdhFormatProperty:%lu]\n", status);
                    }
                    else
                    {
                        LogPrintf(L" %ls\n", m_propertyBuffer.data());
                        m_pbData += cbUsed;
                    }

                    break;
                }
            }

            m_indentLevel -= 1;
        }
    }

    void PrintGuid(GUID const& g)
    {
        LogPrintf(L"{%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x}",
            g.Data1, g.Data2, g.Data3, g.Data4[0], g.Data4[1], g.Data4[2],
            g.Data4[3], g.Data4[4], g.Data4[5], g.Data4[6], g.Data4[7]);
    }

    void PrintIndent()
    {
        LogPrintf(L"%*ls", m_indentLevel * 2, L"");
    }

    /*
    Returns true if the current event has the EVENT_HEADER_FLAG_STRING_ONLY
    flag set.
    */
    bool IsStringEvent() const
    {
        return (m_pEvent->EventHeader.Flags & EVENT_HEADER_FLAG_STRING_ONLY) != 0;
    }

    /*
    Returns true if the current event has the EVENT_HEADER_FLAG_TRACE_MESSAGE
    flag set.
    */
    bool IsWppEvent() const
    {
        return (m_pEvent->EventHeader.Flags & EVENT_HEADER_FLAG_TRACE_MESSAGE) != 0;
    }

    /*
    Converts a TRACE_EVENT_INFO offset (e.g. TaskNameOffset) into a string.
    */
    _Ret_z_ LPCWSTR TeiString(unsigned offset)
    {
        return reinterpret_cast<LPCWSTR>(m_teiBuffer.data() + offset);
    }

private:

    TDH_CONTEXT m_tdhContext[1]; // May contain TDH_CONTEXT_WPP_TMFSEARCHPATH.
    BYTE m_tdhContextCount;  // 1 if a TMF search path is present.
    BYTE m_pointerSize;
    BYTE m_indentLevel;      // How far to indent the output.
    EVENT_RECORD* m_pEvent;      // The event we're currently printing.
    BYTE const* m_pbData;        // Position of the next byte of event data to be consumed.
    BYTE const* m_pbDataEnd;     // Position of the end of the event data.
    std::vector<USHORT> m_integerValues; // Stored property values for resolving array lengths.
    std::vector<BYTE> m_teiBuffer; // Buffer for TRACE_EVENT_INFO data.
    std::vector<wchar_t> m_propertyBuffer; // Buffer for the string returned by TdhFormatProperty.
    std::vector<BYTE> m_mapBuffer; // Buffer for the data returned by TdhGetEventMapInformation.
};

/*
Helper class to automatically close TRACEHANDLEs.
*/
class TraceHandles
{
public:

    ~TraceHandles()
    {
        CloseHandles();
    }

    void CloseHandles()
    {
        while (!handles.empty())
        {
            CloseTrace(handles.back());
            handles.pop_back();
        }
    }

    ULONG OpenTraceW(
        _Inout_ EVENT_TRACE_LOGFILEW* pLogFile)
    {
        ULONG status;

        handles.reserve(handles.size() + 1);
        TRACEHANDLE handle = ::OpenTraceW(pLogFile);
        if (handle == INVALID_PROCESSTRACE_HANDLE)
        {
            status = GetLastError();
        }
        else
        {
            handles.push_back(handle);
            status = 0;
        }

        return status;
    }

    ULONG ProcessTrace(
        _In_opt_ LPFILETIME pStartTime,
        _In_opt_ LPFILETIME pEndTime)
    {
        return ::ProcessTrace(
            handles.data(),
            static_cast<ULONG>(handles.size()),
            pStartTime,
            pEndTime);
    }

private:

    std::vector<TRACEHANDLE> handles;
};

// Console Ctrl+C handler: stops the session
BOOL WINAPI ConsoleHandler(DWORD ctrlType)
{
    if (ctrlType == CTRL_C_EVENT || ctrlType == CTRL_CLOSE_EVENT)
    {
        g_Exit = true;
        // Close log file
        if (g_LogFile.is_open()) g_LogFile.close();

        // Build minimal properties struct to stop by name
        size_t nameBytes = (wcslen(SESSION_NAME) + 1) * sizeof(WCHAR);
        ULONG bufSize = sizeof(EVENT_TRACE_PROPERTIES) + (ULONG)nameBytes;
        auto props = (EVENT_TRACE_PROPERTIES*)malloc(bufSize);
        ZeroMemory(props, bufSize);
        props->Wnode.BufferSize = bufSize;
        props->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
        // copy session name just past the struct
        wcscpy_s((WCHAR*)((BYTE*)props + props->LoggerNameOffset), wcslen(SESSION_NAME) + 1, SESSION_NAME);

        ULONG status = ControlTrace(
            g_SessionHandle,
            SESSION_NAME,
            props,
            EVENT_TRACE_CONTROL_STOP
        );
        if (status != ERROR_SUCCESS)
            wprintf(L"\nERROR: ControlTrace(stop) failed: %hs\n", status);
        else
            wprintf(L"Session stopped.\n");

        free(props);
        return TRUE;
    }
    return FALSE;
}

/*
This function will be used as the EventRecordCallback function in EVENT_TRACE_LOGFILE.
It expects that the EVENT_TRACE_LOGFILE's Context pointer is set to a DecoderContext.
*/
static void WINAPI EventRecordCallback(
    _In_ EVENT_RECORD* pEventRecord)
{
    // Only handle events from our provider
    if (!IsEqualGUID(pEventRecord->EventHeader.ProviderId, ProviderGuid))
        return;

    // Filters
    const auto& h = pEventRecord->EventHeader;
    if ((h.Flags & EVENT_HEADER_FLAG_TRACE_MESSAGE) != 0 ||
        (!includeEventIds.empty() && !includeEventIds.count(h.EventDescriptor.Id)) ||
        (includeEventIds.empty() && skipEventIds.count(h.EventDescriptor.Id)))
        return;

    try
    {
        // We expect that the EVENT_TRACE_LOGFILE.Context pointer was set with a
        // pointer to a DecoderContext. ProcessTrace will put the Context value
        // into EVENT_RECORD.UserContext.
        DecoderContext* pContext = static_cast<DecoderContext*>(pEventRecord->UserContext);

        // The actual decoding work is done in PrintEventRecord.
        pContext->PrintEventRecord(pEventRecord);
    }
    catch (std::exception const& ex)
    {
        LogPrintf(L"\nERROR: %hs\n", ex.what());
    }
}

// Launches the real-time consumer; blocks until session stops
void TraceConsumer()
{
    ULONG status;
    try
    {
        DecoderContext context;
        TraceHandles handles;

        EVENT_TRACE_LOGFILEW trace = {};
        trace.LoggerName = (LPWSTR)SESSION_NAME;
        trace.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME
            | PROCESS_TRACE_MODE_EVENT_RECORD;
        trace.EventRecordCallback = EventRecordCallback;
        trace.Context = &context;

        status = handles.OpenTraceW(&trace);
        if (status != 0)
        {
            LogPrintf(L"ERROR: OpenTraceW error %u for LoggerName: %ls\n",
                status,
                SESSION_NAME);
            return;
        }

        LogPrintf(L"Opened: %ls\n", trace.LoggerName);

        status = handles.ProcessTrace(nullptr, nullptr);
        if (status != 0)
        {
            LogPrintf(L"ERROR: ProcessTrace error %u\n",
                status);
            return;
        }
    }
    catch (std::exception const& ex)
    {
        LogPrintf(L"\nERROR: %hs\n", ex.what());
    }
}

int __cdecl wmain(int argc, _In_count_(argc) LPWSTR argv[])
{
    // Open log file
    //g_LogFile.open("etw_events.log", std::ios::out);
    if (!g_LogFile.is_open()) {
        wprintf(L"Failed to open log file.\n");
        return 1;
    }

    LogPrintf(L"\r\n********** ");
    FILETIME ftNow;
    GetSystemTimeAsFileTime(&ftNow);
    PrintFileTime(ftNow);
    LogPrintf(L" **********\r\n");

    // Ensure we catch Ctrl+C
    SetConsoleCtrlHandler(ConsoleHandler, TRUE);

    // Allocate and initialize properties (real-time, no logfile)
    size_t nameBytes = (wcslen(SESSION_NAME) + 1) * sizeof(WCHAR);
    ULONG bufSize = sizeof(EVENT_TRACE_PROPERTIES) + (ULONG)nameBytes;
    auto props = (EVENT_TRACE_PROPERTIES*)malloc(bufSize);
    ZeroMemory(props, bufSize);
    props->Wnode.BufferSize = bufSize;
    props->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    props->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
    props->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
    wcscpy_s((WCHAR*)((BYTE*)props + props->LoggerNameOffset),
        wcslen(SESSION_NAME) + 1,
        SESSION_NAME);

    // Start or join the session
    ULONG status = StartTraceW(
        &g_SessionHandle,
        SESSION_NAME,
        props
    );

    if (status == ERROR_ALREADY_EXISTS) {
        g_SessionCreated = false;
        LogPrintf(L"Session already existed; Recreating...\n");

        status = ControlTrace(
            0,
            SESSION_NAME,
            props,
            EVENT_TRACE_CONTROL_STOP
        );
        if (status != ERROR_SUCCESS) {
            LogPrintf(L"Unable to stop session: %hs\n", status);
            return 1;
        }

        Sleep(100);

        // Start or join the session
        ULONG status = StartTraceW(
            &g_SessionHandle,
            SESSION_NAME,
            props
        );
    }

    if (status == ERROR_SUCCESS) {
        g_SessionCreated = true;
        LogPrintf(L"Session created.\n");
    }
    else {
        LogPrintf(L"StartTrace failed: %hs\n", status);
        free(props);
        return 1;
    }

    // If new, enable your provider
    if (g_SessionCreated) {
        status = EnableTraceEx2(
            g_SessionHandle,
            &ProviderGuid,
            EVENT_CONTROL_CODE_ENABLE_PROVIDER,
            TRACE_LEVEL_VERBOSE,
            0x4ULL,            // MatchAnyKeyword
            0,            // MatchAllKeyword
            0,            // Timeout
            nullptr       // EnableParameters
        );
        if (status != ERROR_SUCCESS) {
            LogPrintf(L"EnableTraceEx2 failed: %hs\n", status);
            // stop if failed
            ControlTrace(g_SessionHandle, SESSION_NAME, props, EVENT_TRACE_CONTROL_STOP);
            free(props);
            return 1;
        }
    }

    free(props);

    // Start the consumer thread
    std::thread consumer(TraceConsumer);

    // Wait for Ctrl+C
    while (!g_Exit) Sleep(100);

    // Wait for consumer to exit
    consumer.join();
    return 0;
}