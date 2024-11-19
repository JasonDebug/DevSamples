namespace SleepDisable
{
    using System.Runtime.InteropServices;

    internal class NativeHelper
    {
        // GUID for the Sleep button action
        // https://learn.microsoft.com/en-us/windows-hardware/customize/power-settings/power-button-and-lid-settings-sleep-button-action
        internal static Guid GUID_SLEEP_BUTTON_ACTION = new Guid("96996bc0-ad50-47ec-923b-6f41874dd9eb");

        // Settings in this subgroup control configuration of the system power buttons.
        internal static Guid GUID_SYSTEM_BUTTON_SUBGROUP = new Guid("4f971e89-eebd-4455-a8de-9e59040e7347");

        internal enum SleepButtonSettings : uint
        {
            DoNothing = 0,
            Sleep = 1,
            Hibernate = 2,
            Shutdown = 3
        }

        // Import PowerGetActiveScheme from powrprof.dll
        // https://learn.microsoft.com/en-us/windows/win32/api/powersetting/nf-powersetting-powergetactivescheme
        [DllImport("powrprof.dll", SetLastError = true)]
        public static extern uint PowerGetActiveScheme(
            IntPtr UserRootPowerKey,
            out IntPtr ActivePolicyGuid
        );

        // Import PowerSetActiveScheme from powrprof.dll
        // https://learn.microsoft.com/en-us/windows/win32/api/powersetting/nf-powersetting-powersetactivescheme
        [DllImport("powrprof.dll", SetLastError = true)]
        public static extern uint PowerSetActiveScheme(
            IntPtr RootPowerKey,
            ref Guid SchemeGuid
        );

        // Import PowerWriteACValueIndex from powrprof.dll
        // https://learn.microsoft.com/en-us/windows/win32/api/powersetting/nf-powersetting-powerwriteacvalueindex
        [DllImport("powrprof.dll", SetLastError = true)]
        public static extern uint PowerWriteACValueIndex(
            IntPtr rootPowerKey,
            ref Guid schemeGuid,
            ref Guid subgroupOfPowerSettingsGuid,
            ref Guid powerSettingGuid,
            uint acValueIndex
        );
    }
}
