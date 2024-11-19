namespace SleepDisable
{
    using System;
    using System.Runtime.InteropServices;
    using static SleepDisable.NativeHelper;

    internal class Program
    {
        static void Main(string[] args)
        {
            // Get the active power scheme GUID
            Guid activeSchemeGuid = GetActivePowerScheme();

            // Set the sleep button action for "Plugged in" to "Do nothing" (value 0)
            Console.WriteLine("Updating 'Plugged in' Sleep button action to 'Do nothing' (0)...");
            uint result = PowerWriteACValueIndex(
                IntPtr.Zero,
                ref activeSchemeGuid,
                ref GUID_SYSTEM_BUTTON_SUBGROUP,
                ref GUID_SLEEP_BUTTON_ACTION,
                (uint)SleepButtonSettings.DoNothing);

            if (result != 0)
            {
                Console.WriteLine($"Failed to update setting. Error code: {result}");
                return;
            }

            // Apply the changes by calling PowerSetActiveScheme
            result = PowerSetActiveScheme(IntPtr.Zero, ref activeSchemeGuid);
            if (result != 0)
            {
                Console.WriteLine($"Failed to apply updated power scheme. Error code: {result}");
                return;
            }

            Console.WriteLine("Successfully updated and applied the 'Plugged in' Sleep button action.");
        }

        static Guid GetActivePowerScheme()
        {
            IntPtr activePolicyGuidPtr = IntPtr.Zero;

            try
            {
                // Call PowerGetActiveScheme to retrieve the GUID of the active power scheme
                uint result = PowerGetActiveScheme(IntPtr.Zero, out activePolicyGuidPtr);

                if (result != 0)
                {
                    throw new Exception($"Failed to get active power scheme. Error code: {result}");
                }

                // Marshal the GUID from the pointer
                Guid activePolicyGuid = Marshal.PtrToStructure<Guid>(activePolicyGuidPtr);
                return activePolicyGuid;
            }
            finally
            {
                // Free the memory allocated by PowerGetActiveScheme
                if (activePolicyGuidPtr != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(activePolicyGuidPtr);
                }
            }
        }
    }

}
