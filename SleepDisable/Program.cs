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
            Console.WriteLine($"Active power scheme GUID: {activeSchemeGuid}");

            // Read the Sleep Button Action value for AC power
            uint acValue;
            uint result = PowerReadACValueIndex(
                IntPtr.Zero,
                ref activeSchemeGuid,
                ref GUID_SYSTEM_BUTTON_SUBGROUP,
                ref GUID_SLEEP_BUTTON_ACTION,
                out acValue
            );

            if (result != 0)
            {
                Console.WriteLine($"Error reading Sleep Button Action: {result}");
                return;
            }

            // Interpret the value
            string action = InterpretSleepButtonAction(acValue);
            Console.WriteLine($"Sleep Button Action (AC): {action}");

            // Set the sleep button action for "Plugged in" to "Do nothing" (value 0)
            Console.WriteLine("Updating 'Plugged in' Sleep button action to 'Do nothing' (0)...");
            result = PowerWriteACValueIndex(
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

        // Helper method to interpret the action index
        // Note that these line up with the Settings app values, not the Control Panel
        static string InterpretSleepButtonAction(uint value)
        {
            return value switch
            {
                0 => "Do nothing",
                1 => "Sleep",
                2 => "Hibernate",
                3 => "Shut down",
                4 => "Turn off the Display",
                _ => "Unknown"
            };
        }
    }
}
