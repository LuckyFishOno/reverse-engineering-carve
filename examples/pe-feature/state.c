/* Owned data/state fixture: session-local counter and source-backed settings. */
#pragma section(".carvec", read)
#pragma section(".carves", read, write)
struct Settings { unsigned rates[3]; char label[8]; };
__declspec(allocate(".carvec")) const volatile struct Settings settings = {{2u, 5u, 9u}, "counter"};
/* RT_STRING block63: nine empty values, string1001="ready", six empty values. */
__declspec(allocate(".carvec")) const volatile unsigned short resource_strings[21] = {0,0,0,0,0,0,0,0,0,5,'r','e','a','d','y',0,0,0,0,0,0};
__declspec(allocate(".carves")) volatile unsigned counter = 7u;

__declspec(noinline) int state_command(int operation, int value) {
    if (operation == 0) { counter = 0; return 0; }
    if (operation == 1) {
        if (value < 0) return -2;
        counter += (unsigned)value * settings.rates[(unsigned)value % 3u];
        return (int)counter;
    }
    if (operation == 2) return (int)counter;
    if (operation == 3) return (unsigned char)settings.label[(unsigned)value & 7u];
    if (operation == 4) return resource_strings[10u + (unsigned)value % 5u];
    return -1;
}
