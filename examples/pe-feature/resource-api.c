/* Static-analysis probe only. This example never executes a Windows resource API. */
__declspec(dllimport) int __stdcall LoadStringW(void *module, unsigned id, unsigned short *buffer, int capacity);
__declspec(noinline) int resource_api_probe(void *module) {
    const unsigned short *text;
    return LoadStringW(module, 1001u, (unsigned short *)&text, 0);
}
