/* Owned freestanding Windows x64 function fixture; no original UI execution claim. */
__declspec(dllimport) unsigned unit_rate(int member);

__declspec(noinline) unsigned billing_blocks(unsigned minutes) {
    return (minutes + 14u) / 15u;
}

__declspec(noinline) int quote_command(int minutes, int member) {
    if (minutes < 0) return -1;
    if (minutes <= 15) return 0;
    unsigned blocks = billing_blocks((unsigned)minutes);
    unsigned amount = blocks * unit_rate(member);
    return amount > 300u ? 300 : (int)amount;
}
