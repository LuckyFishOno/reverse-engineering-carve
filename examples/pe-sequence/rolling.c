// Owned freestanding CRC session fixture, not a third-party implementation claim.
#pragma section(".carves", read, write)
struct Session { unsigned table[256]; unsigned state; };
__declspec(allocate(".carves")) volatile struct Session session = {{0}, 7};
__declspec(noinline) void session_init(unsigned seed) {
    for (unsigned i=0; i<256; ++i) {
        unsigned value=i;
        for (unsigned bit=0; bit<8; ++bit)
            value=(value>>1)^((value&1)?0xedb88320u:0);
        session.table[i]=value;
    }
    session.state=seed;
}
__declspec(noinline) unsigned session_byte(unsigned state, unsigned byte) {
    return (state>>8)^session.table[(state^byte)&255];
}
__declspec(noinline) unsigned session_update(const unsigned char *data, unsigned long long length) {
    unsigned value=session.state;
    for (unsigned long long i=0; i<length; ++i) value=session_byte(value,data[i]);
    session.state=value;
    return value;
}
// Bounded output transform consumes only bytes that fit in the output capacity.
__declspec(noinline) unsigned session_transform(const unsigned char *data, unsigned long long length, unsigned char *target, unsigned capacity) {
    unsigned count=length<capacity?(unsigned)length:capacity;
    unsigned value=session.state;
    for (unsigned i=0; i<count; ++i) {
        target[i]=(unsigned char)(data[i]^(value&255));
        value=session_byte(value,data[i]);
    }
    session.state=value;
    return count;
}
// Initialized caller bytes can be read and modified in place; the suffix is preserved.
__declspec(noinline) unsigned session_inplace(unsigned char *target, unsigned long long length, unsigned limit) {
    unsigned count=length<limit?(unsigned)length:limit;
    unsigned value=session.state;
    for (unsigned i=0; i<count; ++i) {
        unsigned byte=target[i];
        target[i]=(unsigned char)(byte^(value&255));
        value=session_byte(value,byte);
    }
    session.state=value;
    return count;
}
