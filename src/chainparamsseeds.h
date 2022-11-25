#ifndef BITCOIN_CHAINPARAMSSEEDS_H
#define BITCOIN_CHAINPARAMSSEEDS_H
/**
 * List of fixed seed nodes for the bitcoin network
 * AUTOGENERATED by contrib/seeds/generate-seeds.py
 *
 * Each line contains a BIP155 serialized (networkID, addr, port) tuple.
 */
static const uint8_t chainparams_seed_main[] = {
    0x01,0x04,0x3f,0x8d,0xf0,0x9b,0x26,0x19,
    0x01,0x04,0x3f,0x8d,0xf0,0x9c,0x26,0x19,
    0x01,0x04,0x3f,0x8d,0xf0,0x9d,0x26,0x19,
};

static const uint8_t chainparams_seed_test[] = {
    0x01,0x04,0x8e,0x36,0xbd,0x4d,0x49,0xc8,
    0x01,0x04,0x8e,0x36,0xbd,0x4e,0x49,0xc8,
};
#endif // BITCOIN_CHAINPARAMSSEEDS_H