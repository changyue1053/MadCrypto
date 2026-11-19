import MadCrypto

// Calls only the unmodified public ABI in the installed binary.
public enum PackageProbe {
    public static func abiVersion() -> UInt32 { madcrypto_abi_version() }
    public static func existingSelftest() -> Int32 { madcrypto_selftest() }
}
