//! A compiled AppleScript built into the test binary.

/// Portable end-to-end input for filefacts adapter/bytecode tests. Generated
/// with `osacompile -x` from this harmless script (compiled, never executed):
///
/// ```text
/// on greet(x)
///     return {x,-123,32767,32768,65535,"Hello World"}
/// end greet
/// return greet(1)
/// ```
///
/// Contains two functions, a name, an aevt.oapp event, UTF-16BE text, negative
/// short and positive long integers, literal pools, and untyped function code.
/// Tests call it without macOS or external files.
pub(super) fn compiled() -> Vec<u8> {
    let hex = concat!(
        "4661736455415320312e3130312e31300e000000040ffffffffe0001000201ffff000001fffe00000e000100000f1000",
        "020004fffd00030004000501fffd00001000030002fffcfffb0bfffc0009300005677265657400000afffb00182e6165",
        "76746f6170706e756c6c00008000000090002a2a2a2a0e0004000710fffafff9fff8fff700060007fff60bfffa000930",
        "00056772656574000001fff900000efff8000204fff5000803fff500010e0008000100fff40bfff40005300001780000",
        "02fff700001000060001fff30bfff300053000017800001000070006fff2fff1fff0ffef0009ffee03fff2ff8503fff1",
        "7fff07fff000040000800007ffef00040000ffff0e00090001b1000a11000a001600480065006c006c006f0020005700",
        "6f0072006c006403ffee000611fff6000aa0e0e1e2e3e4e5760f0f0e0005000710ffedffecffebffea000b000cffe90a",
        "ffed00182e616576746f6170706e756c6c00008000000090002a2a2a2a01ffec000001ffeb000002ffea000010000b00",
        "0010000c0001ffe80bffe800093000056772656574000011ffe900082a6b6b2b00000f0f617363720001000cfadedead",
    );
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("static fixture hex"))
        .collect()
}
