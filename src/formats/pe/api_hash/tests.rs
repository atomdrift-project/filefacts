use super::*;
use crate::formats::pe::tests::read_fixture;

#[test]
fn manual_resolver_code_signals_require_the_complete_mechanics() {
    // A bounds-checking export walker: MZ → e_lfanew → PE signature →
    // PE32 export-directory offset and size. Keep this independent from a fixture
    // so a future parser change cannot accidentally widen the detector.
    let checked_walk = [
        0x66, 0x81, 0x3f, 0x4d, 0x5a, 0x8b, 0x47, 0x3c, 0x81, 0x3c, 0x07, 0x50, 0x45, 0x00, 0x00,
        0x8b, 0x4c, 0x07, 0x78, 0x8b, 0x54, 0x07, 0x7c,
    ];
    assert_eq!(find_checked_export_walks_x86(&checked_walk).len(), 1);
    assert_eq!(
        find_checked_export_walks_x86(&checked_walk),
        vec![CheckedExportWalk {
            mz_check: 0,
            e_lfanew: 5,
            pe_check: 8,
            export_rva: 15,
            export_size: 19,
        }]
    );
    assert!(find_checked_export_walks_x86(&checked_walk[..8]).is_empty());

    // A byte-wise custom hash: multiply, byte load, XOR with the
    // accumulator and a constant, then rotate.
    let hash_loop = [
        0xb8, 0xdb, 0xf7, 0x26, 0xab, 0x80, 0xcd, 0x20, 0x80, 0xf9, 0x1a, 0x0f, 0x43, 0xcb, 0x69,
        0xd8, 0x7f, 0x85, 0x3b, 0x80, 0x0f, 0xb6, 0xc1, 0x31, 0xd8, 0x35, 0x38, 0x9f, 0x93, 0x87,
        0xc1, 0xc0, 0x09,
    ];
    assert_eq!(find_custom_byte_hash_profiles_x86(&hash_loop).len(), 1);
    assert_eq!(
        find_custom_byte_hash_profiles_x86(&hash_loop),
        vec![ApiHashProfile {
            loop_offset: 14,
            kind: HashKind::MultiplyXorRotate,
            seed: Some(0xab26f7db),
            multiplier: 0x803b857f,
            xor_constant: 0x87939f38,
            rotate_bits: 9,
            ascii_lowercase: true,
        }]
    );
    assert!(find_custom_byte_hash_profiles_x86(&hash_loop[..29]).is_empty());
}

#[test]
fn flattened_xor_rotate_multiply_hash_profile_recovers_seed_flow() {
    let hash_loop = [
        // seed -> stack slot 0x10
        0xc7, 0x44, 0x24, 0x10, 0xb5, 0xcf, 0x88, 0x11,
        // dispatcher copies slot 0x10 -> accumulator slot 0x1c
        0x8b, 0x44, 0x24, 0x10, 0x89, 0x44, 0x24, 0x1c,
        // lowercase normalization and accumulator update
        0x8b, 0x44, 0x24, 0x18, 0x0f, 0xb6, 0x0c, 0x07, 0x89, 0xca, 0x80, 0xc2, 0xbf, 0x88, 0xce,
        0x80, 0xce, 0x20, 0x80, 0xfa, 0x1a, 0x0f, 0xb6, 0xd6, 0x0f, 0x43, 0xd1, 0x8b, 0x4c, 0x24,
        0x1c, 0xbd, 0xa7, 0x79, 0x02, 0x34, 0x31, 0xe9, 0xc1, 0xc1, 0x15, 0x69, 0xc9, 0x59, 0x94,
        0x27, 0x85, 0x0f, 0xb6, 0xd2, 0x31, 0xca,
    ];
    let profiles = find_custom_byte_hash_profiles_x86(&hash_loop);
    assert_eq!(profiles.len(), 1);
    assert_eq!(profiles[0].kind, HashKind::XorRotateMultiplyXor);
    assert_eq!(profiles[0].seed, Some(0x1188cfb5));
    assert_eq!(profiles[0].xor_constant, 0x340279a7);
    assert_eq!(profiles[0].multiplier, 0x85279459);
    assert_eq!(profiles[0].rotate_bits, 21);
    assert!(profiles[0].ascii_lowercase);
}

#[test]
fn recovered_profile_exactly_matches_native_api_name() {
    let profile = LocatedHashProfile {
        va: 0x40ed6d,
        seed: 0x1188cfb5,
        profile: ApiHashProfile {
            loop_offset: 0,
            kind: HashKind::XorRotateMultiplyXor,
            seed: Some(0x1188cfb5),
            multiplier: 0x85279459,
            xor_constant: 0x340279a7,
            rotate_bits: 21,
            ascii_lowercase: true,
        },
    };
    assert_eq!(profile.hash("NtQueryInformationProcess"), 0x3b1471e8);
    assert_ne!(profile.hash("NtQuerySystemInformation"), 0x3b1471e8);
}

#[test]
fn recovers_immediate_and_constant_folded_hash_arguments() {
    let mut bytes = read_fixture("test.exe");
    let pe_offset = u32::from_le_bytes(bytes[0x3c..0x40].try_into().unwrap()) as usize;
    let optional_offset = pe_offset + 24;
    assert_eq!(
        u16::from_le_bytes(
            bytes[optional_offset..optional_offset + 2]
                .try_into()
                .unwrap()
        ),
        0x20b
    );
    bytes[optional_offset + 24..optional_offset + 32]
        .copy_from_slice(&0x0040_0000_u64.to_le_bytes());
    let pe = PE::parse(&bytes).expect("fixture PE");
    let section = pe
        .sections
        .iter()
        .find(|section| section.size_of_raw_data >= 0x100)
        .expect("fixture code section");
    let section_file = section.pointer_to_raw_data as usize;
    let section_va = pe.image_base + u64::from(section.virtual_address);
    drop(pe);

    let direct_offset = section_file + 0x20;
    bytes[direct_offset..direct_offset + 11]
        .copy_from_slice(&[0x68, 0xe8, 0x71, 0x14, 0x3b, 0x50, 0xe8, 0, 0, 0, 0]);

    let memory_offset = section_file + 0x80;
    bytes[memory_offset..memory_offset + 4].copy_from_slice(&0x0000bd87_u32.to_le_bytes());
    let memory_va = u32::try_from(section_va + 0x80).expect("PE32 fixture VA");
    let folded_offset = section_file + 0x40;
    let mut folded = vec![0xa1];
    folded.extend_from_slice(&memory_va.to_le_bytes());
    folded.push(0xb9);
    folded.extend_from_slice(&0x9bf7790b_u32.to_le_bytes());
    folded.extend_from_slice(&[0x31, 0xc8, 0x05]);
    folded.extend_from_slice(&0x9f1cad5c_u32.to_le_bytes());
    folded.extend_from_slice(&[0x50, 0xff, 0x74, 0x24, 0x0c, 0xe8, 0, 0, 0, 0]);
    bytes[folded_offset..folded_offset + folded.len()].copy_from_slice(&folded);
    // The same computation in other registers: mov edx,[abs]; mov ebx,imm;
    // xor edx,ebx; add edx,imm; push edx; push esi; call.
    let other_offset = section_file + 0xa0;
    let mut other = vec![0x8b, 0x15];
    other.extend_from_slice(&memory_va.to_le_bytes());
    other.push(0xbb);
    other.extend_from_slice(&0x9bf7790b_u32.to_le_bytes());
    other.extend_from_slice(&[0x31, 0xda, 0x81, 0xc2]);
    other.extend_from_slice(&0x9f1cad5c_u32.to_le_bytes());
    other.extend_from_slice(&[0x52, 0x56, 0xe8, 0, 0, 0, 0]);
    bytes[other_offset..other_offset + other.len()].copy_from_slice(&other);
    let pe = PE::parse(&bytes).expect("mutated fixture PE");
    assert_eq!(
        recover_x86_hash_argument(&pe, &bytes, section_va + 0x26),
        Some((0x3b1471e8, HashSource::Immediate))
    );
    assert_eq!(
        recover_x86_hash_argument(&pe, &bytes, section_va + 0x40 + 22),
        Some((0x3b1471e8, HashSource::ConstantFolded))
    );
    assert_eq!(
        recover_x86_hash_argument(&pe, &bytes, section_va + 0xa0 + 21),
        Some((0x3b1471e8, HashSource::ConstantFolded))
    );
}

/// A value a register merely might hold is not a constant: a load through a
/// register, or an instruction the evaluator does not model, leaves it
/// unknown rather than guessed.
#[test]
fn hash_argument_is_unknown_unless_every_step_is_constant() {
    let code = [
        0x8b, 0x06, // mov eax, [esi]
        0x35, 0x78, 0x56, 0x34, 0x12, // xor eax, 0x12345678
        0x50, // push eax
        0x56, // push esi
    ];
    let fixture = read_fixture("test.exe");
    let pe = PE::parse(&fixture).expect("fixture PE");
    let mut info = InstructionInfoFactory::new();
    let pushes = straight_line_pushes(&pe, &[], &code, 0x1000, &mut info).unwrap();
    assert_eq!(pushes, [None, None]);
    let code = [
        0xb8, 0x78, 0x56, 0x34, 0x12, // mov eax, 0x12345678
        0x0f, 0xa2, // cpuid: writes eax
        0x50, // push eax
        0x31, 0xc9, // xor ecx, ecx
        0x41, // inc ecx
        0x51, // push ecx
    ];
    let pushes = straight_line_pushes(&pe, &[], &code, 0x1000, &mut info).unwrap();
    assert_eq!(pushes, [None, None]);
    // A decode that runs past the end is not straight-line code ending here.
    assert!(straight_line_pushes(&pe, &[], &[0x68, 0x01], 0x1000, &mut info).is_none());
}

/// The byte-hash loop detector reads instruction shapes, not one
/// compiler's registers: here the seed is in ESI, the case folding uses DL,
/// and the constant is XORed through the `81 /6` form.
#[test]
fn hash_profiles_are_register_agnostic() {
    let hash_loop = [
        0xbe, 0x44, 0x33, 0x22, 0x11, // mov esi, 0x11223344
        0x80, 0xca, 0x20, // or dl, 0x20
        0x80, 0xfa, 0x1a, // cmp dl, 0x1a
        0x69, 0xc6, 0x7f, 0x85, 0x3b, 0x80, // imul eax, esi, 0x803b857f
        0x0f, 0xb6, 0x1f, // movzx ebx, byte [edi]
        0x33, 0xc3, // xor eax, ebx
        0x81, 0xf0, 0x38, 0x9f, 0x93, 0x87, // xor eax, 0x87939f38
        0xc1, 0xc0, 0x09, // rol eax, 9
    ];
    assert_eq!(
        find_custom_byte_hash_profiles_x86(&hash_loop),
        vec![ApiHashProfile {
            loop_offset: 11,
            kind: HashKind::MultiplyXorRotate,
            seed: Some(0x11223344),
            multiplier: 0x803b857f,
            xor_constant: 0x87939f38,
            rotate_bits: 9,
            ascii_lowercase: true,
        }]
    );
    // Without the range check, folding alone is not the case idiom.
    let mut no_range_check = hash_loop;
    no_range_check[10] = 0x1b;
    assert!(!find_custom_byte_hash_profiles_x86(&no_range_check)[0].ascii_lowercase);
}

/// The flattened resolver's seed travels through whichever register the
/// dispatcher uses, but only through the same one for load and store.
#[test]
fn flattened_seed_flow_is_register_agnostic() {
    let mut code = vec![
        0xc7, 0x44, 0x24, 0x10, 0xb5, 0xcf, 0x88, 0x11, // mov [esp+10], seed
        0x8b, 0x54, 0x24, 0x10, 0x89, 0x54, 0x24, 0x1c, // via edx: [esp+10] -> [esp+1c]
        0x8b, 0x4c, 0x24, 0x1c, // mov ecx, [esp+1c]
    ];
    let end = code.len();
    assert_eq!(
        recover_flattened_stack_hash_seed(&code, end),
        Some(0x1188cfb5)
    );
    // Loaded into EDX, stored from EBX: no copy connects the slots.
    code[13] = 0x5c;
    assert_eq!(recover_flattened_stack_hash_seed(&code, end), None);
}

/// Every section header pointed at one executable run of `fs:[0x30]` loads:
/// the bytes are scanned once (not once per header), the count is exact, and
/// the per-site records stop at the cap with the cap reported.
#[test]
fn native_resolver_scan_clips_overlapping_sections_and_caps_sites() {
    const NEEDLE: &[u8] = b"\x64\xa1\x30\x00\x00\x00";
    const MATCHES: usize = MAX_NATIVE_SITES + 904;
    let mut bytes = read_fixture("test.exe");
    let pe_offset = u32::from_le_bytes(bytes[0x3c..0x40].try_into().unwrap()) as usize;
    let coff = pe_offset + 4;
    let count = u16::from_le_bytes(bytes[coff + 2..coff + 4].try_into().unwrap()) as usize;
    let size_of_optional = u16::from_le_bytes(bytes[coff + 16..coff + 18].try_into().unwrap());
    let table = coff + 20 + size_of_optional as usize;
    let region = bytes.len().next_multiple_of(0x200);
    let len = NEEDLE.len() * MATCHES;
    bytes.resize(region, 0);
    bytes.extend(NEEDLE.iter().copied().cycle().take(len));
    for i in 0..count {
        let header = table + i * 40;
        bytes[header + 16..header + 20].copy_from_slice(&(len as u32).to_le_bytes());
        bytes[header + 20..header + 24].copy_from_slice(&(region as u32).to_le_bytes());
        bytes[header + 36..header + 40].copy_from_slice(&0x6000_0020_u32.to_le_bytes());
    }
    assert!(
        count > 1,
        "the fixture must have overlapping headers to clip"
    );

    let pe = PE::parse_with_opts(
        &bytes,
        &goblin::pe::options::ParseOptions::default()
            .with_parse_mode(goblin::options::ParseMode::Permissive)
            .with_parse_imports(false),
    )
    .expect("forged fixture parses");
    let mut values = Values::new();
    let mut metrics = Metrics::new();
    native_resolver_signals(&pe, &bytes, &mut values, &mut metrics);
    assert_eq!(
        metrics.get("pe.peb_access_x86_count"),
        Some(MATCHES as f64),
        "each byte scanned once despite {count} overlapping headers"
    );
    let sites = values
        .get("pe.peb_access_sites")
        .and_then(serde_json::Value::as_array)
        .expect("sites");
    assert_eq!(sites.len(), MAX_NATIVE_SITES);
    assert_eq!(metrics.get("pe.native_resolver_sites_capped"), Some(1.0));
    assert_eq!(
        sites[1]["file_offset"],
        serde_json::json!(region + NEEDLE.len())
    );
}

fn located_profile(va: u64) -> LocatedHashProfile {
    LocatedHashProfile {
        va,
        seed: 0,
        profile: ApiHashProfile {
            loop_offset: 0,
            kind: HashKind::MultiplyXorRotate,
            seed: Some(0),
            multiplier: 0,
            xor_constant: 0,
            rotate_bits: 0,
            ascii_lowercase: false,
        },
    }
}

/// A call into a resolver takes the resolver's own hash profile, or that of
/// the first helper it calls; calls into anything else are not requests.
#[test]
fn resolver_calls_pair_each_call_with_its_resolvers_profile() {
    // 0x1000 resolves with its own loop; 0x2000 delegates to helper 0x3000;
    // 0x4000 is an ordinary caller.
    let ranges = [
        (0x1000, 0x100),
        (0x2000, 0x100),
        (0x3000, 0x100),
        (0x4000, 0x100),
    ];
    let profiles = [located_profile(0x3020), located_profile(0x1020)];
    let edges = [
        (0x4000, 0x4005, 0x1000),
        (0x2000, 0x2030, 0x3000),
        (0x4000, 0x400a, 0x2000),
        (0x4000, 0x400f, 0x3000),
    ];
    let calls: Vec<_> = resolver_calls(&ranges, &edges, vec![0x2010, 0x1010], &profiles)
        .into_iter()
        .map(|(caller, callsite, resolver, profile)| (caller, callsite, resolver, profile.va))
        .collect();
    assert_eq!(
        calls,
        [
            (0x4000, 0x4005, 0x1000, 0x1020),
            (0x4000, 0x400a, 0x2000, 0x3020)
        ]
    );
}

/// Rizin can report a million call edges for a few megabytes of `call`
/// instructions; resolving every edge into a resolver with no hash loop must
/// not rescan all edges for a helper.
#[test]
fn resolver_calls_scale_with_the_edge_count() {
    let calls = 200_000;
    let ranges = [(0x1000, 0x100), (0x10_0000, 0x1000_0000)];
    let edges: Vec<_> = (0..calls)
        .map(|i| (0x10_0000, 0x10_0000 + 5 * i, 0x1000))
        .collect();
    assert!(resolver_calls(&ranges, &edges, vec![0x1010], &[]).is_empty());
    let profiles = [located_profile(0x1020)];
    assert_eq!(
        resolver_calls(&ranges, &edges, vec![0x1010], &profiles).len(),
        calls as usize
    );
}
