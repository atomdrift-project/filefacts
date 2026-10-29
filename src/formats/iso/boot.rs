//! El Torito boot catalog: the boot entries an image declares, and the boot
//! images themselves surfaced as members.

use serde_json::{Value as JsonValue, json};

use super::{MAX_BOOT_ENTRIES, Pvd, SECTOR, decode_field, field, sector_at};
use crate::formats::common::bytes_at::{u16_le, u32_le};
use crate::metric;
use crate::output::{ArchiveMember, EntryType, Metrics, Values};
use crate::value_key;

/// What a boot record adds to the image-wide accounting.
#[derive(Default)]
pub(super) struct BootTally {
    /// A well-formed El Torito catalog was found.
    pub(super) el_torito: bool,
    pub(super) anomalies: Vec<&'static str>,
    /// Byte ranges the catalog and its boot images occupy.
    pub(super) claimed: Vec<(u64, u64)>,
}

pub(super) fn emit_boot(
    bytes: &[u8],
    body: &[u8],
    pvd: &Pvd,
    values: &mut Values,
    metrics: &mut Metrics,
    archive_members: &mut Vec<ArchiveMember>,
) -> BootTally {
    let mut tally = BootTally::default();
    let boot_system = decode_field(&field(body, 7, 32), false);
    values.insert_key(
        value_key!("iso.boot.system_id"),
        JsonValue::String(boot_system.clone()),
    );
    if !boot_system.to_ascii_uppercase().starts_with("EL TORITO") {
        // A boot record that isn't El Torito still means "this image
        // claims to boot"; record the claim without inventing a catalog.
        values.insert_key(value_key!("iso.boot.bootable"), JsonValue::Bool(true));
        return tally;
    }

    let catalog_lba = u32_le(body, 71).unwrap_or(0);
    metrics.insert(metric!("iso.boot.catalog_lba"), f64::from(catalog_lba));
    if catalog_lba >= pvd.volume_space_sectors {
        tally.anomalies.push("boot-catalog-out-of-range");
    }
    let Some(catalog) = sector_at(bytes, catalog_lba as usize) else {
        tally.anomalies.push("boot-catalog-unreadable");
        return tally;
    };
    let catalog_start = u64::from(catalog_lba) * SECTOR as u64;
    tally
        .claimed
        .push((catalog_start, catalog_start + SECTOR as u64));

    // Validation entry: header 0x01, a platform id, and a 0x55AA key.
    let valid = catalog.first() == Some(&0x01) && catalog.get(30..32) == Some(&[0x55, 0xAA]);
    if !valid {
        tally.anomalies.push("boot-catalog-invalid");
    }
    let manufacturer = decode_field(&field(catalog, 4, 24), false);
    if !manufacturer.is_empty() {
        values.insert_key(
            value_key!("iso.boot.manufacturer"),
            JsonValue::String(manufacturer),
        );
    }

    let mut entries = Vec::new();
    let mut platforms: Vec<&'static str> = Vec::new();
    let mut current_platform = catalog.get(1).copied().unwrap_or(0);
    let mut bootable_count = 0_u32;
    let mut offset = 32;

    while offset + 32 <= catalog.len() && entries.len() < MAX_BOOT_ENTRIES {
        let Some(e) = catalog.get(offset..offset + 32) else {
            break;
        };
        offset += 32;
        let header = e.first().copied().unwrap_or(0);
        match header {
            // Section header: switches the platform for the entries after it.
            0x90 | 0x91 => {
                current_platform = e.get(1).copied().unwrap_or(0);
                continue;
            }
            // Extension entry — continuation of the previous section entry.
            0x44 => continue,
            // Bootable (0x88) or non-bootable (0x00) section entry. A zero
            // byte is also what padding looks like, so an all-zero record
            // ends the catalog.
            0x88 | 0x00 => {
                if e.iter().all(|b| *b == 0) {
                    break;
                }
            }
            _ => break,
        }
        let bootable = header == 0x88;
        if bootable {
            bootable_count += 1;
        }
        let platform = platform_name(current_platform);
        if !platforms.contains(&platform) {
            platforms.push(platform);
        }
        let media = e.get(1).copied().unwrap_or(0);
        let load_rba = u32_le(e, 8).unwrap_or(0);
        let sectors = u16_le(e, 6).unwrap_or(0);
        entries.push(json!({
            "bootable": bootable,
            "platform": platform,
            "platform_id": current_platform,
            "media_type": media_name(media),
            "load_segment": u16_le(e, 2).unwrap_or(0),
            "system_type": e.get(4).copied().unwrap_or(0),
            "sector_count": sectors,
            "load_rba": load_rba,
            // Boot images are addressed in 512-byte virtual sectors but
            // located by 2048-byte LBA; the byte offset is what a caller
            // needs to carve the image out.
            "offset": u64::from(load_rba) * SECTOR as u64,
        }));
        if load_rba >= pvd.volume_space_sectors {
            tally.anomalies.push("boot-image-out-of-range");
        }
        // El Torito counts a boot image in 512-byte virtual sectors even
        // though it is placed on a 2048-byte boundary.
        let image_start = u64::from(load_rba) * SECTOR as u64;
        let image_len = u64::from(sectors).saturating_mul(512).max(SECTOR as u64);
        tally
            .claimed
            .push((image_start, image_start.saturating_add(image_len)));
        // The boot image is executable content that no directory entry
        // names — a bootkit lives here, not in the file tree — so it is
        // surfaced as a member and analysed like any other payload.
        let mut member = ArchiveMember::new(
            format!(".iso-boot/{platform}-{}.img", entries.len()),
            image_len,
            EntryType::BootImage,
        );
        member.offsets.data = Some(image_start);
        archive_members.push(member);
    }

    metrics.insert(metric!("iso.boot.entry_count"), entries.len() as f64);
    metrics.insert(
        metric!("iso.boot.bootable_entry_count"),
        f64::from(bootable_count),
    );
    values.insert_key(
        value_key!("iso.boot.bootable"),
        JsonValue::Bool(bootable_count > 0),
    );
    values.insert_key(
        value_key!("iso.boot.platforms"),
        JsonValue::Array(platforms.iter().map(|p| json!(p)).collect()),
    );
    values.insert_key(
        value_key!("iso.boot.efi"),
        JsonValue::Bool(platforms.contains(&"efi")),
    );
    values.insert_key(value_key!("iso.boot.entries"), JsonValue::Array(entries));
    tally.el_torito = true;
    tally
}

fn platform_name(id: u8) -> &'static str {
    match id {
        0x00 => "x86",
        0x01 => "powerpc",
        0x02 => "mac",
        0xEF => "efi",
        _ => "unknown",
    }
}

fn media_name(id: u8) -> &'static str {
    match id & 0x0F {
        0 => "no-emulation",
        1 => "floppy-1.2m",
        2 => "floppy-1.44m",
        3 => "floppy-2.88m",
        4 => "hard-disk",
        _ => "reserved",
    }
}
