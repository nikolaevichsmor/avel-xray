use std::env;
use std::fs;
use std::path::PathBuf;

// Generates a COFF .rsrc object with app icon sizes (16..64 px) and a Win11 PerMonitorV2 manifest.
fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=CARGO_PKG_VERSION");

    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let target_arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
    if target_os != "windows" || target_arch != "x86_64" {
        return;
    }

    let sizes: [usize; 5] = [16, 24, 32, 48, 64];
    let mut icon_payloads: Vec<(u16, Vec<u8>)> = Vec::with_capacity(sizes.len());
    let mut group_icon: Vec<u8> = Vec::new();

    // GRPICONDIR header
    group_icon.extend_from_slice(&0u16.to_le_bytes()); // reserved
    group_icon.extend_from_slice(&1u16.to_le_bytes()); // type = ICO
    group_icon.extend_from_slice(&(sizes.len() as u16).to_le_bytes());

    for (i, &sz) in sizes.iter().enumerate() {
        let id = (i + 1) as u16;
        let dib = build_icon_dib_payload(sz);
        // GRPICONDIRENTRY (14 bytes)
        group_icon.push(if sz >= 256 { 0 } else { sz as u8 });
        group_icon.push(if sz >= 256 { 0 } else { sz as u8 });
        group_icon.push(0); // color count
        group_icon.push(0); // reserved
        group_icon.extend_from_slice(&1u16.to_le_bytes()); // planes
        group_icon.extend_from_slice(&32u16.to_le_bytes()); // bit count
        group_icon.extend_from_slice(&(dib.len() as u32).to_le_bytes());
        group_icon.extend_from_slice(&id.to_le_bytes());

        icon_payloads.push((id, dib));
    }

    let pkg_ver = env::var("CARGO_PKG_VERSION").unwrap_or_else(|_| "0.2.0".to_string());
    let manifest = format!(
        r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0" xmlns:asmv3="urn:schemas-microsoft-com:asm.v3">
  <assemblyIdentity version="{}.0" processorArchitecture="*" name="Avel.XrayClient" type="win32"/>
  <description>avel-xray Native Win32 VPN Client</description>
  <dependency>
    <dependentAssembly>
      <assemblyIdentity type="win32" name="Microsoft.Windows.Common-Controls" version="6.0.0.0" processorArchitecture="*" publicKeyToken="6595b64144ccf1df" language="*"/>
    </dependentAssembly>
  </dependency>
  <trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">
    <security>
      <requestedPrivileges>
        <requestedExecutionLevel level="asInvoker" uiAccess="false"/>
      </requestedPrivileges>
    </security>
  </trustInfo>
  <compatibility xmlns="urn:schemas-microsoft-com:compatibility.v1">
    <application>
      <supportedOS Id="{{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}}"/>
    </application>
  </compatibility>
  <asmv3:application>
    <asmv3:windowsSettings>
      <dpiAware xmlns="http://schemas.microsoft.com/SMI/2005/WindowsSettings">true/pm</dpiAware>
      <dpiAwareness xmlns="http://schemas.microsoft.com/SMI/2016/WindowsSettings">PerMonitorV2</dpiAwareness>
    </asmv3:windowsSettings>
  </asmv3:application>
</assembly>
"#,
        pkg_ver
    );

    // Resource types MUST be sorted by ID ascending: RT_ICON=3, RT_GROUP_ICON=14, RT_MANIFEST=24
    let types: Vec<(u32, Vec<(u32, Vec<u8>)>)> = vec![
        (
            3,
            icon_payloads
                .into_iter()
                .map(|(id, data)| (id as u32, data))
                .collect(),
        ),
        (14, vec![(1, group_icon)]),
        (24, vec![(1, manifest.into_bytes())]),
    ];

    let coff = build_rsrc_coff_amd64(&types);
    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR not set"));
    let obj_path = out_dir.join("avel_res.o");
    fs::write(&obj_path, coff).expect("Failed to write avel_res.o");

    // Link .rsrc only into the main binary, not test binaries.
    println!("cargo:rustc-link-arg-bin=avel={}", obj_path.display());
}

fn render_avel_icon_argb(sz: usize) -> Vec<u32> {
    let mut pixels = vec![0u32; sz * sz];
    const SS: usize = 6;
    const R: f32 = 0.992;
    let inv_total = 1.0f32 / ((SS * SS) as f32);
    let cos18 = (-0.31415927f32).cos();
    let sin18 = (-0.31415927f32).sin();

    for py in 0..sz {
        for px in 0..sz {
            let mut acc_r = 0.0f32;
            let mut acc_g = 0.0f32;
            let mut acc_b = 0.0f32;
            let mut acc_a = 0.0f32;

            for sy in 0..SS {
                let v = ((py as f32 + (sy as f32 + 0.5) / SS as f32) / sz as f32) * 2.0 - 1.0;
                for sx in 0..SS {
                    let u = ((px as f32 + (sx as f32 + 0.5) / SS as f32) / sz as f32) * 2.0 - 1.0;
                    let dist = u.hypot(v);
                    if dist > R {
                        continue;
                    }
                    let s = u * cos18 + v * sin18;
                    let mut base = if s < 0.0 {
                        (30.0f32, 64.0f32, 175.0f32)
                    } else {
                        (59.0f32, 130.0f32, 246.0f32)
                    };
                    if dist >= R - 0.045 {
                        let top_arc = ((-v - 0.12) / 0.85).clamp(0.0, 1.0);
                        let edge = ((dist - (R - 0.045)) / 0.045).clamp(0.0, 1.0);
                        base = mix_color(base, (255.0, 255.0, 255.0), top_arc * edge * 0.22);
                    }
                    let su = u - 0.022;
                    let sv = v - 0.048;
                    let (r, g, b) = match portal_part(u, v) {
                        2 => (255.0, 255.0, 255.0),
                        1 => {
                            if s < 0.0 {
                                (255.0, 255.0, 255.0)
                            } else {
                                mix_color(base, (255.0, 255.0, 255.0), 0.82)
                            }
                        }
                        _ => {
                            if portal_part(su, sv) != 0 {
                                mix_color(base, (0.0, 10.0, 24.0), 0.18)
                            } else {
                                base
                            }
                        }
                    };
                    acc_r += r;
                    acc_g += g;
                    acc_b += b;
                    acc_a += 255.0;
                }
            }
            let a = (acc_a * inv_total).round().clamp(0.0, 255.0) as u32;
            if a == 0 {
                pixels[py * sz + px] = 0;
            } else {
                let cov = acc_a / 255.0;
                let r = (acc_r / cov).round().clamp(0.0, 255.0) as u32;
                let g = (acc_g / cov).round().clamp(0.0, 255.0) as u32;
                let b = (acc_b / cov).round().clamp(0.0, 255.0) as u32;
                pixels[py * sz + px] = (a << 24) | (r << 16) | (g << 8) | b;
            }
        }
    }
    pixels
}

fn mix_color(c1: (f32, f32, f32), c2: (f32, f32, f32), t: f32) -> (f32, f32, f32) {
    (
        c1.0 + (c2.0 - c1.0) * t,
        c1.1 + (c2.1 - c1.1) * t,
        c1.2 + (c2.2 - c1.2) * t,
    )
}

fn portal_part(u: f32, v: f32) -> u8 {
    let d = u.hypot(v);
    if (0.366..=0.604).contains(&d) {
        return 1;
    }
    if (u - 0.054).hypot(v + 0.022) <= 0.173 {
        return 2;
    }
    0
}

// 32-bit BGRA ICO DIB (BITMAPINFOHEADER + bottom-up XOR + 1bpp AND mask)
fn build_icon_dib_payload(sz: usize) -> Vec<u8> {
    let argb = render_avel_icon_argb(sz);
    let xor_bytes = sz * sz * 4;
    let and_row = ((sz + 31) / 32) * 4;
    let and_bytes = and_row * sz;
    let mut out = Vec::with_capacity(40 + xor_bytes + and_bytes);

    // BITMAPINFOHEADER (40 bytes); ICO requires biHeight = 2 * sz (XOR + AND)
    out.extend_from_slice(&40u32.to_le_bytes()); // biSize
    out.extend_from_slice(&(sz as i32).to_le_bytes()); // biWidth
    out.extend_from_slice(&((sz * 2) as i32).to_le_bytes()); // biHeight
    out.extend_from_slice(&1u16.to_le_bytes()); // biPlanes
    out.extend_from_slice(&32u16.to_le_bytes()); // biBitCount
    out.extend_from_slice(&0u32.to_le_bytes()); // biCompression (BI_RGB)
    out.extend_from_slice(&((xor_bytes + and_bytes) as u32).to_le_bytes()); // biSizeImage
    out.extend_from_slice(&0i32.to_le_bytes());
    out.extend_from_slice(&0i32.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());

    // Bottom-up 32-bit BGRA XOR mask
    for y in (0..sz).rev() {
        for x in 0..sz {
            let p = argb[y * sz + x];
            let a = (p >> 24) as u8;
            let r = ((p >> 16) & 0xFF) as u8;
            let g = ((p >> 8) & 0xFF) as u8;
            let b = (p & 0xFF) as u8;
            out.extend_from_slice(&[b, g, r, a]);
        }
    }

    // Bottom-up 1bpp AND mask (1 = transparent where alpha == 0, 0 = opaque)
    for y in (0..sz).rev() {
        let mut row = vec![0u8; and_row];
        for x in 0..sz {
            let a = argb[y * sz + x] >> 24;
            if a == 0 {
                row[x / 8] |= 1u8 << (7 - (x % 8));
            }
        }
        out.extend_from_slice(&row);
    }

    out
}

fn push_dir_header(buf: &mut Vec<u8>, id_count: u16) {
    buf.extend_from_slice(&0u32.to_le_bytes()); // Characteristics
    buf.extend_from_slice(&0u32.to_le_bytes()); // TimeDateStamp
    buf.extend_from_slice(&0u16.to_le_bytes()); // MajorVersion
    buf.extend_from_slice(&0u16.to_le_bytes()); // MinorVersion
    buf.extend_from_slice(&0u16.to_le_bytes()); // NumberOfNamedEntries
    buf.extend_from_slice(&id_count.to_le_bytes()); // NumberOfIdEntries
}

fn align4(buf: &mut Vec<u8>) {
    while buf.len() % 4 != 0 {
        buf.push(0);
    }
}

// Build an AMD64 COFF object with a single .rsrc section and ADDR32NB relocations.
fn build_rsrc_coff_amd64(types: &[(u32, Vec<(u32, Vec<u8>)>)]) -> Vec<u8> {
    const LANG_EN_US: u32 = 0x0409;
    const DIR_BIT: u32 = 0x8000_0000;

    let mut rsrc: Vec<u8> = Vec::new();
    let mut relocs: Vec<u32> = Vec::new();

    // 1. Root directory (Level 1: Types)
    push_dir_header(&mut rsrc, types.len() as u16);
    let mut l1_patch_offsets = Vec::with_capacity(types.len());
    for &(type_id, _) in types {
        rsrc.extend_from_slice(&type_id.to_le_bytes());
        l1_patch_offsets.push(rsrc.len());
        rsrc.extend_from_slice(&0u32.to_le_bytes()); // patched to L2 offset | DIR_BIT
    }

    // 2. Level 2 directories (Resource IDs per Type)
    let mut l2_patch_offsets: Vec<Vec<usize>> = Vec::with_capacity(types.len());
    for (ti, &(_, ref items)) in types.iter().enumerate() {
        let l2_off = rsrc.len() as u32;
        let patch = l1_patch_offsets[ti];
        rsrc[patch..patch + 4].copy_from_slice(&(l2_off | DIR_BIT).to_le_bytes());

        push_dir_header(&mut rsrc, items.len() as u16);
        let mut patches = Vec::with_capacity(items.len());
        for &(res_id, _) in items {
            rsrc.extend_from_slice(&res_id.to_le_bytes());
            patches.push(rsrc.len());
            rsrc.extend_from_slice(&0u32.to_le_bytes()); // patched to L3 offset | DIR_BIT
        }
        l2_patch_offsets.push(patches);
    }

    // 3. Level 3 directories (Language = EN-US)
    let mut l3_patch_offsets: Vec<usize> = Vec::new();
    let mut flat_payloads: Vec<&[u8]> = Vec::new();
    for (ti, &(_, ref items)) in types.iter().enumerate() {
        for (ii, &(_, ref payload)) in items.iter().enumerate() {
            let l3_off = rsrc.len() as u32;
            let patch = l2_patch_offsets[ti][ii];
            rsrc[patch..patch + 4].copy_from_slice(&(l3_off | DIR_BIT).to_le_bytes());

            push_dir_header(&mut rsrc, 1);
            rsrc.extend_from_slice(&LANG_EN_US.to_le_bytes());
            l3_patch_offsets.push(rsrc.len());
            rsrc.extend_from_slice(&0u32.to_le_bytes()); // patched to IMAGE_RESOURCE_DATA_ENTRY offset
            flat_payloads.push(payload.as_slice());
        }
    }

    // 4. IMAGE_RESOURCE_DATA_ENTRY array (16 bytes each)
    let mut data_entry_offsets: Vec<usize> = Vec::with_capacity(flat_payloads.len());
    for (idx, payload) in flat_payloads.iter().enumerate() {
        let de_off = rsrc.len() as u32;
        let patch = l3_patch_offsets[idx];
        rsrc[patch..patch + 4].copy_from_slice(&de_off.to_le_bytes());

        data_entry_offsets.push(rsrc.len());
        relocs.push(rsrc.len() as u32);
        rsrc.extend_from_slice(&0u32.to_le_bytes()); // OffsetToData (patched + ADDR32NB reloc)
        rsrc.extend_from_slice(&(payload.len() as u32).to_le_bytes()); // Size
        rsrc.extend_from_slice(&0u32.to_le_bytes()); // CodePage
        rsrc.extend_from_slice(&0u32.to_le_bytes()); // Reserved
    }

    // 5. Raw resource payloads (4-byte aligned)
    for (idx, payload) in flat_payloads.iter().enumerate() {
        align4(&mut rsrc);
        let payload_off = rsrc.len() as u32;
        let de = data_entry_offsets[idx];
        rsrc[de..de + 4].copy_from_slice(&payload_off.to_le_bytes());
        rsrc.extend_from_slice(payload);
    }
    align4(&mut rsrc);

    // 6. Wrap into COFF object file
    let raw_data_ptr = 20u32 + 40u32;
    let relocs_ptr = raw_data_ptr + rsrc.len() as u32;
    let symtab_ptr = relocs_ptr + (relocs.len() as u32) * 10;

    let mut coff = Vec::with_capacity(symtab_ptr as usize + 18 + 4);

    // IMAGE_FILE_HEADER (20 bytes)
    coff.extend_from_slice(&0x8664u16.to_le_bytes()); // IMAGE_FILE_MACHINE_AMD64
    coff.extend_from_slice(&1u16.to_le_bytes()); // NumberOfSections
    coff.extend_from_slice(&0u32.to_le_bytes()); // TimeDateStamp
    coff.extend_from_slice(&symtab_ptr.to_le_bytes()); // PointerToSymbolTable
    coff.extend_from_slice(&1u32.to_le_bytes()); // NumberOfSymbols
    coff.extend_from_slice(&0u16.to_le_bytes()); // SizeOfOptionalHeader
    coff.extend_from_slice(&0u16.to_le_bytes()); // Characteristics

    // IMAGE_SECTION_HEADER ".rsrc" (40 bytes)
    coff.extend_from_slice(b".rsrc\0\0\0");
    coff.extend_from_slice(&0u32.to_le_bytes()); // VirtualSize
    coff.extend_from_slice(&0u32.to_le_bytes()); // VirtualAddress
    coff.extend_from_slice(&(rsrc.len() as u32).to_le_bytes()); // SizeOfRawData
    coff.extend_from_slice(&raw_data_ptr.to_le_bytes()); // PointerToRawData
    coff.extend_from_slice(&relocs_ptr.to_le_bytes()); // PointerToRelocations
    coff.extend_from_slice(&0u32.to_le_bytes()); // PointerToLinenumbers
    coff.extend_from_slice(&(relocs.len() as u16).to_le_bytes()); // NumberOfRelocations
    coff.extend_from_slice(&0u16.to_le_bytes()); // NumberOfLinenumbers
    coff.extend_from_slice(&0x4000_0040u32.to_le_bytes()); // INITIALIZED_DATA | MEM_READ

    // Section raw bytes
    coff.extend_from_slice(&rsrc);

    // Relocation entries (10 bytes each: VirtualAddress, SymbolTableIndex=0, Type=IMAGE_REL_AMD64_ADDR32NB=3)
    for r_off in relocs {
        coff.extend_from_slice(&r_off.to_le_bytes());
        coff.extend_from_slice(&0u32.to_le_bytes());
        coff.extend_from_slice(&3u16.to_le_bytes());
    }

    // Symbol table: 1 symbol for ".rsrc" section (18 bytes)
    coff.extend_from_slice(b".rsrc\0\0\0");
    coff.extend_from_slice(&0u32.to_le_bytes()); // Value
    coff.extend_from_slice(&1i16.to_le_bytes()); // SectionNumber = 1 (.rsrc)
    coff.extend_from_slice(&0u16.to_le_bytes()); // Type
    coff.push(3); // IMAGE_SYM_CLASS_STATIC
    coff.push(0); // NumberOfAuxSymbols

    // String table size (4 bytes = empty string table)
    coff.extend_from_slice(&4u32.to_le_bytes());

    coff
}
