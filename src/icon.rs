use std::ptr::null_mut;
use windows_sys::Win32::Graphics::Gdi::{
    CreateBitmap, CreateDIBSection, CreatePatternBrush, DeleteObject, BITMAPINFO, BITMAPINFOHEADER,
    BI_RGB, DIB_RGB_COLORS, HBRUSH,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{CreateIconIndirect, HICON, ICONINFO};

// Procedural 32-bit ARGB app icon (6x6 supersampled).
pub fn render_avel_icon_argb(size: i32) -> (usize, Vec<u32>) {
    let sz = size.clamp(16, 128) as usize;
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

                    // Top inner rim highlight
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

    (sz, pixels)
}

#[inline]
fn mix_color(c1: (f32, f32, f32), c2: (f32, f32, f32), t: f32) -> (f32, f32, f32) {
    (
        c1.0 + (c2.0 - c1.0) * t,
        c1.1 + (c2.1 - c1.1) * t,
        c1.2 + (c2.2 - c1.2) * t,
    )
}

#[inline]
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

pub unsafe fn create_soft_round_icon(size: i32) -> HICON {
    let (sz, rendered) = render_avel_icon_argb(size.clamp(16, 64));

    let mut bmi: BITMAPINFO = std::mem::zeroed();
    bmi.bmiHeader.biSize = std::mem::size_of::<BITMAPINFOHEADER>() as u32;
    bmi.bmiHeader.biWidth = sz as i32;
    bmi.bmiHeader.biHeight = -(sz as i32);
    bmi.bmiHeader.biPlanes = 1;
    bmi.bmiHeader.biBitCount = 32;
    bmi.bmiHeader.biCompression = BI_RGB;

    let mut bits_ptr: *mut core::ffi::c_void = null_mut();
    let h_color = CreateDIBSection(
        null_mut(),
        &bmi,
        DIB_RGB_COLORS,
        &mut bits_ptr,
        null_mut(),
        0,
    );
    if h_color.is_null() || bits_ptr.is_null() {
        return null_mut();
    }

    let pixels = std::slice::from_raw_parts_mut(bits_ptr as *mut u32, sz * sz);
    pixels.copy_from_slice(&rendered);

    let row_bytes = ((sz + 31) / 32) * 4;
    let mask = vec![0u8; row_bytes * sz];
    let h_mask = CreateBitmap(sz as i32, sz as i32, 1, 1, mask.as_ptr() as *const _);

    let ii = ICONINFO {
        fIcon: 1,
        xHotspot: 0,
        yHotspot: 0,
        hbmMask: h_mask,
        hbmColor: h_color,
    };
    let hicon = CreateIconIndirect(&ii);
    DeleteObject(h_color as _);
    DeleteObject(h_mask as _);
    hicon
}

#[inline]
fn smoothstep(edge0: f32, edge1: f32, x: f32) -> f32 {
    let t = ((x - edge0) / (edge1 - edge0)).clamp(0.0, 1.0);
    t * t * (3.0 - 2.0 * t)
}

// Render window background with a subtle translucent logo watermark peeking from bottom-right.
// Returns a pattern HBRUSH (the temporary DIB is freed immediately after CreatePatternBrush).
pub unsafe fn create_watermark_brush(w: i32, h: i32, sys_bgr: u32) -> HBRUSH {
    let width = w.max(1) as usize;
    let height = h.max(1) as usize;

    let bg_r = (sys_bgr & 0xFF) as f32;
    let bg_g = ((sys_bgr >> 8) & 0xFF) as f32;
    let bg_b = ((sys_bgr >> 16) & 0xFF) as f32;

    let mut bmi: BITMAPINFO = std::mem::zeroed();
    bmi.bmiHeader.biSize = std::mem::size_of::<BITMAPINFOHEADER>() as u32;
    bmi.bmiHeader.biWidth = width as i32;
    bmi.bmiHeader.biHeight = -(height as i32);
    bmi.bmiHeader.biPlanes = 1;
    bmi.bmiHeader.biBitCount = 32;
    bmi.bmiHeader.biCompression = BI_RGB;

    let mut bits_ptr: *mut core::ffi::c_void = null_mut();
    let hbm = CreateDIBSection(
        null_mut(),
        &bmi,
        DIB_RGB_COLORS,
        &mut bits_ptr,
        null_mut(),
        0,
    );
    if hbm.is_null() || bits_ptr.is_null() {
        return null_mut();
    }

    let pixels = std::slice::from_raw_parts_mut(bits_ptr as *mut u32, width * height);
    let bg_px = ((bg_r as u32) << 16) | ((bg_g as u32) << 8) | (bg_b as u32);

    let wf = width as f32;
    let hf = height as f32;
    let cx = wf * 0.94;
    let cy = hf * 0.87;
    let radius = wf.min(hf) * 0.54;
    let inv_r = 1.0 / radius;
    let aa = 1.6 * inv_r;
    let cos18 = (-0.31415927f32).cos();
    let sin18 = (-0.31415927f32).sin();
    const OPACITY: f32 = 0.145;

    for py in 0..height {
        let v = (py as f32 + 0.5 - cy) * inv_r;
        let row_off = py * width;
        for px in 0..width {
            let u = (px as f32 + 0.5 - cx) * inv_r;
            let dist = u.hypot(v);
            if dist > 1.0 + aa {
                pixels[row_off + px] = bg_px;
                continue;
            }
            let disc_cov = 1.0 - smoothstep(1.0 - aa, 1.0 + aa, dist);
            let s = u * cos18 + v * sin18;
            let split_t = smoothstep(-aa, aa, s);
            let base = mix_color((30.0, 64.0, 175.0), (59.0, 130.0, 246.0), split_t);

            // White/light portal ring (0.366..0.604) and offset floating center core (0.173)
            let ring_in = smoothstep(0.366 - aa, 0.366 + aa, dist);
            let ring_out = 1.0 - smoothstep(0.604 - aa, 0.604 + aa, dist);
            let ring_cov = ring_in * ring_out;

            let core_d = (u - 0.054).hypot(v + 0.022);
            let core_cov = 1.0 - smoothstep(0.173 - aa, 0.173 + aa, core_d);

            let ring_color = mix_color((255.0, 255.0, 255.0), mix_color(base, (255.0, 255.0, 255.0), 0.82), split_t);
            let mut col = mix_color(base, ring_color, ring_cov);
            col = mix_color(col, (255.0, 255.0, 255.0), core_cov);

            let alpha = OPACITY * disc_cov;
            let r = (bg_r + (col.0 - bg_r) * alpha).round().clamp(0.0, 255.0) as u32;
            let g = (bg_g + (col.1 - bg_g) * alpha).round().clamp(0.0, 255.0) as u32;
            let b = (bg_b + (col.2 - bg_b) * alpha).round().clamp(0.0, 255.0) as u32;
            pixels[row_off + px] = (r << 16) | (g << 8) | b;
        }
    }

    let hbr = CreatePatternBrush(hbm);
    DeleteObject(hbm as _);
    hbr
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn icon_fills_full_36px_bounds() {
        let (sz, px) = render_avel_icon_argb(36);
        assert_eq!(sz, 36);
        let (mut min_x, mut max_x, mut min_y, mut max_y) = (36, 0, 36, 0);
        for y in 0..36 {
            for x in 0..36 {
                let a = px[y * 36 + x] >> 24;
                if a >= 32 {
                    min_x = min_x.min(x);
                    max_x = max_x.max(x);
                    min_y = min_y.min(y);
                    max_y = max_y.max(y);
                }
            }
        }
        assert_eq!((min_x, max_x, min_y, max_y), (0, 35, 0, 35));
    }
}
