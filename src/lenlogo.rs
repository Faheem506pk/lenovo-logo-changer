use crc32fast::Hasher;
use efivar::efi::{Variable, VariableFlags};
use log::{debug, error, info};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io;
use std::io::Read;
use std::path::Path;
use std::str::FromStr;

use crate::esp_partition::{copy_file_to_esp, delete_logo_path};

#[cfg(target_os = "linux")]
use crate::platform::linux::LinuxPlatform;

/// 跨平台的EFI变量写入包装函数
/// Linux下需要处理immutable属性，Windows下直接调用
fn with_efi_var_writable<F>(var_name: &str, f: F) -> Result<(), String>
where
    F: FnOnce() -> Result<(), String>,
{
    #[cfg(target_os = "linux")]
    {
        LinuxPlatform::with_efi_var_writable(var_name, f)
    }

    #[cfg(not(target_os = "linux"))]
    {
        // Windows和其他平台直接执行
        let _ = var_name; // 消除未使用变量警告
        f()
    }
}

fn get_image_dimensions<P: AsRef<Path>>(path: P) -> Option<(u32, u32)> {
    let mut file = File::open(path).ok()?;
    let mut header = [0u8; 32];
    file.read_exact(&mut header).ok()?;

    if header.starts_with(b"BM") {
        // BMP: width at 18..22, height at 22..26 (little endian)
        let width = u32::from_le_bytes(header[18..22].try_into().ok()?);
        let height = u32::from_le_bytes(header[22..26].try_into().ok()?);
        Some((width, height))
    } else if header.starts_with(b"\x89PNG\r\n\x1a\n") {
        // PNG: width at 16..20, height at 20..24 (big endian)
        let width = u32::from_be_bytes(header[16..20].try_into().ok()?);
        let height = u32::from_be_bytes(header[20..24].try_into().ok()?);
        Some((width, height))
    } else if header.starts_with(b"GIF8") {
        // GIF: width at 6..8, height at 8..10 (little endian u16)
        let width = u16::from_le_bytes(header[6..8].try_into().ok()?) as u32;
        let height = u16::from_le_bytes(header[8..10].try_into().ok()?) as u32;
        Some((width, height))
    } else if header.starts_with(b"\xFF\xD8") {
        // JPEG: scan for SOF marker (0xFF, 0xC0..=0xC3)
        use std::io::Seek;
        let _ = file.seek(std::io::SeekFrom::Start(2));
        let mut buf = [0u8; 2];
        while file.read_exact(&mut buf).is_ok() {
            if buf[0] == 0xFF {
                let marker = buf[1];
                if marker == 0xFF {
                    let _ = file.seek(std::io::SeekFrom::Current(-1));
                    continue;
                }
                if (0xC0..=0xC3).contains(&marker) {
                    let mut sof = [0u8; 7];
                    if file.read_exact(&mut sof).is_ok() {
                        let height = u16::from_be_bytes(sof[3..5].try_into().ok()?) as u32;
                        let width = u16::from_be_bytes(sof[5..7].try_into().ok()?) as u32;
                        return Some((width, height));
                    }
                    break;
                } else if marker == 0xD8 || marker == 0xD9 || (0xD0..=0xD7).contains(&marker) {
                    continue;
                } else {
                    let mut len_bytes = [0u8; 2];
                    if file.read_exact(&mut len_bytes).is_ok() {
                        let len = u16::from_be_bytes(len_bytes) as i64;
                        if file.seek(std::io::SeekFrom::Current(len - 2)).is_err() {
                            break;
                        }
                    } else {
                        break;
                    }
                }
            } else {
                break;
            }
        }
        None
    } else {
        None
    }
}

pub(crate) struct PlatformInfo {
    pub(crate) enable: u8,
    pub(crate) width: u32,
    pub(crate) height: u32,
    pub(crate) version: u32,
    pub(crate) support: Vec<&'static str>,
    pub(crate) lbldesp_var: [u8; 10],
    pub(crate) lbldvc_var: [u8; 40],
    pub(crate) lbl_only_mode: bool,
    pub(crate) lbl_var_val: u8,
}

impl Default for PlatformInfo {
    fn default() -> Self {
        Self {
            enable: 0,
            width: 0,
            height: 0,
            version: 0,
            support: Vec::new(),
            lbldesp_var: [0u8; 10],
            lbldvc_var: [0u8; 40],
            lbl_only_mode: false,
            lbl_var_val: 0,
        }
    }
}

impl PlatformInfo {
    pub(crate) fn get_info(&mut self) -> bool {
        let varman = efivar::system();

        let esp_var = Variable::from_str("LBLDESP-871455D0-5576-4FB8-9865-AF0824463B9E").unwrap();

        match varman.read(&esp_var) {
            Ok((esp_buffer, _attr)) => {
                if esp_buffer.len() != 10 {
                    error!("read lbldesp_var failed: buffer length is not 10");
                    return false;
                }
                self.enable = esp_buffer[0];
                self.width = u32::from_le_bytes(esp_buffer[1..5].try_into().unwrap());
                self.height = u32::from_le_bytes(esp_buffer[5..9].try_into().unwrap());
                self.support = Self::support_format(esp_buffer[9]);
                self.lbldesp_var = <[u8; 10]>::try_from(esp_buffer).unwrap();

                let dvc_var = Variable::from_str("LBLDVC-871455D1-5576-4FB8-9865-AF0824463C9F").unwrap();
                match varman.read(&dvc_var) {
                    Ok((dvc_buffer, _attr)) => {
                        if dvc_buffer.len() != 40 {
                            error!("read lbldvc_var failed: buffer length is not 40");
                            return false;
                        }
                        self.version = u32::from_le_bytes(dvc_buffer[0..4].try_into().unwrap());
                        self.lbldvc_var = <[u8; 40]>::try_from(dvc_buffer).unwrap();
                    }
                    Err(err) => {
                        error!("read lbldvc_var failed: {}", err);
                        return false;
                    }
                }
                true
            }
            Err(err) => {
                // If LBLDESP is missing, check if LBL (GUID: 2a4dc6b7-41f5-45dd-b46f-2dd334c1cf65) exists
                let lbl_var = Variable::from_str("LBL-2A4DC6B7-41F5-45DD-B46F-2DD334C1CF65").unwrap();
                match varman.read(&lbl_var) {
                    Ok((lbl_buffer, _attr)) => {
                        if lbl_buffer.is_empty() {
                            error!("read lbl_var failed: empty buffer");
                            return false;
                        }
                        self.lbl_only_mode = true;
                        self.enable = lbl_buffer[0];
                        self.width = 3840; // Safe upper bounds
                        self.height = 2160;
                        self.support = vec!["bmp", "jpg", "png", "gif"];
                        self.version = 0;
                        self.lbl_var_val = lbl_buffer[0];
                        info!("LBL-only variable detected. Custom logo supported.");
                        true
                    }
                    Err(lbl_err) => {
                        error!("read lbldesp_var failed: {}", err);
                        error!("read lbl_var failed: {}", lbl_err);
                        false
                    }
                }
            }
        }
    }

    pub(crate) fn set_logo(&mut self, img_path: &String) -> bool {
        // 复制文件到ESP分区
        let file_path = Path::new(img_path);
        let file_extension = file_path.extension().unwrap().to_str().unwrap();
        debug!("file_extension: {}", file_extension);

        let (width, height) = if self.lbl_only_mode {
            get_image_dimensions(img_path).unwrap_or((1920, 1080))
        } else {
            (self.width, self.height)
        };

        let dst_path = format!(
            r"/EFI/Lenovo/Logo/mylogo_{}x{}.{}",
            width, height, file_extension
        );
        info!("target path: {}", dst_path);

        if copy_file_to_esp(img_path, &dst_path) == false {
            error!("copy file failed");
            return false;
        }

        // In LBL-only mode, write the image to logo.extension and mylogo.extension as well for firmware compatibility
        if self.lbl_only_mode {
            let dst_path_mylogo = format!(r"/EFI/Lenovo/Logo/mylogo.{}", file_extension);
            let dst_path_logo = format!(r"/EFI/Lenovo/Logo/logo.{}", file_extension);
            let _ = copy_file_to_esp(img_path, &dst_path_mylogo);
            let _ = copy_file_to_esp(img_path, &dst_path_logo);
        }

        let mut varman = efivar::system();

        if self.lbl_only_mode {
            let lbl_var = Variable::from_str("LBL-2A4DC6B7-41F5-45DD-B46F-2DD334C1CF65").unwrap();
            // 在Linux下需要先移除immutable属性
            let write_result = with_efi_var_writable(
                "LBL-2a4dc6b7-41f5-45dd-b46f-2dd334c1cf65",
                || match varman.write(
                    &lbl_var,
                    VariableFlags::from_bits(0x7).unwrap(),
                    &[1u8],
                ) {
                    Ok(rt) => {
                        debug!("write lbl_var: {:?}", rt);
                        Ok(())
                    }
                    Err(err) => Err(format!("write lbl_var failed: {}", err)),
                },
            );

            match write_result {
                Ok(_) => {
                    self.enable = 1;
                    self.lbl_var_val = 1;
                }
                Err(err) => {
                    error!("{}", err);
                    return false;
                }
            }
        } else {
            // 修改logoinfo
            let mut esp_buffer = self.lbldesp_var.clone();
            esp_buffer[0] = 1;
            let esp_var = Variable::from_str("LBLDESP-871455D0-5576-4FB8-9865-AF0824463B9E").unwrap();

            // 在Linux下需要先移除immutable属性
            let write_result = with_efi_var_writable(
                "LBLDESP-871455d0-5576-4fb8-9865-af0824463b9e",
                || match varman.write(
                    &esp_var,
                    VariableFlags::from_bits(0x7).unwrap(),
                    &esp_buffer,
                ) {
                    Ok(rt) => {
                        debug!("write lbldesp_var: {:?}", rt);
                        Ok(())
                    }
                    Err(err) => Err(format!("write lbldesp_var failed: {}", err)),
                },
            );

            match write_result {
                Ok(_) => {
                    self.enable = 1;
                    self.lbldesp_var = esp_buffer;
                }
                Err(err) => {
                    error!("{}", err);
                    return false;
                }
            }

            // 修改logocheck - 根据version选择SHA256或CRC32
            let mut dvc_buffer = self.lbldvc_var.clone();

            if self.version == 0x20003 {
                // version 0x20003: 使用SHA256 (32字节)
                let sha256_bytes;
                match calculate_sha256(img_path) {
                    Ok(sha256) => {
                        // 将sha256十六进制字符串转化为十六进制序列
                        sha256_bytes = hex::decode(sha256).unwrap();
                    }
                    Err(e) => {
                        error!("read error {}: {}", img_path, e);
                        return false;
                    }
                }
                dvc_buffer[4..36].clone_from_slice(&sha256_bytes);
                debug!("sha256_bytes: {:?}", sha256_bytes);
            } else if self.version == 0x20000 {
                // version 0x20000: 使用CRC32 (4字节)
                match calculate_crc32_first_512(img_path) {
                    Ok(crc32) => {
                        dvc_buffer[4..8].clone_from_slice(&crc32.to_le_bytes());
                        debug!("crc32: 0x{:08x}", crc32);
                    }
                    Err(e) => {
                        error!("read error {}: {}", img_path, e);
                        return false;
                    }
                }
            } else {
                error!("unsupported version: 0x{:x}", self.version);
                return false;
            }
            debug!("dvc_buffer: {:?}", dvc_buffer);

            let dvc_var = Variable::from_str("LBLDVC-871455D1-5576-4FB8-9865-AF0824463C9F").unwrap();

            // 在Linux下需要先移除immutable属性
            let write_result = with_efi_var_writable(
                "LBLDVC-871455d1-5576-4fb8-9865-af0824463c9f",
                || match varman.write(
                    &dvc_var,
                    VariableFlags::from_bits(0x7).unwrap(),
                    &dvc_buffer,
                ) {
                    Ok(rt) => {
                        debug!("write lbldvc_var: {:?}", rt);
                        Ok(())
                    }
                    Err(err) => Err(format!("write lbldvc_var failed: {}", err)),
                },
            );

            match write_result {
                Ok(_) => {
                    self.lbldvc_var = dvc_buffer;
                }
                Err(err) => {
                    error!("{}", err);
                    return false;
                }
            }
        }
        true
    }

    pub(crate) fn restore_logo(&mut self) -> bool {
        let mut status = true;
        if !delete_logo_path() {
            error!("delete logo path failed");
            status = false;
        }

        let mut varman = efivar::system();

        if self.lbl_only_mode {
            if self.lbl_var_val != 0 {
                let lbl_var = Variable::from_str("LBL-2A4DC6B7-41F5-45DD-B46F-2DD334C1CF65").unwrap();
                // 在Linux下需要先移除immutable属性
                let write_result = with_efi_var_writable(
                    "LBL-2a4dc6b7-41f5-45dd-b46f-2dd334c1cf65",
                    || match varman.write(
                        &lbl_var,
                        VariableFlags::from_bits(0x7).unwrap(),
                        &[0u8],
                    ) {
                        Ok(rt) => {
                            debug!("write lbl_var: {:?}", rt);
                            Ok(())
                        }
                        Err(err) => Err(format!("write lbl_var failed: {}", err)),
                    },
                );

                match write_result {
                    Ok(_) => {
                        self.enable = 0;
                        self.lbl_var_val = 0;
                    }
                    Err(err) => {
                        error!("{}", err);
                        status = false;
                    }
                }
            }
        } else {
            // 修改logoinfo
            let mut esp_buffer = self.lbldesp_var.clone();
            if esp_buffer[0] != 0 {
                esp_buffer[0] = 0;
                let esp_var =
                    Variable::from_str("LBLDESP-871455D0-5576-4FB8-9865-AF0824463B9E").unwrap();

                // 在Linux下需要先移除immutable属性
                let write_result =
                    with_efi_var_writable("LBLDESP-871455d0-5576-4fb8-9865-af0824463b9e", || {
                        match varman.write(
                            &esp_var,
                            VariableFlags::from_bits(0x7).unwrap(),
                            &esp_buffer,
                        ) {
                            Ok(rt) => {
                                debug!("write lbldesp_var: {:?}", rt);
                                Ok(())
                            }
                            Err(err) => Err(format!("write lbldesp_var failed: {}", err)),
                        }
                    });

                match write_result {
                    Ok(_) => {
                        self.lbldesp_var = esp_buffer;
                    }
                    Err(err) => {
                        error!("{}", err);
                        status = false;
                    }
                }
            }

            // 修改logocheck - 根据version选择清零范围
            let mut dvc_buffer = self.lbldvc_var.clone();
            let need_clear = if self.version == 0x20000 {
                // version 0x20000
                dvc_buffer[4..8] != [0u8; 4]
            } else {
                // version 0x20003...
                dvc_buffer[4..40] != [0u8; 36]
            };

            if need_clear {
                if self.version == 0x20000 {
                    // version 0x20000: 只清零CRC32 of the 4 bytes (offset 4-8)
                    dvc_buffer[4..8].clone_from_slice(&[0u8; 4]);
                } else {
                    // version 0x20003 and other: clear the whole hash area (offset 4-40)
                    dvc_buffer[4..40].clone_from_slice(&[0u8; 36]);
                }

                let dvc_var =
                    Variable::from_str("LBLDVC-871455D1-5576-4FB8-9865-AF0824463C9F").unwrap();

                let write_result = with_efi_var_writable(
                    "LBLDVC-871455d1-5576-4fb8-9865-af0824463c9f",
                    || match varman.write(
                        &dvc_var,
                        VariableFlags::from_bits(0x7).unwrap(),
                        &dvc_buffer,
                    ) {
                        Ok(rt) => {
                            debug!("write lbldvc_var: {:?}", rt);
                            Ok(())
                        }
                        Err(err) => Err(format!("write lbldvc_var failed: {}", err)),
                    },
                );

                match write_result {
                    Ok(_) => {
                        self.lbldvc_var = dvc_buffer;
                    }
                    Err(err) => {
                        error!("{}", err);
                        status = false;
                    }
                }
            }
        }
        status
    }

    fn support_format(support: u8) -> Vec<&'static str> {
        let mut support_types = Vec::new();
        if support & 0x1 == 0x1 {
            support_types.push("jpg");
        }
        if support & 0x2 == 0x2 {
            support_types.push("tga");
        }
        if support & 0x4 == 0x4 {
            support_types.push("pcx");
        }
        if support & 0x8 == 0x8 {
            support_types.push("gif");
        }
        if support & 0x10 == 0x10 {
            support_types.push("bmp");
        }
        if support & 0x20 == 0x20 {
            support_types.push("png");
        }
        support_types
    }
}

fn calculate_sha256(file_path: &str) -> io::Result<String> {
    let mut file = File::open(file_path)?;
    let mut sha256 = Sha256::new();
    let mut buffer = [0; 1024];

    loop {
        let bytes_read = file.read(&mut buffer)?;

        if bytes_read == 0 {
            break;
        }

        sha256.update(&buffer[..bytes_read]);
    }
    Ok(format!("{:x}", sha256.finalize()))
}

fn calculate_crc32_first_512(file_path: &str) -> io::Result<u32> {
    let mut file = File::open(file_path)?;
    let mut buffer = [0u8; 512];
    let bytes_read = file.read(&mut buffer)?;

    let mut hasher = Hasher::new();
    hasher.update(&buffer[..bytes_read]);
    Ok(hasher.finalize())
}
