//loader.rs
//PE loading logic for x86 and x64
//Author: iss4cf0ng/ISSAC
//GitHub: https://github.com/iss4cf0ng/IronPE

use std::ffi::CString;
use windows::{
    Win32::{
        Foundation::HANDLE,
        System::{
            LibraryLoader::{GetProcAddress, LoadLibraryA},
            Memory::{MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE, VirtualAlloc},
            Threading::{CreateThread, INFINITE, WaitForSingleObject},
        },
    }, core::PCSTR
};

#[allow(unused_imports)]
use crate::logger::{log_error, log_info, log_ok};
use crate::pe_structures::*;

//x86 PE loader

pub struct X86PeLoader {
    pub raw_bytes: Vec<u8>, //file bytes
    pub dos_header: IMAGE_DOS_HEADER,
    pub file_header: IMAGE_FILE_HEADER,
    pub optional_header: IMAGE_OPTIONAL_HEADER32,
    pub sections: Vec<IMAGE_SECTION_HEADER>,
}

impl X86PeLoader {
    pub fn new(bytes: Vec<u8>) -> Result<Self, String> {
        unsafe {
            let data = bytes.as_ptr();
            let dos: IMAGE_DOS_HEADER = read_struct(data, 0);
            if dos.e_magic != 0x5A4D {
                return Err("Invalid DOS signature (not MZ)".to_string());
            }

            let nt_offset = dos.e_lfanew as usize;
            let file_hdr: IMAGE_FILE_HEADER = read_struct(data, nt_offset + 4);
            let opt_hdr: IMAGE_OPTIONAL_HEADER32 = read_struct(data, nt_offset + 4 + std::mem::size_of::<IMAGE_FILE_HEADER>());
            let sections_offset = nt_offset + 4 + std::mem::size_of::<IMAGE_FILE_HEADER>() + std::mem::size_of::<IMAGE_OPTIONAL_HEADER32>();
            
            let mut sections = Vec::new();
            for i in 0..file_hdr.number_of_sections as usize {
                let sec: IMAGE_SECTION_HEADER = read_struct(data, sections_offset + i * std::mem::size_of::<IMAGE_SECTION_HEADER>());
                sections.push(sec);
            }

            Ok(Self {
                raw_bytes: bytes,
                dos_header: dos,
                file_header: file_hdr,
                optional_header: opt_hdr,
                sections,
            })
        }
    }

    pub fn is_32bit(&self) -> bool {
        return self.optional_header.magic == 0x010B; //PE32
    }
}

pub fn load_x86(pe: &X86PeLoader) -> Result<(), String> {
    unsafe {
        //Memory allocation
        let opt = &pe.optional_header;
        let image_base = VirtualAlloc(
            None,
            opt.size_of_image as usize, 
            MEM_COMMIT | MEM_RESERVE, 
            PAGE_EXECUTE_READWRITE, 
        );

        if image_base.is_null() {
            return Err("VirtualAlloc() failed".to_string());
        }

        let size_of_image = opt.size_of_image;
        log_ok(&format!("Alloced {:#X} bytes at {:#X}", size_of_image, image_base as usize));

        let base = image_base as *mut u8;
        let raw = pe.raw_bytes.as_ptr();

        //Copy headers
        std::ptr::copy_nonoverlapping(raw, base, opt.size_of_headers as usize);

        //Copy sections
        for sec in &pe.sections {
            let dest = base.add(sec.virtual_address as usize);
            std::ptr::copy_nonoverlapping(raw.add(sec.pointer_to_raw_data as usize), dest, sec.size_of_raw_data as usize);

            log_info(&format!("Section {:>8} copied to {:#X}", sec.name_str(), dest as usize));
        }

        //Relocation
        let delta = image_base as i64 - opt.image_base as i64;
        if delta != 0 {
            let reloc_dir = &opt.base_relocation_table;
            if reloc_dir.size == 0 {
                return Err("Relocation table size is zero".to_string());
            }

            let reloc_base = base.add(reloc_dir.virtual_address as usize);
            let mut offset: usize = 0;

            loop {
                let block: IMAGE_BASE_RELOCATION = read_struct(reloc_base, offset);
                if block.size_of_block == 0 {
                    break;
                }

                let count = ((block.size_of_block - 8) / 2) as usize;
                let fixup_base = base.add(block.virtual_address as usize);

                for i in 0..count {
                    let value = std::ptr::read_unaligned(reloc_base.add(offset + 8 + i * 2) as *const u16, );

                    let reloc_type = value >> 12;
                    let rva = (value & 0xFFF) as usize;

                    if reloc_type == 0x3 {
                        let patch = fixup_base.add(rva) as *mut i32;
                        let original = std::ptr::read_unaligned(patch);

                        std::ptr::write_unaligned(patch, original + delta as i32);
                    }
                }

                offset += block.size_of_block as usize;
            }
        }

        //Import libraries
        let import_dir = &opt.import_table;
        if import_dir.size == 0 {
            return Err("Import table size is zero".to_string());
        }

        let desc_size = std::mem::size_of::<IMAGE_IMPORT_DESCRIPTOR>();
        let mut desc_ptr = base.add(import_dir.virtual_address as usize) as *const IMAGE_IMPORT_DESCRIPTOR;

        loop {
            let desc: IMAGE_IMPORT_DESCRIPTOR = std::ptr::read_unaligned(desc_ptr);
            if desc.name == 0 {
                break;
            }

            let ptr_dll_name = base.add(desc.name as usize);
            let dll_name = read_ansi_string(ptr_dll_name);
            log_info(&format!("DLL: {}", dll_name));

            let dll_cstr = CString::new(dll_name.clone()).map_err(|e| e.to_string())?;
            let h_dll = LoadLibraryA(PCSTR(dll_cstr.as_ptr() as *const u8)).map_err(|e| format!("LoadLibrary({}) failed: {}", dll_name, e))?;

            let mut thunk_ref = base.add(if desc.original_first_thunk != 0 {
                desc.original_first_thunk as usize
            } else {
                desc.first_thunk as usize
            }) as *const u32;

            let mut func_ref = base.add(desc.first_thunk as usize) as *mut u32;
            loop {
                let thunk_data = std::ptr::read_unaligned(thunk_ref);
                if thunk_data == 0 {
                    break;
                }

                let func_addr = if (thunk_data & 0x80000000) != 0 {
                    //Import by ordinal
                    let oridinal = (thunk_data & 0xFFFF) as usize;
                    
                    GetProcAddress(h_dll, PCSTR(oridinal as *const u8))
                } else {
                    //Import by name
                    let pName = base.add(thunk_data as usize + 2);
                    let func_name = read_ansi_string(pName);
                    let func_cstr = CString::new(func_name).map_err(|e| e.to_string())?;

                    GetProcAddress(h_dll, PCSTR(func_cstr.as_ptr() as *const u8))
                };

                if let Some(addr) = func_addr {
                    std::ptr::write_unaligned(func_ref, addr as usize as u32);
                }

                thunk_ref = thunk_ref.add(1);
                func_ref = func_ref.add(1);
            }

            desc_ptr = (desc_ptr as *const u8).add(desc_size) as *const IMAGE_IMPORT_DESCRIPTOR;
        }

        //Go to OEP
        log_ok("Jump to OEP");
        let entry = base.add(opt.address_of_entry_point as usize);
        let hThread = CreateThread(
            None, 
            0, 
            Some(std::mem::transmute(entry as *const())), 
            None, 
            Default::default(), 
        None,
        )
        .map_err(|e| format!("CreateThread failed: {}", e))?;

        WaitForSingleObject(HANDLE(hThread.0), INFINITE);
        Ok(())
    }
}

//x64 PE loader

pub struct X64PeLoader {
    pub raw_bytes: Vec<u8>,
    pub dos_header: IMAGE_DOS_HEADER,
    pub file_header: IMAGE_FILE_HEADER,
    pub optional_header32: IMAGE_OPTIONAL_HEADER32,
    pub optional_header64: IMAGE_OPTIONAL_HEADER64,
    pub sections: Vec<IMAGE_SECTION_HEADER>,
}

impl X64PeLoader {
    pub fn new(bytes: Vec<u8>) -> Result<Self, String> {
        unsafe {
            let data = bytes.as_ptr();

            let dos: IMAGE_DOS_HEADER = read_struct(data, 0);
            if dos.e_magic != 0x5A4D {
                return Err("Invalid DOS signature (not MZ)".to_string())
            }

            let nt_offset = dos.e_lfanew as usize;
            let file_hdr: IMAGE_FILE_HEADER = read_struct(data, nt_offset + 4);
            let opt_offset = nt_offset + 4 + std::mem::size_of::<IMAGE_FILE_HEADER>();
            let is_32bit = (file_hdr.characteristics & IMAGE_FILE_32BIT_MACHINE) != 0;

            let opt32: IMAGE_OPTIONAL_HEADER32 = if is_32bit {
                read_struct(data, opt_offset)
            } else {
                Default::default()
            };

            let opt64: IMAGE_OPTIONAL_HEADER64 = if !is_32bit {
                read_struct(data, opt_offset)
            } else {
                Default::default()
            };

            let sections_offset = opt_offset + if is_32bit {
                std::mem::size_of::<IMAGE_OPTIONAL_HEADER32>()
            } else {
                std::mem::size_of::<IMAGE_OPTIONAL_HEADER64>()
            };

            let mut sections = Vec::new();
            for i in 0..file_hdr.number_of_sections as usize {
                let sec: IMAGE_SECTION_HEADER = read_struct(data, sections_offset + i * std::mem::size_of::<IMAGE_SECTION_HEADER>());
                sections.push(sec);
            }


            Ok(Self {
                raw_bytes: bytes,
                dos_header: dos,
                file_header: file_hdr,
                optional_header32: opt32,
                optional_header64: opt64,
                sections,
            })
        }
    }

    pub fn is_32bit_header(&self) -> bool {
        return (self.file_header.characteristics & IMAGE_FILE_32BIT_MACHINE) != 0;
    }
}

pub fn load_x64(pe: &X64PeLoader) -> Result<(), String> {
    unsafe {
        let opt = &pe.optional_header64;
        let raw = pe.raw_bytes.as_ptr();

        //Memory allocation
        let codebase = VirtualAlloc(
            None, 
            opt.size_of_image as usize, 
            MEM_COMMIT | MEM_RESERVE, 
            PAGE_EXECUTE_READWRITE,
        );

        if codebase.is_null() {
            return Err("VirtualAlloc() failed".to_string());
        }

        let base = codebase as *mut u8;
        let size_of_image = opt.size_of_image;
        log_ok(&format!("Allocated {:#X} bytes at {:#X}", size_of_image, codebase as usize));

        //Copy sections
        log_info("Copying sections");
        for sec in &pe.sections {
            let dest = VirtualAlloc(
                Some(base.add(sec.virtual_address as usize) as *mut _), 
                sec.size_of_raw_data as usize, 
                MEM_COMMIT, 
                PAGE_EXECUTE_READWRITE,
            );

            std::ptr::copy_nonoverlapping(raw.add(sec.pointer_to_raw_data as usize), dest as *mut u8, sec.size_of_raw_data as usize, );

            log_info(&format!("Section {:>8} copied to {:#X}", sec.name_str(), dest as usize));
        }

        //Relocation
        let delta = codebase as i64 - opt.image_base as i64;
        log_ok(&format!("Delta = {:#X}", delta));

        let reloc_va = opt.base_relocation_table.virtual_address;
        let reloc_size = opt.base_relocation_table.size;
        log_info(&format!("Relocation table VA: {:#X}, size: {:#X}", reloc_va, reloc_size));

        let reloc_table = base.add(reloc_va as usize);
        let base_reloc_size = std::mem::size_of::<IMAGE_BASE_RELOCATION>();

        let mut current_offset: usize = 0;
        let total_reloc_size = reloc_size as usize;

        while current_offset < total_reloc_size {
            let block: IMAGE_BASE_RELOCATION = read_struct(reloc_table, current_offset);
            if block.size_of_block == 0 {
                break;
            }

            let entry_count = (block.size_of_block as usize - base_reloc_size) / 2;
            let dest = base.add(block.virtual_address as usize);

            log_info(&format!("Relocation block: {} entries", entry_count));

            for i in 0..entry_count {
                let value = std::ptr::read_unaligned(reloc_table.add(current_offset + base_reloc_size + i * 2) as * const u16, );
                let reloc_type = value >> 12;
                let fixup = (value & 0xFFF) as usize;

                match reloc_type {
                    0x0 => {}
                    0xA => {
                        let patch = dest.add(fixup) as *mut i64;
                        let original = std::ptr::read_unaligned(patch);

                        std::ptr::write_unaligned(patch, original + delta);
                    }

                    _ => {}
                }
            }

            current_offset += block.size_of_block as usize;
        }

        //Import libraries
        let import_rva = opt.import_table.virtual_address as usize;
        let desc_size = std::mem::size_of::<IMAGE_IMPORT_DESCRIPTOR>();
        let mut j = 0usize;

        loop {
            let desc: IMAGE_IMPORT_DESCRIPTOR = read_struct(base, import_rva + j * desc_size);

            if desc.name == 0 {
                break;
            }

            let dll_name = read_ansi_string(base.add(desc.name as usize));
            log_info(&format!("DLL: {}", dll_name));

            let dll_cstr = CString::new(dll_name.clone()).map_err(|e| e.to_string())?;
            let h_dll = LoadLibraryA(PCSTR(dll_cstr.as_ptr() as *const u8)).map_err(|e| format!("LoadLibrary({}) failed: {}", dll_name, e))?;

            let int_rva = if desc.original_first_thunk != 0 {
                desc.original_first_thunk as usize
            } else {
                desc.first_thunk as usize
            };
            let iat_rva = desc.first_thunk as usize;

            let mut k = 0usize;
            loop {
                let thunk = std::ptr::read_unaligned(base.add(int_rva + k * 8) as *const u64);
                if thunk == 0 {
                    break;
                }

                let func_addr = if (thunk & (1u64 << 63)) != 0 {
                    //Ordinal import
                    let ordinal = (thunk & 0xFFFF) as usize;
                    GetProcAddress(h_dll, PCSTR(ordinal as *const u8))
                } else {
                    //Name import
                    let name_ptr = base.add((thunk & 0x7FFF_FFFF_FFFF) as usize + 2);
                    let func_name = read_ansi_string(name_ptr);
                    let func_cstr = CString::new(func_name).map_err(|e| e.to_string())?;
                    GetProcAddress(h_dll, PCSTR(func_cstr.as_ptr() as *const u8))
                };

                if let Some(addr) = func_addr {
                    let iat_entry = base.add(iat_rva + k * 8) as *mut u64;
                    std::ptr::write_unaligned(iat_entry, addr as usize as u64);
                }

                k += 1;
            }

            j += 1;
        }

        //Go to OEP
        log_ok("Jump to OEP");
        let entry = base.add(opt.address_of_entry_point as usize);

        let h_thread = CreateThread(
            None,
            0,
            Some(std::mem::transmute(entry as *const ())),
            None,
            Default::default(),
            None,
        )
        .map_err(|e| format!("CreateThread failed: {}", e))?;

        WaitForSingleObject(HANDLE(h_thread.0), INFINITE);
        Ok(())
    }
}