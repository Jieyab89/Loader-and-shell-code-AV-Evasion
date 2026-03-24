//pe_structures.rs
//PE format structures for x86 and x64
//Author: iss4cf0ng/ISSAC
//GitHub: https://github.com/iss4cf0ng/IronPE

#![allow(non_snake_case, dead_code)]

use std::{fmt, u64};


//DOS Header (COFF/PE Header)
#[repr(C, packed)]
#[derive(Clone, Copy, Default)]
pub struct IMAGE_DOS_HEADER {
    pub e_magic   : u16,         //Magic number ("MZ")
    pub e_cblp    : u16,         //Bytes on last page of file
    pub e_cp      : u16,         //Pages in file
    pub e_crlc    : u16,         //Relocation
    pub e_cparhdr : u16,         //Size of header in paragraphs
    pub e_minalloc: u16,         //Minimum extra paragraphs needed
    pub e_maxalloc: u16,         //Maximum extra paragraphs needed
    pub e_ss      : u16,         //Initial (relative) SS value
    pub e_sp      : u16,         //Initial SP value
    pub e_csum    : u16,         //Checksum
    pub e_ip      : u16,         //Initial IP value
    pub e_cs      : u16,         //Initial (relative) CS value
    pub e_lfarlc  : u16,         //File address of relocation table
    pub e_ovno    : u16,         //Overlay number
    pub e_res     : [u16; 4],    //Reserved words
    pub e_oemid   : u16,         //OEM identifier
    pub e_oeminfo : u16,         //OEM information
    pub e_res2    : [u16; 10],   //Reserved words
    pub e_lfanew  : u32,         //File address of new exe header
}

//File Header (COFF/PE Header)
#[repr(C, packed)]
#[derive(Clone, Copy, Default)]
pub struct IMAGE_FILE_HEADER {
    pub machine                : u16,   //Target machien type (CPU architecture), e.g., 0x014c = Intel 386, 0x8664 = x64
    pub number_of_sections     : u16,   //Number of sections in the file
    pub time_data_stamp        : u32,   //Time the file was created (UTC, seconds since 1970-01-01)
    pub pointer_to_symbol_table: u32,   //File offset to the COFF symbol table (usually 0 in PE files)
    pub number_of_symbols      : u32,   //Number of symbols in the COFF symbol table (usually 0 in PE files)
    pub size_of_optional_header: u16,   //Size of the optional header that follows this structure
    pub characteristics        : u16,   //File characteristics flags
}

pub const IMAGE_FILE_32BIT_MACHINE: u16 = 0x0100; //Flag indicating 32-bit machine

//Data Directory
#[repr(C, packed)]
#[derive(Clone, Copy, Default)]
pub struct IMAGE_DATA_DIRECTORY {
    pub virtual_address: u32,   //RVA of the table
    pub size           : u32,   //Size of the table in bytes
}

//Optional Header (32-bit)
#[repr(C, packed)]
#[derive(Clone, Copy, Default)]
pub struct IMAGE_OPTIONAL_HEADER32 {
    pub magic                     : u16,                    //Magic number identifying PE32 format (0x10b)
    pub major_linker_version      : u8,                     //Linker major version
    pub minor_linker_version      : u8,                     //Linker minor version
    pub size_of_code              : u32,                    //Size of code section(s)
    pub size_of_initialized_data  : u32,                    //Size of initialized data section(s)
    pub size_of_uninitialized_data: u32,                    //Size of uninitialized data section(s)
    pub address_of_entry_point    : u32,                    //RVA of entry point
    pub base_of_code              : u32,                    //RVA where code section begins
    pub base_of_data              : u32,                    //RVA where data section begins
    pub image_base                : u32,                    //Preferred load address
    pub section_alignment         : u32,                    //Alignment of sections in memory
    pub file_alignment            : u32,                    //Alignment of sections in file
    pub major_os_version          : u16,                    //OS major version required
    pub minor_os_version          : u16,                    //OS minor version required
    pub major_image_version       : u16,                    //Image major version
    pub minor_image_version       : u16,                    //Image minor version
    pub major_subsystem_version   : u16,                    //Subsystem major version
    pub minor_subsystem_version   : u16,                    //Subsystem minor version
    pub win32_version_value       : u32,                    //Reserved, usually 0
    pub size_of_image             : u32,                    //Total size of image in memory
    pub size_of_headers           : u32,                    //Size of headers in file
    pub check_sum                 : u32,                    //Checksum
    pub subsystem                 : u16,                    //Subsystem required to run the image
    pub dll_characteristics       : u16,                    //DLL flags
    pub size_of_stack_reserve     : u32,                    //Size of stack to reserve
    pub size_of_stack_commit      : u32,                    //Size of stack to commit
    pub size_of_heap_reserve      : u32,                    //Size of heap to reserve
    pub size_of_heap_commit       : u32,                    //Size of heap to commit
    pub loader_flags              : u32,                    //Reserved, usually 0
    pub number_of_rva_and_sizes   : u32,                    //Number of data directories
    pub export_table              : IMAGE_DATA_DIRECTORY,
    pub import_table              : IMAGE_DATA_DIRECTORY,
    pub resource_table            : IMAGE_DATA_DIRECTORY,
    pub exception_table           : IMAGE_DATA_DIRECTORY,
    pub certificate_table         : IMAGE_DATA_DIRECTORY,
    pub base_relocation_table     : IMAGE_DATA_DIRECTORY,
    pub debug                     : IMAGE_DATA_DIRECTORY,
    pub architecture              : IMAGE_DATA_DIRECTORY,
    pub global_ptr                : IMAGE_DATA_DIRECTORY,
    pub tls_table                 : IMAGE_DATA_DIRECTORY,   //Thread Local Storage (TLS)
    pub load_config_table         : IMAGE_DATA_DIRECTORY,
    pub bound_import              : IMAGE_DATA_DIRECTORY,
    pub iat                       : IMAGE_DATA_DIRECTORY,   //Import Address Table (IAT)
    pub delay_import_descriptor   : IMAGE_DATA_DIRECTORY,
    pub clr_runtime_header        : IMAGE_DATA_DIRECTORY,
    pub reserved                  : IMAGE_DATA_DIRECTORY,
}

//Optional Header (64-bit)
#[repr(C, packed)]
#[derive(Clone, Copy, Default)]
pub struct IMAGE_OPTIONAL_HEADER64 {
    pub magic                     : u16,                    //Magic number identifying PE32+ format (0x20b)
    pub major_linker_version      : u8,
    pub minor_linker_version      : u8,
    pub size_of_code              : u32,
    pub size_of_initialized_data  : u32,
    pub size_of_uninitialized_data: u32,
    pub address_of_entry_point    : u32,
    pub base_of_code              : u32,
    pub image_base                : u64,                    //64-bit image base
    pub section_alignment         : u32,
    pub file_alignment            : u32,
    pub major_os_version          : u16,
    pub minor_os_version          : u16,
    pub major_image_version       : u16,
    pub minor_image_version       : u16,
    pub major_subsystem_version   : u16,
    pub minor_subsystem_version   : u16,
    pub win32_version_value       : u32,
    pub size_of_image             : u32,
    pub size_of_headers           : u32,
    pub check_sum                 : u32,
    pub subsystem                 : u16,
    pub dll_characteristics       : u16,
    pub size_of_stack_reserve     : u64,                    //64-bit stack reserve
    pub size_of_stack_commit      : u64,                    //64-bit stack commit
    pub size_of_heap_reserve      : u64,                    //64-bit heap reserve
    pub size_of_heap_commit       : u64,                    //64-bit heap commit
    pub loader_flags              : u32,
    pub number_of_rva_and_sizes   : u32,
    pub export_table              : IMAGE_DATA_DIRECTORY,
    pub import_table              : IMAGE_DATA_DIRECTORY,
    pub resource_table            : IMAGE_DATA_DIRECTORY,
    pub exception_table           : IMAGE_DATA_DIRECTORY,
    pub certificate_table         : IMAGE_DATA_DIRECTORY,
    pub base_relocation_table     : IMAGE_DATA_DIRECTORY,
    pub debug                     : IMAGE_DATA_DIRECTORY,
    pub architecture              : IMAGE_DATA_DIRECTORY,
    pub global_ptr                : IMAGE_DATA_DIRECTORY,
    pub tls_table                 : IMAGE_DATA_DIRECTORY,
    pub load_config_table         : IMAGE_DATA_DIRECTORY,
    pub bound_import              : IMAGE_DATA_DIRECTORY,
    pub iat                       : IMAGE_DATA_DIRECTORY,
    pub delay_import_descriptor   : IMAGE_DATA_DIRECTORY,
    pub clr_runtime_header        : IMAGE_DATA_DIRECTORY,
    pub reserved                  : IMAGE_DATA_DIRECTORY,
}

//Section Header
#[repr(C, packed)]
#[derive(Clone, Copy, Default)]
pub struct IMAGE_SECTION_HEADER {
    pub name                  : [u8; 8],   //Section name
    pub virtual_size          : u32,       //Total size in memory
    pub virtual_address       : u32,       //RVA where section is loaded
    pub size_of_raw_data      : u32,       //Size of section in file
    pub pointer_to_raw_data   : u32,       //File offset to section data
    pub pointer_to_relocations: u32,       //File offset to relocation table
    pub pointer_to_linenumbers: u32,       //File offset to line number table
    pub number_of_relocations : u16,       //Number of relocations
    pub number_of_linenumbers : u16,       //Number of line numbers
    pub characteristics       : u32,       //Section flags (code, data, executable, etc.)
}

impl IMAGE_SECTION_HEADER {
    pub fn name_str(&self) -> String {
        let nul = self.name.iter().position(|&b| b == 0).unwrap_or(8);
        String::from_utf8_lossy(&self.name[..nul]).to_string()
    }
}

impl fmt::Display for IMAGE_SECTION_HEADER {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name_str())
    }
}

//Base relocation
#[repr(C, packed)]
#[derive(Clone, Copy, Default)]
pub struct IMAGE_BASE_RELOCATION {
    pub virtual_address: u32,   //RVA of page containing relocations
    pub size_of_block  : u32,   //Size of this relocation block
}

//Import descriptor
#[repr(C, packed)]
#[derive(Clone, Copy, Default)]
pub struct IMAGE_IMPORT_DESCRIPTOR {
    pub original_first_thunk: u32,   //RVA of original IAT
    pub time_data_stamp     : u32,   //0 or timestamp
    pub forwarder_chain     : u32,   //Index of first forwarder
    pub name                : u32,   //RVA to DLL name
    pub first_thunk         : u32,   //RVA to IAT (runtime address table)
}

//Helper functions
pub unsafe fn read_struct<T: Copy>(data: *const u8, offset: usize) -> T {
    let ptr = data.add(offset) as *const T;
    return std::ptr::read_unaligned(ptr);
}

pub unsafe fn read_ansi_string(ptr: *const u8) -> String {
    let mut len = 0usize;

    //strlen()
    while *ptr.add(len) != 0 {
        len += 1;
    }

    return String::from_utf8_lossy(std::slice::from_raw_parts(ptr, len)).to_string();
}