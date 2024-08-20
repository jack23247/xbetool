/**
 * @file xbe.rs
 * @author Jacopo Maltagliati
 * @brief XBE file description
 * @copyright Copyright (c) 2024, Jacopo Maltagliati.
 *            Released under the MIT License.
 */

// https://xboxdevwiki.net/XBE

use std::fmt::{Display};

pub enum InitFlags {
    MountUtilityDrive = 0x00000001,
    FormatUtilityDrive = 0x00000002,
    Limit64Megabytes = 0x00000004,
    DontSetupHarddisk = 0x00000008,
}

pub enum EntryPointKeys {
    Beta = 0xE682F45B,
    Debug = 0x94859D4B,
    Retail = 0xA8FC57AB,
}

pub enum KernelThunkKeys {
    Beta = 0x46437DCD,
    Debug = 0xEFB1F152,
    Retail = 0x5B6D40B6,
}

pub enum LibraryFlags {
    QFEVersion = 0x1FFF,
    Approved = 0x6000,
    DebugBuild = 0x8000,
}

pub struct HeaderFieldDesc<'a, T> {
    pub offset: usize,
    pub default: T,
    pub name: &'a str,
    pub desc: &'a str,
}

pub trait ExtractFrom {
    fn extract_from(&mut self, data: &Vec<u8>);
}

impl ExtractFrom for HeaderField<u32> {
    fn extract_from(&mut self, data: &Vec<u8>) {
        self.data = u32::from_be_bytes(data[self.desc.offset..(self.desc.offset + size_of::<u32>())].try_into().unwrap())
    }
}

impl ExtractFrom for HeaderField<u64> {
    fn extract_from(&mut self, data: &Vec<u8>) {
        self.data = u64::from_be_bytes(data[self.desc.offset..(self.desc.offset + size_of::<u64>())].try_into().unwrap())
    }
}

impl Display for HeaderField<u32> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", format!("{}: {:#010X}", &self.desc.name, &self.data))
    }
}

impl Display for HeaderField<u64> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", format!("{}: {:#018X}", &self.desc.name, &self.data))
    }
}

impl Display for HeaderField<[u8; 256]> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", todo!())
    }
}

impl HeaderFieldDesc<'_, u32> {
    pub const MAGIC_NUMBER: HeaderFieldDesc<'static, u32> = HeaderFieldDesc {
        offset: 0x0000,
        default: 0x00000000,
        name: "Magic Number",
        desc: "Used to identify an XBOX Executable, must be equal to \"XBEH\"",
    };

    pub const BASE_ADDRESS: HeaderFieldDesc<'static, u32> = HeaderFieldDesc {
        offset: 0x0104,
        default: 0x00000000,
        name: "Base Address",
        desc: "Address at which to load this .xbe. Typically this will be 0x00010000.",
    };

    pub const HEADERS_SIZE: HeaderFieldDesc<'static, u32> = HeaderFieldDesc {
        offset: 0x0108,
        default: 0x00000000,
        name: "Size of Headers",
        desc: "Number of bytes that should be reserved for headers.",
    };

    pub const IMAGE_SIZE: HeaderFieldDesc<'static, u32> = HeaderFieldDesc {
        offset: 0x010C,
        default: 0x00000000,
        name: "Size of Image",
        desc: "Number of bytes that should be reserved for this image.",
    };

    pub const IMAGE_HEADER_SIZE: HeaderFieldDesc<'static, u32> = HeaderFieldDesc {
        offset: 0x0110,
        default: 0x00000000,
        name: "Size of Image Header",
        desc: "Number of bytes that should be reserved for the image header. The header size varies by XDK version, but is at least 0x178.",
    };

    pub const TIMEDATE: HeaderFieldDesc<'static, u32> = HeaderFieldDesc {
        offset: 0x0114,
        default: 0x00000000,
        name: "TimeDate",
        desc: "Time and Date when this image was created. UNIX timestamp format.",
    };

    pub const CERT_ADDRESS: HeaderFieldDesc<'static, u32> = HeaderFieldDesc {
        offset: 0x0118,
        default: 0x00000000,
        name: "Certificate Address",
        desc: "Address to a Certificate structure, after the .xbe is loaded into memory.",
    };

    pub const NUMBER_OF_SECTIONS: HeaderFieldDesc<'static, u32> = HeaderFieldDesc {
        offset: 0x011C,
        default: 0x00000000,
        name: "Number of Sections",
        desc: "Number of sections contained in this .xbe.",
    };

    pub const SECTION_HEADERS_ADDRESS: HeaderFieldDesc<'static, u32> = HeaderFieldDesc {
        offset: 0x0120,
        default: 0x00000000,
        name: "Section Headers Address",
        desc: "Address to an array of SectionHeader structures, after the .xbe is loaded into memory.",
    };

    pub const INIT_FLAGS: HeaderFieldDesc<'static, u32> = HeaderFieldDesc {
        offset: 0x0124,
        default: 0x00000000,
        name: "Initialization Flags",
        desc: "Various flags for this .xbe file",
    };

    pub const ENTRY_POINT: HeaderFieldDesc<'static, u32> = HeaderFieldDesc {
        offset: 0x0128,
        default: 0x00000000,
        name: "Entry Point",
        desc: "Address to the Image entry point, after the .xbe is loaded into memory. This is where execution starts. This value is encoded with an XOR key",
    };

    pub const TLS_ADDRESS: HeaderFieldDesc<'static, u32> = HeaderFieldDesc {
        offset: 0x012C,
        default: 0x00000000,
        name: "TLS Address",
        desc: "Address to a TLS (Thread Local Storage) structure.",
    };

    pub const STACK_SIZE: HeaderFieldDesc<'static, u32> = HeaderFieldDesc {
        offset: 0x0130,
        default: 0x00000000,
        name: "Stack Size",
        desc: "Default stack size. As the Xbox does not allow for stacks to grow, this needs to be copied from the SizeOfStackReserve PE field, not SizeOfStackCommit!",
    };

    pub const PE_HEAP_RESERVE: HeaderFieldDesc<'static, u32> = HeaderFieldDesc {
        offset: 0x0134,
        default: 0x00000000,
        name: "PE Heap Reserve",
        desc: "Copied from the PE file this .xbe was created from.",
    };

    pub const PE_HEAP_COMMIT: HeaderFieldDesc<'static, u32> = HeaderFieldDesc {
        offset: 0x0138,
        default: 0x00000000,
        name: "PE Heap Commit",
        desc: "Copied from the PE file this .xbe was created from.",
    };

    pub const PE_BASE_ADDRESS: HeaderFieldDesc<'static, u32> = HeaderFieldDesc {
        offset: 0x013C,
        default: 0x00000000,
        name: "PE Base Address",
        desc: "Copied from the PE file this .xbe was created from.",
    };

    pub const PE_IMAGE_SIZE: HeaderFieldDesc<'static, u32> = HeaderFieldDesc {
        offset: 0x0140,
        default: 0x00000000,
        name: "PE Size of Image",
        desc: "Copied from the PE file this .xbe was created from.",
    };

    pub const PE_CHECKSUM: HeaderFieldDesc<'static, u32> = HeaderFieldDesc {
        offset: 0x0144,
        default: 0x00000000,
        name: "PE Checksum",
        desc: "Copied from the PE file this .xbe was created from.",
    };

    pub const PE_TIMEDATE: HeaderFieldDesc<'static, u32> = HeaderFieldDesc {
        offset: 0x0148,
        default: 0x00000000,
        name: "PE TimeDate",
        desc: "Copied from the PE file this .xbe was created from (UNIX timestamp format).",
    };

    pub const DEBUG_PATHNAME_ADDRESS: HeaderFieldDesc<'static, u32> = HeaderFieldDesc {
        offset: 0x014C,
        default: 0x00000000,
        name: "Debug PathName Address",
        desc: "Address to the debug pathname (i.e. \"D:\\Nightlybuilds\\011026.0\\code\\build\\xbox\\Release\\simpsons.exe\").",
    };

    pub const DEBUG_FILENAME_ADDRESS: HeaderFieldDesc<'static, u32> = HeaderFieldDesc {
        offset: 0x0150,
        default: 0x00000000,
        name: "Debug FileName Address",
        desc: "Address to the debug filename (i.e. \"simpsons.exe\").",
    };

    pub const UTF16_DEBUG_FILENAME_ADDRESS: HeaderFieldDesc<'static, u32> = HeaderFieldDesc {
        offset: 0x0154,
        default: 0x00000000,
        name: "UTF-16 Debug FileName Address",
        desc: "Address to the UTF-16 debug filename (i.e. L\"simpsons.exe\")",
    };

    pub const KERNEL_IMAGE_THUNK_ADDRESS: HeaderFieldDesc<'static, u32> = HeaderFieldDesc {
        offset: 0x0158,
        default: 0x00000000,
        name: "Kernel Image Thunk Address",
        desc: "Address to the Kernel Image Thunk Table, after the .xbe is loaded into memory. This is how .xbe files import kernel functions and data.",
    };

    pub const NON_KERNEL_IMPORT_DIR_ADDRESS: HeaderFieldDesc<'static, u32> = HeaderFieldDesc {
        offset: 0x015C,
        default: 0x00000000,
        name: "Non-Kernel Import Directory Address",
        desc: "Address to the Non-Kernel Import Directory. It is typically safe to set this to zero.",
    };

    pub const NUMBER_OF_LIBRARY_VERSIONS: HeaderFieldDesc<'static, u32> = HeaderFieldDesc {
        offset: 0x0160,
        default: 0x00000000,
        name: "Number of Library Versions",
        desc: "Number of Library Versions pointed to by Library Versions Address.",
    };

    pub const LIBRARY_VERSIONS_ADDRESS: HeaderFieldDesc<'static, u32> = HeaderFieldDesc {
        offset: 0x0164,
        default: 0x00000000,
        name: "Library Versions Address",
        desc: "Address to an array of LibraryVersion structures, after the .xbe is loaded into memory.",
    };

    pub const KERNEL_LIBRARY_VERSION_ADDRESS: HeaderFieldDesc<'static, u32> = HeaderFieldDesc {
        offset: 0x0168,
        default: 0x00000000,
        name: "Kernel Library Version Address",
        desc: "Address to a LibraryVersion structure, after the .xbe is loaded into memory.",
    };

    pub const XAPI_LIBRARY_VERSION_ADDRESS: HeaderFieldDesc<'static, u32> = HeaderFieldDesc {
        offset: 0x016C,
        default: 0x00000000,
        name: "XAPI Library Version Address",
        desc: "Address to a LibraryVersion structure, after the .xbe is loaded into memory.",
    };

    pub const LOGO_BITMAP_ADDRESS: HeaderFieldDesc<'static, u32> = HeaderFieldDesc {
        offset: 0x0170,
        default: 0x00000000,
        name: "Logo Bitmap Address",
        desc: "Address to the Logo Bitmap (Typically a 'Microsoft' logo). The format of this image is described here. This field can be set to zero, meaning there is no bitmap present.",
    };

    pub const LOGO_BITMAP_SIZE: HeaderFieldDesc<'static, u32> = HeaderFieldDesc {
        offset: 0x0174,
        default: 0x00000000,
        name: "Logo Bitmap Size",
        desc: "Size (in bytes) of the Logo Bitmap data. The format of this image is described here.",
    };

    pub const UNKNOWN2: HeaderFieldDesc<'static, u32> = HeaderFieldDesc {
        offset: 0x0180,
        default: 0x00000000,
        name: "Unknown2",
        desc: "The meaning of this field hasn't been figured out yet. It only exists on XBEs built with an XDK version >= 5455.",
    };
}

impl HeaderFieldDesc<'static, [u8; 256]> {
    pub const DIGITAL_SIGNATURE: HeaderFieldDesc<'static, [u8; 256]> = HeaderFieldDesc {
        offset: 0x0004,
        default: [0x00; 256],
        name: "Digital Signature",
        desc: "256 Bytes. This is where a game is signed. Only on officially signed games is this field worthwhile",
    };
}

impl HeaderFieldDesc<'static, u64> {
    pub const UNKNOWN1: HeaderFieldDesc<'static, u64> = HeaderFieldDesc {
        offset: 0x0178,
        default: 0x0000000000000000,
        name: "Unknown1",
        desc: "The meaning of this field hasn't been figured out yet. It only exists on XBEs built with an XDK version >= 5028.",
    };
}

// Why isn't this placed on the stack by default??
pub const MAGIC_NUMBER_STRING: [u8; 4] = *b"XBEH";

pub struct LibraryVersion {
    pub library_name: [char; 8],
    pub major_version: u16,
    pub minor_version: u16,
    pub build_version: u16,
    pub library_flags: u32,
}

pub struct TLSTable {
    pub raw_data_start: u32,
    pub raw_data_end: u32,
    pub index_address: u32,
    pub callbacks_address: u32,
    pub zero_fill_size: u32,
    pub characteristics: u32,
}

pub struct HeaderField<T> {
    pub desc: HeaderFieldDesc<'static, T>,
    pub data: T,
}

pub struct Header {
    pub magic_number: HeaderField<u32>,
    pub digital_signature: HeaderField<[u8; 256]>,
    pub base_address: HeaderField<u32>,
    pub headers_size: HeaderField<u32>,
    pub image_size: HeaderField<u32>,
    pub image_header_size: HeaderField<u32>,
    pub time_date: HeaderField<u32>,
    pub cert_address: HeaderField<u32>,
    pub number_of_sections: HeaderField<u32>,
    pub section_headers_address: HeaderField<u32>,
    pub init_flags: HeaderField<u32>,
    pub entry_point: HeaderField<u32>,
    pub tls_address: HeaderField<u32>,
    pub stack_size: HeaderField<u32>,
    pub pe_heap_reserve: HeaderField<u32>,
    pub pe_heap_commit: HeaderField<u32>,
    pub pe_base_address: HeaderField<u32>,
    pub pe_image_size: HeaderField<u32>,
    pub pe_checksum: HeaderField<u32>,
    pub pe_time_date: HeaderField<u32>,
    pub debug_pathname_address: HeaderField<u32>,
    pub debug_filename_address: HeaderField<u32>,
    pub utf16_debug_file_name_address: HeaderField<u32>,
    pub kernel_image_thunk_address: HeaderField<u32>,
    pub non_kernel_import_dir_address: HeaderField<u32>,
    pub number_of_library_versions: HeaderField<u32>,
    pub library_versions_address: HeaderField<u32>,
    pub kernel_library_versions_address: HeaderField<u32>,
    pub xapi_library_version_address: HeaderField<u32>,
    pub logo_bitmap_address: HeaderField<u32>,
    pub logo_bitmap_size: HeaderField<u32>,
    pub unknown_1: HeaderField<u64>,
    pub unknown_2: HeaderField<u32>,
}

impl Display for Header {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "{} ({})", self.magic_number, String::from_utf8_lossy(&self.magic_number.data.to_be_bytes()));
        writeln!(f, "{}", self.base_address);
        writeln!(f, "{}", self.headers_size);
        writeln!(f, "{}", self.image_size);
        writeln!(f, "{}", self.image_header_size);
        writeln!(f, "{}", self.time_date);
        writeln!(f, "{}", self.cert_address);
        writeln!(f, "{}", self.number_of_sections);
        writeln!(f, "{}", self.section_headers_address);
        writeln!(f, "{}", self.init_flags);
        writeln!(f, "{}", self.entry_point);
        writeln!(f, "{}", self.tls_address);
        writeln!(f, "{}", self.stack_size);
        writeln!(f, "{}", self.pe_heap_reserve);
        writeln!(f, "{}", self.pe_heap_commit);
        writeln!(f, "{}", self.pe_base_address);
        writeln!(f, "{}", self.pe_image_size);
        writeln!(f, "{}", self.pe_checksum);
        writeln!(f, "{}", self.pe_time_date);
        writeln!(f, "{}", self.debug_pathname_address);
        writeln!(f, "{}", self.debug_filename_address);
        writeln!(f, "{}", self.utf16_debug_file_name_address);
        writeln!(f, "{}", self.kernel_image_thunk_address);
        writeln!(f, "{}", self.non_kernel_import_dir_address);
        writeln!(f, "{}", self.number_of_library_versions);
        writeln!(f, "{}", self.library_versions_address);
        writeln!(f, "{}", self.kernel_library_versions_address);
        writeln!(f, "{}", self.xapi_library_version_address);
        writeln!(f, "{}", self.logo_bitmap_address);
        writeln!(f, "{}", self.logo_bitmap_size);
        writeln!(f, "{}", self.unknown_1);
        write!(f, "{}", self.unknown_2)
    }
}

pub const HEADER_DEFAULTS: Header = Header {
    magic_number: HeaderField {
        desc: HeaderFieldDesc::MAGIC_NUMBER,
        data: HeaderFieldDesc::MAGIC_NUMBER.default,
    },
    digital_signature: HeaderField {
        desc: HeaderFieldDesc::DIGITAL_SIGNATURE,
        data: [0x00; 256],
    },
    base_address: HeaderField {
        desc: HeaderFieldDesc::BASE_ADDRESS,
        data: 0x0000,
    },
    headers_size: HeaderField {
        desc: HeaderFieldDesc::HEADERS_SIZE,
        data: 0x0000,
    },
    image_size: HeaderField {
        desc: HeaderFieldDesc::IMAGE_SIZE,
        data: 0x0000,
    },
    image_header_size: HeaderField {
        desc: HeaderFieldDesc::IMAGE_HEADER_SIZE,
        data: 0x0000,
    },
    time_date: HeaderField {
        desc: HeaderFieldDesc::TIMEDATE,
        data: 0x0000,
    },
    cert_address: HeaderField {
        desc: HeaderFieldDesc::CERT_ADDRESS,
        data: 0x0000,
    },
    number_of_sections: HeaderField {
        desc: HeaderFieldDesc::NUMBER_OF_SECTIONS,
        data: 0x0000,
    },
    section_headers_address: HeaderField {
        desc: HeaderFieldDesc::SECTION_HEADERS_ADDRESS,
        data: 0x0000,
    },
    init_flags: HeaderField {
        desc: HeaderFieldDesc::INIT_FLAGS,
        data: 0x0000,
    },
    entry_point: HeaderField {
        desc: HeaderFieldDesc::ENTRY_POINT,
        data: 0x0000,
    },
    tls_address: HeaderField {
        desc: HeaderFieldDesc::TLS_ADDRESS,
        data: 0x0000,
    },
    stack_size: HeaderField {
        desc: HeaderFieldDesc::STACK_SIZE,
        data: 0x0000,
    },
    pe_heap_reserve: HeaderField {
        desc: HeaderFieldDesc::PE_HEAP_RESERVE,
        data: 0x0000,
    },
    pe_heap_commit: HeaderField {
        desc: HeaderFieldDesc::PE_HEAP_COMMIT,
        data: 0x0000,
    },
    pe_base_address: HeaderField {
        desc: HeaderFieldDesc::PE_BASE_ADDRESS,
        data: 0x0000,
    },
    pe_image_size: HeaderField {
        desc: HeaderFieldDesc::PE_IMAGE_SIZE,
        data: 0x0000,
    },
    pe_checksum: HeaderField {
        desc: HeaderFieldDesc::PE_CHECKSUM,
        data: 0x0000,
    },
    pe_time_date: HeaderField {
        desc: HeaderFieldDesc::PE_TIMEDATE,
        data: 0x0000,
    },
    debug_pathname_address: HeaderField {
        desc: HeaderFieldDesc::DEBUG_PATHNAME_ADDRESS,
        data: 0x0000,
    },
    debug_filename_address: HeaderField {
        desc: HeaderFieldDesc::DEBUG_FILENAME_ADDRESS,
        data: 0x0000,
    },
    utf16_debug_file_name_address: HeaderField {
        desc: HeaderFieldDesc::UTF16_DEBUG_FILENAME_ADDRESS,
        data: 0x0000,
    },
    kernel_image_thunk_address: HeaderField {
        desc: HeaderFieldDesc::KERNEL_IMAGE_THUNK_ADDRESS,
        data: 0x0000,
    },
    non_kernel_import_dir_address: HeaderField {
        desc: HeaderFieldDesc::NON_KERNEL_IMPORT_DIR_ADDRESS,
        data: 0x0000,
    },
    number_of_library_versions: HeaderField {
        desc: HeaderFieldDesc::NUMBER_OF_LIBRARY_VERSIONS,
        data: 0x0000,
    },
    library_versions_address: HeaderField {
        desc: HeaderFieldDesc::LIBRARY_VERSIONS_ADDRESS,
        data: 0x0000,
    },
    kernel_library_versions_address: HeaderField {
        desc: HeaderFieldDesc::KERNEL_LIBRARY_VERSION_ADDRESS,
        data: 0x0000,
    },
    xapi_library_version_address: HeaderField {
        desc: HeaderFieldDesc::XAPI_LIBRARY_VERSION_ADDRESS,
        data: 0x0000,
    },
    logo_bitmap_address: HeaderField {
        desc: HeaderFieldDesc::LOGO_BITMAP_ADDRESS,
        data: 0x0000,
    },
    logo_bitmap_size: HeaderField {
        desc: HeaderFieldDesc::LOGO_BITMAP_SIZE,
        data: 0x0000,
    },
    unknown_1: HeaderField {
        desc: HeaderFieldDesc::UNKNOWN1,
        data: 0x00000000,
    },
    unknown_2: HeaderField {
        desc: HeaderFieldDesc::UNKNOWN2,
        data: 0x0000,
    },
};