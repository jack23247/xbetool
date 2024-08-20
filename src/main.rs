mod xbe;

use std::{env, fs};
use std::process::{ExitCode};
use crate::xbe::ExtractFrom;

fn main() -> ExitCode {
    let mut xbe_data: Vec<u8>;
    {
        let args: Vec<String> = env::args().collect();
        if args.len() != 2 {
            println!("Error: Wrong number of arguments.\n\t Usage: xbetool <path_to_xbe>");
            return ExitCode::FAILURE;
        }

        let xbe_path = &args[1];

        print!("Reading file \"{}\"... ", xbe_path);

        xbe_data = match fs::read(xbe_path) {
            Ok(data) => {
                println!("OK.");
                data
            }
            Err(error) => {
                println!("failed.\n\t Reason: {}.", error.to_string());
                return ExitCode::FAILURE;
            }
        };
    }
    let xbe_data = xbe_data;
    let mut xbe_header: xbe::Header = xbe::HEADER_DEFAULTS;

    xbe_header.magic_number.extract_from(&xbe_data);

    if !xbe_header.magic_number.data.eq(&u32::from_be_bytes(xbe::MAGIC_NUMBER_STRING)) {
        println!("Error: Wrong magic number \"{}\"", String::from_utf8_lossy(&xbe_header.magic_number.data.to_be_bytes()));
        return ExitCode::FAILURE;
    }

    xbe_header.digital_signature.data.copy_from_slice(&xbe_data[0x4..0x104]);

    xbe_header.base_address.extract_from(&xbe_data);
    xbe_header.headers_size.extract_from(&xbe_data);
    xbe_header.image_size.extract_from(&xbe_data);
    xbe_header.image_header_size.extract_from(&xbe_data);
    xbe_header.time_date.extract_from(&xbe_data);
    xbe_header.cert_address.extract_from(&xbe_data);
    xbe_header.number_of_sections.extract_from(&xbe_data);
    xbe_header.section_headers_address.extract_from(&xbe_data);

    xbe_header.init_flags.extract_from(&xbe_data);
    // TODO match to one of the possible flags

    xbe_header.entry_point.extract_from(&xbe_data);
    // TODO XOR with key and check if address is valid

    xbe_header.tls_address.extract_from(&xbe_data);
    xbe_header.stack_size.extract_from(&xbe_data);
    xbe_header.pe_heap_reserve.extract_from(&xbe_data);
    xbe_header.pe_heap_commit.extract_from(&xbe_data);
    xbe_header.pe_base_address.extract_from(&xbe_data);
    xbe_header.pe_image_size.extract_from(&xbe_data);
    xbe_header.pe_checksum.extract_from(&xbe_data);
    xbe_header.pe_time_date.extract_from(&xbe_data);
    xbe_header.debug_pathname_address.extract_from(&xbe_data);
    xbe_header.debug_filename_address.extract_from(&xbe_data);
    xbe_header.utf16_debug_file_name_address.extract_from(&xbe_data);
    xbe_header.kernel_image_thunk_address.extract_from(&xbe_data);
    xbe_header.non_kernel_import_dir_address.extract_from(&xbe_data);
    xbe_header.number_of_library_versions.extract_from(&xbe_data);
    xbe_header.library_versions_address.extract_from(&xbe_data);
    xbe_header.kernel_library_versions_address.extract_from(&xbe_data);
    xbe_header.xapi_library_version_address.extract_from(&xbe_data);
    xbe_header.logo_bitmap_address.extract_from(&xbe_data);
    xbe_header.logo_bitmap_size.extract_from(&xbe_data);
    xbe_header.unknown_1.extract_from(&xbe_data);
    xbe_header.unknown_2.extract_from(&xbe_data);

    let xbe_header = xbe_header;

    println!("Header:\n{}", xbe_header);

    ExitCode::SUCCESS
}
