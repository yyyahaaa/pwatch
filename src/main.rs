use clap::Parser;
use colored::Colorize;
use log::error;
use perf::{PerfMap, SampleData};
use perf_event_open_sys as sys;
use std::io;
use libc::{iovec, process_vm_readv, pid_t, c_void};
use procfs::process::{Process, MMapPath};

mod arch;
mod perf;

#[derive(Parser)]
struct Args {
    #[arg(long, default_value = "0")]
    /// buffer size, in power of 2. For example, 2 means 2^2 pages = 4 * 4096 bytes.
    buf_size: usize,
    #[arg(short)]
    /// whether the target is a thread or a process.
    thread: bool,
    #[arg(short, long)]
    /// whether to print backtrace.
    backtrace: bool,
    /// target pid, if thread is true, this is the tid of the target thread.
    pid: u32,
    /// watchpoint type, can be read(r), write(w), readwrite(rw) or execve(x).
    /// if it is one of r, w, rw, the watchpoint length is needed. Valid length is 1, 2, 4, 8.
    /// For example, r4 means a read watchpoint with length 4 and rw1 means a readwrite watchpoint with length 1.
    r#type: String,
    /// watchpoint address, in hex format. 0x prefix is optional.
    addr: String,
    
    #[arg(short, long, num_args = 1..)]
    /// specify the registers to read as const char* pointers.
    xregs: Vec<String>,

    #[arg(short, long)]
    /// if provided, read the string at the register value address.
    string: bool,

    #[arg(long)]
    /// specify the shared object file.
    so: Option<String>,
}

fn parse_len(s: &str) -> Option<u32> {
    match s {
        "1" => Some(sys::bindings::HW_BREAKPOINT_LEN_1),
        "2" => Some(sys::bindings::HW_BREAKPOINT_LEN_2),
        "4" => Some(sys::bindings::HW_BREAKPOINT_LEN_4),
        "8" => Some(sys::bindings::HW_BREAKPOINT_LEN_8),
        "" => Some(sys::bindings::HW_BREAKPOINT_LEN_1),
        _ => None,
    }
}

fn parse_watchpoint_type(s: &str) -> Option<(u32, u32)> {
    if let Some(s) = s.strip_prefix("rw") {
        let len = parse_len(s)?;
        Some((sys::bindings::HW_BREAKPOINT_RW, len))
    } else if let Some(s) = s.strip_prefix('r') {
        let len = parse_len(s)?;
        Some((sys::bindings::HW_BREAKPOINT_R, len))
    } else if let Some(s) = s.strip_prefix('w') {
        let len = parse_len(s)?;
        Some((sys::bindings::HW_BREAKPOINT_W, len))
    } else if s == "x" {
        Some((
            sys::bindings::HW_BREAKPOINT_X,
            std::mem::size_of::<nix::libc::c_long>() as u32,
        ))
    } else {
        None
    }
}

fn parse_addr(s: &str) -> Option<u64> {
    u64::from_str_radix(s.strip_prefix("0x").unwrap_or(s), 16).ok()
}

fn get_so_base_address(pid: u32, so_name: &str) -> Option<u64> {
    let process = Process::new(pid as i32).ok()?;
    let maps = process.maps().ok()?;
    for map in maps {
        if let MMapPath::Path(path) = map.pathname {
            if path.to_string_lossy().contains(so_name) {
                return Some(map.address.0);
            }
        }
    }
    None
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    pretty_env_logger::init();
    let args = Args::parse();

    let (ty, bp_len) = parse_watchpoint_type(&args.r#type)
        .ok_or_else(|| anyhow::anyhow!(format!("invalid watchpoint type: {}", args.r#type)))?;

    let addr = if let Some(so_name) = &args.so {
        let base_addr = get_so_base_address(args.pid, so_name)
            .ok_or_else(|| anyhow::anyhow!(format!("failed to find base address for {}", so_name)))?;
        let offset = parse_addr(&args.addr)
            .ok_or_else(|| anyhow::anyhow!(format!("invalid address: {}", args.addr)))?;
        base_addr + offset
    } else {
        parse_addr(&args.addr)
            .ok_or_else(|| anyhow::anyhow!(format!("invalid address: {}", args.addr)))?
    };

    let maps = if !args.thread {
        procfs::process::Process::new(args.pid as i32)?
            .tasks()?
            .filter_map(Result::ok)
            .map(|t| {
                PerfMap::new(
                    ty,
                    addr,
                    bp_len as u64,
                    t.tid,
                    args.buf_size,
                    args.backtrace,
                )
            })
            .filter_map(|r| match r {
                Ok(m) => Some(m),
                Err(e) => {
                    error!("perf_map_open error: {}", e);
                    None
                }
            })
            .collect::<Vec<_>>()
    } else {
        vec![PerfMap::new(
            ty,
            addr,
            bp_len as u64,
            args.pid as i32,
            args.buf_size,
            args.backtrace,
        )?]
    };
    if maps.is_empty() {
        error!("no valid perf map");
        return Ok(());
    }
    let (res, _, _) = futures::future::select_all(maps.into_iter().map(|m| {
        let xregs = args.xregs.clone();
        let string = args.string;
        tokio::spawn(async move {
            if let Err(e) = m.events(move |data| handle_event(data, &xregs, string)).await {
                error!("error: {}", e);
            }
        })
    }))
    .await;
    res?;
    Ok(())
}

fn handle_event(data: SampleData, xregs: &Vec<String>, read_string: bool) {
    println!("-------");
    println!(
        "{}: {} {}: {}",
        "pid".yellow().bold(),
        data.pid,
        "tid".yellow().bold(),
        data.tid
    );
    for (i, reg) in data.regs.iter().enumerate() {
        print!("{:>5}: 0x{:016x} ", arch::id_to_str(i).bold().blue(), reg);
        if (i + 1) % 4 == 0 {
            println!();
        }
    }
    if data.regs.len() % 4 != 0 {
        println!();
    }

    // 打印寄存器指向的地址处内容
    if !xregs.is_empty() {
        println!("{}", "XRegs:".yellow().bold());
    }
    for xreg in xregs {
        if let Some(reg_index) = arch::str_to_id(xreg) {
            if let Some(&reg_value) = data.regs.get(reg_index) {
                let reg_value = reg_value & 0xFFFFFFFFFF;
                println!(" {:>3}: 0x{:016x}", xreg.blue().bold(), reg_value); // Print reg_value
                if reg_value != 0 {
                    // Check if the register value is within the user space address range
                    if reg_value < 0x7FFFFFFFFF {
                        if read_string {
                            // Attempt to read the string from the address using process_vm_readv
                            match read_string_from_process(data.pid as libc::pid_t, reg_value) {
                                Ok(string) => println!("{}: {}", "   String".green().bold(), string),
                                Err(e) => println!("{}: Failed to read string: {}", xreg.yellow().bold(), e),
                            }
                        } else {
                            match read_bytes_from_process(data.pid as libc::pid_t, reg_value, 8) {
                                Ok(bytes) => println!("{}: {}", "   Bytes".green().bold(), format_bytes(&bytes)),
                                Err(e) => println!("{}: Failed to read bytes: {}", xreg.yellow().bold(), e),
                            }
                        }
                    } else {
                        println!("      {}", "Address out of user space range".red().bold());
                    }
                } else {
                    println!("      {}", "Null pointer".red().bold());
                }
            } else {
                println!("      {}", "Register not available".red().bold());
            }
        } else {
            println!("      {}", "Invalid register name".red().bold());
        }
    }

    if let Some(backtrace) = data.backtrace {
        println!("{}:", "backtrace".yellow().bold());
        for addr in backtrace {
            println!("  0x{:016x}", addr);
        }
    }
}

fn read_string_from_process(pid: pid_t, addr: u64) -> Result<String, io::Error> {
    const MAX_STRING_LENGTH: usize = 256; // Define a maximum string length to read
    let mut buffer = vec![0u8; MAX_STRING_LENGTH];

    let local_iov = iovec {
        iov_base: buffer.as_mut_ptr() as *mut c_void,
        iov_len: buffer.len(),
    };

    let remote_iov = iovec {
        iov_base: addr as *mut c_void,
        iov_len: buffer.len(),
    };

    let nread = unsafe {
        process_vm_readv(
            pid,
            &local_iov as *const iovec,
            1,
            &remote_iov as *const iovec,
            1,
            0,
        )
    };

    if nread == -1 {
        return Err(io::Error::last_os_error());
    }

    // Find the null terminator to determine the actual string length
    if let Some(pos) = buffer.iter().position(|&c| c == 0) {
        buffer.truncate(pos);
    }

    Ok(String::from_utf8_lossy(&buffer).to_string())
}

fn read_bytes_from_process(pid: pid_t, addr: u64, len: usize) -> Result<Vec<u8>, io::Error> {
    let mut buffer = vec![0u8; len];

    let local_iov = iovec {
        iov_base: buffer.as_mut_ptr() as *mut c_void,
        iov_len: buffer.len(),
    };

    let remote_iov = iovec {
        iov_base: addr as *mut c_void,
        iov_len: buffer.len(),
    };

    let nread = unsafe {
        process_vm_readv(
            pid,
            &local_iov as *const iovec,
            1,
            &remote_iov as *const iovec,
            1,
            0,
        )
    };

    if nread == -1 {
        return Err(io::Error::last_os_error());
    }

    Ok(buffer)
}

fn format_bytes(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02X}", b)).collect::<Vec<_>>().join(" ")
}