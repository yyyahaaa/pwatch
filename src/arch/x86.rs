pub const SAMPLE_REGS_USER: u64 = 0b1111_1111_0000_1111_1111_1111;

pub fn id_to_str(id: usize) -> &'static str {
    match id {
        0 => "ax",
        1 => "bx",
        2 => "cx",
        3 => "dx",
        4 => "si",
        5 => "di",
        6 => "bp",
        7 => "sp",
        8 => "ip",
        9 => "flags",
        10 => "cs",
        11 => "ss",
        12 => "r8",
        13 => "r9",
        14 => "r10",
        15 => "r11",
        16 => "r12",
        17 => "r13",
        18 => "r14",
        19 => "r15",
        _ => "unknown",
    }
}

pub fn str_to_id(reg_name: &str) -> Option<usize> {
    match reg_name {
        "ax" => Some(0),
        "bx" => Some(1),
        "cx" => Some(2),
        "dx" => Some(3),
        "si" => Some(4),
        "di" => Some(5),
        "bp" => Some(6),
        "sp" => Some(7),
        "ip" => Some(8),
        "flags" => Some(9),
        "cs" => Some(10),
        "ss" => Some(11),
        "r8" => Some(12),
        "r9" => Some(13),
        "r10" => Some(14),
        "r11" => Some(15),
        "r12" => Some(16),
        "r13" => Some(17),
        "r14" => Some(18),
        "r15" => Some(19),
        _ => None,
    }
}
