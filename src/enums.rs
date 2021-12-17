use bitflags::bitflags;
use perf_event_open_sys::bindings::*;

pub const PERF_RECORD_MMAP: perf_event_type = perf_event_type_PERF_RECORD_MMAP;
pub const PERF_RECORD_LOST: perf_event_type = perf_event_type_PERF_RECORD_LOST;
pub const PERF_RECORD_COMM: perf_event_type = perf_event_type_PERF_RECORD_COMM;
pub const PERF_RECORD_EXIT: perf_event_type = perf_event_type_PERF_RECORD_EXIT;
pub const PERF_RECORD_THROTTLE: perf_event_type = perf_event_type_PERF_RECORD_THROTTLE;
pub const PERF_RECORD_UNTHROTTLE: perf_event_type = perf_event_type_PERF_RECORD_UNTHROTTLE;
pub const PERF_RECORD_FORK: perf_event_type = perf_event_type_PERF_RECORD_FORK;
pub const PERF_RECORD_READ: perf_event_type = perf_event_type_PERF_RECORD_READ;
pub const PERF_RECORD_SAMPLE: perf_event_type = perf_event_type_PERF_RECORD_SAMPLE;
pub const PERF_RECORD_MMAP2: perf_event_type = perf_event_type_PERF_RECORD_MMAP2;
pub const PERF_RECORD_AUX: perf_event_type = perf_event_type_PERF_RECORD_AUX;
pub const PERF_RECORD_ITRACE_START: perf_event_type = perf_event_type_PERF_RECORD_ITRACE_START;
pub const PERF_RECORD_LOST_SAMPLES: perf_event_type = perf_event_type_PERF_RECORD_LOST_SAMPLES;
pub const PERF_RECORD_SWITCH: perf_event_type = perf_event_type_PERF_RECORD_SWITCH;
pub const PERF_RECORD_SWITCH_CPU_WIDE: perf_event_type = perf_event_type_PERF_RECORD_SWITCH_CPU_WIDE;
pub const PERF_RECORD_NAMESPACES: perf_event_type = perf_event_type_PERF_RECORD_NAMESPACES;
pub const PERF_RECORD_KSYMBOL: perf_event_type = perf_event_type_PERF_RECORD_KSYMBOL;
pub const PERF_RECORD_BPF_EVENT: perf_event_type = perf_event_type_PERF_RECORD_BPF_EVENT;
pub const PERF_RECORD_CGROUP: perf_event_type = 19;
pub const PERF_RECORD_TEXT_POKE: perf_event_type = 20;

bitflags! {
    pub struct PerfSample: perf_event_sample_format {
        const IP = perf_event_sample_format_PERF_SAMPLE_IP;
        const TID = perf_event_sample_format_PERF_SAMPLE_TID;
        const TIME = perf_event_sample_format_PERF_SAMPLE_TIME;
        const ADDR = perf_event_sample_format_PERF_SAMPLE_ADDR;
        const READ = perf_event_sample_format_PERF_SAMPLE_READ;
        const CALLCHAIN = perf_event_sample_format_PERF_SAMPLE_CALLCHAIN;
        const ID = perf_event_sample_format_PERF_SAMPLE_ID;
        const CPU = perf_event_sample_format_PERF_SAMPLE_CPU;
        const PERIOD = perf_event_sample_format_PERF_SAMPLE_PERIOD;
        const STREAM_ID = perf_event_sample_format_PERF_SAMPLE_STREAM_ID;
        const RAW = perf_event_sample_format_PERF_SAMPLE_RAW;
        const BRANCH_STACK = perf_event_sample_format_PERF_SAMPLE_BRANCH_STACK;
        const REGS_USER = perf_event_sample_format_PERF_SAMPLE_REGS_USER;
        const STACK_USER = perf_event_sample_format_PERF_SAMPLE_STACK_USER;
        const WEIGHT = perf_event_sample_format_PERF_SAMPLE_WEIGHT;
        const DATA_SRC = perf_event_sample_format_PERF_SAMPLE_DATA_SRC;
        const IDENTIFIER = perf_event_sample_format_PERF_SAMPLE_IDENTIFIER;
        const TRANSACTION = perf_event_sample_format_PERF_SAMPLE_TRANSACTION;
        const REGS_INTR = perf_event_sample_format_PERF_SAMPLE_REGS_INTR;
        const PHYS_ADDR = perf_event_sample_format_PERF_SAMPLE_PHYS_ADDR;
        const AUX = perf_event_sample_format_PERF_SAMPLE_AUX;
        const CGROUP = 1 << 23;
    }

    pub struct PerfFormat: u64 {
        const TOTAL_TIME_ENABLED = perf_event_read_format_PERF_FORMAT_TOTAL_TIME_ENABLED as _;
        const TOTAL_TIME_RUNNING = perf_event_read_format_PERF_FORMAT_TOTAL_TIME_RUNNING as _;
        const ID = perf_event_read_format_PERF_FORMAT_ID as _;
        const GROUP = perf_event_read_format_PERF_FORMAT_GROUP as _;
    }
}
