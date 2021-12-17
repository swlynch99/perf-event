//! Types for reading the data returned by the kernel within the perf_events
//! ringbuffer.
//!

use crate::{PerfFormat, PerfSample};
use perf_event_open_sys::bindings::{perf_branch_entry, perf_event_attr, perf_event_header};
use std::borrow::Cow;
use std::convert::TryInto;
use std::ffi::OsStr;
use std::fmt;
use std::mem::size_of;
use std::os::unix::prelude::OsStrExt;

pub struct Record<'a> {
    sample: PerfSample,
    format: PerfFormat,
    sample_id_all: bool,
    data: Cow<'a, [u8]>,
}

impl<'a> Record<'a> {
    /// Create a record from existing data.
    ///
    /// # Panics
    /// - Panics if `data` is too small to contain even the required
    ///   `perf_event_header`.
    /// - Panics if `data` is improperly aligned. This should only occur if
    ///   `data` is a reference to an arbitrary slice.
    pub fn new(attrs: &perf_event_attr, mut data: Cow<'a, [u8]>) -> Self {
        assert!(data.len() >= size_of::<perf_event_header>());
        // Some sample types are not supported yet.
        assert!(attrs.sample_type & PerfSample::READ.bits() == 0);
        assert!(attrs.sample_type & PerfSample::REGS_USER.bits() == 0);
        assert!(attrs.sample_type & PerfSample::REGS_INTR.bits() == 0);

        if data.as_ptr() as usize % std::mem::align_of::<perf_event_header>() != 0 {
            data = data.to_owned();
        }

        Self {
            sample: PerfSample::from_bits(attrs.sample_type)
                .expect("sample_type contained unexpected bit flags"),
            format: PerfFormat::from_bits(attrs.read_format)
                .expect("read_format contained unexpected bit flags"),
            sample_id_all: attrs.sample_id_all() != 0,
            data,
        }
    }

    /// Convert this record into one which owns it's own data. If the data is
    /// already owned then this is a no-op.
    pub fn into_owned(self) -> Record<'static> {
        Record {
            sample: self.sample,
            format: self.format,
            sample_id_all: self.sample_id_all,
            data: Cow::Owned(self.data.into_owned()),
        }
    }

    /// Get a reference to the stored header.
    pub fn header(&self) -> &perf_event_header {
        let (head, slice, _) = unsafe { self.data.align_to() };
        assert!(head.len() == 0);
        &slice[0]
    }

    pub fn sample_id(&self) -> Option<SampleId<'a, '_>> {
        if !self.sample_id_all {
            return None;
        }

        Some(SampleId {
            record: self,
            offset: self.data.len() - SampleId::expected_len(self.sample),
        })
    }

    fn u64_at(&self, offset: usize) -> u64 {
        assert!(offset < self.data.len());

        u64::from_ne_bytes(self.data[offset..][..size_of::<u64>()].try_into().unwrap())
    }

    fn u32_at(&self, offset: usize) -> u32 {
        assert!(offset < self.data.len());

        u32::from_ne_bytes(self.data[offset..][..size_of::<u32>()].try_into().unwrap())
    }
}

pub struct SampleId<'a, 'b> {
    record: &'b Record<'a>,
    offset: usize,
}

impl SampleId<'_, '_> {
    pub fn pid(&self) -> Option<u32> {
        let field = self.get_field(PerfSample::TID, PerfSample::empty())?;
        Some(field as u32)
    }

    pub fn tid(&self) -> Option<u32> {
        let field = self.get_field(PerfSample::TID, PerfSample::empty())?;
        Some((field >> u32::BITS) as u32)
    }

    pub fn time(&self) -> Option<u64> {
        self.get_field(PerfSample::TIME, PerfSample::TID)
    }

    pub fn id(&self) -> Option<u64> {
        self.get_field(PerfSample::ID, PerfSample::TID | PerfSample::TIME)
    }

    pub fn stream_id(&self) -> Option<u64> {
        self.get_field(
            PerfSample::STREAM_ID,
            PerfSample::TID | PerfSample::TIME | PerfSample::ID,
        )
    }

    pub fn cpu(&self) -> Option<u32> {
        self.get_field(
            PerfSample::CPU,
            PerfSample::TID | PerfSample::TIME | PerfSample::ID | PerfSample::STREAM_ID,
        )
        .map(|x| x as u32)
    }

    pub fn identifier(&self) -> Option<u64> {
        self.get_field(
            PerfSample::IDENTIFIER,
            PerfSample::TID
                | PerfSample::TIME
                | PerfSample::ID
                | PerfSample::STREAM_ID
                | PerfSample::CPU,
        )
    }

    fn expected_len(sample: PerfSample) -> usize {
        let all_fields = PerfSample::TID
            | PerfSample::TIME
            | PerfSample::ID
            | PerfSample::STREAM_ID
            | PerfSample::CPU
            | PerfSample::IDENTIFIER;

        (sample & all_fields).bits().count_ones() as usize * size_of::<u64>()
    }

    fn get_field(&self, field: PerfSample, pre: PerfSample) -> Option<u64> {
        if !self.record.sample.contains(field) {
            return None;
        }

        let field = (self.record.sample & pre).bits().count_ones() as usize;
        let offset = self.offset + field * size_of::<u64>();

        Some(self.record.u64_at(offset))
    }
}

#[derive(Clone, Copy)]
struct FieldSlice<'a> {
    data: &'a [u8],
}

impl<'a> FieldSlice<'a> {
    pub fn get_u32(&self, index: usize) -> u32 {
        u32::from_ne_bytes(
            self.data[index * size_of::<u32>()..][..size_of::<u32>()]
                .try_into()
                .unwrap(),
        )
    }

    pub fn get_u64(&self, index: usize) -> u64 {
        self.get_u64_raw(0, index)
    }

    pub fn get_u64_raw(&self, base: usize, index: usize) -> u64 {
        assert!(self.data.len() >= base + index * size_of::<u64>() + size_of::<u64>());

        u64::from_ne_bytes(
            self.data[base + index * size_of::<u64>()..][..size_of::<u64>()]
                .try_into()
                .unwrap(),
        )
    }

    pub fn get_rest(&self, index: usize) -> &'a [u8] {
        &self.data[size_of::<u64>() * index..]
    }
}

#[derive(Copy, Clone)]
pub struct MmapRecord<'a> {
    data: FieldSlice<'a>,
}

impl<'a> MmapRecord<'a> {
    /// The process ID.
    pub fn pid(&self) -> u32 {
        self.data.get_u32(0)
    }

    /// The thread ID.
    pub fn tid(&self) -> u32 {
        self.data.get_u32(1)
    }

    /// The address of the allocated memory.
    pub fn addr(&self) -> u64 {
        self.data.get_u64(1)
    }

    /// The length of the allocated memory.
    pub fn len(&self) -> u64 {
        self.data.get_u64(2)
    }

    /// The page offset of the allocated memory.
    pub fn pgoff(&self) -> u64 {
        self.data.get_u64(3)
    }

    /// A string describing the backing of the allocated memory.
    ///
    /// For file mappings this is a path pointing to the file that was mapped.
    /// However, non-file mappings do occur and in that case this will not be a
    /// filename.
    pub fn filename(&self) -> &'a OsStr {
        OsStr::from_bytes(&self.data.get_rest(4))
    }
}

impl fmt::Debug for MmapRecord<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MmapRecord")
            .field("pid", &self.pid())
            .field("tid", &self.tid())
            .field("addr", &self.addr())
            .field("len", &self.len())
            .field("pgoff", &self.pgoff())
            .field("filename", &self.filename())
            .finish()
    }
}

#[derive(Copy, Clone)]
pub struct LostRecord<'a> {
    data: FieldSlice<'a>,
}

impl LostRecord<'_> {
    pub fn id(&self) -> u64 {
        self.data.get_u64(0)
    }

    pub fn lost(&self) -> u64 {
        self.data.get_u64(1)
    }
}

impl fmt::Debug for LostRecord<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LostRecord")
            .field("id", &self.id())
            .field("lost", &self.lost())
            .finish()
    }
}

#[derive(Clone, Copy)]
pub struct CommRecord<'a> {
    data: FieldSlice<'a>,
}

impl<'a> CommRecord<'a> {
    pub fn pid(&self) -> u32 {
        self.data.get_u32(0)
    }

    pub fn tid(&self) -> u32 {
        self.data.get_u32(1)
    }

    pub fn filename(&self) -> &'a OsStr {
        OsStr::from_bytes(self.data.get_rest(1))
    }
}

impl fmt::Debug for CommRecord<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CommRecord")
            .field("pid", &self.pid())
            .field("tid", &self.tid())
            .field("filename", &self.filename())
            .finish()
    }
}

#[derive(Clone, Copy)]
pub struct ProcessRecord<'a> {
    data: FieldSlice<'a>,
}

impl<'a> ProcessRecord<'a> {
    pub fn pid(&self) -> u32 {
        self.data.get_u32(0)
    }

    pub fn ppid(&self) -> u32 {
        self.data.get_u32(1)
    }

    pub fn tid(&self) -> u32 {
        self.data.get_u32(2)
    }

    pub fn ptid(&self) -> u32 {
        self.data.get_u32(3)
    }

    pub fn time(&self) -> u64 {
        self.data.get_u64(2)
    }
}

impl fmt::Debug for ProcessRecord<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProcessRecord")
            .field("pid", &self.pid())
            .field("ppid", &self.ppid())
            .field("tid", &self.tid())
            .field("ptid", &self.ptid())
            .field("time", &self.time())
            .finish()
    }
}

#[derive(Clone, Copy)]
pub struct ThrottleRecord<'a> {
    data: FieldSlice<'a>,
}

impl<'a> ThrottleRecord<'a> {
    pub fn time(&self) -> u64 {
        self.data.get_u64(0)
    }

    pub fn id(&self) -> u64 {
        self.data.get_u64(1)
    }

    pub fn stream_id(&self) -> u64 {
        self.data.get_u64(2)
    }
}

impl fmt::Debug for ThrottleRecord<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ThrottleRecord")
            .field("time", &self.time())
            .field("id", &self.id())
            .field("stream_id", &self.stream_id())
            .finish()
    }
}

#[derive(Clone, Copy)]
pub struct SampleRecord<'a> {
    sample: PerfSample,
    _format: PerfFormat,
    data: FieldSlice<'a>,
}

impl<'a> SampleRecord<'a> {
    pub fn sample_id(&self) -> Option<u64> {
        self.get_field(0, PerfSample::IDENTIFIER, PerfSample::empty())
    }

    pub fn ip(&self) -> Option<u64> {
        self.get_field(0, PerfSample::IP, PerfSample::IDENTIFIER)
    }

    pub fn pid(&self) -> Option<u32> {
        let bytes = self
            .get_field(0, PerfSample::TID, PerfSample::IDENTIFIER | PerfSample::IP)?
            .to_ne_bytes()[..size_of::<u32>()]
            .try_into()
            .unwrap();

        Some(u32::from_ne_bytes(bytes))
    }

    pub fn tid(&self) -> Option<u32> {
        let bytes = self
            .get_field(0, PerfSample::TID, PerfSample::IDENTIFIER | PerfSample::IP)?
            .to_ne_bytes()[size_of::<u32>()..]
            .try_into()
            .unwrap();

        Some(u32::from_ne_bytes(bytes))
    }

    pub fn time(&self) -> Option<u64> {
        self.get_field(
            0,
            PerfSample::TIME,
            PerfSample::IDENTIFIER | PerfSample::IP | PerfSample::TID,
        )
    }

    pub fn addr(&self) -> Option<u64> {
        self.get_field(
            0,
            PerfSample::ADDR,
            PerfSample::IDENTIFIER | PerfSample::IP | PerfSample::TID | PerfSample::TIME,
        )
    }

    pub fn id(&self) -> Option<u64> {
        self.get_field(
            0,
            PerfSample::ID,
            PerfSample::IDENTIFIER
                | PerfSample::IP
                | PerfSample::TID
                | PerfSample::TIME
                | PerfSample::ADDR,
        )
    }

    pub fn stream_id(&self) -> Option<u64> {
        self.get_field(
            0,
            PerfSample::STREAM_ID,
            PerfSample::IDENTIFIER
                | PerfSample::IP
                | PerfSample::TID
                | PerfSample::TIME
                | PerfSample::ADDR
                | PerfSample::ID,
        )
    }

    pub fn cpu(&self) -> Option<u32> {
        let bytes = self
            .get_field(
                0,
                PerfSample::CPU,
                PerfSample::IDENTIFIER
                    | PerfSample::IP
                    | PerfSample::TID
                    | PerfSample::TIME
                    | PerfSample::ADDR
                    | PerfSample::ID
                    | PerfSample::STREAM_ID,
            )?
            .to_ne_bytes()[..size_of::<u32>()]
            .try_into()
            .unwrap();

        Some(u32::from_ne_bytes(bytes))
    }

    pub fn period(&self) -> Option<u64> {
        self.get_field(
            0,
            PerfSample::PERIOD,
            PerfSample::IDENTIFIER
                | PerfSample::IP
                | PerfSample::TID
                | PerfSample::TIME
                | PerfSample::ADDR
                | PerfSample::ID
                | PerfSample::STREAM_ID
                | PerfSample::CPU,
        )
    }

    fn read_offset(&self) -> usize {
        let base = self.get_offset(
            PerfSample::IDENTIFIER
                | PerfSample::IP
                | PerfSample::TID
                | PerfSample::TIME
                | PerfSample::ADDR
                | PerfSample::ID
                | PerfSample::STREAM_ID
                | PerfSample::CPU
                | PerfSample::PERIOD,
        );

        if self.sample.contains(PerfSample::READ) {
            unimplemented!()
        }

        base
    }

    pub fn callchain(&self) -> Option<&'a [u64]> {
        if !self.sample.contains(PerfSample::CALLCHAIN) {
            return None;
        }

        Some(unsafe { self.get_slice(self.read_offset()) })
    }

    fn callchain_offset(&self) -> usize {
        self.get_slice_offset::<u64>(self.read_offset(), PerfSample::CALLCHAIN)
    }

    pub fn raw(&self) -> Option<&'a [u8]> {
        if !self.sample.contains(PerfSample::RAW) {
            return None;
        }

        let base = self.callchain_offset();
        Some(unsafe { self.get_slice(base) })
    }

    fn raw_offset(&self) -> usize {
        self.get_slice_offset::<u8>(self.callchain_offset(), PerfSample::RAW)
    }

    pub fn lbr(&self) -> Option<&'a [perf_branch_entry]> {
        if !self.sample.contains(PerfSample::BRANCH_STACK) {
            return None;
        }

        let base = self.raw_offset();
        Some(unsafe { self.get_slice(base) })
    }

    fn lbr_offset(&self) -> usize {
        self.get_slice_offset::<perf_branch_entry>(
            self.callchain_offset(),
            PerfSample::BRANCH_STACK,
        )
    }

    fn regs_user_offset(&self) -> usize {
        let base = self.lbr_offset();

        if self.sample.contains(PerfSample::REGS_USER) {
            unimplemented!()
        }

        base
    }

    pub fn user_stack(&self) -> Option<&'a [u8]> {
        if !self.sample.contains(PerfSample::STACK_USER) {
            return None;
        }

        let offset = self.regs_user_offset();
        let data = unsafe { self.get_slice(offset) };
        let dyn_size = self.data.get_u64_raw(offset + data.len(), 0);

        Some(&data[..dyn_size as usize])
    }

    fn user_stack_offset(&self) -> usize {
        let mut offset = self.regs_user_offset();

        if self.sample.contains(PerfSample::STACK_USER) {
            offset += self.get_slice_offset::<u8>(offset, PerfSample::STACK_USER);
            offset += size_of::<u64>();
        }

        offset
    }

    pub fn weight(&self) -> Option<u64> {
        let offset = self.user_stack_offset();
        self.get_field(offset, PerfSample::WEIGHT, PerfSample::empty())
    }

    pub fn data_src(&self) -> Option<u64> {
        let offset = self.user_stack_offset();
        self.get_field(offset, PerfSample::DATA_SRC, PerfSample::WEIGHT)
    }

    pub fn transaction(&self) -> Option<u64> {
        let offset = self.user_stack_offset();
        self.get_field(
            offset,
            PerfSample::TRANSACTION,
            PerfSample::WEIGHT | PerfSample::DATA_SRC,
        )
    }

    fn transaction_offset(&self) -> usize {
        self.user_stack_offset()
            + self.get_offset(PerfSample::WEIGHT | PerfSample::DATA_SRC | PerfSample::TRANSACTION)
    }

    fn regs_intr_offset(&self) -> usize {
        let base = self.transaction_offset();

        if self.sample.contains(PerfSample::REGS_INTR) {
            unimplemented!()
        }

        base
    }

    pub fn phys_addr(&self) -> Option<u64> {
        let base = self.regs_intr_offset();
        self.get_field(base, PerfSample::PHYS_ADDR, PerfSample::empty())
    }

    pub fn cgroup(&self) -> Option<u64> {
        let base = self.regs_intr_offset();
        self.get_field(base, PerfSample::CGROUP, PerfSample::PHYS_ADDR)
    }

    fn get_offset(&self, fields: PerfSample) -> usize {
        (self.sample & fields).bits().count_ones() as usize * size_of::<u64>()
    }

    fn get_field(&self, base: usize, field: PerfSample, pre: PerfSample) -> Option<u64> {
        if !self.sample.contains(field) {
            return None;
        }

        Some(
            self.data
                .get_u64_raw(base, (self.sample & pre).bits().count_ones() as usize),
        )
    }

    unsafe fn get_slice<T>(&self, base: usize) -> &'a [T] {
        let len = self.data.get_u64_raw(base, 0) as usize;
        let (head, slice, _) = self.data.data[base + size_of::<u64>()..].align_to();

        assert!(head.is_empty());
        assert!(slice.len() >= len);

        &slice[..len]
    }

    fn get_slice_offset<T>(&self, base: usize, field: PerfSample) -> usize {
        if !self.sample.contains(field) {
            return base;
        }

        let len = self.data.get_u64_raw(base, 0) as usize;
        base + size_of::<u64>() + len * size_of::<T>()
    }
}

pub struct Mmap2Record<'a> {
    data: FieldSlice<'a>
}

impl<'a> Mmap2Record<'a> {
    pub fn pid(&self) -> u32 {
        self.data.get_u32(0)
    }

    pub fn tid(&self) -> u32 {
        self.data.get_u32(1)
    }

    pub fn addr(&self) -> u64 {
        self.data.get_u64(1)
    }

    pub fn len(&self) -> u64 {
        self.data.get_u64(2)
    }

    pub fn pgoff(&self) -> u64 {
        self.data.get_u64(3)
    }

    pub fn maj(&self) -> u32 {
        self.data.get_u32(4 * 2)
    }

    pub fn min(&self) -> u32 {
        self.data.get_u32(4 * 2 + 1)
    }

    pub fn ino(&self) -> u64 {
        self.data.get_u64(5)
    }

    pub fn ino_generation(&self) -> u64 {
        self.data.get_u64(6)
    }

    pub fn prot(&self) -> u32 {
        self.data.get_u32(7 * 2)
    }

    pub fn flags(&self) -> u32 {
        self.data.get_u32(7 * 2 + 1)
    }

    pub fn filename(&self) -> &'a OsStr {
        OsStr::from_bytes(self.data.get_rest(8))
    }
}

pub struct AuxRecord<'a> {
    data: FieldSlice<'a>
}

impl<'a> AuxRecord<'a> {
    pub fn aux_offset(&self) -> u64 {
        self.data.get_u64(0)
    }

    pub fn aux_size(&self) -> u64 {
        self.data.get_u64(1)
    }

    pub fn flags(&self) -> u64 {
        self.data.get_u64(2)
    }
}

pub struct ITraceStartRecord<'a> {
    data: FieldSlice<'a>,
}

impl<'a> ITraceStartRecord<'a> {
    pub fn pid(&self) -> u32 {
        self.data.get_u32(0)
    }

    pub fn tid(&self) -> u32 {
        self.data.get_u32(1)
    }
}

pub struct LostSamplesRecord<'a> {
    data: FieldSlice<'a>
}

impl<'a> LostSamplesRecord<'a> {
    pub fn lost(&self) -> u64 {
        self.data.get_u64(0)
    }
}
