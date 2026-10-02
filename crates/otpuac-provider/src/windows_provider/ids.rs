use windows_sys::core::GUID;

pub(super) const CLSID_OTPUAC: GUID =
    GUID::from_u128(crate::parse_guid_u128(crate::OTPUAC_PROVIDER_CLSID));

pub(super) const IID_IUNKNOWN: GUID = GUID {
    data1: 0x00000000,
    data2: 0x0000,
    data3: 0x0000,
    data4: [0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46],
};

pub(super) const IID_ICLASS_FACTORY: GUID = GUID {
    data1: 0x00000001,
    data2: 0x0000,
    data3: 0x0000,
    data4: [0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46],
};

pub(super) const IID_ICREDENTIAL_PROVIDER: GUID = GUID {
    data1: 0xD27C3481,
    data2: 0x5A1C,
    data3: 0x45B2,
    data4: [0x8A, 0xAA, 0xC2, 0x0E, 0xBB, 0xE8, 0x22, 0x9E],
};

pub(super) const IID_ICREDENTIAL_PROVIDER_SET_USER_ARRAY: GUID = GUID {
    data1: 0x095C1484,
    data2: 0x1C0C,
    data3: 0x4388,
    data4: [0x9C, 0x6D, 0x50, 0x0E, 0x61, 0xBF, 0x84, 0xBD],
};

pub(super) const IID_ICREDENTIAL_PROVIDER_CREDENTIAL: GUID = GUID {
    data1: 0x63913A93,
    data2: 0x40C1,
    data3: 0x481A,
    data4: [0x81, 0x8D, 0x40, 0x72, 0xFF, 0x8C, 0x70, 0xCC],
};

pub(super) const IID_ICREDENTIAL_PROVIDER_CREDENTIAL2: GUID = GUID {
    data1: 0xFD672C54,
    data2: 0x40EA,
    data3: 0x4D6E,
    data4: [0x9B, 0x49, 0xCF, 0xB1, 0xA7, 0x50, 0x7B, 0xD7],
};

pub(super) fn guid_eq(a: &GUID, b: &GUID) -> bool {
    a.data1 == b.data1 && a.data2 == b.data2 && a.data3 == b.data3 && a.data4 == b.data4
}
