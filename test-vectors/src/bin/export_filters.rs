use mosaic_core::{
    Address, Error, Id, Kind, OwnedFilter, OwnedFilterElement, OwnedTag, PublicKey, SecretKey,
    TagType, Timestamp,
};
use std::{
    fs,
    io::{self, Write},
    path::{Path, PathBuf},
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let out_dir = Path::new("filters");
    fs::create_dir_all(out_dir)?;

    write_fixture(out_dir, "author_kinds", filter_author_kinds()?)?;
    write_fixture(out_dir, "signing_keys", filter_signing_keys()?)?;
    write_fixture(out_dir, "timestamps", filter_timestamps()?)?;
    write_fixture(out_dir, "since_until", filter_since_until()?)?;
    write_fixture(out_dir, "received", filter_received_bounds()?)?;
    write_fixture(out_dir, "include_tags", filter_include_tags()?)?;
    write_fixture(out_dir, "exclude_tags", filter_exclude_tags()?)?;
    write_fixture(out_dir, "exclude_ids", filter_exclude_ids()?)?;
    write_fixture(out_dir, "mixed", filter_mixed()?)?;

    Ok(())
}

fn write_fixture(out_dir: &Path, name: &str, filter: OwnedFilter) -> io::Result<()> {
    let path = out_dir.join(PathBuf::from(format!("{name}.bin")));
    let mut file = fs::File::create(&path)?;
    file.write_all(filter.as_bytes())
}

fn filter_author_kinds() -> Result<OwnedFilter, Error> {
    let (pk1, pk2) = fixed_keys(0xA0);
    let authors = OwnedFilterElement::new_author_keys(&[pk1, pk2])?;
    let kinds = OwnedFilterElement::new_kinds(&[Kind::MICROBLOG_ROOT, Kind::REPLY_COMMENT])?;
    filter_from_elements(vec![authors, kinds])
}

fn filter_signing_keys() -> Result<OwnedFilter, Error> {
    let (pk1, pk2) = fixed_keys(0xB0);
    let signing = OwnedFilterElement::new_signing_keys(&[pk1, pk2])?;
    filter_from_elements(vec![signing])
}

fn filter_timestamps() -> Result<OwnedFilter, Error> {
    let ts1 = Timestamp::from_nanoseconds(1_700_000_000_000_000_000)?;
    let ts2 = Timestamp::from_nanoseconds(1_800_000_000_000_000_000)?;
    let timestamps = OwnedFilterElement::new_timestamps(&[ts1, ts2])?;
    filter_from_elements(vec![timestamps])
}

fn filter_since_until() -> Result<OwnedFilter, Error> {
    let since =
        OwnedFilterElement::new_since(Timestamp::from_nanoseconds(1_650_000_000_000_000_000)?);
    let until =
        OwnedFilterElement::new_until(Timestamp::from_nanoseconds(1_750_000_000_000_000_000)?);
    filter_from_elements(vec![since, until])
}

fn filter_received_bounds() -> Result<OwnedFilter, Error> {
    let since = OwnedFilterElement::new_received_since(Timestamp::from_nanoseconds(
        1_660_000_000_000_000_000,
    )?);
    let until = OwnedFilterElement::new_received_until(Timestamp::from_nanoseconds(
        1_760_000_000_000_000_000,
    )?);
    filter_from_elements(vec![since, until])
}

fn filter_include_tags() -> Result<OwnedFilter, Error> {
    let (pk, _) = fixed_keys(0xC0);
    let notify_tag = OwnedTag::new_notify_public_key(&pk);
    let custom_tag = OwnedTag::new(TagType::CONTENT_SEGMENT_URL, &b"https://example.com")?;
    let tags = OwnedFilterElement::new_included_tags(&[&notify_tag, &custom_tag])?;
    filter_from_elements(vec![tags])
}

fn filter_exclude_tags() -> Result<OwnedFilter, Error> {
    let (_, pk) = fixed_keys(0xD0);
    let notify_tag = OwnedTag::new_notify_public_key(&pk);
    let custom_tag = OwnedTag::new(TagType::CONTENT_SEGMENT_IMAGE, &b"/img/1")?;
    let tags = OwnedFilterElement::new_excluded_tags(&[&notify_tag, &custom_tag])?;
    filter_from_elements(vec![tags])
}

fn filter_exclude_ids() -> Result<OwnedFilter, Error> {
    let prefix_a = [0x11_u8; 40];
    let prefix_b = [0x22_u8; 40];
    let ts_a = Timestamp::from_nanoseconds(1_640_000_000_000_000_000)?;
    let ts_b = Timestamp::from_nanoseconds(1_640_100_000_000_000_000)?;
    let id_a = Id::from_parts(&prefix_a, ts_a);
    let id_b = Id::from_parts(&prefix_b, ts_b);
    let exclude = OwnedFilterElement::new_exclude(&[id_a, id_b])?;
    filter_from_elements(vec![exclude])
}

fn filter_mixed() -> Result<OwnedFilter, Error> {
    let (pk1, pk2) = fixed_keys(0xE0);
    let authors = OwnedFilterElement::new_author_keys(&[pk1])?;
    let signing = OwnedFilterElement::new_signing_keys(&[pk2])?;
    let kinds = OwnedFilterElement::new_kinds(&[Kind::BLOG_POST])?;
    let since =
        OwnedFilterElement::new_since(Timestamp::from_nanoseconds(1_600_000_000_000_000_000)?);
    let address_bytes = fixed_address_bytes();
    let subkey_tag = OwnedTag::new(TagType::SUBKEY, &address_bytes)?;
    let tags = OwnedFilterElement::new_included_tags(&[&subkey_tag])?;
    filter_from_elements(vec![authors, signing, kinds, since, tags])
}

fn filter_from_elements(elements: Vec<OwnedFilterElement>) -> Result<OwnedFilter, Error> {
    let references: Vec<&OwnedFilterElement> = elements.iter().collect();
    OwnedFilter::new(&references)
}

fn fixed_keys(seed_base: u8) -> (PublicKey, PublicKey) {
    let mut seed1 = [0_u8; 32];
    let mut seed2 = [0_u8; 32];
    for (i, b) in seed1.iter_mut().enumerate() {
        *b = seed_base.wrapping_add(i as u8);
    }
    for (i, b) in seed2.iter_mut().enumerate() {
        *b = seed_base.wrapping_add(0x40).wrapping_add(i as u8);
    }
    let sk1 = SecretKey::from_bytes(&seed1);
    let sk2 = SecretKey::from_bytes(&seed2);
    (sk1.public(), sk2.public())
}

fn fixed_address_bytes() -> Vec<u8> {
    let (pk, _) = fixed_keys(0xAA);
    let address = Address::new_deterministic(pk, Kind::PROFILE, &[0x55; 24]);
    address.as_bytes().to_vec()
}
