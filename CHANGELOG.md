# Changelog

## 0.4.0
### Added
- New PCAP (PCAPNG) file support, in either octet order.
- PCAP files are read in either octet order, the order is told by the magic number of the file.
- An integer field can be declared _swappable_, which lets the data decide its octet order
- IEEE 802.11 (Wi-Fi) MAC frames are parsed from captures with PCAP LinkType 105, including the
  IEEE 802.2 LLC/SNAP encapsulation, which makes the IP traffic in them accessible

### Changed
- **Breaking**: The octet order of an integer field is chosen with `IntegerFormat(lsb_first=...)`.
  The methods `big_endian()` and `little_endian()` are removed, as they did the opposite of what
  their names said: `big_endian()` produced least significant octet first. Replace a call to
  `big_endian()` with `lsb_first=True` and a call to `little_endian()` with the default
- A capture file is verified to be a supported PCAP file, unsupported files, e.g. PCAPNG files,
  are rejected with an error message instead of being parsed into nonsense records

### Fixed
- Encoding a frame with a `Selection` stored the type value of the last declared alternative,
  instead of the value of the chosen one
- A value cut short by the end of the data was not detected for least significant octet first
  integers, which gave a wrong value instead of an error
- Setting a value to a freshly selected alternative of a `Selection` raised `KeyError`

## 0.3.0
### Added
- Pcap files containing raw IP frames, without an Ethernet header, can now be parsed
- A dev container for development
- Automatic code checks on pull requests, running pylint, mypy and pytest
- A release workflow that uploads to PyPI on a version tag push

### Changed
- Packaging moved from `setup.py` to `pyproject.toml`
- Python 3.11 or newer is required

### Fixed
- A large number of pylint and mypy findings across the codebase, and dead code removed

### Documentation
- README and documentation updated to reflect the current status of the repository
