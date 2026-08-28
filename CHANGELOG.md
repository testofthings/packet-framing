# Changelog

## 0.3.0
### Added
- IEEE 802.11 (Wi-Fi) MAC frames are parsed from captures with PCAP LinkType 105, including the
  IEEE 802.2 LLC/SNAP encapsulation, which makes the IP traffic in them accessible
- Pcap files containing raw IP frames, without an Ethernet header, can now be parsed
- A dev container for development
- Automatic code checks on pull requests, running pylint, mypy and pytest
- A release workflow that uploads to PyPI on a version tag push

### Changed
- A capture file is verified to be a supported PCAP file, unsupported files, e.g. PCAPNG files, are rejected with an error
  message instead of being parsed into nonsense records
- Packaging moved from `setup.py` to `pyproject.toml`
- Python 3.11 or newer is required

### Fixed
- A large number of pylint and mypy findings across the codebase, and dead code removed

### Documentation
- README and documentation updated to reflect the current status of the repository
