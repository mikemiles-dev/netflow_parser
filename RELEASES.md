# 0.4.4
* Fix Readme example packets.
* Optimized IPFix, V9 NetflowCommon lookup.
* DataNumbers can now be downcast into actual data types: (u8, u16, i32, u32, u64, u128).

# 0.4.3
 * Fixed bug in NetflowCommon where ProtocolType was never set.
 * Minor Readme Changes.

# 0.4.2
 * Increased coverage.
 * Reworked Readme.

# 0.4.1
 * Added NetflowCommon structure.  This acts as a helper for common Netflow Fields (like src_ip, src_port, etc).
 * V5, V7 SysUpTime, First, Last times now u32 from Duration.
 * IPFix export time u32 from Duration.

# 0.4.0
 * NetflowPacketResult now simply NetflowPacket.
 * General parser cleanup and removal of uneeded code.
 * Small performance optimization in lib parse_bytes.

# 0.3.6
 * Added V9 Post NAT fields 225-228.
 * Added Tokio Async Example

# 0.3.5
 * 3 Byte Data Numbers now correctly converts back to be_bytes.

# 0.3.4
 * Added 3 byte DataNumber support.

# 0.3.3
 * Renamed Sets to FlowSets for IPFIX for consistency.
 * Concrete error type for parsing
 * V5, V7, V9, IPFix now supports exporting back into bytes with `to_be_bytes`.
 * V9,IPFix field maps are now keyed by order.
 * Removed unix timestamp feature.  May re-implement in the future.

# 0.3.2
 * Readme changes

# 0.3.1
  * Added 0 length check when parsing template lengths.

# 0.3.0
  * Reworked IPFIX + V9 Parsing.  Flowset length is now used.
  * Flow data field Counts are now correctly calculated.
  * Added `parse_unknown_fields` feature flag to attempt to parse unknown fields not supported by the library.
  * `parse_unknown_fields` is enabled by default.

# 0.2.9
  * Fixed parsing issue with V9 flow and padding.

# 0.2.8
  * Removed body for V5, V7.  Only has Sets now.

# 0.2.7
  * Added support for multiple flowsets for V5, V7.

# 0.2.6
  * Re-added static and variable versions as public.

# 0.2.5
  * Now Parsing V9 Mac Addresses correctly.
  * More code reorganization. (Moved tests to tests.rs and added parsing.rs for majority of parsing).
  * Removed unneeded IPFIX Option Template Code.

# 0.2.4
  * Fixes for V9 parsing.  Now supports processing multiple templates.
  * General code cleanup/Removal of uneeded code.

# 0.2.3
  * Small performance improvement by not parsing netflow version twice each packet.
  * General Code cleanup for field_types and DataNumbers.

# 0.2.2
  * Optimizations in V9/IPFIX, removed some clone/cloned.
  * Reworked Template Fields/Option Template Fields into single struct.
    This avoids having to make an additional clone for each parse.

# 0.2.1
  * Fixed issue where v9/ipfix template fields can infinite loop.

# 0.2.0
  * Clippy updates for 1.76
  * Removed dbg! macros for now for performance reason until we have a better solution.
  * Fixed issue where bad IPFIX options template causes panic.

# 0.1.9
  * Fixed bug with flow counts in V9.

# 0.1.8
  * Introduced parse unix_timestamp feature. 

# 0.1.7
  * Renamed NetflowPacket to NetflowPacketResult.
  * Created an Error Type on NetflowPacketResult.  Contains the error message and bytes that was trying to be parsed.

# 0.1.6
  * Fixed bug when parsing empty byte arrays or empty remaining slices.

# 0.1.5
  * Removed logging crate dependency 

# 0.1.4
  * Removed insta for non dev-dependency.

# 0.1.3
  * unix_secs and unix_nsecs for V5 are now pub.

# 0.1.2
  * Added Cisco to README.md
  * Fixed some IPFIX Fields not being correctly mapped.
  * Safer addition and subtraction in V9/IPFix

# 0.1.1
  * Removed serde import from filter example.
  * Removed link to ipfix in V9 doc string.
  * Added RELEASES.md

