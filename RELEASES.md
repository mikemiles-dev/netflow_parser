# 0.5.8
* IPFix Protocol Identifier now parsers as ProtocolIdentifier Field Type and not UnsignedDataNumber.
* IPFix added Application ID Data Type.
* Enterprise Fields are no longer classified as an "enterprise" field type.
* IPFix now supports some Cisco PEN fields listed below:
```
    CiscoServerBytesNetwork = 8337,
    CiscoClientBytesNetwork = 8338,
    CiscoServicesWaasSegment = 9252,
    CiscoServicesWaasPassthroughReason = 9253,
    CiscoAppHttpUriStatistics = 9357,
    CiscoAppCategoryName = 12232,
    CiscoAppGroupName = 12234,
    CiscoAppHttpHost = 12235,
    CiscoClientIpv4Address = 12236,
    CiscoServerIpv4Address = 12237,
    CiscoClientL4Port = 12240,
    CiscoServerL4Port = 12241,
    CiscoConnectionId = 12242,
    CiscoAppBusiness = 12244,
```

# 0.5.7
* Fix Scope Data Parsing.

# 0.5.6
* Simplify V9/IPFix Parse function.
* Added more cases for DataNumber Parsing.
* IPFix now supports V9 Templates/Options Templates.

# 0.5.5
* More IPFIx/V9 Cleanup.
* Reworked FlowSetBody for V9/IPFIX into an enum since a flowset can only contain a single type.
* Fixed potential V9 parsing bug with a potential divide by 0.
* DataNumber to_be_bytes to now a Result type return to handle failed u24 conversions.
* FieldValue to_be_bytes now supports all data types.

# 0.5.4
* Reworked how padding is calculated for IPFIx.
* Fixed Vecs not being exported for DataNumber.

# 0.5.3
* Fixed bug when calcualting the enteperise field.
* Now properly parses variable length fields.
* Cleanup ipfix code.
* Rust 2024 Edition.

# 0.5.2
* Can now parse enterprise fields in non options templates for IPFIX.

# 0.5.1
* Reworked NetflowParseError.  Added a Partial Type.
* Added ability to parse only `allowed_versions`.
* V9, IPFix, Datanumber Code cleanup.
* Added benchmarking

# 0.5.0
* Typos in documentation fixed.
* Added cargo-fuzz for fuzzing.
  * Uncovered area in V9 that could cause panic.

# 0.4.9
* Added FlowStartMilliseconds, FlowEndMilliseconds 

# 0.4.8
* Now Parsing IPFix Mac Addresses correctly.

# 0.4.7
* Added `src_mac` and `dst_mac` to NetflowCommonFlowSet to help identify devices on V9, IPFix.

# 0.4.6
* Added `NetflowParser` function `parse_bytes_as_netflow_common_flowsets`.  Will allow the caller
  to gather all flowsets from all `NetflowPacket` into a single `Vec` of `NetflowCommonFlowSet`.

# 0.4.5
 * Fixed bug with NetflowCommon V9 where Src and Dst IP where Ipv6 wasn't being checked.

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
 * General parser cleanup and removal of unneeded code.
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
  * General code cleanup/Removal of unneeded code.

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

