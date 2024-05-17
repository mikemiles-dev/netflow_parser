# 0.3.0
  * Reworked V9 Parsing.  Flowset length is now used.  Padding is now ignored.
  * DataNumber parsing now checks if the field_length is 0.
  * Added guard to prevent infinite loop in ipfix parsing.
  * Add greedy_parsing feature.

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

