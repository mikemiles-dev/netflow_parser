# 0.2.1
  * Fixed issue where no ipfix template fields can infinite loop.

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

