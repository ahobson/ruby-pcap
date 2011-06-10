require 'mkmf'

pcap_dir        = with_config("pcap-dir", "/usr/local")
pcap_includedir = with_config("pcap-includedir", pcap_dir + "/include")
pcap_libdir     = with_config("pcap-libdir", pcap_dir + "/lib")

$CFLAGS  = "-I#{pcap_includedir}"
$LDFLAGS = "-L#{pcap_libdir}"

# According to the blog entry at
# http://blog.phusion.nl/2010/06/10/making-ruby-threadable-properly-handling-context-switching-in-native-extensions/
# TRAP_BEG and TRAP_END just release / reacquire the GIL (global interpreter lock) on Ruby 1.9, which means
# they should not be used in our case.
$defs.push("-DPCAP_DONT_TRAP=1") if RUBY_VERSION >= '1.9'

have_library("socket", "socket")
have_library("xnet", "gethostbyname")
have_func("hstrerror")
if have_header("pcap.h") && have_library("pcap", "pcap_open_live")
  have_func("pcap_compile_nopcap")
  create_makefile("pcap")
end
