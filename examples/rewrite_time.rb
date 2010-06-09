#!/usr/bin/env ruby
require 'rubygems'
require 'pcap'

if 3 != ARGV.size
  STDERR.puts "Usage: #{$0} in.pcap out.pcap delta"
  exit(2)
end

in_filename, out_filename, delta = ARGV

inp = outc = outp = nil
begin
  inp = Pcap::Capture.open_offline(in_filename)
  outc = Pcap::Capture.open_dead(inp.datalink, inp.snaplen)
  outp = Pcap::Dumper.open(outc, out_filename)
  inp.loop(-1) do |pkt|
    pkt.time_i += delta.to_i
    outp.dump(pkt)
  end
rescue Exception => e
  STDERR.puts e.message,e.backtrace
ensure
  inp.close if inp
  outp.close if outp
  outc.close if outc
end

