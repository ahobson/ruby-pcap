begin
  require 'rubygems'
  require 'jeweler'
  Jeweler::Tasks.new do |gemspec|
    gemspec.name = "pcap"
    gemspec.summary = "Interface to LBL Packet Capture library (libpcap)"
    gemspec.email = "fukusima@goto.info.waseda.ac.jp"
    gemspec.homepage = "http://www.goto.info.waseda.ac.jp/~fukusima/ruby/pcap-e.html"
    gemspec.description = "Ruby interface to LBL Packet Capture library. This library also includes classes to access packet header fields."
    gemspec.authors = ["Masaki Fukushima", "Andrew Hobson"]
    gemspec.extensions = ["ext/extconf.rb"]
    gemspec.files = FileList["[A-Z]*", "{doc,doc-ja,ext,lib,examples}/**/*"]
    gemspec.test_files = []
  end
rescue LoadError
  puts "Jeweler not available. Install it with: sudo gem install technicalpickles-jeweler -s http://gems.github.com"
end
