require 'pcap'
require 'optparse'

def pcaplet_usage()
  $stderr.print <<END
Usage: #{File.basename $0} [ -dnv ] [ -i interface | -r file ]
       #{' ' * File.basename($0).length} [ -c count ] [ -s snaplen ] [ filter ]
Options:
  -n  do not convert address to name
  -d  debug mode
  -v  verbose mode
END
end

module Pcap
  class Pcaplet
    def usage(status, msg = nil)
      $stderr.puts msg if msg
      pcaplet_usage
      exit(status)
    end

    def initialize(args = nil)
      if args
        ARGV[0,0] = args.split(/\s+/)
      end
      @device = nil
      @rfile = nil
      @count = -1
      @snaplen = 68
      opts = OptionParser.new do |opts|
        opts.on('-d') {$DEBUG = true}
        opts.on('-v') {$VERBOSE = true}
        opts.on('-n') {Pcap.convert = false}
        opts.on('-i IFACE') {|s| @device = s}
        opts.on('-r FILE') {|s| @rfile = s}
        opts.on('-c COUNT', OptionParser::DecimalInteger) {|i| @count = i}
        opts.on('-s LEN', OptionParser::DecimalInteger) {|i| @snaplen = i}
      end
      begin
        opts.parse!
      rescue
        usage(1)
      end
      
      @filter = ARGV.join(' ')

      # check option consistency
      usage(1) if @device && @rfile
      if !@device and !@rfile
        @device = Pcap.lookupdev
      end

      # open
      begin
        if @device
          @capture = Capture.open_live(@device, @snaplen)
        elsif @rfile
          if @rfile !~ /\.gz$/
            @capture = Capture.open_offline(@rfile)
          else
            $stdin = IO.popen("gzip -dc < #@rfile", 'r')
            @capture = Capture.open_offline('-')
          end
        end
        @capture.setfilter(@filter)
      rescue PcapError, ArgumentError
        $stdout.flush
        $stderr.puts $!
        exit(1)
      end
    end

    attr('capture')

    def add_filter(f)
      if @filter == nil || @filter =~ /^\s*$/  # if empty
        @filter = f
      else
        f = f.source if f.is_a? Filter
        @filter = "( #{@filter} ) and ( #{f} )"
      end
      @capture.setfilter(@filter)
    end

    def each_packet(&block)
      begin
        duplicated = (RUBY_PLATFORM =~ /linux/ && @device == "lo")
        unless duplicated
          @capture.loop(@count, &block)
        else
          flip = true
          @capture.loop(@count) do |pkt|
            flip = (! flip)
            next if flip
            block.call pkt
          end
        end
      rescue Interrupt
        $stdout.flush
        $stderr.puts("Interrupted.")
        $stderr.puts $@.join("\n\t") if $DEBUG
      ensure
        # print statistics if live
        if @device
          stat = @capture.stats
          if stat
            $stderr.print("#{stat.recv} packets received by filter\n");
            $stderr.print("#{stat.drop} packets dropped by kernel\n");
          end
        end
      end
    end

    alias each each_packet

    def close
      @capture.close
    end
  end
end

Pcaplet = Pcap::Pcaplet
