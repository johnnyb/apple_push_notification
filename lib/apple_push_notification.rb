require 'socket'
require 'openssl'

module ApplePushNotification

  def self.extended(base)
    # Added device_token attribute if not included by acts_as_pushable
    unless base.respond_to?(:acts_as_push_options)
      base.class_eval do
        attr_accessor :device_token
      end
    end
  end

  APN_PORT = 2195
  APN_FEEDBACK_PORT = 2196
  @@apn_cert = nil
  @@apn_host = nil
  
  def self.apn_enviroment
    @@apn_enviroment
  end
  
  def self.apn_development?
    @@apn_enviroment != :production
  end

  def self.apn_production?
    @@apn_enviroment == :production
  end
  
  def self.apn_enviroment= enviroment
    @@apn_enviroment = enviroment.to_sym
    @@apn_host = self.apn_production? ? "gateway.push.apple.com" : "gateway.sandbox.push.apple.com"
    @@apn_feedback_host = self.apn_production? ? "feedback.push.apple.com" : "feedback.sandbox.push.apple.com"
    cert = self.apn_production? ? "apn_production.pem" : "apn_development.pem"
    path = File.join(File.expand_path(RAILS_ROOT), "config", "certs", cert)
    @@apn_cert = File.exists?(path) ? File.read(path) : nil
    raise "Missing apple push notification certificate in #{path}" unless @@apn_cert
  end
  
  self.apn_enviroment = :development

  def process_feedback_notifications(&block)
    begin
      ctx = OpenSSL::SSL::SSLContext.new
      ctx.key = OpenSSL::PKey::RSA.new(@@apn_cert)
      ctx.cert = OpenSSL::X509::Certificate.new(@@apn_cert)

      s = TCPSocket.new(@@apn_feedback_host, APN_FEEDBACK_PORT)
      ssl = OpenSSL::SSL::SSLSocket.new(s, ctx)
      ssl.sync = true
      ssl.connect

      while(!ssl.closed?)
        feedback_record = ssl.read(38)
        if feedback_record.length != 38
          logger.warn("Bad record: #{feedback_record}")
          break
        else
          time_t = feedback_record[0..3]
          token = feedback_record[6..37].unpack('H*').first
          feedback_info = {
		:device_token => token,
		:time_t => time_t
          }
          yield(feedback_info)
        end
      end

      ssl.close
      s.close
    rescue
      logger.warn("error during SSL feedback: #{$!}")
    end 
  end
 
  def socket_for_notifications(force_new = false)
    raise "Missing apple push notification certificate" unless @@apn_cert

    @ssl_socket = nil if force_new

    @ssl_socket ||= begin
      ctx = OpenSSL::SSL::SSLContext.new
      ctx.key = OpenSSL::PKey::RSA.new(@@apn_cert)
      ctx.cert = OpenSSL::X509::Certificate.new(@@apn_cert)

      s = TCPSocket.new(@@apn_host, APN_PORT)
      ssl = OpenSSL::SSL::SSLSocket.new(s, ctx)
      ssl.sync = true
      ssl.connect

      ssl
    end

    return @ssl_socket
  end
 
  def send_notification options
    msg = self.apn_message_for_sending(options)
    socket_for_notifications.write(msg)
  rescue SocketError => error
    # Try again with a new connection
    begin
      logger.warn("Retrying notification: #{error}")
      socket_for_notifications(true).write(msg)
    rescue
      logger.warn("Error while sending notifications: #{$!}")
      raise "Error while sending notifications: #{$!}"
    end
  end
  
  def self.send_notification token, options = {}
    d = Object.new
    d.extend ApplePushNotification
    d.device_token = token
    d.send_notification options
  end

  protected

  def apn_message_for_sending options
    json = ApplePushNotification::apple_json_array options
    message = "\0\0 #{self.device_token_hexa}\0#{json.length.chr}#{json}"
    raise "The maximum size allowed for a notification payload is 256 bytes." if message.size.to_i > 256
    message
  end

  def device_token_hexa
    # Use `device_token` as the method to get the token from
    # unless it is overridde from acts_as_pushable
    apn_token_field = "device_token"
    if respond_to?(:acts_as_push_options)
      apn_token_field = acts_as_push_options[:device_token_field]
    end
    token = send(apn_token_field.to_sym)
    raise "Cannot send push notification without device token" if !token || token.empty?
    [token.delete(' ')].pack('H*')
  end

  def self.apple_json_array options
    result = {}
    result['aps'] = {}
    result['aps']['alert'] = options[:alert].to_s if options[:alert]
    result['aps']['badge'] = options[:badge].to_i if options[:badge]
    result['aps']['sound'] = options[:sound] if options[:sound] and options[:sound].is_a? String
    result['aps']['sound'] = 'default' if options[:sound] and options[:sound].is_a? TrueClass
    result.to_json
  end
    
end

require File.dirname(__FILE__) + "/apple_push_notification/acts_as_pushable"
