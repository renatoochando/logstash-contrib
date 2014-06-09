# encoding: utf-8
require "logstash/namespace"
require "logstash/outputs/base"
require "shellwords"
require "logstash/outputs/zabbix/zabbix_send"

# The zabbix output is used for sending item data to zabbix via the
# zabbix_sender executable.
#
# For this output to work, your event must have the following fields:
#
# * "zabbix_host"    (the host configured in Zabbix)
# * "zabbix_item"    (the item key on the host in Zabbix)
# * "send_field"    (the field name that is sending to Zabbix)
#
# In Zabbix, create your host with the same name (no spaces in the name of 
# the host supported) and create your item with the specified key as a
# Zabbix Trapper item. Also you need to set field that will be send to zabbix
# as item.value, otherwise @message wiil be sent.
#
# The easiest way to use this output is with the grep filter.
# Presumably, you only want certain events matching a given pattern
# to send events to zabbix, so use grep or grok to match and also to add the required
# fields.
#
#      filter {
#        grep {
#          type => "linux-syslog"
#          match => [ "@message", "(error|ERROR|CRITICAL)" ]
#          add_tag => [ "zabbix-sender" ]
#          add_field => [
#            "zabbix_host", "%{source_host}",
#            "zabbix_item", "item.key"
#            "send_field", "field_name"
#          ]
#       }
#        grok {
#          match => [ "message", "%{SYSLOGBASE} %{DATA:data}" ]
#          add_tag => [ "zabbix-sender" ]
#          add_field => [
#            "zabbix_host", "%{source_host}",
#            "zabbix_item", "item.key",
#            "send_field", "data"
#          ]
#       }
#     }
#      
#     output {
#       zabbix {
#         # only process events with this tag
#         tags => "zabbix-sender"
#
#         # specify the hostname or ip of your zabbix server
#         # (defaults to localhost)
#         host => "localhost"
#
#         # specify the port to connect to (default 10051)
#         port => "10051"
#
#         # specify the path to zabbix_sender
#         # (defaults to "/usr/local/bin/zabbix_sender")
#         zabbix_sender => "/usr/local/bin/zabbix_sender"
#       }
#     }
class LogStash::Outputs::Zabbix < LogStash::Outputs::Base

  config_name "zabbix"
  milestone 2

  config :host, :validate => :string, :default => "localhost"
  config :port, :validate => :number, :default => 10051

  public
  def register
    # nothing to do
  end # def register

  public
  def receive(event)
    return unless output?(event)

    host = event["zabbix_host"]
    if !host
      @logger.warn("Skipping zabbix output; zabbix_host field is missing",
                   :missed_event => event)
      return
    end

    item = event["zabbix_item"]
    if !item
      @logger.warn("Skipping zabbix output; zabbix_item field is missing",
                   :missed_event => event)
      return
    end

    field = event["send_field"]
    if !field
      field = "message"
    end

    host = [host] if host.is_a?(String)
    item = [item] if item.is_a?(String)
    field = [field] if field.is_a?(String)

    if host.is_a?(Array) && item.is_a?(Array) && field.is_a?(Array) 
      item.each_with_index do |key, index|
        begin
          zmsg = event[field[index]]
          zmsg = Shellwords.shellescape(zmsg)
        rescue => e
          @logger.warn("Error during receiving message for sending",
                       :event => event,
                       :exception => e, :backtrace => e.backtrace)
        end
        
        sender = ZabbixSend::Sender.new
        sender.zabbix_send("#{@host}","#{host[index]}","#{item[index]}","#{zmsg}", Time.now.to_i, "#{@port}")

      end
    else
      @logger.warn("Skipping zabbix output; some issues with zabbix parameters conversion",
                   :missed_event => event, :zabbix_host => host,
                   :zabbix_item => item, :send_field => field)
    end
  end # def receive
end # class LogStash::Outputs::Zabbix
