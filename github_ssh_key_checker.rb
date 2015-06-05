#!/usr/bin/env ruby

require 'bundler/setup'
require 'octokit'
require 'sshkey'
require 'terminal-table/import'
require 'trollop'

opts = Trollop::options do
  opt :github_oauth_token,   'Github OAuth token', type: String,  default: ENV['GITHUB_OAUTH']
  opt :min_key_size,         'SSH min key size',   type: Integer, default: 2048
  opt :verbose,              'Verbose output',                    default: false
end

github = Octokit::Client.new(access_token: opts[:github_oauth_token])

def key_size(key)
  begin
    SSHKey.ssh_public_key_bits(key)
  rescue SSHKey::PublicKeyError
    key.split(' ').first.split('-').last
  end
end

def signature_exception?(key_size)
  %w{ ed25519 }.include?(key_size)
end

weak_keys = []

ssh_table = table do |row|
  row.title = "Github users with weak SSH keys"
  row.headings = "Users", "Organisation", "Key size in bits", "Key"
  github.organizations.each do |org|
    github.organization_members(org[:login]).each do |user|
      github.user_keys(user[:login]).each do |key|
        size = key_size(key[:key])
        if size.to_i < opts[:min_key_size] && !signature_exception?(size)
          tt = []
          tt << user[:login]
          tt << org[:login]
          tt << key_size(key[:key])
          tt << key[:key][0,50]
          row << tt
          weak_keys << tt
        end
      end
    end
  end
end

if opts[:verbose]
  puts ssh_table
  exit 0
elsif weak_keys.any?
  puts "WARNING: #{weak_keys.count} weak SSH keys found"
  exit 1
else
  puts "OK: No weak SSH keys found"
  exit 0
end
