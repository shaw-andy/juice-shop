# frozen_string_literal: true

# Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
# SPDX-License-Identifier: MIT

require "digest"
require "fileutils"
require "json"
require "pathname"
require "tmpdir"
require "webrick"

require "vagrant"

# Drives Vagrant 2.4.9's box add the way `vagrant up` does when the guest
# does not already have a local box: shorthand name, server catalog, then
# the version constraint from the loaded Vagrantfile (nil becomes ">= 0"
# inside BoxAdd).
module VagrantBoxPinHarness
  PROVIDER = "virtualbox"

  module_function

  def named_versions(constraint)
    return [] if constraint.nil? || constraint.to_s.strip.empty?

    constraint.to_s.split(",").flat_map do |part|
      Gem::Requirement.new(part.strip).requirements.map { |_op, ver| ver.to_s }
    end.uniq
  end

  def next_published(version)
    segments = Gem::Version.new(version).segments
    segments.pop while segments.any? { |segment| segment.is_a?(String) }
    segments << 0 if segments.empty?
    segments[-1] = segments[-1] + 1
    segments.join(".")
  end

  def write_box(dir, version, role)
    stage = File.join(dir, "stage-#{role}-#{version}")
    FileUtils.rm_rf(stage)
    FileUtils.mkdir_p(stage)
    File.write(File.join(stage, "metadata.json"), JSON.generate("provider" => PROVIDER))
    File.write(File.join(stage, "marker.txt"), role)
    box_path = File.join(dir, "#{role}-#{version}.box")
    result = Vagrant::Util::Subprocess.execute(
      "bsdtar", "-c", "-f", box_path, "-C", stage, "metadata.json", "marker.txt"
    )
    raise "bsdtar failed to pack the box: #{result.stderr}" if result.exit_code != 0

    [box_path, Digest::SHA256.file(box_path).hexdigest]
  end

  def start_server(state, boxes)
    server = WEBrick::HTTPServer.new(
      BindAddress: "127.0.0.1",
      Port: 0,
      Logger: WEBrick::Log.new(File::NULL),
      AccessLog: []
    )
    server.mount_proc "/" do |req, res|
      if boxes.key?(req.path)
        res.status = 200
        res["Content-Type"] = "application/octet-stream"
        res.body = File.binread(boxes[req.path])
      elsif state[:metadata_paths].include?(req.path)
        res.status = 200
        res["Content-Type"] = "application/json"
        res.body = state[:body]
      else
        res.status = 404
        res["Content-Type"] = "text/plain"
        res.body = "missing #{req.path}"
      end
    end
    thread = Thread.new { server.start }
    deadline = Time.now + 5
    sleep 0.01 while server.listeners.empty? && Time.now < deadline
    port = server.listeners.first.addr[1]
    [server, thread, port]
  end

  def install_box(vagrant_env, versions, roles)
    server = nil
    thread = nil
    work = Dir.mktmpdir("vagrant-box-files")
    box_name = vagrant_env.vagrantfile.config.vm.box
    box_files = {}
    versions.each do |version|
      box_path, checksum = write_box(work, version, roles.fetch(version))
      box_files[version] = ["/boxes/#{version}.box", checksum, box_path]
    end
    boxes = {}
    box_files.each_value { |url_path, _checksum, box_path| boxes[url_path] = box_path }
    state = {
      body: "{}",
      metadata_paths: [
        "/api/v2/vagrant/#{box_name}",
        "/#{box_name}"
      ]
    }
    server, thread, port = start_server(state, boxes)
    state[:body] = JSON.generate(
      "name" => box_name,
      "versions" => versions.map do |version|
        url_path, checksum, = box_files[version]
        {
          "version" => version,
          "providers" => [
            {
              "name" => PROVIDER,
              "url" => "http://127.0.0.1:#{port}#{url_path}",
              "checksum_type" => "sha256",
              "checksum" => checksum
            }
          ]
        }
      end
    )
    ENV["VAGRANT_SERVER_URL"] = "http://127.0.0.1:#{port}"
    ENV.delete("VAGRANT_SERVER_ACCESS_TOKEN_BY_URL")

    vm = vagrant_env.vagrantfile.config.vm
    collection = Vagrant::BoxCollection.new(
      Pathname.new(Dir.mktmpdir("vagrant-boxes")),
      hook: vagrant_env.method(:hook)
    )
    action_env = {
      action_runner: vagrant_env.action_runner,
      box_collection: collection,
      hook: vagrant_env.method(:hook),
      tmp_path: Pathname.new(Dir.mktmpdir("vagrant-box-add")),
      ui: Vagrant::UI::Silent.new,
      box_name: vm.box,
      box_url: vm.box_url || vm.box,
      box_architecture: vm.box_architecture,
      box_server_url: vm.box_server_url,
      box_provider: PROVIDER,
      box_version: vm.box_version,
      box_download_client_cert: vm.box_download_client_cert,
      box_download_ca_cert: vm.box_download_ca_cert,
      box_download_ca_path: vm.box_download_ca_path,
      box_download_insecure: vm.box_download_insecure,
      box_checksum_type: vm.box_download_checksum_type,
      box_checksum: vm.box_download_checksum,
      box_download_location_trusted: vm.box_download_location_trusted,
      box_download_disable_ssl_revoke_best_effort: vm.box_download_disable_ssl_revoke_best_effort,
      box_extra_download_options: vm.box_extra_download_options,
      env: vagrant_env
    }
    Vagrant::Action::Builtin::BoxAdd.new(->(_) {}, action_env).call(action_env)
    added = action_env[:box_added]
    {
      "installed_version" => added.version.to_s,
      "provider" => added.provider.to_s,
      "marker" => added.directory.join("marker.txt").read
    }
  ensure
    server&.shutdown
    thread&.join
  end
end

cwd = ENV.fetch("VAGRANTFILE_CWD")
vagrant_env = Vagrant::Environment.new(
  cwd: cwd,
  home_path: Dir.mktmpdir("vagrant-home"),
  local_data_path: Dir.mktmpdir("vagrant-dot"),
  ui_class: Vagrant::UI::Silent
)
vm = vagrant_env.vagrantfile.config.vm
shell = vm.provisioners.find { |prov| prov.type == :shell }
raise "Vagrantfile has no shell provisioner" if shell.nil?

script_path = Pathname.new(shell.config.path.to_s).expand_path(vagrant_env.root_path)
script = script_path.read
seed_versions = VagrantBoxPinHarness.named_versions(vm.box_version)
seed_versions = ["1.0.0"] if seed_versions.empty?
phase1 = VagrantBoxPinHarness.install_box(
  vagrant_env,
  seed_versions,
  seed_versions.to_h { |version| [version, "baseline"] }
)
replacement = VagrantBoxPinHarness.next_published(phase1.fetch("installed_version"))
replacement = VagrantBoxPinHarness.next_published(replacement) while seed_versions.include?(replacement)
phase2_versions = seed_versions + [replacement]
phase2 = VagrantBoxPinHarness.install_box(
  vagrant_env,
  phase2_versions,
  phase2_versions.to_h { |version| [version, version == replacement ? "replacement" : "baseline"] }
)

puts JSON.generate(
  "box" => vm.box,
  "box_version" => vm.box_version,
  "shell_path" => shell.config.path,
  "shell_privileged" => shell.config.privileged,
  "shell_script" => script_path.to_s,
  "shell_installs_packages" => script.include?("apt-get install") && script.include?("docker run"),
  "phase1" => phase1,
  "replacement_version" => replacement,
  "phase2" => phase2
)
