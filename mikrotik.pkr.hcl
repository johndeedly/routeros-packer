packer {
  required_plugins {
    qemu = {
      source  = "github.com/hashicorp/qemu"
      version = "~> 1"
    }
  }
}


variable "cpu_cores" {
  type    = number
  default = 4
}

variable "memory" {
  type    = number
  default = 4096
}

variable "headless" {
  type    = bool
  default = false
}

locals {
  build_name_qemu       = join(".", ["mikrotik-x86_64", replace(timestamp(), ":", "꞉"), "qcow2"]) # unicode replacement char for colon
}


source "qemu" "default" {
  shutdown_command     = "/system shutdown"
  disk_size            = "8192M"
  boot_wait            = "1s"
  boot_key_interval    = "10ms"
  boot_command         = [
    "<enter><wait20s>",
    "miy<wait30s><enter><wait5s><enter><wait10s>",
    "admin<enter><wait><enter><wait3s>",
    "n<wait2s><enter><wait>",
    "packer-build-passwd<enter><wait1s>packer-build-passwd<enter><wait2s>",
    "/interface macvlan add name=wan1 mode=private interface=ether1<enter><wait>",
    "/interface macvlan add name=lan1 mode=private interface=ether1<enter><wait>",
    "/interface macvlan add name=mgmt1 mode=private interface=ether1<enter><wait>",
    "/ip dhcp-client add disabled=no interface=mgmt1 add-default-route=no use-peer-dns=no use-peer-ntp=no<enter><wait>",
    "/ipv6 dhcp-client add disabled=no interface=mgmt1 add-default-route=no use-peer-dns=no request=address<enter><wait>",
    "/ip service set ssh disabled=no<enter><wait5s>"
  ]
  memory               = var.memory
  format               = "qcow2"
  accelerator          = "kvm"
  disk_discard         = "unmap"
  disk_detect_zeroes   = "unmap"
  disk_interface       = "ide"
  disk_compression     = false
  skip_compaction      = true
  net_device           = "virtio-net"
  vga                  = "virtio"
  machine_type         = "q35"
  cpu_model            = "host"
  efi_boot             = true
  efi_firmware_code    = "/usr/share/OVMF/x64/OVMF_CODE.secboot.4m.fd"
  efi_firmware_vars    = "/usr/share/OVMF/x64/OVMF_VARS.4m.fd"
  sockets              = 1
  cores                = var.cpu_cores
  threads              = 1
  qemuargs             = [
    ["-device", "virtio-net,netdev=user.0"],
    ["-drive", format("file=output/mikrotik/%s,if=none,id=disk.0,cache=writeback,discard=unmap,format=qcow2,detect-zeroes=unmap", local.build_name_qemu)],
    ["-device", "ide-hd,drive=disk.0,serial=your-serial-nr-here,model=your-model-name-here"],
    ["-drive", "file=mikrotik-7.15.3.iso,media=cdrom"],
    ["-drive", "file=/usr/share/OVMF/x64/OVMF_CODE.secboot.4m.fd,if=pflash,unit=0,format=raw,readonly=on"],
    ["-drive", "file=output/mikrotik/efivars.fd,if=pflash,unit=1,format=raw"],
    ["-rtc", "base=utc,clock=host"],
    ["-usbdevice", "keyboard"]
  ]
  headless             = var.headless
  iso_checksum         = "none"
  iso_url              = "mikrotik-7.15.3.iso"
  output_directory     = "output/mikrotik"
  communicator         = "ssh"
  ssh_username         = "admin"
  ssh_password         = "packer-build-passwd"
  vm_name              = local.build_name_qemu
}


build {
  sources = ["source.qemu.default"]

  provisioner "shell" {
    # more verbose execution to identify script errors:
    # execute_command = ":do { /import verbose=yes {{ .Path }}; } on-error={ :put \"!! error executing {{ .Path }}\"; };"
    execute_command = "/import {{ .Path }};"
    remote_path = format("%s.rsc", uuidv4())
    script = "init.rsc"
  }

  provisioner "shell-local" {
    inline = [<<EOS
tee output/mikrotik/mikrotik-x86_64.run.sh <<EOF
#!/usr/bin/env bash
trap "trap - SIGTERM && kill -- -\$\$" SIGINT SIGTERM EXIT
/usr/bin/qemu-system-x86_64 \\
  -name mikrotik-x86_64 \\
  -machine type=q35,accel=kvm \\
  -vga virtio \\
  -cpu host \\
  -drive file=${local.build_name_qemu},if=none,id=disk.0,cache=writeback,discard=unmap,detect-zeroes=unmap,format=qcow2 \\
  -device "ide-hd,drive=disk.0,serial=your-serial-nr-here,model=your-model-name-here" \\
  -drive file=/usr/share/OVMF/x64/OVMF_CODE.secboot.4m.fd,if=pflash,unit=0,format=raw,readonly=on \\
  -drive file=efivars.fd,if=pflash,unit=1,format=raw \\
  -smp ${var.cpu_cores},sockets=1,cores=${var.cpu_cores},maxcpus=${var.cpu_cores} -m ${var.memory}M \\
  -netdev user,id=user.0,hostfwd=tcp::8080-:80,hostfwd=tcp::8443-:443 -device virtio-net,netdev=user.0 \\
  -rtc base=utc,clock=host
EOF
# -display none, -daemonize, hostfwd=::12345-:22 for running as a daemonized server
chmod +x output/mikrotik/mikrotik-x86_64.run.sh
EOS
    ]
    only_on = ["linux"]
    only    = ["qemu.default"]
  }
}
