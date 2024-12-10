#
# Prerequisites
#

lsblk
drive=/dev/nvme0n1
amount_of_swap=$( free --si -g | grep Mem: | gawk '{ print $2 + 1}' )

#
# Partition Creation
#

sgdisk -Z $drive
sgdisk -o $drive
sgdisk -n 1::+1024M -t 1:ef02 $drive
sgdisk -n 2::+1024M -t 2:8300 $drive
sgdisk -n 3::+3072G -t 3:8300 $drive

part1=${drive}\p1
part2=${drive}\p2
part3=${drive}\p3

#
# Boot Partitions
#

mkfs.vfat -F32 $part1
mkfs -t btrfs -f -L gentoo_boot $part2

cryptsetup luksFormat -s 256 -c aes-xts-plain64 $part3
cryptsetup luksOpen $part3 gentoo_luks

#
# LVM Configuration
#

pvcreate /dev/mapper/gentoo_luks
vgcreate vg0 /dev/mapper/gentoo_luks
lvcreate -L ${amount_of_swap}G vg0 -n swap_lv
lvcreate -l +100%FREE vg0 -n system_lv
vgchange --available y

#
# BTRFS Configuration
#

mkfs -t btrfs -f -L gentoo_btrfs /dev/mapper/vg0-system_lv
mkswap /dev/mapper/vg0-swap_lv

mount -t btrfs /dev/mapper/vg0-system_lv /mnt/gentoo

btrfs subvolume create /mnt/gentoo/@
btrfs subvolume create /mnt/gentoo/@home
btrfs subvolume create /mnt/gentoo/@var_log
btrfs subvolume create /mnt/gentoo/@snapshots
btrfs subvolume list /mnt/gentoo
umount -R /mnt/gentoo

opts_btrfs=acl,autodefrag,barrier,compress-force=zstd,datacow,datasum,discard=async,space_cache=v2,ssd,treelog
mount -t btrfs -o $opts_btrfs,subvol=@ /dev/mapper/vg0-system_lv /mnt/gentoo
mkdir -p /mnt/gentoo/boot/
mount -t btrfs -o $opts_btrfs $part2 /mnt/gentoo/boot
mkdir -p /mnt/gentoo/boot/EFI
mount $part1 /mnt/gentoo/boot/EFI
swapon /dev/mapper/vg0-swap_lv

#
# Stage3 Download
#

cd /mnt/gentoo

wget https://distfiles.gentoo.org/releases/amd64/autobuilds/current-stage3-amd64-hardened-selinux-openrc/latest-stage3-amd64-hardened-selinux-openrc.txt
filename='latest-stage3-amd64-hardened-selinux-openrc.txt'
stage3_dl_version=$(grep -oP '(?<=^# ts=)[^\s]+|\w+/\S+\.tar\.xz' $filename | grep -oP '\d{8}T\d{6}Z/\S+\.tar\.xz')
wget https://distfiles.gentoo.org/releases/amd64/autobuilds/${stage3_dl_version}

tar xpvf stage3-*.tar.xz --xattrs-include='*.*' --numeric-owner
rm -f stage3-*.tar.xz

#
# System Mount
#

mkdir /mnt/gentoo/.snapshots
mount -t btrfs -o $opts_btrfs,subvol=@home /dev/mapper/vg0-system_lv /mnt/gentoo/home
mount -t btrfs -o $opts_btrfs,subvol=@var_log /dev/mapper/vg0-system_lv /mnt/gentoo/var/log
mount -t btrfs -o $opts_btrfs,subvol=@snapshots /dev/mapper/vg0-system_lv /mnt/gentoo/.snapshots

mount --types proc /proc /mnt/gentoo/proc
mount --rbind /sys /mnt/gentoo/sys
mount --make-rslave /mnt/gentoo/sys
mount --rbind /dev /mnt/gentoo/dev
mount --make-rslave /mnt/gentoo/dev

mkdir --parents /mnt/gentoo/etc/portage/repos.conf
cp /mnt/gentoo/usr/share/portage/config/repos.conf /mnt/gentoo/etc/portage/repos.conf/gentoo.conf
cp --dereference /etc/resolv.conf /mnt/gentoo/etc/

#
# Chroot
#

chroot /mnt/gentoo /bin/bash

source /etc/profile
export PS1="[chroot] $PS1"

drive=/dev/nvme0n1
part1=${drive}\p1
part2=${drive}\p2
part3=${drive}\p3
part_swap_lv=/dev/mapper/vg0-swap_lv
part_system_lv=/dev/mapper/vg0-system_lv
opts_btrfs=acl,autodefrag,barrier,compress-force=zstd,datacow,datasum,discard=async,space_cache=v2,ssd,treelog

#
# Portage Update
# 

emerge --sync
eselect profile list
eselect profile set 44
emerge -qvj --oneshot portage

#
# Dispatch Config
#
emerge --qavj dev-vcs/rcs
cat << EOF >> /etc/dispatch-conf.conf
use-rcs=yes
EOF

emerge --qavj sys-apps/sysvinit

#
# RC Config
#

cat << EOF >>/etc/rc.conf
rc_logger="YES"
#rc_log_path="/var/log/rc.log"
EOF

emerge -qavj --oneshot sys-apps/openrc

#
# Make.conf
#

emerge -qvj app-portage/cpuid2cpuflags app-misc/resolve-march-native
cpu_flags=$( cpuid2cpuflags | cut -d ' ' -f '2-' )

## append to my make.conf
# use_remove='-3df -3dfx -a52 -accessibility -altivec -apache2 -aqua -berkdb -big-endian -bindist -boundschecking -bsf -canna -cjk -clamav -connman -coreaudio -custom-cflags -css -cups -debug -dedicated -emacs -emboss -gnome -handbook -ibm -infiniband -ios -ipod -ieee1394 -iwmmxt -kde -kontact -ldap-emacs -libav -libedit -libressl -libsamplerate -mono -motif -mule -nas -nls -neon -nntp -oci8 -oci8-instant-client -oracle -oss -pch -pcmcia -plasma -qmail-spp -qt4 -qt5 -quicktime -smartcard -static -syslog -systemd -sysvipc -tcpd -xemacs -yahoo'
use_remove='-3df -3dfx -a52 -accessibility -altivec -apache2 -aqua -berkdb -big-endian -bindist -boundschecking -bsf -canna -cjk -clamav -connman -coreaudio -debug -dedicated -emacs -emboss -handbook -gnome-online-accounts -ibm -infiniband -ios -ipod -ieee1394 -iwmmxt -kde -kontact -ldap-emacs -libav -libedit -libressl -libsamplerate -mono -motif -mule -nas -neon -nntp -oci8 -oci8-instant-client -oracle -oss -pch -pcmcia -plasma -qmail-spp -quicktime -smartcard -static -sysvipc -tcpd -xemacs -yahoo'
use_add='alsa bluetooth calendar cdrc colord cups crypt dbus dbusmenu device-mapper elogind evdev gnome gtk homed initramfs jack lvm libnotify nls man multilib ncurses networkmanager openal opencl opengl perl pipewire-alsa policykit pulseaudio python qt5 qt6 readline screencast secureboot selinux session sound ssl syslog tcl test-rust threads ttf udev udisks uefi unicode upower usb valgrind videos vim-syntax vnc vpx vulkan X xft xinerama xml xpm xscreensaver zip zsh zsh-completion'
make_opts="-j$(( $( nproc ) + 1 ))"
allprocs="$(( $( nproc ) + 1 ))"

cp /etc/portage/make.conf /etc/portage/make.bak
cat << EOF > /etc/portage/make.conf
CFLAGS="-march=znver4 -O2 -pipe"

CXXFLAGS=\${CFLAGS}
CHOST="x86_64-pc-linux-gnu"
CPU_FLAGS_X86="${cpu_flags}"
ABI_X86="64 32"

VIDEO_CARDS="fbdev vesa amdgpu radeonsi"

INPUT_DEVICES="libinput synaptics keyboard mouse joystick wacom"

# enable this if you like living on the edge
ACCEPT_KEYWORDS="~amd64"

ACCEPT_LICENSE="*"

MAKEOPTS="${make_opts}"

# Portage Opts
FEATURES="binpkg-logs buildpkg collision-protect downgrade-backup ipc-sandbox network-sandbox parallel-fetch parallel-install ebuild-locks"
EMERGE_DEFAULT_OPTS="--ask --verbose --quiet-build --deep --complete-graph=y --with-bdeps=y --jobs=${allprocs} --load-average=${allprocs}"
#AUTOCLEAN="yes"
PORTAGE_SCHEDULING_POLICY="idle"
PORTAGE_COMPRESS="zstd"
BINPKG_COMPRESS="zstd"
# BINPKG_COMPRESS_FLAGS_ZSTD flags:
# * -T0 (already the default but adding here so it's not lost)
# * -22: maximum compression level
# * --ultra: work harder
BINPKG_COMPRESS_FLAGS_ZSTD="-T0 -22 --ultra"

ADD="${use_add}"
REMOVE="${use_remove}"
USE="\$REMOVE \$ADD"

GRUB_PLATFORMS="pc efi-64"

QEMU_SOFTMMU_TARGETS="arm x86_64 sparc"
QEMU_USER_TARGETS="x86_64"

# target-cpu=native is the equivalent of -march=native in C/CXXFLAGS:
RUSTFLAGS="-C target-cpu=native"
# enable target-cpu=native and DT_RELR
RUSTFLAGS="-C target-cpu=native -C link-arg=-Wl,-z,pack-relative-relocs"
RUSTFLAGS="-C opt-level=3"

PYTHON_TARGETS = "python3_9 python3_11 python3_12 python3_13"

CGO_CFLAGS="${CFLAGS}"
CGO_CXXFLAGS="${CXXFLAGS}"
CGO_FFLAGS="${FFLAGS}"
CGO_LDFLAGS="${LDFLAGS}"
# https://github.com/golang/go/wiki/MinimumRequirements#architectures
# Pick carefully based on https://en.wikipedia.org/wiki/X86-64#Microarchitecture_levels!
# For amd64 (v1 (default)/v2/v3/v4):
#GOAMD64="v3"
# For x86 (sse2 (default)/softfloat):
#GO386=sse2
# For arm (5/6 (usually default)/7):
#GOARM=6

GENTOO_MIRRORS="https://gentoo.mirrors.ovh.net/gentoo-distfiles/ \
    http://gentoo.mirrors.ovh.net/gentoo-distfiles/ \
    http://ftp.agdsn.de/gentoo \
    https://ftp.agdsn.de/gentoo \
    https://mirror.netcologne.de/gentoo/ \
    http://mirror.netcologne.de/gentoo/"

EOF

mkdir -p /etc/portage/package.{accept_keywords,license,mask,unmask,use,env}

#
# Local Package USE Flags
#

cat << EOF > /etc/portage/package.use/app-admin
app-admin/syslog-ng ampq caps dbi geoip2 grpc http json kafka mongodb mqtt python redis smtp snmp spoof-source tcpd
EOF

cat << EOF > /etc/portage/package.use/app-arch
app-arch/zstd lzma lz4 zlib
EOF

cat << EOF > /etc/portage/package.use/app-editor
app-editor/neovim nvimpager
EOF

cat << EOF > /etc/portage/package.use/app-emulation
app-emulation/libvirt pcap virt-network numa fuse macvtap vepa qemu bash-completion caps libvirtd udev dtrace firewalld glusterfs iscsi iscsi-direct libssh2 lvm lxc nbd nfs nls openvz parted policykit rdb sasl virtiofsd virtualbox wireshark-plugins xen zfs
app-emulation/qemu aio curl doc fdt filecaps gnutls jpeg oss pin-upstream-blobs png seccomp slirp vhost-net vnc alsa bpf bzip2 capstone debug fuse glusterfs gtk infiniband io-uring iscsi jack jemalloc keyutils lzo multipath ncurses nfs nls numa opengl pam pipewire plugins pulseaudio python rdb sasl sdl sdl-image snappy spice ssh systemtap udev usb usbredir vde virgl virtfs vte xattr xdp xen zstd
app-emulation/virt-manager gui policykit sasl
app-emulation/virtualbox gui opengl opus qt5 sdk sdl strip udev vmmraw alsa dbus doc dtrace java lvm nls pam pulseaudio python vboxwebsrv vde vnc
app-emulation/wine-proton alsa fontconfig gecko gstreamer mono sdl ssl strip unwind vkd3d xcomposite crossdev-mingw debug nls openal osmesa perl pulseaudio udev udisks usb v4l wow64
app-emulation/winetricks gui
EOF

cat << EOF > /etc/portage/package.use/app-office
app-office/libreoffice branding cups dbus gtk mariadb base bluetooth clang debug eds firebird googledrive gstreamer java ldap odk pdfimport postgres qt5 qt6 valgrind vulkan
EOF

cat << EOF > /etc/portage/package.use/app-shells
app-shells/zsh caps debug doc examples gdbm maildir pcre valgrind
EOF

cat << EOF > /etc/portage/package.use/dev-debug
dev-debug/valgrind mpi verify-sig
EOF

cat << EOF > /etc/portage/package.use/dev-lang
dev-lang/perl berkdb doc gdbm
dev-lang/python	ensurepip ncurses readline sqlite ssl xml berkdb bluetooth debug examples gdbm libedit pgo tk valgrind verify-sig wininst
dev-lang/rust lto big-endian clippy debug doc miri parallel-compiler profiler rust-analyzer rust-src rustfmt system-bootstrap verify-sig
EOF

cat << EOF > /etc/portage/package.use/dev-libs
dev-libs/libinput doc
EOF

echo "dev-python/PyQt6 -bluetooth" >> /etc/portage/package.use/dev-python

cat << EOF > /etc/portage/package.use/dev-vcs
dev-vcs/git blksha1 curl gpg iconv nls pcre perl safe-directory webdav cgi cvs doc highlight keyring mediawiki perforce subversion tk xinetd
EOF

cat << EOF > /etc/portage/package.use/gnome-base
gnome-base/gnome bluetooth extras cups
EOF

cat << EOF > /etc/portage/package.use/gnome-extra
gnome-extra/nm-applet appindicator
EOF

cat << EOF > /etc/portage/package.use/media-libs 
EOF

cat << EOF > /etc/portage/package.use/media-plugins
media-plugins/alsa-plugins debug ffmpeg jack libsamplerate oss pulseaudio speex
media-plugins/gst-plugins-meta ffmpeg
EOF

cat << EOF > /etc/portage/package.use/media-sound
media-libs/alsa-lib alisp debug doc python
media-sound/mpd	alsa audiofile cue curl dbus eventfd ffmpeg fifo icu id3tag inotify io-uring mad network bizip2 doc expat flac gme jack lame libmpdclient libsamplerate libsoxr mikmod mms modplug musepack nfs openal openmpt opus oss pipe pipewire pulseaudio qobuz recorder samba sid signalfd snapcast sndfile sndio soundcloud sqlite twolame udisks upnp vorbis wavpack webdav wildmidi yajl zip zlib
media-sound/ncmpcpp clock outputs taglib visualizer
media-sound/pulseaudio glib bluetooth jack -daemon
EOF

cat << EOF > /etc/portage/package.use/media-video
media-video/pipewire man X bluetooth dbus doc echo-cancel elogind extra ffmpeg gsetting gstreamer jack-client jack-sdk liblc3 lv2 pipewire-alsa readline roc sound-server ssl v4l
media-video/obs-studio alsa ssl browser decklink fdk jack lua mpegts pipewire pulseaudio python sndio speex test-input truetype v4l vlc websocket
media-video/vlc	X dvbpsi encode ffmpeg gcrypt gui libsamplerate a52 alsa aom archive aribsub bidi bluray cddb chromaprint dav1d dbus dc1394 debug directx dts dvd faad fdk flac fluidsynth fontconfig gme gstreamer jack jpeg kate keyring kms libass libcaca libnotify libplacebo libtar libtiger linsys lirc live lua mad matroska modplug mp3 mpeg mtp musepack ncurses nfs ogg omxil opus png projectm pulseaudio rdp samba sdl-image sftp shout sid skins soxr speex srt ssl svg taglib theora remor truetype twolame udev upnp v4l vaapi vdpau vnc vpx x264 x265 xml zeroconf zvbi
EOF

cat << EOF > /etc/portage/package.use/net-analizer
net-analyzer/nmap nse ipv6 libssh2 ncat ndiff nls nping ssl symlink zenmap
net-analyzer/wireshark capinfos captype dftest dumpcap editcap filecaps gui mergecap minizip netlink pcap plugins randpkt randpktdump reordercap sharkd text2pcap tshark udpdump zstd androiddump bcg729 brotli ciscodump doc dpauxmon http2 http3 ilbc kerberos libxml2 lua lz4 maxminddb opus qt6 sbc sdjournal smi snappy spandsp sshdump ssl tfshark wifi zlib
EOF

cat << EOF > /etc/portage/package.use/net-firewall
net-firewall/iptables conntrack netlink nftables pcap
EOF

cat << EOF > /etc/portage/package.use/net-misc
net-misc/networkmanager	concheck gtk-doc introspection modemmanager nss ppp tools wext wifi bluetooth connection-sharing debug dhcpcd elogind gnutls iptables iwd libedit nftables ovs policykit psl resolvconf syslog teamd vala
EOF

cat << EOF > /etc/portage/package.use/net-vpn
net-vpn/openvpn	lz4 lzo openssl plugins dco down-root examples inotify mbedtls pam pkcs11
EOF

cat << EOF > /etc/portage/package.use/net-wireless
net-wireless/bluez mesh obex readline udev btpclient cups debug deprecated doc experimental extra-tools man midi test-programs
EOF

cat << EOF > /etc/portage/package.use/sys-apps
sys-apps/sysvinit nls verify-sig
sys-apps/openrc sysvinit caps debug pam sysv-utils unicode
sys-apps/dbus X debug doc elogind valgrind
EOF

cat << EOF > /etc/portage/package.use/sys-auth
sys-auth/elogind acl cgroup-hybrid pam policykit debug doc
sys-auth/polkit	daemon duktape introspection examples gtk pam
EOF

cat << EOF > /etc/portage/package.use/sys-boot
sys-boot/grub device-mapper fonts themes doc efiemu libzfs mount nls sdl secureboot truetype
EOF

cat << EOF > /etc/portage/package.use/sys-devel
sys-devel/gcc cxx fortran nls openmp pie sanitize ssp ada cet d debug default-stack-clash-protection doc go graphite hardened libdiagnostics lto multilib objc objc++ objc-gc rust systemtap valgrind vtv zstd
sys-devel/clang	debug extra pie static-analyzer doc verify-sig xml
EOF

cat << EOF > /etc/portage/package.use/sys-fs
sys-fs/cryptsetup argon2 fips gcrypt kernel nettle openssl pwquality ssh urandom nls udev
sys-fs/lvm udev lvm readline sanlock thin valgrind
sys-fs/lvm2 udev lvm readline sanlock thin valgrind
EOF

cat << EOF > /etc/portage/package.use/sys-kernel
sys-kernel/linux-firmware compress-zstd deduplicate initramfs redistributable savedconfig
EOF

cat << EOF > /etc/portage/package.use/sys-libs
sys-libs/glibc clone3 crypt multiarch ssp static-libs caps compile-locales debug doc gd hash-sysv-compat multilib nscd perl profile static-pie systemtap
EOF

cat << EOF > /etc/portage/package.use/virtual
virtual/wine proton
EOF

cat << EOF > /etc/portage/package.use/www-client
www-client/firefox X clang gmp-autoupdate jumbo-build system-av1 system-harfbuzz system-icu system-jpeg system-libevent system-libvpx system-webp -telemetry dbus debug geckodriver gnome-shell hardened hwaccel jack libproxy lto openh264 pgo pulseaudio screencast sndio systempng system-python-libs valgrind wasm
www-client/chromium X hangouts official proprietary-codecs screencast system-harfbuzz system-icu system-png system-toolchain system-zstd vaapi -wayland widevine cups debug gtk4 kerberos pulseaudio qt5 qt6
EOF

cat << EOF > /etc/portage/package.use/x11-base
x11-base/xorg-server elogind udev debug suid unwind xsecurity xorg
EOF

cat << EOF > /etc/env.d/99zstd
# Use number of threads available for parallel compression (0 = Autodetect)
ZSTD_NBTHREADS="0"
EOF

cat << EOF > /etc/portage/env/lto.conflto.conf
CFLAGS="-march=native -O2 -pipe -flto"
CXXFLAGS="${CFLAGS}"
EOF

cat << EOF > /etc/portage/package.env/firefox
www-client/firefox lto.conf
EOF
    
cat << EOF > /etc/portage/env/makeopts.conf
MAKEOPTS="${make_opts}"
EOF

cat << EOF > /etc/portage/package.env/rust
dev-lang/rust makeopts.conf
EOF

echo "*/* *" >> /etc/portage/package.license/custom

echo "media-sound/pulseaudio-daemon" >> /etc/portage/package.mask/media-sound

cat << EOF > /etc/env.d/99zstd
# Use number of threads available for parallel compression (0 = Autodetect)
ZSTD_NBTHREADS="0"
EOF

#
# ZSTD debug patch
#

cat << EOF >/etc/portage/patches/sys-apps/portage/compressdebug-zstd.patch
Make Portage use zstd for debug info compression.
Make sure binutils[zstd], elfutils[zstd], and gdb[zstd] are emerged first!
Portage bug to make this properly configurable: https://bugs.gentoo.org/906367
--- a/bin/estrip
+++ b/bin/estrip
@@ -295,7 +295,7 @@ save_elf_debug() {
		mv "${splitdebug}" "${dst}"
	else
		local objcopy_flags="--only-keep-debug"
-			${FEATURES_compressdebug} && objcopy_flags+=" --compress-debug-sections"
+			${FEATURES_compressdebug} && objcopy_flags+=" --compress-debug-sections=zstd"
		${OBJCOPY} ${objcopy_flags} "${src}" "${dst}" &&
		${OBJCOPY} --add-gnu-debuglink="${dst}" "${src}"
	fi
EOF

#
# Locales
#

ln -sf /usr/share/zoneinfo/Europe/Paris /etc/localtime
echo "Europe/Paris" > /etc/timezone
emerge --config sys-libs/timezone-data
echo "en_US.UTF-8 UTF-8" >> /etc/locale.gen
locale-gen
eselect locale list
eselect locale set 4
env-update && source /etc/profile && export PS1="(chroot) ${PS1}"

#
# Hostname
#

hostname=Threadripper

cat << EOF > /etc/conf.d/hostname
hostname="$hostname"
EOF

cat << EOF > /etc/hosts
127.0.0.1       $hostname.localdomain	localhost
::1             localhost		$hostname
EOF

emerge -aq net-misc/dhcpcd
rc-service dhcpcd start

#
# First @world Emerge
#

emerge-webrsync
emerge --sync
emerge -qvj --oneshot portage
perl-cleaner --reallyall
time emerge -aqvjUDN --with-bdeps=y  --keep-going --backtrack=30 --autounmask-continue @world

gcc-config --list-profiles
emerge --oneshot --usepkg=n dev-build/libtool
emerge app-editors/neovim
eselect editor list
eselect editor set 1

#
# Polkit Config
#

cat << EOF > /etc/polkit-1/rules.d/10-admin.rules
polkit.addAdminRule(function(action, subject) {
    return ["unix-group:wheel"];
});
EOF

cat << EOF > /etc/polkit-1/rules.d/10-udisks.rules
polkit.addRule(function(action, subject) {
	if (action.id == "org.freedesktop.udisks2.filesystem-mount" &&
    		subject.user == "noided") {
    		return polkit.Result.YES;
	}
});
EOF

#
# FSTAB Config
#

opts_btrfs=acl,autodefrag,barrier,compress-force=zstd,datacow,datasum,discard=async,space_cache=v2,ssd,treelog

blkid
IFS=\" read -r _ part1_UUID _ < <(blkid $part1 -s UUID)
IFS=\" read -r _ part2_UUID _ < <(blkid $part2 -s UUID)
IFS=\" read -r _ part3_UUID _ < <(blkid $part3 -s UUID)
IFS=\" read -r _ part_swap _ < <(blkid /dev/mapper/vg0-swap_lv -s UUID)
IFS=\" read -r _ part_root _ < <(blkid /dev/mapper/vg0-system_lv -s UUID)


cat << EOF > /etc/fstab
# <fs>                                  <mountpoint>        <type>      <opts>                                                                         <dump/pass>

# /dev/nvme0n1p1 -> /boot/EFI
UUID=${part1_UUID}                               /boot/EFI           vfat        defaults,ro                      0 0

# /dev/nvme0n1p2 -> /boot/
UUID=${part2_UUID}                              /boot               btrfs       $opts_btrfs                      1 2

# /dev/mapper/vg0-swap_lv -> SWAP
UUID=${part_swap}      none                swap        defaults                         0 0

# /dev/mapper/vg0-swap_lv -> ROOT
UUID=${part_root}      /                   btrfs       $opts_btrfs,subvol=@             0 0
UUID=${part_root}      /home               btrfs       $opts_btrfs,subvol=@home         0 0
UUID=${part_root}      /.snapshots         btrfs       $opts_btrfs,subvol=@snapshots    0 0
UUID=${part_root}      /var/log            btrfs       $opts_btrfs,subvol=@var_log      0 0

# tmps
tmpfs                                           /tmp                            tmpfs           defaults,size=4G                                                                0 0
tmpfs                                           /run                            tmpfs           size=100M                                                                       0 0
# shm
shm                                             /dev/shm                        tmpfs           nodev,nosuid,noexec                                                             0 0
EOF

#
# Kernel Config
#

MAKEOPTS="-j1" emerge -av util-linux

# gdbus-codegen MUST BE SAME VERSION  as glib
time emerge -aqvjUDN --with-bdeps=y  --keep-going --backtrack=30 --autounmask-continue @world

FEATURES="-collision-protect -protect-owned" emerge -v1a app-alternatives/cpio
emerge -qvjUDN sys-kernel/gentoo-sources genkernel sys-kernel/linux-firmware sys-kernel/linux-headers pciutils usbutils installkernel lvm2 app-portage/gentoolkit app-misc-screen portage-utils nmon
systemctl enable lvm2-monitor.service


eselect kernel list
eselect kernel set 1
time emerge -aqvjUDN --with-bdeps=y  --keep-going --backtrack=30 --autounmask-continue @world

cd /usr/src/linux

cp /etc/genkernel.conf /etc/genkernel.bak

cat << EOF >> vim /etc/genkernel.conf
INSTALL="yes"
OLDCONFIG="yes"
MENUCONFIG="yes"
MRPROPER="yes"
MOUNTBOOT="yes"
SYMLINK="yes"
SAVE_CONFIG="yes"
NOCOLOR="false"
MAKEOPTS="$(portageq envvar MAKEOPTS)"
LVM="yes"
LUKS="yes"
GPG="yes"
KEYCTL="yes"
MICROCODE="amd"
DMRAID="yes"
BUSYBOX="yes"
BTRFS="yes"
FIRMWARE="yes"
FIRMWARE_DIR="/lib/firmware"
BOOTLOADER="grub2"
SANDBOX="yes"
EOF

cat << EOF > /etc/kernel/config.d/btrfs-linux6-1-111.config
CONFIG_BTRFS_FS=y
CONFIG_XOR_BLOCKS=y
CONFIG_RAID6_PQ=y
CONFIG_RAID6_PQ_BENCHMARK=y
CONFIG_ZSTD_COMPRESS=y
EOF

#
# Kernel Install
#

time genkernel --menuconfig --luks --lvm --btrfs --symlink all
#Enable Verbose procfs contents
#Enable Event interface in the kernel (CONFIG_INPUT_EVDEV)
#Disable legacy framebuffer support and enable basic console FB support
#Enable loadable module support (CONFIG_MODULES)
#Enable MTRR support (CONFIG_MTRR)
#Enable VGA Arbitration (CONFIG_VGA_ARB)
#Enable IPMI message handler (CONFIG_ACPI_IPMI)
#Enable agpgart support (CONFIG_AGP)
#Disable support for the in-kernel driver (CONFIG_FB_NVIDIA, CONFIG_FB_RIVA)
#Disable support for the nouveau driver (CONFIG_DRM_NOUVEAU)
#Disable SimpleDRM support (CONFIG_DRM_SIMPLEDRM)
#Enable framebuffer drivers for the kernel 5.15 and later (CONFIG_SYSFB_SIMPLEFB, CONFIG_FB_VESA, CONFIG_FB_EFI, CONFIG_FB_SIMPLE)
#Enable GCC plugins (CONFIG_GCC_PLUGINS)
#Enable zswap

time emerge -aqvjUDN --with-bdeps=y  --keep-going --backtrack=30 --autounmask-continue @world

emerge -avj sys-fs/dmraid sys-apps/keyutils sys-apps/dbus-broker sys-apps/busybox sys-apps/rng-tools net-misc/connman sys-fs/udisks sys-boot/os-prober

#
# ZRAM Config
#

modprobe zram
echo "zram" > /etc/modprobe.d/zram.conf
echo zstd > /sys/block/zram0/comp_algorithm
amount_of_swap=$( free --si -g | grep Mem: | gawk '{ print $2 + 1}' )
amount_of_zram=$((($amount_of_swap*1024*1024*1024)))
echo $amount_of_zram > /sys/block/zram0/disksize

mkswap -L zramswap /dev/zram0
swapon -p 100 /dev/zram0

cat << EOF > /etc/init.d/zram
#!/sbin/openrc-run
depend()
{
    after clock root swap
    before localmount
    keyword -docker -jail -lxc -openvz -prefix -systemd-nspawn -vserver
}
start()
{
    ebegin "Activation de ZRAM"
    # Charge le module
    modprobe zram
    # Compression ZSTD
    echo zstd > /sys/block/zram0/comp_algorithm
    # Taille $amount_of_swap Go
    echo $amount_of_zram > /sys/block/zram0/disksize
    # Création ZRAM
    mkswap -L zramswap /dev/zram0
    # Activation ZRAM
    swapon -p 100 /dev/zram0
    # Fin
    eend 0
}
stop()
{
    # Désactivation ZRAM
    swapoff /dev/zram0
    # Reset du ZRAM
    echo 1 >/sys/block/zram0/reset
    # Suppression du module
    rmmod zram
    # Fin
    eend 0
}
EOF

chmod +x /etc/init.d/zram


#
# Grub Config
#

grub-install --target=x86_64-efi --efi-directory=/boot/EFI
cp -p /etc/default/grub /etc/default/grub.bak

blkid  | egrep '(crypto_LUKS|system_lv)'
IFS=\" read -r _ part1_UUID _ < <(blkid $part1 -s UUID)
IFS=\" read -r _ part2_UUID _ < <(blkid $part2 -s UUID)
IFS=\" read -r _ part3_UUID _ < <(blkid $part3 -s UUID)
IFS=\" read -r _ part_swap _ < <(blkid /dev/mapper/vg0-swap_lv -s UUID)
IFS=\" read -r _ part_root _ < <(blkid /dev/mapper/vg0-system_lv -s UUID)

echo 1 > /sys/module/zswap/parameters/enabled
echo zstd > /sys/module/zswap/parameters/compressor

cp /etc/default/grub /etc/default/grub.bak
cat << EOF > /etc/default/grub

GRUB_DISTRIBUTOR="Gentoo"

GRUB_DEFAULT=0
GRUB_TIMEOUT=5
GRUB_TIMEOUT_STYLE=menu

GRUB_ENABLE_CRYPTODISK=y
GRUB_CMDLINE_LINUX="dolvm crypt_root=UUID=${part3_UUID} root=UUID=${part_root} rootflags=subvol=@ zswap.enabled=1 zswap.compressor=zstd resume=UUID=${part_swap} splash"

GRUB_GFXMODE=auto

#GRUB_THEME="/boot/grub/themes/starfield/theme.txt"
#GRUB_BACKGROUND="/boot/grub/mybackground.png"

# Uncomment if you don't want GRUB to pass "root=UUID=xxx" parameter to kernel
#GRUB_DISABLE_LINUX_UUID=true

# Comment if you don't want GRUB to pass "root=PARTUUID=xxx" parameter to kernel
#GRUB_DISABLE_LINUX_PARTUUID=false

# Uncomment to disable generation of recovery mode menu entries
#GRUB_DISABLE_RECOVERY=true

#GRUB_DISABLE_SUBMENU=y

#GRUB_INIT_TUNE="60 800 1"
EOF

grub-mkconfig -o /boot/grub/grub.cfg

#
# Base Packages Install
#

PACKAGE=(
    app-admin/logrotate
    app-admin/sudo 
    app-admin/syslog-ng
    app-admin/syslog-ng 
    app-arch/lzop 
    app-arch/zstd 
    app-backup/snapper 
    app-emulation/libvirt
    app-emulation/q4wine
    app-emulation/qemu
    app-emulation/virt-manager
    app-emulation/virtualbox
    app-emulation/virtualbox-additions
    app-emulation/virtualbox-guest-additions
    app-emulation/wine-proton
    app-misc/jq 
    app-misc/radeontop
    app-office/libreoffice
    app-portage/eix 
    app-shells/bash-completion
    app-shells/gentoo-zsh-completions
    app-shells/zsh
    app-shells/zsh-completions
    app-text/hunspell
    app-vim/fugitive
    dev-debug/valgrind
    dev-libs/libisoburn
    dev-util/debugedit
    dev-vcs/git
    dev-vcs/git-cola
    dev-vcs/git-flow
    dev-vcs/gitg
    gnome-base/gnome
    gnome-base/gnome
    gnome-extra/gnome-browser-connector
    gnome-extra/gnome-shell-extensions
    gui-libs/display-manager-init
    gui-libs/display-manager-init
    media-gfx/scrot 
    media-libs/alsa-lib 
    media-libs/libpulse 
    media-plugins/alsa-plugins
    media-sound/alsa-tools 
    media-sound/alsa-utils 
    media-sound/mpd 
    media-sound/ncmpcpp 
    media-sound/paprefs
    media-sound/playerctl 
    media-sound/pulseaudio 
    media-sound/pulsemixer
    media-video/obs-studio
    media-video/pipewire 
    media-video/vlc
    media-video/wireplumber 
    net-analyzer/nmap
    net-analyzer/tcpdump
    net-analyzer/wireshark
    net-dns/knot
    net-dns/openresolv
    net-firewall/iptables
    net-misc/bridge-utils
    net-misc/curl
    net-misc/ndisc6
    net-misc/networkmanager
    net-misc/ntp
    net-misc/ntp
    net-misc/whois
    net-vpn/networkmanager-openvpn
    net-vpn/openvpn
    net-vpn/wireguard-tools
    net-wireless/blueman
    net-wireless/bluez 
    sys-apps/dmidecode 
    sys-apps/haveged 
    sys-apps/hdparm 
    sys-apps/smartmontools 
    sys-apps/usermode-utilities
    sys-auth/rtkit
    sys-boot/grml-rescueboot
    sys-boot/os-prober
    sys-fs/btrfs-progs
    sys-fs/btrfsmaintenance
    sys-fs/cryptsetup
    sys-fs/lvm2
    sys-power/acpid 
    sys-power/upower 
    sys-process/cronie 
    sys-process/htop 
    sys-process/lsof 
    virtual/wine
    www-client/chromium
    www-client/firefox
    x11-apps/mesa-progs
    x11-apps/xclock 
    x11-apps/xinit 
    x11-base/xcb-proto
    x11-base/xorg-apps 
    x11-base/xorg-drivers 
    x11-base/xorg-drivers 
    x11-base/xorg-fonts
    x11-base/xorg-proto 
    x11-base/xorg-server 
    x11-base/xorg-server 
    x11-base/xorg-sgml-doctools
    x11-drivers/xf86-video-amdgpu 
    x11-libs/lib3dXft x11-libs/libxcb
    x11-libs/libX11 x11-libs/libXau
    x11-libs/libXaw x11-libs/libZaw3d
    x11-libs/libXcomposite
    x11-libs/libXcursor
    x11-libs/libxcvt
    x11-libs/libXdamage
    x11-libs/libXdmcp
    x11-libs/libXext
    x11-libs/libXfixes
    x11-libs/libXfont2
    x11-libs/libXft
    x11-libs/libXft 
    x11-libs/libXi
    x11-libs/libXinerama
    x11-libs/libXinerama 
    x11-libs/libxkbcommon
    x11-libs/libxkbfile
    x11-libs/libxklavier
    x11-libs/libXmu
    x11-libs/libXpm
    x11-libs/libXpresent
    x11-libs/libXrandr
    x11-libs/libXrender
    x11-libs/libXres
    x11-libs/libXScrnSaver
    x11-libs/libxshmfence
    x11-libs/libXt
    x11-libs/libXtst
    x11-libs/libXv
    x11-libs/libXvMC
    x11-libs/libXxf86dga
    x11-libs/libXxf86vm
    x11-libs/xcb-imdkit
    x11-libs/xcb-util
    x11-libs/xcb-util-cursor
    x11-libs/xcb-util-errors
    x11-libs/xcb-util-image
    x11-libs/xcb-util-keysyms
    x11-libs/xcb-util-renderutil
    x11-libs/xcb-util-wm
    x11-libs/xcb-util-xrm
    x11-misc/xdotool 
    x11-misc/wmctrl
    x11-terms/xterm 
    x11-themes/adwaita-icon-theme
    x11-wm/twm 
)
emerge -qvj --autounmask-continue ${PACKAGE[@]}

cp /usr/share/X11/xorg.conf.d/40-libinput.conf /etc/X11/xorg.conf.d/

cp /usr/share/pipewire/pipewire.conf /etc/pipewire/pipewire.conf
sudo cp /usr/share/pipewire/pipewire.conf ~/.config/pipewire/pipewire.conf

echo 'DISPLAYMANAGER="gdm"' >> /etc/conf.d/display-manager

eselect repository add nightdragon_layman git https://github.com/NightDragon1/nightdragon_layman.git
mkdir -p /etc/portage/repos.conf
wget -O /etc/portage/repos.conf/gyakovlev.conf https://raw.githubusercontent.com/gyakovlev/gentoo-overlay/master/gyakovlev.conf
curl -Lo /etc/portage/repos.conf/gyakovlev.conf --create-dirs https://raw.githubusercontent.com/gyakovlev/gentoo-overlay/master/gyakovlev.conf

cat << EOF > /etc/mpd.conf
music_directory      "/var/lib/mpd/music"
playlist_directory   "/var/lib/mpd/playlists"
db_file              "/var/lib/mpd/database"
log_file             "/var/lib/mpd/log"
state_file           "/var/lib/mpd/state"

user                 "mpd"

bind_to_address      "localhost"
bind_to_address      "/var/lib/mpd/socket"

input {
    plugin "curl"
}

audio_output {
    type            "pipewire"
    name            "Pipewire Output"
    mixer_type      "software"
}
EOF

cat << EOF >/etc/bluetooth/main.conf
[General]
Experimental=true

[Policy]
AutoEnable=true
EOF

cat << EOF >/etc/udev/rules.d/10-local-powersave.rules
SUBSYSTEM=="rfkill", ATTR{type}=="bluetooth", ATTR{state}="1"
EOF

cat << EOF > /etc/modprobe.d/xpadneo.conf
options bluetooth disable_ertm=Y
EOF

for x in /etc/runlevels/default/net.* ; do rc-update del $(basename $x) default ; rc-service --ifstarted $(basename $x) stop; done

echo wireguard >> /etc/modules-load.d/wireguard.conf

echo tun >> /etc/modules-load.d/qemu-modules.conf

echo "options kvm ignore_msrs=1" >> /etc/modprobe.d/kvm.conf

cat << EOF >/etc/modules-load.d/virtualbox.conf
vboxdrv
vboxnetadp
vboxnetflt
EOF

echo 'CHROMIUM_FLAGS="--force-dark-mode --enable-features=WebUIDarkMode"' >> /etc/chromium/default

emerge --ask sys-libs/zlib dev-libs/glib sys-libs/glibc

eselect rust list
eselect rust set 1
rustup-init-gentoo --symlink

#
# Enabling Daemons
#

rc-status sysinit | grep udev
rc-update add dbus default
rc-update add elogind boot
rc-update add haveged default
rc-update add cronie default
rc-update add zram
rc-update add NetworkManager default
rc-update add ntpd default
rc-update add acpid default
rc-update add syslog-ng default
rc-update add modules boot
rc-update add dmcrypt boot
rc-update add display-manager default
rc-update add iptables default
rc-update add ip6tables default
rc-update add bluetooth 
rc-update add openvpn default
rc-update add vboxwebsrv default
rc-update add libvirtd default

#
# Users Management
#

passwd

useradd -m -G users,wheel,audio,video,cdrom,cdrw,usb,plugdev,libvirt,vboxusers,kvm,pipewire,pcap,vboxsf,input noided -s /bin/zsh
#vboxusers,libvirt,docker,kvm,
passwd noided
vim /etc/sudoers

#
# Cleanup & Reboot
#

emerge -ac
exit
cd
umount -R /mnt/gentoo
sync
reboot

#
# As Noided
#

cat << EOF > ~/.zshrc
#!/bin/zsh

# Completion
autoload -U compinit
compinit
zstyle ':completion:*:descriptions' format '%U%B%d%b%u'
zstyle ':completion:*:warnings' format '%BSorry, no matches for: %d%b'

# Correction
setopt correctall

# Prompt
autoload -U promptinit
promptinit
prompt gentoo
EOF

###############################################################################################################
###############################################################################################################
###############################################################################################################

#
# System Rescue
#

drive=/dev/nvme0n1
part1=${drive}\p1
part2=${drive}\p2
part3=${drive}\p3
part_swap_lv=/dev/mapper/vg0-swap_lv
part_system_lv=/dev/mapper/vg0-system_lv
opts_btrfs=acl,autodefrag,barrier,compress-force=zstd,datacow,datasum,discard=async,space_cache=v2,ssd,treelog
cryptsetup luksOpen $part3 root

mount -t btrfs -o $opts_btrfs,subvol=@ /dev/mapper/vg0-system_lv /mnt/gentoo
mount -t btrfs -o $opts_btrfs $part2 /mnt/gentoo/boot
mount $part1 /mnt/gentoo/boot/EFI
mount -t btrfs -o $opts_btrfs,subvol=@snapshots /dev/mapper/vg0-system_lv /mnt/gentoo/.snapshots
mount -t btrfs -o $opts_btrfs,subvol=@home /dev/mapper/vg0-system_lv /mnt/gentoo/home
mount --types proc /proc /mnt/gentoo/proc
mount --rbind /sys /mnt/gentoo/sys
mount --make-rslave /mnt/gentoo/sys
mount --rbind /dev /mnt/gentoo/dev
mount --make-rslave /mnt/gentoo/dev
swapon /dev/mapper/vg0-swap_lv

chroot /mnt/gentoo /bin/bash 

source /etc/profile
export PS1="[chroot] $PS1"
