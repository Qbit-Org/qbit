package=openssl
$(package)_version=3.0.15
$(package)_download_path=https://github.com/openssl/openssl/releases/download/openssl-$($(package)_version)
$(package)_file_name=$(package)-$($(package)_version).tar.gz
$(package)_sha256_hash=23c666d0edf20f14249b3d8f0368acaee9ab585b09e1de82107c66e1f3ec9533

define $(package)_set_vars
  $(package)_config_env=AR="$($(package)_ar)" RANLIB="$($(package)_ranlib)" CC="$($(package)_cc)"
  $(package)_config_opts=--prefix=$(host_prefix) --openssldir=$(host_prefix)/etc/openssl --libdir=$(host_prefix)/lib
  $(package)_config_opts+=no-shared no-tests no-legacy
  $(package)_config_opts+=$(filter-out -std=c11,$($(package)_cflags)) $($(package)_cppflags)
  $(package)_config_opts+=-pipe
  $(package)_config_opts_linux=-fPIC -Wa,--noexecstack
  $(package)_config_opts_x86_64_linux=linux-x86_64
  $(package)_config_opts_arm_linux=linux-generic32
  $(package)_config_opts_aarch64_linux=linux-aarch64
  $(package)_config_opts_riscv64_linux=linux64-riscv64
  $(package)_config_opts_powerpc64_linux=linux-ppc64
endef

define $(package)_config_cmds
  ./Configure $($(package)_config_opts)
endef

define $(package)_build_cmds
  $(MAKE) build_sw
endef

define $(package)_stage_cmds
  $(MAKE) DESTDIR=$($(package)_staging_dir) install_sw
endef

define $(package)_postprocess_cmds
  rm -rf share bin etc lib/pkgconfig
endef
