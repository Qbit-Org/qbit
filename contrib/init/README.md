Sample configuration files for:
```
systemd: qbitd.service
Upstart: qbitd.conf
OpenRC:  qbitd.openrc
         qbitd.openrcconf
CentOS:  qbitd.init
macOS:   org.qbit.qbitd.plist
```
have been made available to assist packagers in creating node packages here.

Legacy `bitcoind.*` init files are kept for one release as compatibility aliases.

See [doc/deployment/init.md](../../doc/deployment/init.md) for more information.
