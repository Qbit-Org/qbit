Sample init scripts and service configuration for qbitd
=======================================================

Sample scripts and configuration files for systemd, Upstart, OpenRC, and
macOS launchd can be found in the `contrib/init` folder.

    contrib/init/qbitd.service:       systemd service unit configuration
    contrib/init/qbitd.openrc:        OpenRC compatible SysV style init script
    contrib/init/qbitd.openrcconf:    OpenRC conf.d file
    contrib/init/qbitd.conf:          Upstart service configuration file
    contrib/init/qbitd.init:          CentOS compatible SysV style init script
    contrib/init/org.qbit.qbitd.plist: macOS LaunchAgent template

Deprecated compatibility aliases remain for one transition release:

    contrib/init/bitcoind.service
    contrib/init/bitcoind.openrc
    contrib/init/bitcoind.openrcconf
    contrib/init/bitcoind.conf
    contrib/init/bitcoind.init
    contrib/init/org.bitcoin.bitcoind.plist

The active qbitd init files ship qbit-native defaults. Legacy Bitcoin-shaped
paths and names are no longer implicit defaults; if you still need them, set
them explicitly as compatibility overrides.

Service User
---------------------------------

The Linux startup configurations assume the existence of a `qbit` user and
group. They must be created before attempting to use these scripts. The macOS
LaunchAgent template assumes `qbitd` will run as the current user.

Configuration
---------------------------------

Running qbitd as a daemon does not require any manual configuration. You may
set the `rpcauth` setting in the `qbit.conf` configuration file to override the
default behavior of using a special cookie for authentication.

This password does not have to be remembered or typed as it is mostly used as a
fixed token that qbitd and client programs read from the configuration file.
However, it is recommended that a strong and secure password be used as this
password is security critical to securing the wallet should the wallet be
enabled.

If qbitd is run with the `-server` flag (set by default), and no `rpcpassword`
is set, it will use a special cookie file for authentication. The cookie is
generated with random content when the daemon starts, and deleted when it
exits. Read access to this file controls who can access it through RPC.

By default the cookie is stored in the data directory, but its location can be
overridden with the option `-rpccookiefile`. Default file permissions for the
cookie are `owner` (i.e. user read/writeable) via default application-wide file
umask of `0077`, but these can be overridden with the `-rpccookieperms` option.

`conf`, `pid`, and `wallet` accept relative paths which are interpreted as
relative to the data directory. `wallet` *only* supports relative paths.

To generate an example configuration file that describes the configuration
settings, see
[contrib/devtools/README.md](/contrib/devtools/README.md#gen-qbit-confsh).

Paths
---------------------------------

### Linux

The shipped Linux service files use these qbit-native defaults:

    Binary:              /usr/bin/qbitd
    Configuration file:  /etc/qbit/qbit.conf
    Data directory:      /var/lib/qbit
    PID file:            /run/qbit/qbitd.pid
    Lock file:           /var/lock/subsys/qbitd (CentOS)

The configuration file, runtime directory, and data directory should be owned
by the `qbit` user and group. Access to qbit-cli and other qbitd RPC clients
can then be controlled by group membership.

When using the systemd `.service` file, directory creation and permissions are
handled by systemd via `RuntimeDirectory=`, `ConfigurationDirectory=`, and
`StateDirectory=`.

The service units pass explicit `-conf`, `-datadir`, and `-pid` arguments. If
you need different paths or a compatibility layout, override them in the init
system layer:

- systemd: `systemctl edit qbitd`
- OpenRC / Upstart: set the relevant `QBITD_*` variables
- CentOS SysV: edit `/etc/sysconfig/qbitd`

Examples of retained explicit compatibility inputs include:

- `-conf=/path/to/bitcoin.conf`
- a legacy `-datadir`
- a custom `-rpccookiefile`
- service-level overrides for custom paths, users, or groups

### macOS

    Binary:              /usr/local/bin/qbitd
    Configuration file:  ~/Library/Application Support/Qbit/qbit.conf
    Data directory:      ~/Library/Application Support/Qbit
    Lock file:           ~/Library/Application Support/Qbit/.lock

Installing Service Configuration
-----------------------------------

### systemd

Copy `qbitd.service` to the appropriate systemd unit directory, then run
`systemctl daemon-reload` to update running systemd configuration.

To test, run `systemctl start qbitd` and to enable for system startup run
`systemctl enable qbitd`.

NOTE: On Debian/Ubuntu, the unit file may need to be installed under
`/lib/systemd/system`.

### OpenRC

Rename `qbitd.openrc` to `qbitd` and place it in `/etc/init.d`. Double check
ownership and permissions and make it executable. Test it with
`/etc/init.d/qbitd start` and configure it to run on startup with
`rc-update add qbitd`.

### Upstart (for Debian/Ubuntu based distributions)

Upstart is the default init system for Debian/Ubuntu versions older than 15.04.
If you are using version 15.04 or newer and have not manually configured
Upstart, follow the systemd instructions instead.

Drop `qbitd.conf` in `/etc/init`. Test by running `service qbitd start`; it
will automatically start on reboot.

NOTE: This script is incompatible with CentOS 5 and Amazon Linux 2014 as they
use old versions of Upstart and do not supply the `start-stop-daemon` utility.

### CentOS

Copy `qbitd.init` to `/etc/init.d/qbitd`. Test by running
`service qbitd start`.

Using this script, you can adjust the path and flags to the qbitd program by
setting the `QBITD_BIN`, `QBITD_CONFIGFILE`, `QBITD_DATADIR`, `QBITD_PIDFILE`,
`QBITD_OPTS`, `QBITD_LOCKFILE`, `QBITD_USER`, and `QBITD_GROUP` environment
variables in `/etc/sysconfig/qbitd`. The default service user and group are
`qbit:qbit`; use these variables for custom service identities. You can also
use the `DAEMONOPTS` environment variable there for other CentOS daemon helper
options. `QBITD_DATADIR` and `QBITD_PIDFILE` must be absolute paths so the
script can prepare ownership before dropping privileges. Use dedicated qbit
directories; the script refuses to manage shared system directories such as
`/var/run` or `/var/lib`, and refuses symbolic links for managed paths.

### macOS

Copy `org.qbit.qbitd.plist` into `~/Library/LaunchAgents`. Load the launch
agent by running
`launchctl load ~/Library/LaunchAgents/org.qbit.qbitd.plist`.

This Launch Agent will cause qbitd to start whenever the user logs in.

Auto-respawn
-----------------------------------

Auto respawning is currently only configured for Upstart and systemd.
Reasonable defaults have been chosen but YMMV.
