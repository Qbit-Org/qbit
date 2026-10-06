I2P post-quantum encryption
---------------------------

qbit now asks the I2P router for post-quantum hybrid session encryption,
MLKEM768-X25519 with ECIES-X25519 for peers without it
(`i2cp.leaseSetEncType=6,4`), as Bitcoin Core does. Java I2P 2.10.0 or newer,
and i2pd 2.58.0 or newer built with OpenSSL 3.5 or newer, use it; other i2pd
versions ignore it.

Java I2P older than 2.10.0 rejects the request, naming the encryption type in
its reply. qbit then retries once with the previous setting, `4,0`, and warns
the first time this happens with a router. After two sessions in a row in
which the router rejects the post-quantum type this way and accepts `4,0`,
qbit uses `4,0` with that router until qbit restarts; a session that gets the
post-quantum type starts the count anew, so one passing router error does not
turn it off. Other rejections, such as a failure to build tunnels or a SAM
`RESULT=TIMEOUT` reply, are retried the same way but do not count and do not
warn. Upgrade the router to get the post-quantum type, then restart qbit. No
reply from the router (a timeout while waiting for it, or a closed or broken
connection) is not retried.

Creating an I2P session now has a single 3-minute limit that covers every
step, and stops promptly when qbit shuts down. (#223)
