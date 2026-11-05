Send confirmation re-entrancy
=============================

qbit-qt could abort while a send confirmation was open, a bug present since
v1.0.0. Mouse and keyboard input cannot reach the Send page behind the
confirmation, but an accessibility client, such as VoiceOver, or a UI
automation tool still can. Pressing Send through one prepared a second
transaction and opened a second confirmation. Confirming the second one
broadcast its transaction, and confirming the first one then aborted
qbit-qt. Pressing Clear All the same way and then confirming aborted it too.
The transaction from the second confirmation could therefore already have
been broadcast when qbit-qt aborted. No funds were at risk.

Send now does nothing while a send is in progress, from the passphrase prompt
until the confirmation closes, so one Send sends at most one transaction.
Clear All still clears the form, and the confirmation still sends the
transaction it shows.

qbit-qt also no longer uses freed memory when it is asked to quit while a
send confirmation is open, and Send no longer stays unavailable after an
internal error is reported while a send is being started.
