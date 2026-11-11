IPC mining: invalid coinbase in `submitSolution`
================================================

`BlockTemplate.submitSolution` on the IPC mining interface (`qbit-node
-ipcbind`) now returns `false` when its coinbase argument is missing, empty,
or cannot be deserialized as a transaction. The template is left unchanged and
can still be used. With `-debug=ipc`, a coinbase that cannot be deserialized is
logged. Valid submissions behave as before.
