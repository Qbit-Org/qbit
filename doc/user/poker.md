# Poker Lobby (Play Money)

qbit-qt includes a play-money Texas Hold'em game. Open it from
**Window → Poker Lobby**.

- No-limit Texas Hold'em against computer players, at heads-up, 6-max or
  full-ring (9-seat) tables.
- Chips are play money. They have no value, cannot be bought, sold or
  withdrawn, and never touch your wallet.
- The game runs inside qbit-qt only. It sends nothing over the network and
  does not affect your node.

## Playing

- **Lobby:** pick a game type on the left, then join a table on the right or
  use **Open New Table**. You can play several tables at once.
- **Your turn:** **Fold**, **Check** or **Call**, and **Bet** or **Raise**. Set
  the amount with the slider, the amount box, or **Half pot**, **Pot** and
  **All-in**.
- **Before your turn:** tick **Fold**, **Call**, **Call any**, **Raise** or
  **Raise any** to act automatically when your turn comes. **Fold** checks
  instead when nobody has bet. **Call** and **Raise** clear themselves if
  someone raises first, so they never commit you to a bigger bet than you
  picked.
- **Deal Me Out** sits you out from the next hand while the computer players
  keep playing. **Deal Hand** deals the next hand at once. **Rebuy** and
  **Top up** refill your stack between hands.
- The log under the table records every action, every hand shown and who won
  each pot.

## Rules

Standard no-limit hold'em: the button moves one seat each hand, heads-up the
button posts the small blind and acts first before the flop, a raise must be at
least the size of the previous raise, an all-in for less than a full raise does
not reopen the betting, uncalled bets are returned, and side pots are split
between the players who are eligible for them.

## History

The lobby and table windows follow two windows Satoshi Nakamoto designed for
the first Bitcoin client (`CPokerLobbyDialogBase` and `CPokerDialogBase`). They
were never connected to a game and were removed in November 2009. qbit keeps
their layout and button names and adds the game itself.
