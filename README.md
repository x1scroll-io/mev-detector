# x1scroll MEV Detector

**Flash loan and price manipulation detection for X1 validators.**

Scans every transaction before it confirms. Alerts on flash loan patterns and suspicious volume spikes. First MEV protection layer on any SVM chain.

## Install (One Line)

```bash
curl -sSL https://raw.githubusercontent.com/x1scroll-io/mev-detector/main/install.sh | bash
```

## What It Detects

### Flash Loans
Large XNT borrow + interaction + repay in a single transaction. Net flow near zero = borrow/repay pattern.

### Price Manipulation
Single transaction volume 10x+ above block average = potential price attack.

## Detection Modes

| Mode | Action |
|------|--------|
| `log` | Log only — no alert |
| `alert` | Telegram alert on detection |
| `block` | Reject tx (coming in v0.2) |

## Fee Structure

- Subscription: **10 XNT every 90 epochs**
- Split: **50% treasury / 50% burned** 🔥
- Same model as Validator Shield — auto-renews from hot wallet

## Config (`detector-config.json`)

```json
{
  "validatorIdentity": "YOUR_VALIDATOR_PUBKEY",
  "validatorName": "My Validator",
  "mode": "alert",
  "hotKeypairPath": "./detector-wallet.json",
  "telegramBotToken": "YOUR_BOT_TOKEN",
  "telegramChatId": "YOUR_CHAT_ID"
}
```

## Commands

```bash
pm2 logs mev-detector     # view detections live
pm2 status mev-detector   # check status
pm2 restart mev-detector  # restart
```

## Why This Matters

Flash loans can manipulate XNT price on thin liquidity pools. Price manipulation attacks have cost DeFi protocols billions on Ethereum. X1 needs this protection layer before it happens here.

x1scroll built it first. 🛡️

Built by [x1scroll.io](https://x1scroll.io) | @ArnettX1
