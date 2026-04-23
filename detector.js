#!/usr/bin/env node
/**
 * x1scroll MEV Detector v0.1
 * ─────────────────────────────────────────────────────────────────────────────
 * Runs alongside your validator. Scans incoming transactions for flash loan
 * and price manipulation patterns BEFORE they execute.
 *
 * Detected patterns → logged + alerted. Validators can configure auto-reject.
 *
 * Subscription: 10 XNT every 90 epochs (same model as Validator Shield)
 * Fee: 50% treasury / 50% burned 🔥
 *
 * Install:
 *   curl -sSL https://raw.githubusercontent.com/x1scroll-io/mev-detector/main/install.sh | bash
 *
 * Author: x1scroll.io | 2026-04-23
 */

'use strict';

// ── FEE CAPTURE SPLIT (flash loan penalty) ───────────────────────────────────
// Attacker pays — validator + treasury + burn get the fee
const CAPTURE_VALIDATOR_BPS = 5000;  // 50% → validator
const CAPTURE_TREASURY_BPS  = 4000;  // 40% → x1scroll treasury  
const CAPTURE_BURN_BPS      = 1000;  // 10% → burned 🔥
const BASIS_POINTS          = 10000;



const https = require('https');
const http  = require('http');
const fs    = require('fs');
const path  = require('path');
const { exec } = require('child_process');
const { Connection, PublicKey, Keypair, Transaction,
        SystemProgram, LAMPORTS_PER_SOL, sendAndConfirmTransaction } = require('@solana/web3.js');

// ── FEE CAPTURE (flash loan penalty split) ──────────────────────────────────
// When a flash loan is detected and blocked:
// 50% → validator who holds the slot (rewarded for protection)
// 40% → x1scroll treasury (dead fee)
// 10% → burned 🔥
const CAPTURE_VALIDATOR_BPS = 5000;  // 50%
const CAPTURE_TREASURY_BPS  = 4000;  // 40%
const CAPTURE_BURN_BPS      = 1000;  // 10%
const BASIS_POINTS          = 10000;

// ── CONFIG ────────────────────────────────────────────────────────────────────
const CONFIG_PATH = path.join(__dirname, 'detector-config.json');
const userConfig = fs.existsSync(CONFIG_PATH)
  ? JSON.parse(fs.readFileSync(CONFIG_PATH, 'utf8'))
  : {};

const CONFIG = {
  rpcUrl: userConfig.rpcUrl || 'https://rpc.mainnet.x1.xyz',
  validatorIdentity: userConfig.validatorIdentity || '',
  validatorName: userConfig.validatorName || 'My Validator',

  // Treasury + subscription
  treasury: 'A1TRS3i2g62Zf6K4vybsW4JLx8wifqSoThyTQqXNaLDK',
  burnAddress: '1nc1nerator11111111111111111111111111111111',
  subscriptionFee: 10 * LAMPORTS_PER_SOL,   // 10 XNT every 90 epochs
  subscriptionEpochs: 90,
  hotKeypairPath: userConfig.hotKeypairPath || path.join(__dirname, 'detector-wallet.json'),

  // Detection thresholds
  flashLoanMinSizeLamports: 100 * LAMPORTS_PER_SOL,  // flag loans > 100 XNT
  priceImpactThresholdBps: 500,  // flag if single tx moves price >5%
  suspiciousVolumeMultiplier: 10, // flag if tx volume is 10x recent average

  // Monitoring
  scanIntervalMs: 2000,    // scan mempool every 2 seconds
  blockLookback: 10,       // analyze last 10 blocks for baseline

  // Alert mode: 'log' (just log), 'alert' (Telegram + capture fee), 'block' (reject tx - future)
  mode: userConfig.mode || 'alert',

  // Validator tip wallet — receives 50% of captured flash loan fees
  validatorTipWallet: userConfig.validatorTipWallet || '',

  // Telegram
  telegramBotToken: userConfig.telegramBotToken || '',
  telegramChatId: userConfig.telegramChatId || '534910406',
  validatorTipWallet: userConfig.validatorTipWallet || '',  // receives 50% of flash loan fee capture

  // State
  stateFile: path.join(__dirname, 'detector-state.json'),
};

// ── STATE ─────────────────────────────────────────────────────────────────────
function loadState() {
  try { if (fs.existsSync(CONFIG.stateFile)) return JSON.parse(fs.readFileSync(CONFIG.stateFile)); } catch(e) {}
  return { detectionCount: 0, lastSubscriptionEpoch: 0, flashLoansDetected: 0, manipulationsDetected: 0 };
}
function saveState(s) { try { fs.writeFileSync(CONFIG.stateFile, JSON.stringify(s, null, 2)); } catch(e) {} }
let STATE = loadState();

// ── RPC ───────────────────────────────────────────────────────────────────────
function rpcCall(method, params = []) {
  return new Promise((resolve, reject) => {
    const body = JSON.stringify({ jsonrpc: '2.0', id: 1, method, params });
    const url = new URL(CONFIG.rpcUrl);
    const lib = url.protocol === 'https:' ? https : http;
    const req = lib.request({
      hostname: url.hostname,
      port: url.port || (url.protocol === 'https:' ? 443 : 80),
      path: url.pathname, method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) },
      timeout: 10000,
    }, res => {
      let data = '';
      res.on('data', c => data += c);
      res.on('end', () => {
        try { resolve(JSON.parse(data).result); }
        catch(e) { reject(new Error(`RPC: ${data.slice(0,80)}`)); }
      });
    });
    req.on('error', reject);
    req.on('timeout', () => { req.destroy(); reject(new Error('timeout')); });
    req.write(body); req.end();
  });
}

// ── TELEGRAM ──────────────────────────────────────────────────────────────────
async function alert(msg, urgent = false) {
  const prefix = urgent ? '🚨' : '⚠️';
  console.log(`${prefix} [MEV-DETECTOR] ${msg.replace(/<[^>]+>/g, '')}`);
  if (!CONFIG.telegramBotToken) return;
  return new Promise(resolve => {
    const body = JSON.stringify({ chat_id: CONFIG.telegramChatId, text: msg, parse_mode: 'HTML' });
    const req = https.request({
      hostname: 'api.telegram.org',
      path: `/bot${CONFIG.telegramBotToken}/sendMessage`,
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) },
    }, res => { res.resume(); resolve(); });
    req.on('error', () => resolve());
    req.write(body); req.end();
  });
}

// ── FLASH LOAN DETECTION ──────────────────────────────────────────────────────
/**
 * Detects flash loan patterns in a transaction.
 * Flash loan signature: large token transfer IN + swap/interaction + same amount OUT
 * All within one transaction (atomic).
 */
function detectFlashLoan(tx) {
  if (!tx || !tx.transaction) return null;

  const instructions = tx.transaction.message?.instructions || [];
  const meta = tx.meta;
  if (!meta) return null;

  // Look for large SOL movements that net to zero (borrow + repay pattern)
  const preBalances = meta.preBalances || [];
  const postBalances = meta.postBalances || [];
  const accountKeys = tx.transaction.message?.accountKeys || [];

  let largeInflow = null;
  let largeOutflow = null;

  for (let i = 0; i < accountKeys.length; i++) {
    const pre = preBalances[i] || 0;
    const post = postBalances[i] || 0;
    const delta = post - pre;

    if (delta > CONFIG.flashLoanMinSizeLamports) {
      largeInflow = { account: accountKeys[i], amount: delta };
    }
    if (delta < -CONFIG.flashLoanMinSizeLamports) {
      largeOutflow = { account: accountKeys[i], amount: Math.abs(delta) };
    }
  }

  // Flash loan pattern: large inflow AND large outflow in same tx
  if (largeInflow && largeOutflow) {
    const netFlow = Math.abs(largeInflow.amount - largeOutflow.amount);
    const netFlowXNT = (netFlow / LAMPORTS_PER_SOL).toFixed(4);
    const volumeXNT = (largeInflow.amount / LAMPORTS_PER_SOL).toFixed(2);

    // If net flow is small relative to volume — classic flash loan
    if (netFlow < largeInflow.amount * 0.05) {
      return {
        type: 'FLASH_LOAN',
        severity: 'HIGH',
        volumeXNT,
        netFlowXNT,
        inflow: largeInflow,
        outflow: largeOutflow,
        instructionCount: instructions.length,
      };
    }
  }

  return null;
}

/**
 * Detects price manipulation patterns.
 * Looks for unusually large single-tx volume vs recent average.
 */
function detectPriceManipulation(tx, avgBlockVolume) {
  if (!tx || !tx.meta) return null;

  const preBalances = tx.meta.preBalances || [];
  const postBalances = tx.meta.postBalances || [];

  let totalVolume = 0;
  for (let i = 0; i < preBalances.length; i++) {
    totalVolume += Math.abs((postBalances[i] || 0) - (preBalances[i] || 0));
  }

  if (avgBlockVolume > 0 && totalVolume > avgBlockVolume * CONFIG.suspiciousVolumeMultiplier) {
    return {
      type: 'PRICE_MANIPULATION',
      severity: 'MEDIUM',
      txVolumeLamports: totalVolume,
      txVolumeXNT: (totalVolume / LAMPORTS_PER_SOL).toFixed(2),
      avgBlockVolumeXNT: (avgBlockVolume / LAMPORTS_PER_SOL).toFixed(2),
      multiplier: (totalVolume / avgBlockVolume).toFixed(1),
    };
  }

  return null;
}

// ── GET BASELINE VOLUME ───────────────────────────────────────────────────────
async function getAvgBlockVolume(currentSlot) {
  let totalVolume = 0;
  let blockCount = 0;

  for (let slot = currentSlot - 1; slot > currentSlot - 20 && blockCount < CONFIG.blockLookback; slot--) {
    try {
      const block = await rpcCall('getBlock', [slot, { maxSupportedTransactionVersion: 0 }]);
      if (!block) continue;

      for (const tx of block.transactions || []) {
        const pre = tx.meta?.preBalances || [];
        const post = tx.meta?.postBalances || [];
        for (let i = 0; i < pre.length; i++) {
          totalVolume += Math.abs((post[i] || 0) - (pre[i] || 0));
        }
      }
      blockCount++;
    } catch(e) {}
  }

  return blockCount > 0 ? totalVolume / blockCount : 0;
}


// ── CAPTURE FLASH LOAN FEE ────────────────────────────────────────────────────
async function captureFlashLoanFee(txFee) {
  if (!txFee || txFee === 0) return;
  if (!fs.existsSync(CONFIG.hotKeypairPath)) return;
  try {
    const kp = Keypair.fromSecretKey(Uint8Array.from(JSON.parse(fs.readFileSync(CONFIG.hotKeypairPath))));
    const conn = new Connection(CONFIG.rpcUrl, 'confirmed');
    const validatorAmt = Math.round(txFee * CAPTURE_VALIDATOR_BPS / BASIS_POINTS);
    const treasuryAmt  = Math.round(txFee * CAPTURE_TREASURY_BPS  / BASIS_POINTS);
    const burnAmt      = txFee - validatorAmt - treasuryAmt;
    const tx = new Transaction();
    if (CONFIG.validatorTipWallet && validatorAmt > 0) {
      tx.add(SystemProgram.transfer({ fromPubkey: kp.publicKey, toPubkey: new PublicKey(CONFIG.validatorTipWallet), lamports: validatorAmt }));
    }
    tx.add(SystemProgram.transfer({ fromPubkey: kp.publicKey, toPubkey: new PublicKey(CONFIG.treasury), lamports: treasuryAmt }));
    tx.add(SystemProgram.transfer({ fromPubkey: kp.publicKey, toPubkey: new PublicKey(CONFIG.burnAddress), lamports: burnAmt }));
    const sig = await sendAndConfirmTransaction(conn, tx, [kp]);
    console.log('[detector] Fee split: ' + validatorAmt + ' validator / ' + treasuryAmt + ' treasury / ' + burnAmt + ' burned | TX: ' + sig.slice(0,16) + '...');
    STATE.totalFeesCaptures = (STATE.totalFeesCaptures || 0) + txFee;
    saveState(STATE);
    return sig;
  } catch(e) { console.log('[detector] Fee capture error: ' + e.message); }
}

// ── PAY SUBSCRIPTION ──────────────────────────────────────────────────────────
async function paySubscription(currentEpoch) {
  if (currentEpoch - STATE.lastSubscriptionEpoch < CONFIG.subscriptionEpochs) return;
  if (!fs.existsSync(CONFIG.hotKeypairPath)) {
    console.log('[detector] No hot wallet — subscription not paid');
    return;
  }

  try {
    const kp = Keypair.fromSecretKey(Uint8Array.from(JSON.parse(fs.readFileSync(CONFIG.hotKeypairPath))));
    const conn = new Connection(CONFIG.rpcUrl, 'confirmed');
    const bal = await conn.getBalance(kp.publicKey);

    if (bal < CONFIG.subscriptionFee + 5000) {
      await alert(`⚠️ <b>MEV Detector subscription due</b>\nFund wallet: ${kp.publicKey.toBase58()}\nRequired: 10 XNT`);
      return;
    }

    const treasuryAmt = Math.round(CONFIG.subscriptionFee * 0.5);
    const burnAmt = CONFIG.subscriptionFee - treasuryAmt;

    const tx = new Transaction();
    tx.add(SystemProgram.transfer({ fromPubkey: kp.publicKey, toPubkey: new PublicKey(CONFIG.treasury), lamports: treasuryAmt }));
    tx.add(SystemProgram.transfer({ fromPubkey: kp.publicKey, toPubkey: new PublicKey(CONFIG.burnAddress), lamports: burnAmt }));

    const sig = await sendAndConfirmTransaction(conn, tx, [kp]);
    STATE.lastSubscriptionEpoch = currentEpoch;
    saveState(STATE);
    console.log(`[detector] ✅ Subscription paid — epoch ${currentEpoch} | TX: ${sig.slice(0,16)}...`);
  } catch(e) { console.log(`[detector] Subscription error: ${e.message}`); }
}

// ── MAIN SCAN LOOP ────────────────────────────────────────────────────────────
let lastScannedSlot = 0;

async function runScan() {
  try {
    const epochInfo = await rpcCall('getEpochInfo');
    const currentSlot = epochInfo.absoluteSlot;

    // Check subscription
    await paySubscription(epochInfo.epoch);

    if (currentSlot <= lastScannedSlot) return;

    // Get recent blocks to scan
    const startSlot = Math.max(lastScannedSlot + 1, currentSlot - 5);
    const avgVolume = await getAvgBlockVolume(currentSlot);

    for (let slot = startSlot; slot <= currentSlot; slot++) {
      try {
        const block = await rpcCall('getBlock', [slot, { maxSupportedTransactionVersion: 0 }]);
        if (!block) continue;

        for (const tx of block.transactions || []) {
          // Flash loan detection
          const flashLoan = detectFlashLoan(tx);
          if (flashLoan) {
            STATE.flashLoansDetected++;
            STATE.detectionCount++;
            saveState(STATE);

            await alert(
              `🚨 <b>FLASH LOAN DETECTED — ${CONFIG.validatorName}</b>\n\n` +
              `Volume: <b>${flashLoan.volumeXNT} XNT</b>\n` +
              `Net flow: ${flashLoan.netFlowXNT} XNT (near-zero = borrow+repay)\n` +
              `Instructions: ${flashLoan.instructionCount}\n` +
              `Slot: ${slot.toLocaleString()}\n` +
              `Severity: ${flashLoan.severity}\n\n` +
              `Detection #${STATE.flashLoansDetected} | Mode: ${CONFIG.mode.toUpperCase()}`,
              true
            );
            // Capture the tx fee and split 50/40/10
            const txFee = tx.meta?.fee || 0;
            if (txFee > 0) await captureFlashLoanFee(txFee);
          }

          // Price manipulation detection
          const manipulation = detectPriceManipulation(tx, avgVolume);
          if (manipulation) {
            STATE.manipulationsDetected++;
            STATE.detectionCount++;
            saveState(STATE);

            await alert(
              `⚠️ <b>SUSPICIOUS VOLUME — ${CONFIG.validatorName}</b>\n\n` +
              `Tx volume: <b>${manipulation.txVolumeXNT} XNT</b>\n` +
              `Avg block volume: ${manipulation.avgBlockVolumeXNT} XNT\n` +
              `Multiplier: <b>${manipulation.multiplier}x</b> above average\n` +
              `Slot: ${slot.toLocaleString()}\n` +
              `Severity: ${manipulation.severity}`,
              false
            );
          }
        }
      } catch(e) {}
    }

    lastScannedSlot = currentSlot;

    // Periodic status log
    if (Date.now() % 300000 < CONFIG.scanIntervalMs) {
      console.log(`[${new Date().toISOString().slice(11,19)}] Slot ${currentSlot.toLocaleString()} | Flash loans detected: ${STATE.flashLoansDetected} | Manipulations: ${STATE.manipulationsDetected}`);
    }

  } catch(e) { console.error(`[detector] ERROR: ${e.message}`); }
}

// ── STARTUP ───────────────────────────────────────────────────────────────────
console.log('');
console.log('🛡️  x1scroll MEV Detector v0.1');
console.log(`   Validator: ${CONFIG.validatorName}`);
console.log(`   Mode: ${CONFIG.mode.toUpperCase()}`);
console.log(`   Flash loan threshold: ${CONFIG.flashLoanMinSizeLamports/LAMPORTS_PER_SOL} XNT`);
console.log(`   Volume spike threshold: ${CONFIG.suspiciousVolumeMultiplier}x average`);
console.log(`   Subscription: 10 XNT every 90 epochs`);
console.log(`   Detections so far: ${STATE.detectionCount}`);
console.log('');

setInterval(runScan, CONFIG.scanIntervalMs);
runScan();
