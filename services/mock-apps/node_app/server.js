const express = require('express');
const { SecurityTelemetryEmitter } = require('./emitter');

const app = express();
const PORT = process.env.PORT || 3001;

const emitter = new SecurityTelemetryEmitter({
  appId: 'application-b-payments',
  controlPlaneUrl: process.env.CONTROL_PLANE_URL || 'http://localhost:8080/api/v1/telemetry'
});
emitter.start();

app.use(express.json());
app.use(emitter.middleware());

app.get('/', (req, res) => {
  res.json({ status: 'ok', service: 'payments-api' });
});

app.post('/api/charge', (req, res) => {
  const { amount, currency } = req.body || {};
  if (!amount || amount <= 0) {
    return res.status(400).json({ error: 'Invalid amount' });
  }
  res.json({ transaction_id: 'txn_' + Date.now(), status: 'approved' });
});

app.get('/api/accounts/:id', (req, res) => {
  res.json({ account_id: req.params.id, balance: 15420.00 });
});

app.listen(PORT, () => {
  console.log(`Application B (Payments) listening on port ${PORT}`);
});
