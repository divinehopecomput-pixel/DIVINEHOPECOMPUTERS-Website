require('dotenv').config();
const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const path = require('path');

const app = express();
const PORT = Number(process.env.PORT || 3000);
const isProduction = process.env.NODE_ENV === 'production';

for (const key of ['DB_HOST','DB_NAME','DB_USER','DB_PASSWORD','JWT_SECRET']) {
  if (!process.env[key]) {
    console.error('Missing required environment variable:', key);
    process.exit(1);
  }
}
if (process.env.JWT_SECRET.length < 32) {
  console.error('JWT_SECRET must be at least 32 characters long.');
  process.exit(1);
}

const pool = mysql.createPool({
  host: process.env.DB_HOST,
  port: Number(process.env.DB_PORT || 3306),
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
  charset: 'utf8mb4',
  ssl: process.env.DB_SSL === 'true' ? { rejectUnauthorized: true } : undefined
});

app.disable('x-powered-by');
app.set('trust proxy', isProduction ? 1 : false);
app.use(helmet({ crossOriginResourcePolicy: { policy: 'cross-origin' } }));
const allowedOrigins = (process.env.CORS_ORIGINS || '').split(',').map(s => s.trim()).filter(Boolean);
app.use(cors({
  origin(origin, callback) {
    if (!origin || allowedOrigins.includes(origin) || (!isProduction && origin.startsWith('http://localhost:'))) return callback(null, true);
    return callback(new Error('Origin not allowed by CORS'));
  },
  methods: ['GET','POST','PUT','PATCH','DELETE','OPTIONS'],
  allowedHeaders: ['Content-Type','Authorization']
}));

// Paystack webhook signature is verified against the raw request bytes.
app.post('/api/payments/paystack/webhook', express.raw({ type: 'application/json', limit: '256kb' }), async (req, res) => {
  try {
    const secret = process.env.PAYSTACK_SECRET_KEY;
    const signature = req.get('x-paystack-signature');
    if (!secret || !signature || !Buffer.isBuffer(req.body)) return res.sendStatus(401);
    const expected = crypto.createHmac('sha512', secret).update(req.body).digest('hex');
    const supplied = Buffer.from(signature, 'utf8');
    const expectedBuffer = Buffer.from(expected, 'utf8');
    if (supplied.length !== expectedBuffer.length || !crypto.timingSafeEqual(supplied, expectedBuffer)) return res.sendStatus(401);
    const event = JSON.parse(req.body.toString('utf8'));
    if (event.event === 'charge.success' && event.data && event.data.reference) {
      await markOrderPaid(event.data.reference, event.data.amount, event.data.currency, event.data.status);
    }
    const eventId = String(event.data && event.data.id || event.id || crypto.createHash('sha256').update(req.body).digest('hex'));
    await pool.execute(
      'INSERT IGNORE INTO payment_events (provider_event_id,event_type,order_reference,payload) VALUES (?,?,?,?)',
      [eventId, String(event.event || 'unknown'), event.data && event.data.metadata && event.data.metadata.order_reference || null, JSON.stringify(event)]
    );
    return res.sendStatus(200);
  } catch (error) {
    console.error('Paystack webhook error:', error.message);
    return res.sendStatus(500);
  }
});

app.use(express.json({ limit: '100kb' }));
app.use(express.urlencoded({ extended: false, limit: '20kb' }));
app.use('/api', rateLimit({ windowMs: 15 * 60 * 1000, limit: 240, standardHeaders: 'draft-7', legacyHeaders: false }));
app.use('/api/auth/login', rateLimit({ windowMs: 15 * 60 * 1000, limit: 8, standardHeaders: 'draft-7', legacyHeaders: false }));

function asyncRoute(fn) { return (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next); }
function adminOnly(req, res, next) {
  const header = req.get('authorization') || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : '';
  if (!token) return res.status(401).json({ error: 'Admin authentication required.' });
  try {
    const payload = jwt.verify(token, process.env.JWT_SECRET, { algorithms: ['HS256'] });
    if (payload.role !== 'admin') return res.sendStatus(403);
    req.admin = payload;
    return next();
  } catch (_) { return res.status(401).json({ error: 'Session expired. Please sign in again.' }); }
}
function cleanText(value, max) { return typeof value === 'string' ? value.trim().slice(0, max) : ''; }
function validEmail(value) { return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value); }
function validImageUrl(value) {
  if (!value) return true;
  try { const u = new URL(value); return u.protocol === 'https:'; } catch (_) { return false; }
}
function publicProduct(row) {
  return { id: row.id, name: row.name, slug: row.slug, category: row.category, description: row.description,
    imageUrl: row.image_url, pricePesewas: row.price_pesewas, stockQuantity: row.stock_quantity, active: Boolean(row.active) };
}

app.get('/api/health', (req, res) => res.json({ status: 'ok' }));

app.get('/api/products', asyncRoute(async (req, res) => {
  const search = cleanText(req.query.search, 100);
  const category = cleanText(req.query.category, 80);
  const params = [];
  let sql = 'SELECT id,name,slug,category,description,image_url,price_pesewas,stock_quantity,active FROM products WHERE active=1';
  if (category && category !== 'All') { sql += ' AND category=?'; params.push(category); }
  if (search) {
    sql += ' AND (name LIKE ? OR description LIKE ? OR category LIKE ?)';
    const q = '%' + search + '%'; params.push(q,q,q);
  }
  sql += ' ORDER BY created_at DESC LIMIT 100';
  const [rows] = await pool.execute(sql, params);
  res.json({ products: rows.map(publicProduct) });
}));

app.get('/api/products/:id', asyncRoute(async (req, res) => {
  if (!/^\d+$/.test(req.params.id)) return res.status(400).json({ error: 'Invalid product ID.' });
  const [rows] = await pool.execute('SELECT id,name,slug,category,description,image_url,price_pesewas,stock_quantity,active FROM products WHERE id=? AND active=1', [req.params.id]);
  if (!rows.length) return res.status(404).json({ error: 'Product not found.' });
  res.json({ product: publicProduct(rows[0]) });
}));

app.post('/api/auth/login', asyncRoute(async (req, res) => {
  const email = cleanText(req.body.email, 254).toLowerCase();
  const password = typeof req.body.password === 'string' ? req.body.password : '';
  if (!validEmail(email) || !password) return res.status(401).json({ error: 'Invalid email or password.' });
  const [rows] = await pool.execute('SELECT id,email,password_hash FROM admins WHERE email=? LIMIT 1', [email]);
  const admin = rows[0];
  // A database admin row is required; ADMIN_PASSWORD_HASH is a bootstrap check only.
  const hash = admin ? admin.password_hash : (process.env.ADMIN_PASSWORD_HASH || '$2a$12$invalidhashinvalidhashinvalidhashinvalidhashinvalidhashin');
  const matches = await bcrypt.compare(password, hash).catch(() => false);
  if (!admin || !matches) return res.status(401).json({ error: 'Invalid email or password.' });
  const token = jwt.sign({ sub: String(admin.id), email: admin.email, role: 'admin' }, process.env.JWT_SECRET, { algorithm: 'HS256', expiresIn: '2h', issuer: 'divine-hope-shop' });
  res.json({ token, expiresIn: 7200, admin: { id: admin.id, email: admin.email } });
}));

app.get('/api/admin/products', adminOnly, asyncRoute(async (req, res) => {
  const [rows] = await pool.query('SELECT id,name,slug,category,description,image_url,price_pesewas,stock_quantity,active,created_at,updated_at FROM products ORDER BY created_at DESC LIMIT 500');
  res.json({ products: rows.map(publicProduct) });
}));

app.post('/api/admin/products', adminOnly, asyncRoute(async (req, res) => {
  const product = validateProduct(req.body);
  if (product.error) return res.status(400).json({ error: product.error });
  const slug = product.name.toLowerCase().normalize('NFKD').replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '').slice(0, 180) + '-' + crypto.randomBytes(3).toString('hex');
  const [result] = await pool.execute(
    'INSERT INTO products (name,slug,category,description,image_url,price_pesewas,stock_quantity,active) VALUES (?,?,?,?,?,?,?,?)',
    [product.name,slug,product.category,product.description,product.imageUrl || null,product.pricePesewas,product.stockQuantity,product.active]
  );
  const [rows] = await pool.execute('SELECT id,name,slug,category,description,image_url,price_pesewas,stock_quantity,active FROM products WHERE id=?', [result.insertId]);
  res.status(201).json({ product: publicProduct(rows[0]) });
}));

app.put('/api/admin/products/:id', adminOnly, asyncRoute(async (req, res) => {
  if (!/^\d+$/.test(req.params.id)) return res.status(400).json({ error: 'Invalid product ID.' });
  const product = validateProduct(req.body);
  if (product.error) return res.status(400).json({ error: product.error });
  const [result] = await pool.execute(
    'UPDATE products SET name=?,category=?,description=?,image_url=?,price_pesewas=?,stock_quantity=?,active=? WHERE id=?',
    [product.name,product.category,product.description,product.imageUrl || null,product.pricePesewas,product.stockQuantity,product.active,req.params.id]
  );
  if (!result.affectedRows) return res.status(404).json({ error: 'Product not found.' });
  const [rows] = await pool.execute('SELECT id,name,slug,category,description,image_url,price_pesewas,stock_quantity,active FROM products WHERE id=?', [req.params.id]);
  res.json({ product: publicProduct(rows[0]) });
}));

app.delete('/api/admin/products/:id', adminOnly, asyncRoute(async (req, res) => {
  if (!/^\d+$/.test(req.params.id)) return res.status(400).json({ error: 'Invalid product ID.' });
  const [result] = await pool.execute('UPDATE products SET active=0 WHERE id=?', [req.params.id]);
  if (!result.affectedRows) return res.status(404).json({ error: 'Product not found.' });
  res.sendStatus(204);
}));

function validateProduct(body) {
  const name = cleanText(body.name, 180), category = cleanText(body.category, 80), description = cleanText(body.description, 4000);
  const imageUrl = cleanText(body.imageUrl, 1000);
  const pricePesewas = Number(body.pricePesewas), stockQuantity = Number(body.stockQuantity);
  const active = body.active === undefined ? true : Boolean(body.active);
  if (!name || !category || !description) return { error: 'Name, category and description are required.' };
  if (!Number.isSafeInteger(pricePesewas) || pricePesewas < 1 || pricePesewas > 100000000) return { error: 'Price must be a valid amount in pesewas.' };
  if (!Number.isSafeInteger(stockQuantity) || stockQuantity < 0 || stockQuantity > 1000000) return { error: 'Stock must be a non-negative whole number.' };
  if (!validImageUrl(imageUrl)) return { error: 'Product image must use an HTTPS URL.' };
  return { name,category,description,imageUrl,pricePesewas,stockQuantity,active };
}

app.post('/api/orders', asyncRoute(async (req, res) => {
  const customer = {
    name: cleanText(req.body.customer && req.body.customer.name, 160),
    email: cleanText(req.body.customer && req.body.customer.email, 254).toLowerCase(),
    phone: cleanText(req.body.customer && req.body.customer.phone, 40),
    address: cleanText(req.body.customer && req.body.customer.address, 1500),
    notes: cleanText(req.body.customer && req.body.customer.notes, 1000)
  };
  const items = req.body.items;
  if (!customer.name || !validEmail(customer.email) || !customer.phone || !customer.address) return res.status(400).json({ error: 'Name, valid email, phone and delivery address are required.' });
  if (!Array.isArray(items) || items.length < 1 || items.length > 30) return res.status(400).json({ error: 'Provide between 1 and 30 cart items.' });
  if (!process.env.PAYSTACK_SECRET_KEY || !process.env.PAYSTACK_CALLBACK_URL) return res.status(503).json({ error: 'Checkout is not configured yet. Please contact the store.' });

  const quantities = new Map();
  for (const item of items) {
    const id = Number(item.productId), qty = Number(item.quantity);
    if (!Number.isSafeInteger(id) || id < 1 || !Number.isSafeInteger(qty) || qty < 1 || qty > 20) return res.status(400).json({ error: 'Invalid product or quantity.' });
    quantities.set(id, (quantities.get(id) || 0) + qty);
  }
  if ([...quantities.values()].some(qty => qty > 20)) return res.status(400).json({ error: 'Maximum quantity per product is 20.' });

  const conn = await pool.getConnection();
  let orderId, reference, total = 0;
  try {
    await conn.beginTransaction();
    const ids = [...quantities.keys()];
    const placeholders = ids.map(() => '?').join(',');
    const [products] = await conn.query('SELECT id,name,price_pesewas,stock_quantity,active FROM products WHERE id IN (' + placeholders + ') FOR UPDATE', ids);
    if (products.length !== ids.length) { await conn.rollback(); return res.status(400).json({ error: 'One or more products are no longer available.' }); }
    for (const p of products) {
      const qty = quantities.get(Number(p.id));
      if (!p.active || p.stock_quantity < qty) { await conn.rollback(); return res.status(409).json({ error: 'Insufficient stock for ' + p.name + '.' }); }
      total += p.price_pesewas * qty;
      if (!Number.isSafeInteger(total) || total > 1000000000) { await conn.rollback(); return res.status(400).json({ error: 'Order total is too large.' }); }
    }
    // Reserve stock atomically so concurrent customers cannot purchase the same final unit.
    for (const p of products) {
      const qty = quantities.get(Number(p.id));
      const [reserved] = await conn.execute('UPDATE products SET stock_quantity=stock_quantity-? WHERE id=? AND active=1 AND stock_quantity>=?', [qty,p.id,qty]);
      if (!reserved.affectedRows) { await conn.rollback(); return res.status(409).json({ error: 'Stock changed while checking out. Please refresh your cart.' }); }
    }
    reference = crypto.randomUUID();
    const [result] = await conn.execute(
      'INSERT INTO orders (public_reference,customer_name,customer_email,customer_phone,shipping_address,notes,total_pesewas,status,payment_provider) VALUES (?,?,?,?,?,?,?,\'pending_payment\',\'paystack\')',
      [reference,customer.name,customer.email,customer.phone,customer.address,customer.notes || null,total]
    );
    orderId = result.insertId;
    for (const p of products) {
      const qty = quantities.get(Number(p.id));
      await conn.execute('INSERT INTO order_items (order_id,product_id,product_name,unit_price_pesewas,quantity,line_total_pesewas) VALUES (?,?,?,?,?,?)',
        [orderId,p.id,p.name,p.price_pesewas,qty,p.price_pesewas * qty]);
    }
    await conn.commit();
  } catch (error) {
    await conn.rollback();
    throw error;
  } finally { conn.release(); }

  try {
    const response = await fetch('https://api.paystack.co/transaction/initialize', {
      method: 'POST',
      headers: { Authorization: 'Bearer ' + process.env.PAYSTACK_SECRET_KEY, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        email: customer.email,
        amount: total,
        currency: 'GHS',
        reference,
        callback_url: process.env.PAYSTACK_CALLBACK_URL,
        metadata: { order_reference: reference, order_id: orderId, customer_name: customer.name },
        channels: ['card','mobile_money']
      }),
      signal: AbortSignal.timeout(15000)
    });
    const data = await response.json();
    if (!response.ok || !data.status || !data.data || !data.data.authorization_url) {
      await releaseOrderReservation(reference, 'payment_failed');
      console.error('Paystack initialize rejected:', data.message || response.status);
      return res.status(502).json({ error: 'Unable to start payment. Please try again.' });
    }
    await pool.execute('UPDATE orders SET payment_reference=? WHERE public_reference=?', [reference, reference]);
    res.status(201).json({ orderReference: reference, checkoutUrl: data.data.authorization_url });
  } catch (error) {
    await releaseOrderReservation(reference, 'payment_failed');
    console.error('Payment initialization failed:', error.message);
    res.status(502).json({ error: 'Payment provider is temporarily unavailable. Please try again.' });
  }
}));

async function releaseOrderReservation(reference, finalStatus) {
  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();
    const [orders] = await conn.execute('SELECT id,status FROM orders WHERE public_reference=? FOR UPDATE', [reference]);
    if (!orders.length || orders[0].status !== 'pending_payment') { await conn.rollback(); return false; }
    const [items] = await conn.execute('SELECT product_id,quantity FROM order_items WHERE order_id=? FOR UPDATE', [orders[0].id]);
    for (const item of items) {
      if (item.product_id) await conn.execute('UPDATE products SET stock_quantity=stock_quantity+? WHERE id=?', [item.quantity,item.product_id]);
    }
    await conn.execute("UPDATE orders SET status=? WHERE id=? AND status='pending_payment'", [finalStatus,orders[0].id]);
    await conn.commit();
    return true;
  } catch (error) { await conn.rollback(); throw error; }
  finally { conn.release(); }
}

async function markOrderPaid(reference, amount, currency, status) {
  if (!reference || status !== 'success' || currency !== 'GHS' || !Number.isSafeInteger(Number(amount))) return false;
  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();
    const [orders] = await conn.execute('SELECT id,total_pesewas,status FROM orders WHERE payment_reference=? OR public_reference=? FOR UPDATE', [reference,reference]);
    if (!orders.length) { await conn.rollback(); return false; }
    const order = orders[0];
    if (Number(order.total_pesewas) !== Number(amount)) { await conn.rollback(); console.error('Payment amount mismatch for order', order.id); return false; }
    if (order.status === 'paid' || ['processing','shipped','completed'].includes(order.status)) { await conn.commit(); return true; }
    if (order.status !== 'pending_payment') { await conn.rollback(); return false; }
    // Stock was reserved in the order-creation transaction; do not deduct it twice.
    await conn.execute("UPDATE orders SET status='paid',paid_at=UTC_TIMESTAMP() WHERE id=?", [order.id]);
    await conn.commit();
    return true;
  } catch (error) { await conn.rollback(); throw error; }
  finally { conn.release(); }
}

app.get('/payment/callback', asyncRoute(async (req, res) => {
  const reference = cleanText(req.query.reference, 120);
  if (!reference || !process.env.PAYSTACK_SECRET_KEY) return res.status(400).send('Missing payment reference.');
  try {
    const response = await fetch('https://api.paystack.co/transaction/verify/' + encodeURIComponent(reference), {
      headers: { Authorization: 'Bearer ' + process.env.PAYSTACK_SECRET_KEY },
      signal: AbortSignal.timeout(15000)
    });
    const result = await response.json();
    if (!response.ok || !result.status || !result.data) return res.status(502).send('Unable to verify payment. Contact the store before paying again.');
    const data = result.data;
    const paid = await markOrderPaid(reference, data.amount, data.currency, data.status);
    if (paid) return res.redirect('/?payment=success&reference=' + encodeURIComponent(reference));
    return res.redirect('/?payment=pending&reference=' + encodeURIComponent(reference));
  } catch (error) {
    console.error('Payment verification failed:', error.message);
    return res.status(502).send('Payment verification is temporarily unavailable. Please contact the store.');
  }
}));

app.get('/api/orders/:reference/status', asyncRoute(async (req, res) => {
  const reference = cleanText(req.params.reference, 120);
  if (!/^[0-9a-f-]{36}$/i.test(reference)) return res.status(400).json({ error: 'Invalid order reference.' });
  const [rows] = await pool.execute('SELECT public_reference,status,total_pesewas,currency,created_at,paid_at FROM orders WHERE public_reference=? LIMIT 1', [reference]);
  if (!rows.length) return res.status(404).json({ error: 'Order not found.' });
  res.json({ order: { reference: rows[0].public_reference, status: rows[0].status, totalPesewas: rows[0].total_pesewas, currency: rows[0].currency, createdAt: rows[0].created_at, paidAt: rows[0].paid_at } });
}));

app.get('/api/admin/orders', adminOnly, asyncRoute(async (req, res) => {
  const [rows] = await pool.query('SELECT id,public_reference,customer_name,customer_email,customer_phone,shipping_address,total_pesewas,currency,status,created_at,paid_at FROM orders ORDER BY created_at DESC LIMIT 200');
  res.json({ orders: rows });
}));

app.patch('/api/admin/orders/:id/status', adminOnly, asyncRoute(async (req, res) => {
  const allowed = ['processing','shipped','completed','cancelled'];
  const status = cleanText(req.body.status, 30);
  if (!/^\d+$/.test(req.params.id) || !allowed.includes(status)) return res.status(400).json({ error: 'Invalid order or status.' });
  const [result] = await pool.execute('UPDATE orders SET status=? WHERE id=? AND status IN (\'paid\',\'processing\',\'shipped\',\'completed\')', [status,req.params.id]);
  if (!result.affectedRows) return res.status(409).json({ error: 'Order not found or cannot transition to that status.' });
  res.json({ success: true });
}));

app.use(express.static(path.join(__dirname, 'public'), { index: 'index.html', dotfiles: 'deny', etag: true, maxAge: isProduction ? '1h' : 0 }));
app.get('/admin', (req, res) => res.sendFile(path.join(__dirname, 'public', 'admin.html')));
app.use((req, res) => res.status(404).json({ error: 'Not found.' }));
app.use((err, req, res, next) => {
  if (res.headersSent) return next(err);
  console.error('Request error:', err.message);
  if (err.message === 'Origin not allowed by CORS') return res.status(403).json({ error: 'Origin not allowed.' });
  return res.status(500).json({ error: 'Unexpected server error.' });
});

// Release inventory reserved for abandoned unpaid checkouts after 30 minutes.
const reservationCleanup = setInterval(async () => {
  try {
    const [expired] = await pool.query("SELECT public_reference FROM orders WHERE status='pending_payment' AND created_at < UTC_TIMESTAMP() - INTERVAL 30 MINUTE LIMIT 25");
    for (const order of expired) await releaseOrderReservation(order.public_reference, 'cancelled');
  } catch (error) { console.error('Reservation cleanup failed:', error.message); }
}, 5 * 60 * 1000);
if (typeof reservationCleanup.unref === 'function') reservationCleanup.unref();

const server = app.listen(PORT, () => console.log('Divine Hope shop server listening on port ' + PORT));
async function shutdown() { console.log('Shutting down...'); clearInterval(reservationCleanup); server.close(async () => { await pool.end(); process.exit(0); }); }
process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);
