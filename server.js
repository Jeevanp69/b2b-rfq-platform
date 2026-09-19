import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import db from './db.js';

const PORT = process.env.PORT || 3000;
const SECRET = process.env.JWT_SECRET || 'development-secret-change-me';
const root = path.resolve('public');
const today = () => new Date().toISOString().slice(0, 10);

if (process.env.NODE_ENV === 'production' && !process.env.JWT_SECRET) {
  throw Error('JWT_SECRET must be set in production.');
}

const clean = (value, max = 500) => typeof value === 'string' ? value.trim().slice(0, max) : '';
const respond = (response, status, payload) => {
  response.writeHead(status, { 'Content-Type': 'application/json' });
  response.end(JSON.stringify(payload));
};
const fail = (response, status, message) => respond(response, status, { error: message });

const sign = user => {
  const payload = Buffer.from(JSON.stringify({ ...user, exp: Date.now() + 6048e5 })).toString('base64url');
  return `${payload}.${crypto.createHmac('sha256', SECRET).update(payload).digest('base64url')}`;
};

const currentUser = request => {
  const parts = request.headers.authorization?.replace(/^Bearer\s+/i, '')?.split('.');
  if (!parts || parts.length !== 2) return null;
  const signature = crypto.createHmac('sha256', SECRET).update(parts[0]).digest('base64url');
  if (parts[1] !== signature) return null;
  try {
    const user = JSON.parse(Buffer.from(parts[0], 'base64url'));
    return user.exp > Date.now() ? user : null;
  } catch {
    return null;
  }
};

const guard = (request, response, roles = []) => {
  const user = currentUser(request);
  if (!user) {
    fail(response, 401, 'Please log in to continue.');
    return null;
  }
  if (roles.length && !roles.includes(user.role)) {
    fail(response, 403, 'You are not allowed to perform this action.');
    return null;
  }
  return user;
};

const hashPassword = password => {
  const salt = crypto.randomBytes(16).toString('hex');
  return `${salt}:${crypto.scryptSync(password, salt, 64).toString('hex')}`;
};
const checkPassword = (password, stored) => {
  const [salt, key] = stored.split(':');
  return crypto.timingSafeEqual(Buffer.from(key, 'hex'), crypto.scryptSync(password, salt, 64));
};

const readBody = request => new Promise((resolve, reject) => {
  let text = '';
  request.on('data', chunk => {
    text += chunk;
    if (text.length > 20000) {
      reject(Error('Request body is too large.'));
      request.destroy();
    }
  });
  request.on('end', () => {
    try {
      resolve(JSON.parse(text || '{}'));
    } catch {
      reject(Error('Invalid JSON'));
    }
  });
  request.on('error', reject);
});

const rows = `SELECT r.*,u.name buyer_name,(SELECT COUNT(*) FROM quotations q WHERE q.rfq_id=r.id) quotation_count FROM rfqs r JOIN users u ON u.id=r.buyer_id`;
const parseRfq = body => {
  const product = clean(body.productName, 120);
  const description = clean(body.description, 1500);
  const location = clean(body.deliveryLocation, 150);
  const quantity = Number(body.quantity);
  const deadline = clean(body.deadline, 10);
  if (product.length < 2 || description.length < 10 || !Number.isInteger(quantity) || quantity < 1 || !location || !/^\d{4}-\d{2}-\d{2}$/.test(deadline)) return null;
  return { product, description, location, quantity, deadline };
};

async function api(request, response, url) {
  const route = url.pathname;
  const method = request.method;

  if (method === 'POST' && route === '/api/auth/signup') {
    const body = await readBody(request);
    const name = clean(body.name, 80);
    const email = clean(body.email, 120).toLowerCase();
    const password = body.password || '';
    const role = body.role;
    if (name.length < 2 || !/^\S+@\S+\.\S+$/.test(email) || password.length < 8 || !['buyer', 'supplier'].includes(role)) {
      return fail(response, 400, 'Use a name, valid email, 8+ character password, and a valid role.');
    }
    try {
      const result = db.prepare('INSERT INTO users (name,email,password_hash,role) VALUES (?,?,?,?)').run(name, email, hashPassword(password), role);
      const user = { id: Number(result.lastInsertRowid), name, email, role };
      return respond(response, 201, { token: sign(user), user });
    } catch {
      return fail(response, 409, 'An account with that email already exists.');
    }
  }

  if (method === 'POST' && route === '/api/auth/login') {
    const body = await readBody(request);
    const account = db.prepare('SELECT * FROM users WHERE email=?').get(clean(body.email, 120).toLowerCase());
    if (!account || !checkPassword(body.password || '', account.password_hash)) return fail(response, 401, 'Invalid email or password.');
    const user = { id: account.id, name: account.name, email: account.email, role: account.role };
    return respond(response, 200, { token: sign(user), user });
  }

  if (method === 'GET' && route === '/api/rfqs') {
    if (!guard(request, response)) return;
    let sql = `${rows} WHERE r.status='open' AND r.deadline>=date('now')`;
    const values = [];
    const search = clean(url.searchParams.get('search') || '', 100);
    const location = clean(url.searchParams.get('location') || '', 100);
    if (search) {
      sql += ' AND (r.product_name LIKE ? OR r.description LIKE ?)';
      values.push(`%${search}%`, `%${search}%`);
    }
    if (location) {
      sql += ' AND r.delivery_location LIKE ?';
      values.push(`%${location}%`);
    }
    return respond(response, 200, db.prepare(`${sql} ORDER BY r.deadline ASC`).all(...values));
  }

  if (method === 'GET' && route === '/api/rfqs/mine') {
    const user = guard(request, response, ['buyer']);
    if (user) respond(response, 200, db.prepare(`${rows} WHERE r.buyer_id=? ORDER BY r.created_at DESC`).all(user.id));
    return;
  }

  if (method === 'POST' && route === '/api/rfqs') {
    const user = guard(request, response, ['buyer']);
    if (!user) return;
    const rfq = parseRfq(await readBody(request));
    if (!rfq || rfq.deadline < today()) return fail(response, 400, 'Complete all fields; deadline cannot be in the past.');
    const result = db.prepare('INSERT INTO rfqs (buyer_id,product_name,description,quantity,delivery_location,deadline) VALUES (?,?,?,?,?,?)').run(user.id, rfq.product, rfq.description, rfq.quantity, rfq.location, rfq.deadline);
    return respond(response, 201, db.prepare(`${rows} WHERE r.id=?`).get(Number(result.lastInsertRowid)));
  }

  const rfqMatch = route.match(/^\/api\/rfqs\/(\d+)$/);
  if (rfqMatch && method === 'GET') {
    if (!guard(request, response)) return;
    const rfq = db.prepare(`${rows} WHERE r.id=?`).get(Number(rfqMatch[1]));
    return rfq ? respond(response, 200, rfq) : fail(response, 404, 'RFQ not found.');
  }

  if (rfqMatch && method === 'PUT') {
    const user = guard(request, response, ['buyer']);
    if (!user) return;
    const id = Number(rfqMatch[1]);
    const owned = db.prepare('SELECT id FROM rfqs WHERE id=? AND buyer_id=?').get(id, user.id);
    const rfq = parseRfq(await readBody(request));
    if (!owned) return fail(response, 404, 'RFQ not found.');
    if (!rfq || rfq.deadline < today()) return fail(response, 400, 'Please provide valid RFQ details; deadline cannot be in the past.');
    db.prepare('UPDATE rfqs SET product_name=?,description=?,quantity=?,delivery_location=?,deadline=?,updated_at=CURRENT_TIMESTAMP WHERE id=?').run(rfq.product, rfq.description, rfq.quantity, rfq.location, rfq.deadline, id);
    return respond(response, 200, db.prepare(`${rows} WHERE r.id=?`).get(id));
  }

  const quotationMatch = route.match(/^\/api\/rfqs\/(\d+)\/quotations$/);
  if (quotationMatch && method === 'GET') {
    const user = guard(request, response, ['buyer']);
    if (!user) return;
    const rfq = db.prepare('SELECT id FROM rfqs WHERE id=? AND buyer_id=?').get(Number(quotationMatch[1]), user.id);
    return rfq ? respond(response, 200, db.prepare('SELECT q.*,u.name supplier_name,u.email supplier_email FROM quotations q JOIN users u ON u.id=q.supplier_id WHERE q.rfq_id=? ORDER BY q.created_at DESC').all(rfq.id)) : fail(response, 404, 'RFQ not found.');
  }

  if (quotationMatch && method === 'POST') {
    const user = guard(request, response, ['supplier']);
    if (!user) return;
    const body = await readBody(request);
    const id = Number(quotationMatch[1]);
    const price = Number(body.price);
    const deliveryDays = Number(body.deliveryDays);
    const notes = clean(body.notes, 1000);
    const rfq = db.prepare("SELECT id FROM rfqs WHERE id=? AND status='open' AND deadline>=date('now')").get(id);
    if (!rfq) return fail(response, 404, 'This RFQ is no longer available.');
    if (!Number.isFinite(price) || price < 0 || !Number.isInteger(deliveryDays) || deliveryDays < 1 || notes.length < 3) return fail(response, 400, 'Enter a valid price, delivery time, and message.');
    try {
      const result = db.prepare('INSERT INTO quotations (rfq_id,supplier_id,price,delivery_days,notes) VALUES (?,?,?,?,?)').run(id, user.id, price, deliveryDays, notes);
      return respond(response, 201, db.prepare('SELECT * FROM quotations WHERE id=?').get(Number(result.lastInsertRowid)));
    } catch {
      return fail(response, 409, 'You already submitted a quotation for this RFQ.');
    }
  }

  if (method === 'GET' && route === '/api/quotations/mine') {
    const user = guard(request, response, ['supplier']);
    if (user) respond(response, 200, db.prepare('SELECT q.*,r.product_name,r.quantity,r.delivery_location,r.deadline FROM quotations q JOIN rfqs r ON r.id=q.rfq_id WHERE q.supplier_id=? ORDER BY q.created_at DESC').all(user.id));
    return;
  }

  fail(response, 404, 'API route not found.');
}

http.createServer((request, response) => {
  const url = new URL(request.url, 'http://localhost');
  if (url.pathname.startsWith('/api/')) {
    return api(request, response, url).catch(error => {
      console.error(error);
      if (!response.headersSent) fail(response, 500, 'Something went wrong. Please try again.');
    });
  }

  let file = path.join(root, url.pathname === '/' ? 'index.html' : url.pathname);
  if (!file.startsWith(root) || !fs.existsSync(file)) file = path.join(root, 'index.html');
  response.writeHead(200, { 'Content-Type': file.endsWith('.css') ? 'text/css' : file.endsWith('.js') ? 'application/javascript' : 'text/html' });
  fs.createReadStream(file).pipe(response);
}).listen(PORT, () => console.log(`RFQ Marketplace running on http://localhost:${PORT}`));
