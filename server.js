// backend/server.js
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const multer = require('multer');
const cloudinary = require('cloudinary').v2;
const crypto = require('crypto');
const axios = require('axios');

const app = express();

// CORS: allow all origins (for development); restrict later if needed
app.use(cors());
app.use(express.json());

// PostgreSQL connection pool
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
});

// Test database connection on startup
pool.connect((err, client, release) => {
    if (err) {
        console.error('❌ Database connection error:', err.stack);
    } else {
        console.log('✅ Connected to PostgreSQL');
        release();
    }
});

// Cloudinary configuration
cloudinary.config({
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
    api_key: process.env.CLOUDINARY_API_KEY,
    api_secret: process.env.CLOUDINARY_API_SECRET,
});

// Multer memory storage
const storage = multer.memoryStorage();
const upload = multer({ storage });

// ---------- Payment Initiation ----------
app.post('/api/orders/initiate-payment', async (req, res) => {
    const { orderId, email, amount, customer_name } = req.body;
    if (!orderId || !email || !amount) {
        return res.status(400).json({ error: 'Missing required fields' });
    }

    try {
        const response = await axios.post('https://api.paystack.co/transaction/initialize', {
            email,
            amount: amount * 100,
            metadata: {
                orderId,
                customer_name
            },
            callback_url: `${process.env.FRONTEND_URL}/payment-callback.html`
        }, {
            headers: {
                Authorization: `Bearer ${process.env.PAYSTACK_SECRET_KEY}`,
                'Content-Type': 'application/json'
            }
        });

        const { authorization_url, reference } = response.data.data;

        await pool.query(
            `UPDATE orders SET transaction_reference = $1 WHERE id = $2`,
            [reference, orderId]
        );

        res.json({ authorization_url, reference });
    } catch (err) {
        console.error('Paystack init error:', err.response?.data || err.message);
        res.status(500).json({ error: 'Payment initiation failed' });
    }
});

// ---------- Webhook (Paystack calls this) ----------
app.post('/api/webhooks/paystack', express.raw({type: 'application/json'}), async (req, res) => {
    const signature = req.headers['x-paystack-signature'];
    const secret = process.env.PAYSTACK_SECRET_KEY;
    const hash = crypto.createHmac('sha512', secret).update(JSON.stringify(req.body)).digest('hex');

    if (hash !== signature) {
        console.warn('Invalid webhook signature');
        return res.status(401).send('Invalid signature');
    }

    const event = req.body;
    if (event.event === 'charge.success') {
        const { reference, metadata } = event.data;
        const orderId = metadata.orderId;
        if (!orderId) {
            console.warn('No orderId in metadata');
            return res.sendStatus(200);
        }

        await pool.query(
            `UPDATE orders SET payment_status = 'paid', status = 'pending' WHERE id = $1 AND transaction_reference = $2`,
            [orderId, reference]
        );

        console.log(`Order ${orderId} paid successfully.`);
    }
    res.sendStatus(200);
});

// ---------- Image Upload ----------
app.post('/api/upload', upload.single('image'), async (req, res) => {
    if (!req.file) {
        return res.status(400).json({ error: 'No file uploaded' });
    }
    try {
        const b64 = Buffer.from(req.file.buffer).toString('base64');
        const dataURI = `data:${req.file.mimetype};base64,${b64}`;
        const result = await cloudinary.uploader.upload(dataURI, {
            folder: 'campusdash/products',
        });
        res.json({ url: result.secure_url });
    } catch (err) {
        console.error('Upload error:', err);
        res.status(500).json({ error: 'Upload failed' });
    }
});

// ---------- Products (customer facing) ----------
app.get('/api/products', async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT p.id, p.name, p.price, p.icon, p.image_url, p.available, v.name as vendor_name
            FROM products p
            JOIN vendors v ON p.vendor_id = v.id
            WHERE p.available = true
            ORDER BY p.id
        `);
        res.json(result.rows);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Failed to fetch products' });
    }
});

// ---------- Orders ----------
app.post('/api/orders', async (req, res) => {
    const { 
        customer_name, 
        customer_phone, 
        location, 
        instructions, 
        items, 
        subtotal, 
        total, 
        payment_method,
        delivery_latitude,
        delivery_longitude
    } = req.body;
    
    if (!customer_name || !customer_phone || !location || !items || !items.length) {
        return res.status(400).json({ error: 'Missing required fields' });
    }

    const client = await pool.connect();
    try {
        await client.query('BEGIN');
        
        const orderResult = await client.query(
            `INSERT INTO orders
             (customer_name, customer_phone, location, instructions, subtotal, delivery_fee, total, status, vendor_id, 
              payment_status, payment_method, delivery_latitude, delivery_longitude)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
             RETURNING id`,
            [
                customer_name, 
                customer_phone, 
                location, 
                instructions, 
                subtotal, 
                5.00, 
                total, 
                'pending', 
                1,
                'pending',
                payment_method || 'cash',
                delivery_latitude || null,
                delivery_longitude || null
            ]
        );
        const orderId = orderResult.rows[0].id;

        for (const item of items) {
            await client.query(
                `INSERT INTO order_items (order_id, product_id, quantity, price_at_time)
                 VALUES ($1, $2, $3, $4)`,
                [orderId, item.id, item.quantity, item.price]
            );
        }

        await client.query('COMMIT');
        res.status(201).json({ orderId, message: 'Order placed successfully' });
    } catch (err) {
        await client.query('ROLLBACK');
        console.error(err);
        res.status(500).json({ error: 'Failed to place order' });
    } finally {
        client.release();
    }
});

// ---------- Vendor Payment System Endpoints ----------

// Get vendor wallet balance and transactions
app.get('/api/vendors/:vendorId/wallet', async (req, res) => {
    const { vendorId } = req.params;
    try {
        const walletResult = await pool.query(
            'SELECT * FROM vendor_wallets WHERE vendor_id = $1',
            [vendorId]
        );
        
        const transactionsResult = await pool.query(
            `SELECT * FROM vendor_transactions 
             WHERE vendor_id = $1 
             ORDER BY created_at DESC 
             LIMIT 50`,
            [vendorId]
        );
        
        const payoutsResult = await pool.query(
            `SELECT * FROM vendor_payouts 
             WHERE vendor_id = $1 AND status IN ('pending', 'processing')
             ORDER BY created_at DESC`,
            [vendorId]
        );
        
        res.json({
            wallet: walletResult.rows[0] || { balance: 0, pending_balance: 0, total_earned: 0 },
            transactions: transactionsResult.rows,
            pending_payouts: payoutsResult.rows
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Failed to fetch wallet data' });
    }
});

// Update vendor payout settings
app.put('/api/vendors/:vendorId/payout-settings', async (req, res) => {
    const { vendorId } = req.params;
    const { mobile_money_number, bank_account_details } = req.body;
    
    try {
        await pool.query(
            `UPDATE vendors 
             SET mobile_money_number = COALESCE($1, mobile_money_number),
                 bank_account_details = COALESCE($2, bank_account_details),
                 payout_settings = jsonb_build_object('mobile_money', $1, 'bank', $2)
             WHERE id = $3`,
            [mobile_money_number, bank_account_details, vendorId]
        );
        
        res.json({ success: true, message: 'Payout settings updated' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Failed to update payout settings' });
    }
});

// Request payout (vendor initiates withdrawal)
app.post('/api/vendors/:vendorId/request-payout', async (req, res) => {
    const { vendorId } = req.params;
    const { amount, payment_method } = req.body;
    
    if (!amount || amount <= 0) {
        return res.status(400).json({ error: 'Invalid amount' });
    }
    
    const client = await pool.connect();
    try {
        await client.query('BEGIN');
        
        const walletResult = await client.query(
            'SELECT balance FROM vendor_wallets WHERE vendor_id = $1 FOR UPDATE',
            [vendorId]
        );
        
        const currentBalance = parseFloat(walletResult.rows[0]?.balance || 0);
        
        if (amount > currentBalance) {
            await client.query('ROLLBACK');
            return res.status(400).json({ error: 'Insufficient balance' });
        }
        
        const payoutResult = await client.query(
            `INSERT INTO vendor_payouts (vendor_id, amount, payment_method, status)
             VALUES ($1, $2, $3, 'pending')
             RETURNING *`,
            [vendorId, amount, payment_method]
        );
        
        await client.query(
            'UPDATE vendor_wallets SET balance = balance - $1 WHERE vendor_id = $2',
            [amount, vendorId]
        );
        
        await client.query(
            `INSERT INTO vendor_transactions (vendor_id, type, amount, description, status, reference)
             VALUES ($1, 'payout', $2, 'Payout request initiated', 'completed', $3)`,
            [vendorId, -amount, `PO-${Date.now()}`]
        );
        
        await client.query('COMMIT');
        res.json({ success: true, payout: payoutResult.rows[0] });
    } catch (err) {
        await client.query('ROLLBACK');
        console.error(err);
        res.status(500).json({ error: 'Failed to request payout' });
    } finally {
        client.release();
    }
});

// Admin endpoint to process payouts
app.patch('/api/admin/payouts/:payoutId/process', async (req, res) => {
    const { payoutId } = req.params;
    const { transaction_reference } = req.body;
    
    try {
        const result = await pool.query(
            `UPDATE vendor_payouts 
             SET status = 'completed', 
                 processed_at = NOW(),
                 reference = COALESCE($1, reference)
             WHERE id = $2 AND status = 'pending'
             RETURNING *`,
            [transaction_reference, payoutId]
        );
        
        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Payout not found or already processed' });
        }
        
        res.json({ success: true, payout: result.rows[0] });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Failed to process payout' });
    }
});

// ---------- Vendor endpoints ----------
// Get all products for a specific vendor
app.get('/api/vendors/:vendorId/products', async (req, res) => {
    const { vendorId } = req.params;
    try {
        const result = await pool.query(
            'SELECT * FROM products WHERE vendor_id = $1 ORDER BY id',
            [vendorId]
        );
        res.json(result.rows);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Failed to fetch products' });
    }
});

// Add a new product
app.post('/api/vendors/:vendorId/products', async (req, res) => {
    const { vendorId } = req.params;
    const { name, price, icon, available, image_url } = req.body;
    if (!name || !price) {
        return res.status(400).json({ error: 'Name and price are required' });
    }
    try {
        const result = await pool.query(
            `INSERT INTO products (vendor_id, name, price, icon, available, image_url)
             VALUES ($1, $2, $3, $4, $5, $6)
             RETURNING *`,
            [vendorId, name, price, icon || '📦', available !== undefined ? available : true, image_url || null]
        );
        res.status(201).json(result.rows[0]);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Failed to add product' });
    }
});

// ---------- Vendor Login ----------
app.post('/api/vendors/login', async (req, res) => {
    const { phone, pin } = req.body;
    
    if (!phone || !pin) {
        return res.status(400).json({ error: 'Phone and PIN required' });
    }
    
    try {
        const result = await pool.query(
            'SELECT id, name, phone, location FROM vendors WHERE phone = $1 AND pin = $2',
            [phone, pin]
        );
        
        if (result.rows.length === 0) {
            return res.status(401).json({ error: 'Invalid phone number or PIN' });
        }
        
        res.json({ 
            success: true, 
            vendor: result.rows[0]
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Login failed' });
    }
});

// ---------- Rider Login ----------
app.post('/api/riders/login', async (req, res) => {
    const { phone, pin } = req.body;
    
    if (!phone || !pin) {
        return res.status(400).json({ error: 'Phone and PIN required' });
    }
    
    try {
        const result = await pool.query(
            'SELECT id, name, phone, available FROM riders WHERE phone = $1 AND pin = $2',
            [phone, pin]
        );
        
        if (result.rows.length === 0) {
            return res.status(401).json({ error: 'Invalid phone number or PIN' });
        }
        
        res.json({ 
            success: true, 
            rider: result.rows[0]
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Login failed' });
    }
});

// ---------- Get Current Vendor (verify session) ----------
app.get('/api/vendors/:vendorId/verify', async (req, res) => {
    const { vendorId } = req.params;
    try {
        const result = await pool.query(
            'SELECT id, name, phone FROM vendors WHERE id = $1',
            [vendorId]
        );
        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Vendor not found' });
        }
        res.json(result.rows[0]);
    } catch (err) {
        res.status(500).json({ error: 'Verification failed' });
    }
});

// ---------- Get Current Rider (verify session) ----------
app.get('/api/riders/:riderId/verify', async (req, res) => {
    const { riderId } = req.params;
    try {
        const result = await pool.query(
            'SELECT id, name, phone FROM riders WHERE id = $1',
            [riderId]
        );
        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Rider not found' });
        }
        res.json(result.rows[0]);
    } catch (err) {
        res.status(500).json({ error: 'Verification failed' });
    }
});

// Update a product
app.put('/api/products/:productId', async (req, res) => {
    const { productId } = req.params;
    const { name, price, icon, available, image_url } = req.body;
    try {
        const result = await pool.query(
            `UPDATE products
             SET name = COALESCE($1, name),
                 price = COALESCE($2, price),
                 icon = COALESCE($3, icon),
                 available = COALESCE($4, available),
                 image_url = COALESCE($5, image_url)
             WHERE id = $6
             RETURNING *`,
            [name, price, icon, available, image_url, productId]
        );
        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Product not found' });
        }
        res.json(result.rows[0]);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Failed to update product' });
    }
});

// Get vendor location
app.get('/api/vendors/:vendorId/location', async (req, res) => {
    const { vendorId } = req.params;
    try {
        const result = await pool.query(
            'SELECT id, name, location, latitude, longitude, mobile_money_number, bank_account_details FROM vendors WHERE id = $1',
            [vendorId]
        );
        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Vendor not found' });
        }
        res.json(result.rows[0]);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Failed to fetch vendor location' });
    }
});

// Update vendor location
app.put('/api/vendors/:vendorId/location', async (req, res) => {
    const { vendorId } = req.params;
    const { latitude, longitude, location_name } = req.body;
    
    console.log(`Updating vendor ${vendorId} location:`, { latitude, longitude, location_name });
    
    if (!latitude || !longitude) {
        return res.status(400).json({ error: 'Latitude and longitude are required' });
    }
    
    try {
        const vendorCheck = await pool.query(
            'SELECT id FROM vendors WHERE id = $1',
            [vendorId]
        );
        
        if (vendorCheck.rows.length === 0) {
            return res.status(404).json({ error: 'Vendor not found' });
        }
        
        const result = await pool.query(
            `UPDATE vendors 
             SET latitude = $1, 
                 longitude = $2, 
                 location = COALESCE($3, location)
             WHERE id = $4
             RETURNING id, name, latitude, longitude, location`,
            [latitude, longitude, location_name, vendorId]
        );
        
        console.log('Vendor location updated:', result.rows[0]);
        res.json({ success: true, vendor: result.rows[0] });
    } catch (err) {
        console.error('Error updating vendor location:', err);
        res.status(500).json({ error: 'Failed to update vendor location', details: err.message });
    }
});

// Delete a product
app.delete('/api/products/:productId', async (req, res) => {
    const { productId } = req.params;
    try {
        const productCheck = await pool.query(
            'SELECT id FROM products WHERE id = $1',
            [productId]
        );
        if (productCheck.rows.length === 0) {
            return res.status(404).json({ error: 'Product not found' });
        }
        
        const result = await pool.query(
            'DELETE FROM products WHERE id = $1 RETURNING id',
            [productId]
        );
        
        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Product not found' });
        }
        
        res.json({ success: true, message: 'Product deleted successfully' });
    } catch (err) {
        console.error('Delete error:', err);
        if (err.code === '23503') {
            return res.status(400).json({ error: 'Cannot delete: product has existing orders' });
        }
        res.status(500).json({ error: 'Failed to delete product', details: err.message });
    }
});

// Get orders for a specific vendor
app.get('/api/vendors/:vendorId/orders', async (req, res) => {
    const { vendorId } = req.params;
    try {
        const result = await pool.query(`
            SELECT o.*,
                   json_agg(json_build_object('product_id', oi.product_id, 'quantity', oi.quantity, 'price', oi.price_at_time)) as items
            FROM orders o
            LEFT JOIN order_items oi ON o.id = oi.order_id
            WHERE o.vendor_id = $1
            GROUP BY o.id
            ORDER BY o.created_at DESC
        `, [vendorId]);
        res.json(result.rows);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Failed to fetch orders' });
    }
});

// Update order status
app.patch('/api/orders/:orderId/status', async (req, res) => {
    const { orderId } = req.params;
    const { status } = req.body;
    const allowed = ['pending', 'accepted', 'ready', 'picked', 'delivered'];
    if (!allowed.includes(status)) {
        return res.status(400).json({ error: 'Invalid status' });
    }
    try {
        await pool.query('UPDATE orders SET status = $1 WHERE id = $2', [status, orderId]);
        res.json({ success: true });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Failed to update status' });
    }
});

// ---------- Rider endpoints ----------
// Get all orders ready for pickup
app.get('/api/orders/ready', async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT o.*, 
                   v.name as vendor_name, 
                   v.location as vendor_location,
                   v.latitude as vendor_latitude,
                   v.longitude as vendor_longitude,
                   o.delivery_latitude,
                   o.delivery_longitude
            FROM orders o
            JOIN vendors v ON o.vendor_id = v.id
            WHERE o.status = 'ready' AND o.rider_id IS NULL
            ORDER BY o.created_at ASC
        `);
        res.json(result.rows);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Failed to fetch ready orders' });
    }
});

// Get orders assigned to a specific rider
app.get('/api/riders/:riderId/orders', async (req, res) => {
    const { riderId } = req.params;
    try {
        const result = await pool.query(`
            SELECT o.*, 
                   v.name as vendor_name, 
                   v.location as vendor_location,
                   v.latitude as vendor_latitude,
                   v.longitude as vendor_longitude,
                   o.delivery_latitude,
                   o.delivery_longitude
            FROM orders o
            JOIN vendors v ON o.vendor_id = v.id
            WHERE o.rider_id = $1 AND o.status IN ('picked')
            ORDER BY o.created_at DESC
        `, [riderId]);
        res.json(result.rows);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Failed to fetch rider orders' });
    }
});

// Get rider order history
app.get('/api/riders/:riderId/orders/history', async (req, res) => {
    const { riderId } = req.params;
    try {
        const result = await pool.query(`
            SELECT o.*, 
                   v.name as vendor_name, 
                   v.location as vendor_location,
                   o.delivery_latitude,
                   o.delivery_longitude
            FROM orders o
            JOIN vendors v ON o.vendor_id = v.id
            WHERE o.rider_id = $1 AND o.status = 'delivered'
            ORDER BY o.delivered_at DESC
            LIMIT 50
        `, [riderId]);
        res.json(result.rows);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Failed to fetch rider history' });
    }
});

// Assign a rider to an order
app.patch('/api/orders/:orderId/assign', async (req, res) => {
    const { orderId } = req.params;
    const { riderId } = req.body;
    if (!riderId) {
        return res.status(400).json({ error: 'riderId is required' });
    }
    try {
        const result = await pool.query(
            `UPDATE orders
             SET rider_id = $1, status = 'picked'
             WHERE id = $2 AND status = 'ready' AND rider_id IS NULL
             RETURNING *`,
            [riderId, orderId]
        );
        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Order not available for pickup' });
        }
        res.json(result.rows[0]);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Failed to assign rider' });
    }
});

// Mark order as delivered and credit vendor AND rider
app.patch('/api/orders/:orderId/deliver', async (req, res) => {
    const { orderId } = req.params;
    const { riderId } = req.body;
    
    const client = await pool.connect();
    try {
        await client.query('BEGIN');
        
        // Get order details with vendor and rider info
        const orderResult = await client.query(
            `SELECT o.*, v.name as vendor_name, v.id as vendor_id, r.id as rider_id
             FROM orders o 
             JOIN vendors v ON o.vendor_id = v.id 
             LEFT JOIN riders r ON o.rider_id = r.id
             WHERE o.id = $1`,
            [orderId]
        );
        
        if (orderResult.rows.length === 0) {
            await client.query('ROLLBACK');
            return res.status(404).json({ error: 'Order not found' });
        }
        
        const order = orderResult.rows[0];
        const actualRiderId = riderId || order.rider_id;
        
        // Check if order is already delivered
        if (order.status === 'delivered') {
            await client.query('ROLLBACK');
            return res.status(400).json({ error: 'Order already delivered' });
        }
        
        // Check if order has a rider assigned
        if (!actualRiderId) {
            await client.query('ROLLBACK');
            return res.status(400).json({ error: 'No rider assigned to this order' });
        }
        
        // Calculate earnings
        const commissionRate = 0.12;
        const subtotal = parseFloat(order.subtotal);
        const commission = subtotal * commissionRate;
        const vendorEarnings = subtotal - commission;
        const riderEarnings = 4.00; // Rider gets ₵4 per delivery (out of ₵5 delivery fee)
        
        // Update order status to delivered
        const orderUpdateResult = await client.query(
            `UPDATE orders 
             SET status = 'delivered', 
                 delivered_at = NOW() 
             WHERE id = $1 
             RETURNING *`,
            [orderId]
        );
        
        // CREDIT VENDOR
        // Check if vendor wallet exists
        const vendorWalletCheck = await client.query(
            'SELECT id FROM vendor_wallets WHERE vendor_id = $1',
            [order.vendor_id]
        );
        
        if (vendorWalletCheck.rows.length === 0) {
            await client.query(
                `INSERT INTO vendor_wallets (vendor_id, balance, pending_balance, total_earned)
                 VALUES ($1, 0, 0, 0)`,
                [order.vendor_id]
            );
        }
        
        await client.query(
            `UPDATE vendor_wallets 
             SET balance = balance + $1,
                 total_earned = total_earned + $1,
                 updated_at = NOW()
             WHERE vendor_id = $2`,
            [vendorEarnings, order.vendor_id]
        );
        
        await client.query(
            `INSERT INTO vendor_transactions 
             (vendor_id, order_id, type, amount, description, status, reference)
             VALUES ($1, $2, 'earning', $3, $4, 'completed', $5)`,
            [order.vendor_id, orderId, vendorEarnings, 
             `Earnings from Order #${orderId}`,
             `ORD-${orderId}-${Date.now()}`]
        );
        
        // CREDIT RIDER
        // Check if rider wallet exists
        const riderWalletCheck = await client.query(
            'SELECT id FROM rider_wallets WHERE rider_id = $1',
            [actualRiderId]
        );
        
        if (riderWalletCheck.rows.length === 0) {
            await client.query(
                `INSERT INTO rider_wallets (rider_id, balance, pending_balance, total_earned)
                 VALUES ($1, 0, 0, 0)`,
                [actualRiderId]
            );
        }
        
        await client.query(
            `UPDATE rider_wallets 
             SET balance = balance + $1,
                 total_earned = total_earned + $1,
                 updated_at = NOW()
             WHERE rider_id = $2`,
            [riderEarnings, actualRiderId]
        );
        
        await client.query(
            `INSERT INTO rider_transactions 
             (rider_id, order_id, type, amount, description, status, reference)
             VALUES ($1, $2, 'earning', $3, $4, 'completed', $5)`,
            [actualRiderId, orderId, riderEarnings, 
             `Delivery earnings from Order #${orderId}`,
             `RID-${orderId}-${Date.now()}`]
        );
        
        await client.query('COMMIT');
        
        res.json({ 
            success: true, 
            message: 'Order delivered successfully',
            order: orderUpdateResult.rows[0],
            vendor_earnings: vendorEarnings,
            rider_earnings: riderEarnings
        });
    } catch (err) {
        await client.query('ROLLBACK');
        console.error('Deliver error:', err);
        res.status(500).json({ error: 'Failed to mark delivered', details: err.message });
    } finally {
        client.release();
    }
});

// Debug endpoint - check rider's today's earnings
app.get('/api/debug/rider-earnings/:riderId', async (req, res) => {
    const { riderId } = req.params;
    try {
        // Get today's date (start of day)
        const today = new Date();
        today.setHours(0, 0, 0, 0);
        
        // Get all delivered orders for this rider today
        const ordersResult = await pool.query(`
            SELECT id, delivered_at, status 
            FROM orders 
            WHERE rider_id = $1 AND status = 'delivered' AND delivered_at >= $2
            ORDER BY delivered_at DESC
        `, [riderId, today]);
        
        // Get transactions from rider_transactions
        const transactionsResult = await pool.query(`
            SELECT * FROM rider_transactions 
            WHERE rider_id = $1 AND type = 'earning' AND created_at >= $2
            ORDER BY created_at DESC
        `, [riderId, today]);
        
        // Get wallet balance
        const walletResult = await pool.query(`
            SELECT * FROM rider_wallets WHERE rider_id = $1
        `, [riderId]);
        
        res.json({
            rider_id: riderId,
            orders_today: ordersResult.rows,
            orders_count: ordersResult.rows.length,
            transactions_today: transactionsResult.rows,
            transactions_count: transactionsResult.rows.length,
            wallet: walletResult.rows[0] || null,
            calculated_earnings: ordersResult.rows.length * 4
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: err.message });
    }
});

// ---------- Rider Payment Endpoints ----------

// Get rider wallet balance and transactions
app.get('/api/riders/:riderId/wallet', async (req, res) => {
    const { riderId } = req.params;
    try {
        const walletResult = await pool.query(
            'SELECT * FROM rider_wallets WHERE rider_id = $1',
            [riderId]
        );
        
        const transactionsResult = await pool.query(
            `SELECT * FROM rider_transactions 
             WHERE rider_id = $1 
             ORDER BY created_at DESC 
             LIMIT 50`,
            [riderId]
        );
        
        const payoutsResult = await pool.query(
            `SELECT * FROM rider_payouts 
             WHERE rider_id = $1 AND status IN ('pending', 'processing')
             ORDER BY created_at DESC`,
            [riderId]
        );
        
        // Get rider details
        const riderResult = await pool.query(
            'SELECT id, name, phone, mobile_money_number, total_earned FROM riders WHERE id = $1',
            [riderId]
        );
        
        res.json({
            rider: riderResult.rows[0],
            wallet: walletResult.rows[0] || { balance: 0, pending_balance: 0, total_earned: 0 },
            transactions: transactionsResult.rows,
            pending_payouts: payoutsResult.rows
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Failed to fetch wallet data' });
    }
});

// Update rider payment settings
app.put('/api/riders/:riderId/payment-settings', async (req, res) => {
    const { riderId } = req.params;
    const { mobile_money_number } = req.body;
    
    try {
        await pool.query(
            `UPDATE riders 
             SET mobile_money_number = $1
             WHERE id = $2`,
            [mobile_money_number, riderId]
        );
        
        res.json({ success: true, message: 'Payment settings updated' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Failed to update payment settings' });
    }
});

// Request payout (rider initiates withdrawal)
app.post('/api/riders/:riderId/request-payout', async (req, res) => {
    const { riderId } = req.params;
    const { amount, mobile_number } = req.body;
    
    if (!amount || amount <= 0) {
        return res.status(400).json({ error: 'Invalid amount' });
    }
    
    const minPayout = 50; // Minimum ₵50 to withdraw
    if (amount < minPayout) {
        return res.status(400).json({ error: `Minimum payout amount is ₵${minPayout}` });
    }
    
    const client = await pool.connect();
    try {
        await client.query('BEGIN');
        
        // Get current balance
        const walletResult = await client.query(
            'SELECT balance FROM rider_wallets WHERE rider_id = $1 FOR UPDATE',
            [riderId]
        );
        
        const currentBalance = parseFloat(walletResult.rows[0]?.balance || 0);
        
        if (amount > currentBalance) {
            await client.query('ROLLBACK');
            return res.status(400).json({ error: 'Insufficient balance' });
        }
        
        // Get rider's mobile number if not provided
        let payoutNumber = mobile_number;
        if (!payoutNumber) {
            const riderResult = await client.query(
                'SELECT mobile_money_number FROM riders WHERE id = $1',
                [riderId]
            );
            payoutNumber = riderResult.rows[0]?.mobile_money_number;
        }
        
        // Create payout request
        const payoutResult = await client.query(
            `INSERT INTO rider_payouts (rider_id, amount, payment_method, mobile_number, status)
             VALUES ($1, $2, 'mobile_money', $3, 'pending')
             RETURNING *`,
            [riderId, amount, payoutNumber]
        );
        
        // Deduct from balance
        await client.query(
            'UPDATE rider_wallets SET balance = balance - $1 WHERE rider_id = $2',
            [amount, riderId]
        );
        
        // Record transaction
        await client.query(
            `INSERT INTO rider_transactions (rider_id, type, amount, description, status, reference)
             VALUES ($1, 'payout', $2, 'Payout request initiated', 'completed', $3)`,
            [riderId, -amount, `PO-${Date.now()}`]
        );
        
        await client.query('COMMIT');
        res.json({ success: true, payout: payoutResult.rows[0] });
    } catch (err) {
        await client.query('ROLLBACK');
        console.error(err);
        res.status(500).json({ error: 'Failed to request payout' });
    } finally {
        client.release();
    }
});

// Admin endpoint to process rider payouts
app.patch('/api/admin/rider-payouts/:payoutId/process', async (req, res) => {
    const { payoutId } = req.params;
    const { transaction_reference } = req.body;
    
    try {
        const result = await pool.query(
            `UPDATE rider_payouts 
             SET status = 'completed', 
                 processed_at = NOW(),
                 reference = COALESCE($1, reference)
             WHERE id = $2 AND status = 'pending'
             RETURNING *`,
            [transaction_reference, payoutId]
        );
        
        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Payout not found or already processed' });
        }
        
        res.json({ success: true, payout: result.rows[0] });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Failed to process payout' });
    }
});

// ---------- Additional Utility Endpoints ----------
app.get('/api/vendors/locations', async (req, res) => {
    try {
        const result = await pool.query(
            'SELECT id, name, location, latitude, longitude FROM vendors WHERE latitude IS NOT NULL AND longitude IS NOT NULL'
        );
        res.json(result.rows);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Failed to fetch vendor locations' });
    }
});

app.get('/api/orders/:orderId/tracking', async (req, res) => {
    const { orderId } = req.params;
    try {
        const result = await pool.query(`
            SELECT o.*, 
                   v.name as vendor_name, 
                   v.location as vendor_location,
                   v.latitude as vendor_latitude,
                   v.longitude as vendor_longitude,
                   o.delivery_latitude,
                   o.delivery_longitude,
                   r.name as rider_name,
                   r.phone as rider_phone
            FROM orders o
            JOIN vendors v ON o.vendor_id = v.id
            LEFT JOIN riders r ON o.rider_id = r.id
            WHERE o.id = $1
        `, [orderId]);
        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Order not found' });
        }
        res.json(result.rows[0]);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Failed to fetch order tracking info' });
    }
});

app.get('/api/orders/test-coordinates', async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT id, customer_name, delivery_latitude, delivery_longitude, status 
            FROM orders 
            WHERE delivery_latitude IS NOT NULL 
            LIMIT 10
        `);
        res.json({ count: result.rows.length, orders: result.rows });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: err.message });
    }
});

app.get('/api/health', (req, res) => {
    res.json({ status: 'ok' });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));