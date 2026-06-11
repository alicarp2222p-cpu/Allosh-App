const express = require('express');
const mysql = require('mysql2');
const cors = require('cors');
const path = require('path');
const multer = require('multer');
const fs = require('fs');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
require('dotenv').config();

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));

// مجلد الصور
const uploadDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir);
app.use('/uploads', express.static(uploadDir));

// رفع الصور
const storage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, uploadDir),
    filename: (req, file, cb) => cb(null, Date.now() + '-' + file.originalname)
});
const upload = multer({ storage });

// إعداد قاعدة البيانات (Pool + Promise)
const db = mysql.createPool({
    host: process.env.DB_HOST || 'localhost',
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD || '12345678',
    database: process.env.DB_NAME || 'vag_shop_saas',
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});
const promiseDb = db.promise();

// ========== دالة التحقق من JWT ==========
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'الوصول ممنوع، يرجى تسجيل الدخول' });
    jwt.verify(token, process.env.JWT_SECRET || 'fallback_secret', (err, user) => {
        if (err) return res.status(403).json({ error: 'توكن غير صالح' });
        req.user = user;
        next();
    });
};

// ========== إعداد البريد الإلكتروني ==========
const transporter = nodemailer.createTransport({
    host: 'smtp.gmail.com',
    port: 465,
    secure: true, // true for 465, false for other ports
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    }
});

async function sendVerificationEmail(email, token) {
    const verificationLink = `http://localhost:3000/api/verify-email?token=${token}&email=${encodeURIComponent(email)}`;
    const mailOptions = {
        from: process.env.EMAIL_USER,
        to: email,
        subject: 'تأكيد حسابك في نظام ALI للمبيعات',
        html: `
            <div dir="rtl" style="font-family: Arial; padding: 20px;">
                <h2>مرحباً بك في نظام ALI</h2>
                <p>شكراً لتسجيلك. يرجى النقر على الرابط أدناه لتأكيد حسابك:</p>
                <a href="${verificationLink}" style="background: #2c3e66; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">تأكيد الحساب</a>
                <p>إذا لم تقم بالتسجيل، يمكنك تجاهل هذه الرسالة.</p>
                <small>الرابط صالح لمدة 24 ساعة.</small>
            </div>
        `
    };
    await transporter.sendMail(mailOptions);
}

// ========== مسارات المصادقة ==========
app.post('/api/register', async (req, res) => {
    const { email, password, subscription_type } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'البريد الإلكتروني وكلمة المرور مطلوبان' });

    // التحقق من قوة كلمة المرور
    const digits = (password.match(/\d/g) || []).length;
    const lower = (password.match(/[a-z]/g) || []).length;
    const hasUpper = /[A-Z]/.test(password);
    if (digits < 4) return res.status(400).json({ error: 'كلمة المرور يجب أن تحتوي على 4 أرقام على الأقل' });
    if (lower < 3) return res.status(400).json({ error: 'كلمة المرور يجب أن تحتوي على 3 أحرف صغيرة على الأقل' });
    if (!hasUpper) return res.status(400).json({ error: 'كلمة المرور يجب أن تحتوي على حرف كبير واحد على الأقل' });

    try {
        const [existing] = await promiseDb.query('SELECT id FROM users WHERE email = ?', [email]);
        if (existing.length > 0) return res.status(400).json({ error: 'البريد الإلكتروني موجود مسبقاً' });

        const hashedPassword = await bcrypt.hash(password, 10);
        let subscription_end_date = null;
        if (subscription_type === 'monthly') subscription_end_date = new Date(Date.now() + 30*24*60*60*1000);
        else if (subscription_type === '6months') subscription_end_date = new Date(Date.now() + 180*24*60*60*1000);
        else if (subscription_type === 'yearly') subscription_end_date = new Date(Date.now() + 365*24*60*60*1000);

        await promiseDb.query(
            'INSERT INTO users (email, password_hash, subscription_type, subscription_end_date, is_verified) VALUES (?, ?, ?, ?, FALSE)',
            [email, hashedPassword, subscription_type || null, subscription_end_date]
        );

        const token = crypto.randomBytes(32).toString('hex');
        const expiresAt = new Date(Date.now() + 24*60*60*1000);
        await promiseDb.query('INSERT INTO email_verifications (email, token, expires_at) VALUES (?, ?, ?)', [email, token, expiresAt]);

        await sendVerificationEmail(email, token);
        res.json({ message: 'تم إنشاء الحساب بنجاح. يرجى التحقق من بريدك الإلكتروني لتفعيل الحساب.' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'البريد الإلكتروني وكلمة المرور مطلوبان' });
    try {
        const [rows] = await promiseDb.query('SELECT id, password_hash, subscription_end_date FROM users WHERE email = ? AND is_verified = TRUE', [email]);
        if (rows.length === 0) return res.status(401).json({ error: 'بيانات غير صحيحة أو الحساب غير مفعل' });
        const user = rows[0];
        const match = await bcrypt.compare(password, user.password_hash);
        if (!match) return res.status(401).json({ error: 'بيانات غير صحيحة' });
        const token = jwt.sign({ id: user.id, email }, process.env.JWT_SECRET || 'fallback_secret', { expiresIn: '30d' });
        res.json({ token, user: { id: user.id, email, subscription_end_date: user.subscription_end_date } });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.get('/api/verify-email', async (req, res) => {
    const { token, email } = req.query;
    if (!token || !email) return res.status(400).send('رابط غير صالح');
    try {
        const [rows] = await promiseDb.query('SELECT * FROM email_verifications WHERE email = ? AND token = ? AND expires_at > NOW()', [email, token]);
        if (rows.length === 0) return res.status(400).send('رابط التأكيد غير صالح أو منتهي الصلاحية');
        await promiseDb.query('UPDATE users SET is_verified = TRUE WHERE email = ?', [email]);
        await promiseDb.query('DELETE FROM email_verifications WHERE email = ?', [email]);
        res.send(`
            <html dir="rtl"><body style="text-align:center; padding:50px;">
                <h2 style="color:green;">✅ تم تأكيد حسابك بنجاح</h2>
                <p>يمكنك الآن <a href="/login.html">تسجيل الدخول</a> إلى نظام ALI للمبيعات.</p>
            </body></html>
        `);
    } catch (err) {
        console.error(err);
        res.status(500).send('حدث خطأ');
    }
});

app.get('/api/me', authenticateToken, async (req, res) => {
    try {
        const [rows] = await promiseDb.query('SELECT id, email, subscription_type, subscription_end_date FROM users WHERE id = ?', [req.user.id]);
        if (rows.length === 0) return res.status(404).json({ error: 'المستخدم غير موجود' });
        res.json(rows[0]);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ========== المنتجات (مع user_id) ==========
app.get('/api/products', authenticateToken, (req, res) => {
    db.query('SELECT * FROM products WHERE user_id = ? AND is_deleted = FALSE ORDER BY id DESC', [req.user.id], (err, results) => {
        if (err) return res.status(500).json(err);
        res.json(results);
    });
});

app.get('/api/products/deleted', authenticateToken, (req, res) => {
    db.query('SELECT * FROM products WHERE user_id = ? AND is_deleted = TRUE ORDER BY id DESC', [req.user.id], (err, results) => {
        if (err) return res.status(500).json(err);
        res.json(results);
    });
});

app.get('/api/products/:id', authenticateToken, (req, res) => {
    db.query('SELECT * FROM products WHERE id = ? AND user_id = ?', [req.params.id, req.user.id], (err, results) => {
        if (err) return res.status(500).json(err);
        if (results.length === 0) return res.status(404).json({ error: 'المنتج غير موجود' });
        res.json(results[0]);
    });
});

app.post('/api/products', authenticateToken, upload.single('image'), (req, res) => {
    const { name, part_number, price, quantity, engine_model } = req.body;
    const image_url = req.file ? `/uploads/${req.file.filename}` : null;
    db.query('INSERT INTO products (user_id, name, part_number, price, quantity, engine_model, image_url, is_deleted) VALUES (?, ?, ?, ?, ?, ?, ?, FALSE)',
        [req.user.id, name, part_number, price, quantity || 0, engine_model || null, image_url], (err, result) => {
            if (err) return res.status(500).json(err);
            res.json({ id: result.insertId });
        });
});

app.put('/api/products/:id', authenticateToken, upload.single('image'), (req, res) => {
    const { name, part_number, price, quantity, engine_model } = req.body;
    let query = 'UPDATE products SET name=?, part_number=?, price=?, quantity=?, engine_model=?';
    let params = [name, part_number, price, quantity || 0, engine_model || null];
    if (req.file) {
        query += ', image_url=?';
        params.push(`/uploads/${req.file.filename}`);
    }
    query += ' WHERE id=? AND user_id=?';
    params.push(req.params.id, req.user.id);
    db.query(query, params, (err) => {
        if (err) return res.status(500).json(err);
        res.json({ message: 'تم التعديل' });
    });
});

app.delete('/api/products/:id', authenticateToken, (req, res) => {
    db.query('UPDATE products SET is_deleted = TRUE WHERE id = ? AND user_id = ?', [req.params.id, req.user.id], (err, result) => {
        if (err) return res.status(500).json(err);
        if (result.affectedRows === 0) return res.status(404).json({ error: 'المنتج غير موجود' });
        res.json({ message: '✅ تم حذف المنتج' });
    });
});

app.put('/api/products/restore/:id', authenticateToken, (req, res) => {
    db.query('UPDATE products SET is_deleted = FALSE WHERE id = ? AND user_id = ?', [req.params.id, req.user.id], (err) => {
        if (err) return res.status(500).json(err);
        res.json({ message: '✅ تم استعادة المنتج' });
    });
});

// ========== العملاء (مع user_id) ==========
app.get('/api/customers', authenticateToken, (req, res) => {
    db.query('SELECT * FROM customers WHERE user_id = ? ORDER BY id DESC', [req.user.id], (err, results) => {
        if (err) return res.status(500).json(err);
        res.json(results);
    });
});

app.get('/api/customers/:id', authenticateToken, (req, res) => {
    db.query('SELECT * FROM customers WHERE id = ? AND user_id = ?', [req.params.id, req.user.id], (err, results) => {
        if (err) return res.status(500).json(err);
        res.json(results[0]);
    });
});

app.post('/api/customers', authenticateToken, (req, res) => {
    const { name, phone } = req.body;
    if (!name) return res.status(400).json({ error: 'الاسم مطلوب' });
    db.query('INSERT INTO customers (user_id, name, phone) VALUES (?, ?, ?)', [req.user.id, name, phone || null], (err, result) => {
        if (err) return res.status(500).json(err);
        res.json({ id: result.insertId });
    });
});

// ========== المبيعات (مع user_id) ==========
app.get('/api/sales', authenticateToken, (req, res) => {
    const query = `
        SELECT 
            s.id,
            s.sale_date,
            s.total_amount,
            s.paid_amount,
            s.remaining_amount,
            c.name as customer_name,
            COALESCE(p.name, 'منتج محذوف') as product_name,
            COALESCE(p.part_number, '---') as part_number,
            COALESCE(p.image_url, 'https://via.placeholder.com/40x40?text=No+Image') as image_url,
            COALESCE(si.quantity, 1) as quantity,
            COALESCE(si.price_at_sale, s.total_amount / COALESCE(si.quantity, 1)) as price_at_sale
        FROM sales s
        JOIN customers c ON s.customer_id = c.id
        LEFT JOIN sale_items si ON s.id = si.sale_id
        LEFT JOIN products p ON si.product_id = p.id
        WHERE s.user_id = ?
        ORDER BY s.sale_date DESC
    `;
    db.query(query, [req.user.id], (err, results) => {
        if (err) return res.status(500).json(err);
        res.json(results);
    });
});

app.get('/api/all-sales-invoices', authenticateToken, (req, res) => {
    const query = `
        SELECT 
            s.id as sale_id,
            s.sale_date,
            s.total_amount,
            s.paid_amount,
            s.remaining_amount,
            c.name as customer_name,
            si.id as item_id,
            si.quantity,
            si.price_at_sale,
            p.id as product_id,
            p.name as product_name,
            p.part_number,
            p.image_url
        FROM sales s
        JOIN customers c ON s.customer_id = c.id
        LEFT JOIN sale_items si ON s.id = si.sale_id
        LEFT JOIN products p ON si.product_id = p.id
        WHERE s.user_id = ?
        ORDER BY s.sale_date DESC, si.id ASC
    `;
    db.query(query, [req.user.id], (err, results) => {
        if (err) return res.status(500).json(err);
        res.json(results);
    });
});

app.get('/api/sales/customer/:id', authenticateToken, (req, res) => {
    const customerId = req.params.id;
    const query = `
        SELECT 
            s.id as sale_id,
            s.sale_date,
            s.total_amount,
            s.paid_amount,
            s.remaining_amount,
            si.id as item_id,
            si.quantity,
            si.price_at_sale,
            p.id as product_id,
            p.name as product_name,
            p.part_number,
            p.image_url
        FROM sales s
        LEFT JOIN sale_items si ON s.id = si.sale_id
        LEFT JOIN products p ON si.product_id = p.id
        WHERE s.customer_id = ? AND s.user_id = ?
        ORDER BY s.sale_date DESC, si.id ASC
    `;
    db.query(query, [customerId, req.user.id], (err, results) => {
        if (err) return res.status(500).json(err);
        res.json(results);
    });
});

app.post('/api/sales', authenticateToken, async (req, res) => {
    const { customer_id, items, paid_amount } = req.body;
    if (!customer_id || !items || items.length === 0) {
        return res.status(400).json({ error: 'البيانات غير مكتملة' });
    }
    try {
        let totalAmount = 0;
        const productDetails = [];
        for (const item of items) {
            const [product] = await promiseDb.query('SELECT price, quantity FROM products WHERE id = ? AND user_id = ?', [item.product_id, req.user.id]);
            if (!product.length) return res.status(404).json({ error: 'منتج غير موجود' });
            const prod = product[0];
            if (prod.quantity < item.quantity) return res.status(400).json({ error: 'الكمية غير متوفرة' });
            totalAmount += prod.price * item.quantity;
            productDetails.push({ ...item, price_at_sale: prod.price, current_quantity: prod.quantity });
        }
        const remainingAmount = totalAmount - paid_amount;
        const [saleResult] = await promiseDb.query('INSERT INTO sales (user_id, customer_id, total_amount, paid_amount, remaining_amount) VALUES (?, ?, ?, ?, ?)',
            [req.user.id, customer_id, totalAmount, paid_amount, remainingAmount]);
        const saleId = saleResult.insertId;
        for (const item of productDetails) {
            await promiseDb.query('INSERT INTO sale_items (user_id, sale_id, product_id, quantity, price_at_sale) VALUES (?, ?, ?, ?, ?)',
                [req.user.id, saleId, item.product_id, item.quantity, item.price_at_sale]);
            await promiseDb.query('UPDATE products SET quantity = quantity - ? WHERE id = ? AND user_id = ?', [item.quantity, item.product_id, req.user.id]);
        }
        const [customer] = await promiseDb.query('SELECT total_debt, total_paid FROM customers WHERE id = ? AND user_id = ?', [customer_id, req.user.id]);
        if (customer.length) {
            await promiseDb.query('UPDATE customers SET total_debt = total_debt + ?, total_paid = total_paid + ? WHERE id = ? AND user_id = ?',
                [remainingAmount, paid_amount, customer_id, req.user.id]);
        }
        res.json({ id: saleId, message: 'تمت عملية البيع' });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: error.message });
    }
});

app.delete('/api/sales/item/:id', authenticateToken, (req, res) => {
    const itemId = req.params.id;
    db.query('SELECT sale_id, quantity, price_at_sale FROM sale_items WHERE id = ? AND user_id = ?', [itemId, req.user.id], (err, item) => {
        if (err) return res.status(500).json(err);
        if (!item || item.length === 0) return res.status(404).json({ error: 'العنصر غير موجود' });
        const saleId = item[0].sale_id;
        db.query('DELETE FROM sale_items WHERE id = ? AND user_id = ?', [itemId, req.user.id], (err, result) => {
            if (err) return res.status(500).json(err);
            if (result.affectedRows === 0) return res.status(404).json({ error: 'العنصر غير موجود' });
            db.query('SELECT SUM(quantity * price_at_sale) as new_total FROM sale_items WHERE sale_id = ? AND user_id = ?', [saleId, req.user.id], (err, sumResult) => {
                const newTotal = sumResult[0].new_total || 0;
                db.query('SELECT paid_amount FROM sales WHERE id = ? AND user_id = ?', [saleId, req.user.id], (err, saleData) => {
                    if (err) return;
                    const paidAmount = saleData[0].paid_amount;
                    const newRemaining = newTotal - paidAmount;
                    db.query('UPDATE sales SET total_amount = ?, remaining_amount = ? WHERE id = ? AND user_id = ?',
                        [newTotal, newRemaining < 0 ? 0 : newRemaining, saleId, req.user.id], (err) => {
                            if (err) console.error('خطأ في تحديث الفاتورة:', err);
                        });
                });
            });
            res.json({ message: '✅ تم حذف المنتج من الفاتورة' });
        });
    });
});

app.delete('/api/sales/:id', authenticateToken, async (req, res) => {
    const saleId = req.params.id;
    try {
        const [items] = await promiseDb.query('SELECT product_id, quantity FROM sale_items WHERE sale_id = ? AND user_id = ?', [saleId, req.user.id]);
        for (let item of items) {
            await promiseDb.query('UPDATE products SET quantity = quantity + ? WHERE id = ? AND user_id = ?', [item.quantity, item.product_id, req.user.id]);
        }
        await promiseDb.query('DELETE FROM sale_items WHERE sale_id = ? AND user_id = ?', [saleId, req.user.id]);
        const [result] = await promiseDb.query('DELETE FROM sales WHERE id = ? AND user_id = ?', [saleId, req.user.id]);
        if (result.affectedRows === 0) return res.status(404).json({ error: 'الفاتورة غير موجودة' });
        res.json({ message: 'تم حذف الفاتورة وإعادة الكميات للمخزون' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: err.message });
    }
});

app.put('/api/sales/:id', authenticateToken, async (req, res) => {
    const saleId = req.params.id;
    const { paid_amount } = req.body;
    if (paid_amount === undefined) return res.status(400).json({ error: 'المبلغ المدفوع مطلوب' });
    try {
        const [sale] = await promiseDb.query('SELECT total_amount FROM sales WHERE id = ? AND user_id = ?', [saleId, req.user.id]);
        if (sale.length === 0) return res.status(404).json({ error: 'الفاتورة غير موجودة' });
        const total = sale[0].total_amount;
        const newRemaining = total - paid_amount;
        await promiseDb.query('UPDATE sales SET paid_amount = ?, remaining_amount = ? WHERE id = ? AND user_id = ?', [paid_amount, newRemaining < 0 ? 0 : newRemaining, saleId, req.user.id]);
        res.json({ message: 'تم تحديث المبلغ المدفوع' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ========== الشيكات (مع user_id) ==========
app.get('/api/checks', authenticateToken, (req, res) => {
    db.query('SELECT * FROM checks WHERE user_id = ? ORDER BY due_date ASC', [req.user.id], (err, results) => {
        if (err) return res.status(500).json(err);
        res.json(results);
    });
});

app.post('/api/checks', authenticateToken, (req, res) => {
    const { sale_id, amount, due_date, is_cashed } = req.body;
    if (!sale_id || !amount) return res.status(400).json({ error: 'البيانات غير مكتملة' });
    db.query('INSERT INTO checks (user_id, sale_id, amount, due_date, is_cashed) VALUES (?, ?, ?, ?, ?)',
        [req.user.id, sale_id, amount, due_date || null, is_cashed || false], (err, result) => {
            if (err) return res.status(500).json(err);
            res.json({ id: result.insertId });
        });
});

app.put('/api/checks/:id/cash', authenticateToken, (req, res) => {
    db.query('UPDATE checks SET is_cashed = TRUE WHERE id = ? AND user_id = ?', [req.params.id, req.user.id], (err) => {
        if (err) return res.status(500).json(err);
        res.json({ message: 'تم صرف الشيك' });
    });
});

// ========== الصفحات الثابتة ==========
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});
app.get('/customers.html', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'customers.html'));
});
app.get('/customer-sales.html', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'customer-sales.html'));
});
app.get('/login.html', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'login.html'));
});
app.get('/deleted-products.html', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'deleted-products.html'));
});
app.get('/all-checks.html', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'all-checks.html'));
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`🚀 الخادم شغال على http://localhost:${PORT}`);
});