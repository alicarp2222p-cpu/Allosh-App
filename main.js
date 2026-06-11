// main.js
const { app, BrowserWindow } = require('electron');
const { spawn } = require('child_process');
const path = require('path');
const ngrok = require('ngrok');

let mainWindow;
let serverProcess;
let ngrokUrl = null;

async function startNgrok() {
    try {
        // إذا كان لديك حساب في ngrok، يمكنك إضافة authtoken هنا لرابط دائم
        // ngrokUrl = await ngrok.connect({ addr: 3000, authtoken: 'YOUR_AUTH_TOKEN' });
        
        ngrokUrl = await ngrok.connect(3000);
        console.log(`✅ Ngrok tunnel is active! Public URL: ${ngrokUrl}`);
        
        // عرض الرابط في نافذة التطبيق (اختياري)
        if (mainWindow) {
            mainWindow.webContents.send('ngrok-url', ngrokUrl);
        }
    } catch (err) {
        console.error('❌ Error starting ngrok:', err);
    }
}

function createWindow() {
    // تشغيل خادم Node.js
    serverProcess = spawn('node', ['server.js'], {
        cwd: path.join(__dirname, '/'),
        stdio: 'pipe',
        shell: true,
        detached: false
    });

    serverProcess.stdout.on('data', (data) => {
        console.log(`[SERVER LOG]: ${data}`);
    });
    serverProcess.stderr.on('data', (data) => {
        console.error(`[SERVER ERROR]: ${data}`);
    });

    // إنشاء نافذة التطبيق
    mainWindow = new BrowserWindow({
        width: 1400,
        height: 900,
        webPreferences: {
            nodeIntegration: false,
            contextIsolation: true,
            preload: path.join(__dirname, 'preload.js') // سننشئ هذا الملف لاحقًا
        },
        icon: path.join(__dirname, 'public', '1000117025.png'),
    });

    // انتظر 3 ثوانٍ ثم افتح الصفحة المحلية
    setTimeout(() => {
        mainWindow.loadURL('http://localhost:3000');
    }, 3000);

    // بدء تشغيل ngrok بعد تجهيز النافذة
    startNgrok();

    mainWindow.on('closed', () => {
        mainWindow = null;
    });
}

// منع تشغيل أكثر من نسخة
const gotTheLock = app.requestSingleInstanceLock();
if (!gotTheLock) {
    app.quit();
} else {
    app.on('second-instance', (event, commandLine, workingDirectory) => {
        if (mainWindow) {
            if (mainWindow.isMinimized()) mainWindow.restore();
            mainWindow.focus();
        }
    });
    app.on('ready', createWindow);
}

// تنظيف العمليات عند الإغلاق
app.on('will-quit', () => {
    if (serverProcess) serverProcess.kill();
    if (ngrokUrl) ngrok.kill().catch(e => console.error('Ngrok kill error', e));
});