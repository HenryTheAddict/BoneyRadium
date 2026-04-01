const { app, BrowserWindow, nativeImage } = require('electron');
const path = require('path');

let mainWindow;

app.setName('BoneyRadium');
app.name = 'BoneyRadium';
process.title = 'BoneyRadium';

const appIconPath = path.join(__dirname, 'favicon.png');

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1280,
    height: 720,
    fullscreen: true,
    autoHideMenuBar: true,
    title: 'BoneyRadium',
    backgroundColor: '#f2f5fb',
    webPreferences: {
      nodeIntegration: false,
      contextIsolation: true,
      sandbox: true,
      webSecurity: true
    },
    icon: appIconPath
  });

  mainWindow.loadFile('index.html');
  mainWindow.setTitle('BoneyRadium');
  mainWindow.setMenuBarVisibility(false);

  mainWindow.on('closed', function () {
    mainWindow = null;
  });
}

app.whenReady().then(() => {
  app.setAboutPanelOptions({
    applicationName: 'BoneyRadium',
    applicationVersion: app.getVersion()
  });
  if (process.platform === 'darwin' && app.dock) {
    const dockIcon = nativeImage.createFromPath(appIconPath);
    if (!dockIcon.isEmpty()) {
      app.dock.setIcon(dockIcon);
    }
  }
  createWindow();
});

app.on('window-all-closed', function () {
  if (process.platform !== 'darwin') app.quit();
});

app.on('activate', function () {
  if (mainWindow === null) createWindow();
});
