// main.js - Electron main process
const { app, BrowserWindow, ipcMain } = require('electron');
const path = require('path');
const { exec } = require('child_process');
const os = require('os');

let mainWindow;

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1200,
    height: 800,
    webPreferences: {
      nodeIntegration: true,
      contextIsolation: false
    }
  });

  mainWindow.loadFile('index.html');
  mainWindow.webContents.openDevTools(); // Helpful during development
}

app.whenReady().then(createWindow);

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') app.quit();
});

app.on('activate', () => {
  if (BrowserWindow.getAllWindows().length === 0) createWindow();
});

// Handle network scan requests
ipcMain.on('scan-network', (event) => {
  // Get active connections
  const platform = process.platform;
  let command = '';
  
  if (platform === 'win32') {
    command = 'netstat -n';
  } else { // Linux and macOS
    command = 'netstat -n | grep ESTABLISHED';
  }

  exec(command, (error, stdout, stderr) => {
    if (error) {
      event.reply('network-scan-error', error.message);
      return;
    }
    
    // Parse connections
    const connections = parseConnections(stdout, platform);
    event.reply('active-connections', connections);
    
    // Start traceroute for each unique IP
    const uniqueIps = [...new Set(connections.map(conn => conn.remoteIp))];
    uniqueIps.forEach(ip => {
      if (ip !== '127.0.0.1' && !ip.startsWith('192.168.') && !ip.startsWith('10.') && !ip.startsWith('172.')) {
        performTraceroute(ip, event);
      }
    });
  });
});

function parseConnections(output, platform) {
  const connections = [];
  const lines = output.split('\n');
  
  lines.forEach(line => {
    if (platform === 'win32') {
      // Windows netstat parsing
      if (line.includes('TCP') || line.includes('UDP')) {
        const parts = line.trim().split(/\s+/);
        if (parts.length >= 3) {
          const localParts = parts[1].split(':');
          const remoteParts = parts[2].split(':');
          
          connections.push({
            protocol: parts[0],
            localIp: localParts[0],
            localPort: localParts[1],
            remoteIp: remoteParts[0],
            remotePort: remoteParts[1],
            state: parts[3] || 'UNKNOWN'
          });
        }
      }
    } else {
      // Linux/macOS netstat parsing
      if (line.includes('ESTABLISHED')) {
        const parts = line.trim().split(/\s+/);
        if (parts.length >= 5) {
          const localParts = parts[3].split(':');
          const remoteParts = parts[4].split(':');
          
          connections.push({
            protocol: parts[0],
            localIp: localParts[0],
            localPort: localParts[localParts.length - 1],
            remoteIp: remoteParts[0],
            remotePort: remoteParts[remoteParts.length - 1],
            state: parts[5] || 'UNKNOWN'
          });
        }
      }
    }
  });
  
  return connections;
}

function performTraceroute(ip, event) {
  const command = process.platform === 'win32' ? `tracert -d ${ip}` : `traceroute -n ${ip}`;
  
  exec(command, (error, stdout, stderr) => {
    if (error && !stdout) {
      event.reply('traceroute-error', { ip, error: error.message });
      return;
    }
    
    const hops = parseTraceroute(stdout, process.platform, ip);
    event.reply('traceroute-result', { ip, hops });
  });
}

function parseTraceroute(output, platform, targetIp) {
  const hops = [];
  const lines = output.split('\n');
  
  lines.forEach(line => {
    if (platform === 'win32') {
      // Windows tracert parsing
      const match = line.match(/^\s*(\d+)\s+(\d+)\s+ms\s+(\d+)\s+ms\s+(\d+)\s+ms\s+(\S+)/);
      if (match) {
        hops.push({
          hop: parseInt(match[1]),
          ip: match[5],
          latency: (parseInt(match[2]) + parseInt(match[3]) + parseInt(match[4])) / 3
        });
      }
    } else {
      // Linux/macOS traceroute parsing
      const match = line.match(/^\s*(\d+)\s+(\S+)/);
      if (match && match[2] !== '*') {
        const latencyMatches = line.match(/(\d+\.\d+)\s*ms/g);
        const avgLatency = latencyMatches 
          ? latencyMatches.map(l => parseFloat(l)).reduce((a, b) => a + b, 0) / latencyMatches.length 
          : 0;
        
        hops.push({
          hop: parseInt(match[1]),
          ip: match[2],
          latency: avgLatency
        });
      }
    }
  });
  
  // Add target as final hop if not already included
  if (hops.length > 0 && hops[hops.length - 1].ip !== targetIp) {
    hops.push({
      hop: hops.length + 1,
      ip: targetIp,
      latency: 0
    });
  }
  
  return hops;
}