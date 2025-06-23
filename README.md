环境变量设置
  | 变量名        | 是否必须 | 默认值 | 备注 |
  | ------------ | ------ | ------ | ------ |
  | UPLOAD_URL   | 否 | 填写部署Merge-sub项目后的首页地址  |订阅上传地址,例如：https://merge.serv00.net|
  | PROJECT_URL  | 否 | https://www.google.com     |项目分配的域名，用于自动访问保活|
  | AUTO_ACCESS  | 否 |  false |false关闭自动访问保活，true开启，需同时填写PROJECT_URL变量|
  | PORT         | 否 |  3000  |http服务监听端口     |
  | CLOUD_PORT   | 否 |  8001  |Cloudflare隧道端口，固定隧道token需和cloudflare后台设置的一致|
  | KEY          | 否 | 161fc0b2-cfa3-4053-8d51-20aeee66c2dd|用户的唯一标识符(UUID),使用悟空v1在不同的平台部署需要修改|
  | WUKONG_SERVER| 否 |        | 悟空面板域名，v1：nz.aaa.com:8008  v0: nz.aaa.com  |
  | WUKONG_PORT  | 否 |        | 悟空v1没有此项，悟空v0端口为{443,8443,2096,2087,2083,2053}其中之一时，开启tls|
  | WUKONG_KEY   | 否 |        | 悟空v1 或v0 密钥                 |
  | CLOUD_DOMAIN | 否 |        | Cloudflare固定隧道域名                  |
  | CLOUD_TOKEN  | 否 |        | Cloudflare固定隧道json或token           |
  | CFIP         | 否 |skk.moe | 节点优选域名或ip                   |
  | CFPORT       | 否 |  443   |节点端口                           |
  | NAME         | 否 |  Vl   | 节点名称前缀，例如：Koyeb Fly        |
  | FILE_PATH    | 否 |  tmp   | 运行目录,节点存放路径                |
  | SUB_PATH     | 否 |  sub123   | 节点订阅路径                       |