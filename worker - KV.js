// Configuration (可以通过管理员界面覆盖)
const CONFIG = {
  ADMIN_USERNAME: "default-admin-username", // 默认管理员用户名
  ADMIN_PASSWORD: "default-admin-password", // 默认管理员密码
  API_KEY: "default-api-key", // 用于代理认证的默认API密钥
  PAGE_SIZE: 12, // 主界面每页显示的密钥数量
  ACCESS_CONTROL: "open", // 访问控制模式: "open", "restricted", "private"
  GUEST_PASSWORD: "guest_password", // 访客密码，用于restricted模式
};

addEventListener("fetch", event => {
  event.respondWith(handleRequest(event.request));
});

async function handleRequest(request) {
  const url = new URL(request.url);
  const path = url.pathname;

  // 处理预检请求
  if (request.method === "OPTIONS") {
    return new Response(null, {
        status: 204,
        headers: {
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
            "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Requested-With",
            "Access-Control-Max-Age": "86400", // 24小时缓存预检请求结果
            "Access-Control-Allow-Credentials": "true"
        }
    });
  }

  // 管理员界面路由
  if (path === "/admin" || path === "/admin/") {
    return handleAdminInterface(request);
  }
  
  if (path.startsWith("/admin/api/")) {
    return handleAdminAPI(request, path.replace("/admin/api/", ""));
  }

  // API代理路由 - 转发请求到siliconflow API并进行负载均衡
  if (path.startsWith("/v1/")) {
    return handleAPIProxy(request, path);
  }

  // 主界面
  return handleMainInterface(request);
}

// 访客认证中间件
async function authenticateGuest(request) {
  const config = await getConfiguration();
  
  // 如果是完全开放的，直接通过认证
  if (config.accessControl === "open") {
    return true;
  }
  
  // 如果是完全私有的，仅允许管理员访问，检查管理员认证
  if (config.accessControl === "private") {
    return await authenticateAdmin(request);
  }
  
  // 部分开放模式，检查访客密码
  if (config.accessControl === "restricted") {
    if (!config.guestPassword) {
      return false;
    }

    // 获取Authorization头
    const authHeader = request.headers.get("Authorization");
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return false;
    }

    // 检查访客token
    const guestToken = authHeader.replace("Bearer ", "").trim();
    
    // 验证访客密码
    return guestToken === config.guestPassword;
  }
  
  // 默认拒绝访问
  return false;
}

// 管理员认证中间件
async function authenticateAdmin(request) {
  // 尝试获取存储的管理员凭据
  const storedUsername = await SILICONFLOW_KEY.get("admin_username") || CONFIG.ADMIN_USERNAME;
  const storedPassword = await SILICONFLOW_KEY.get("admin_password") || CONFIG.ADMIN_PASSWORD;

  if (!storedUsername || !storedPassword) {
    return false;
  }
  
  // 获取Authorization头
  const authHeader = request.headers.get("Authorization");
  if (!authHeader || !authHeader.startsWith("Basic ")) {
    return false;
  }

  // 解码并验证凭据
  const encodedCredentials = authHeader.split(" ")[1];
  const decodedCredentials = atob(encodedCredentials);
  const [username, password] = decodedCredentials.split(":");
  
  return username === storedUsername && password === storedPassword;
}

// 处理管理员界面
async function handleAdminInterface(request) {
  const isAuthenticated = await authenticateAdmin(request);
  
  if (!isAuthenticated) {
    return new Response("Unauthorized", {
      status: 401,
      headers: {
        "WWW-Authenticate": "Basic realm=\"Admin Interface\""
      }
    });
  }
  
  return new Response(adminHtmlContent, {
    headers: { "Content-Type": "text/html;charset=UTF-8" }
  });
}

// 为每个密钥单独更新检查时间，避免批量请求出现流锁定问题
async function updateKeyLastCheckTime(key, lastUpdated) {
  try {
    // 获取所有密钥
    const keys = await getAllKeys();
    const keyIndex = keys.findIndex(k => k.key === key);
    
    if (keyIndex !== -1) {
      // 更新最后检测时间
      keys[keyIndex].lastUpdated = lastUpdated;
      // 保存更改
      await SILICONFLOW_KEY.put("keys", JSON.stringify(keys));
      return true;
    }
    return false;
  } catch (error) {
    console.error(`更新密钥 ${key} 时间失败:`, error);
    return false;
  }
}

function sanitizeConfigForAdmin(config) {
  return {
    apiKey: config.apiKey || "",
    adminUsername: config.adminUsername || "",
    pageSize: Number.parseInt(config.pageSize, 10) || CONFIG.PAGE_SIZE,
    accessControl: config.accessControl || CONFIG.ACCESS_CONTROL,
    hasGuestPassword: Boolean(config.guestPassword),
  };
}

// 处理管理员API端点
async function handleAdminAPI(request, endpoint) {
  const jsonHeaders = { "Content-Type": "application/json" };

  // 公开端点
  if (endpoint === "pageSize") {
    if (request.method !== "GET") {
      return new Response(JSON.stringify({ success: false, message: "Method Not Allowed" }), {
        status: 405,
        headers: jsonHeaders
      });
    }

    const pageSize = parseInt(await SILICONFLOW_KEY.get("page_size") || CONFIG.PAGE_SIZE, 10);
    return new Response(JSON.stringify({ success: true, data: pageSize }), {
      headers: jsonHeaders
    });
  }

  if (endpoint === "access-control") {
    if (request.method !== "GET") {
      return new Response(JSON.stringify({ success: false, message: "Method Not Allowed" }), {
        status: 405,
        headers: jsonHeaders
      });
    }

    const config = await getConfiguration();
    return new Response(JSON.stringify({
      success: true,
      data: { accessControl: config.accessControl }
    }), { headers: jsonHeaders });
  }

  if (endpoint === "verify-guest") {
    if (request.method !== "POST") {
      return new Response(JSON.stringify({ success: false, message: "Method Not Allowed" }), {
        status: 405,
        headers: jsonHeaders
      });
    }

    const data = await request.json().catch(() => null);
    if (!data || typeof data.password !== "string") {
      return new Response(JSON.stringify({ success: false, message: "请求格式错误" }), {
        status: 400,
        headers: jsonHeaders
      });
    }

    const config = await getConfiguration();
    if (config.accessControl !== "restricted") {
      return new Response(JSON.stringify({
        success: false,
        message: "当前模式不需要访客认证"
      }), { headers: jsonHeaders });
    }

    if (!config.guestPassword) {
      return new Response(JSON.stringify({
        success: false,
        message: "访客认证未配置"
      }), {
        status: 503,
        headers: jsonHeaders
      });
    }

    if (data.password === config.guestPassword) {
      return new Response(JSON.stringify({
        success: true,
        token: config.guestPassword
      }), { headers: jsonHeaders });
    }

    return new Response(JSON.stringify({
      success: false,
      message: "访客密码不正确"
    }), {
      status: 401,
      headers: jsonHeaders
    });
  }

  // 统一鉴权闸门
  const isAdmin = await authenticateAdmin(request);
  const isGuest = !isAdmin && await authenticateGuest(request);
  const guestReadOnlyKeys = isGuest && request.method === "GET" && endpoint === "keys";

  if (!isAdmin && !guestReadOnlyKeys) {
    const config = await getConfiguration();
    return new Response(JSON.stringify({
      success: false,
      message: "需要管理员权限",
      requireAuth: true,
      accessControl: config.accessControl
    }), {
      status: 401,
      headers: jsonHeaders
    });
  }

  try {
    if (request.method === "GET") {
      if (endpoint === "keys") {
        const keys = await getAllKeys();
        return new Response(JSON.stringify({ success: true, data: keys }), {
          headers: jsonHeaders
        });
      }

      if (endpoint === "config") {
        const config = await getConfiguration();
        return new Response(JSON.stringify({
          success: true,
          data: sanitizeConfigForAdmin(config)
        }), { headers: jsonHeaders });
      }
    } else if (request.method === "POST") {
      const data = await request.json().catch(() => null);
      if (!data || typeof data !== "object") {
        return new Response(JSON.stringify({ success: false, message: "请求格式错误" }), {
          status: 400,
          headers: jsonHeaders
        });
      }

      if (endpoint === "add-key") {
        if (typeof data.key !== "string" || !data.key.trim()) {
          return new Response(JSON.stringify({ success: false, message: "Key is required" }), {
            status: 400,
            headers: jsonHeaders
          });
        }

        await addKey(data.key.trim(), data.balance || 0);
        return new Response(JSON.stringify({ success: true }), { headers: jsonHeaders });
      }

      if (endpoint === "add-keys-bulk") {
        if (typeof data.keys !== "string" || !data.keys.trim()) {
          return new Response(JSON.stringify({ success: false, message: "Keys are required" }), {
            status: 400,
            headers: jsonHeaders
          });
        }

        const keys = data.keys.split("\n").map(k => k.trim()).filter(Boolean);
        await addKeys(keys, 0);

        return new Response(JSON.stringify({
          success: true,
          count: keys.length,
          addedKeys: keys,
          autoCheck: true
        }), { headers: jsonHeaders });
      }

      if (endpoint === "delete-key") {
        if (typeof data.key !== "string" || !data.key.trim()) {
          return new Response(JSON.stringify({ success: false, message: "Key is required" }), {
            status: 400,
            headers: jsonHeaders
          });
        }

        await deleteKey(data.key.trim());
        return new Response(JSON.stringify({ success: true }), { headers: jsonHeaders });
      }

      if (endpoint === "update-config") {
        const nextConfig = {};
        const validModes = new Set(["open", "restricted", "private"]);

        if (Object.prototype.hasOwnProperty.call(data, "apiKey")) {
          if (typeof data.apiKey !== "string" || !data.apiKey.trim()) {
            return new Response(JSON.stringify({ success: false, message: "apiKey 不能为空" }), {
              status: 400,
              headers: jsonHeaders
            });
          }
          nextConfig.apiKey = data.apiKey.trim();
        }

        if (Object.prototype.hasOwnProperty.call(data, "adminUsername")) {
          if (typeof data.adminUsername !== "string" || !data.adminUsername.trim()) {
            return new Response(JSON.stringify({ success: false, message: "adminUsername 不能为空" }), {
              status: 400,
              headers: jsonHeaders
            });
          }
          nextConfig.adminUsername = data.adminUsername.trim();
        }

        if (Object.prototype.hasOwnProperty.call(data, "adminPassword")) {
          if (typeof data.adminPassword !== "string" || !data.adminPassword.trim()) {
            return new Response(JSON.stringify({ success: false, message: "adminPassword 不能为空" }), {
              status: 400,
              headers: jsonHeaders
            });
          }
          nextConfig.adminPassword = data.adminPassword.trim();
        }

        if (Object.prototype.hasOwnProperty.call(data, "pageSize")) {
          const pageSize = Number.parseInt(data.pageSize, 10);
          if (!Number.isInteger(pageSize) || pageSize <= 0) {
            return new Response(JSON.stringify({ success: false, message: "pageSize 必须是正整数" }), {
              status: 400,
              headers: jsonHeaders
            });
          }
          nextConfig.pageSize = pageSize;
        }

        if (Object.prototype.hasOwnProperty.call(data, "accessControl")) {
          if (typeof data.accessControl !== "string" || !validModes.has(data.accessControl)) {
            return new Response(JSON.stringify({ success: false, message: "accessControl 非法" }), {
              status: 400,
              headers: jsonHeaders
            });
          }
          nextConfig.accessControl = data.accessControl;
        }

        if (Object.prototype.hasOwnProperty.call(data, "guestPassword")) {
          if (typeof data.guestPassword !== "string") {
            return new Response(JSON.stringify({ success: false, message: "guestPassword 非法" }), {
              status: 400,
              headers: jsonHeaders
            });
          }
          nextConfig.guestPassword = data.guestPassword.trim();
        }

        if (nextConfig.accessControl === "restricted") {
          const hasNewGuestPassword = Object.prototype.hasOwnProperty.call(nextConfig, "guestPassword");
          if (hasNewGuestPassword && !nextConfig.guestPassword) {
            return new Response(JSON.stringify({ success: false, message: "restricted 模式必须设置访客密码" }), {
              status: 400,
              headers: jsonHeaders
            });
          }

          if (!hasNewGuestPassword) {
            const currentConfig = await getConfiguration();
            if (!currentConfig.guestPassword) {
              return new Response(JSON.stringify({ success: false, message: "restricted 模式必须设置访客密码" }), {
                status: 400,
                headers: jsonHeaders
              });
            }
          }
        }

        if (Object.keys(nextConfig).length === 0) {
          return new Response(JSON.stringify({ success: false, message: "没有可更新的配置项" }), {
            status: 400,
            headers: jsonHeaders
          });
        }

        await updateConfiguration(nextConfig);
        return new Response(JSON.stringify({ success: true }), { headers: jsonHeaders });
      }

      if (endpoint === "update-balances") {
        try {
          if (data.test === true) {
            return new Response(JSON.stringify({
              success: true,
              message: "连通性测试成功",
              testTime: new Date().toISOString()
            }), { headers: jsonHeaders });
          }

          if (typeof updateAllKeyBalances !== "function") {
            throw new Error("当前版本未实现批量余额更新");
          }

          const result = await updateAllKeyBalances();
          return new Response(JSON.stringify(result), { headers: jsonHeaders });
        } catch (error) {
          console.error("更新密钥余额时出错:", error);
          return new Response(JSON.stringify({
            success: false,
            message: `更新失败: ${error.message || "未知错误"}`
          }), {
            status: 500,
            headers: jsonHeaders
          });
        }
      }

      if (endpoint === "update-key-balance") {
        if (typeof data.key !== "string" || !data.key.trim()) {
          return new Response(JSON.stringify({ success: false, message: "密钥不能为空" }), {
            status: 400,
            headers: jsonHeaders
          });
        }

        const targetKey = data.key.trim();
        const keys = await getAllKeys();
        const keyIndex = keys.findIndex(k => k.key === targetKey);

        if (keyIndex === -1) {
          return new Response(JSON.stringify({ success: false, message: "密钥不存在" }), {
            status: 404,
            headers: jsonHeaders
          });
        }

        try {
          const result = await checkKeyValidity(targetKey);
          const now = new Date().toISOString();

          if (result.isValid) {
            keys[keyIndex].balance = result.balance;
            keys[keyIndex].lastUpdated = now;
            keys[keyIndex].lastError = null;
          } else {
            keys[keyIndex].balance = 0;
            keys[keyIndex].lastUpdated = now;
            keys[keyIndex].lastError = result.message;
          }

          await SILICONFLOW_KEY.put("keys", JSON.stringify(keys));

          return new Response(JSON.stringify({
            success: result.isValid,
            balance: result.balance,
            message: result.message,
            key: targetKey,
            isValid: result.isValid,
            lastUpdated: now
          }), { headers: jsonHeaders });
        } catch (error) {
          return new Response(JSON.stringify({
            success: false,
            message: "检测余额失败: " + error.message
          }), {
            status: 500,
            headers: jsonHeaders
          });
        }
      }
    } else if (request.method === "DELETE") {
      if (endpoint.startsWith("keys/")) {
        const key = endpoint.replace("keys/", "").trim();
        if (!key) {
          return new Response(JSON.stringify({ success: false, message: "Key is required" }), {
            status: 400,
            headers: jsonHeaders
          });
        }

        await deleteKey(key);
        return new Response(JSON.stringify({ success: true }), { headers: jsonHeaders });
      }
    }
  } catch (error) {
    return new Response(JSON.stringify({ success: false, message: error.message }), {
      status: 500,
      headers: jsonHeaders
    });
  }

  return new Response(JSON.stringify({ success: false, message: "无效的端点" }), {
    status: 404,
    headers: jsonHeaders
  });
}

// 处理主界面
async function handleMainInterface(request) {
  return new Response(mainHtmlContent, {
      headers: { "Content-Type": "text/html;charset=UTF-8" }
  });
}

// 处理API代理，带负载均衡
async function handleAPIProxy(request, path) {
  // 验证API请求
  const authHeader = request.headers.get("Authorization");
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return new Response(JSON.stringify({ 
      error: { message: "需要认证" } 
    }), {
      status: 401,
      headers: { "Content-Type": "application/json" }
    });
  }
  
  // 从Authorization头中提取token
  const providedToken = authHeader.replace("Bearer ", "").trim();
  
  // 从KV获取API密钥或使用默认值
  const apiKey = await SILICONFLOW_KEY.get("api_key") || CONFIG.API_KEY;

  if (!apiKey) {
    return new Response(JSON.stringify({
      error: { message: "服务未完成安全初始化，请先设置代理API密钥" }
    }), {
      status: 503,
      headers: { "Content-Type": "application/json" }
    });
  }
  
  if (!providedToken || providedToken !== apiKey) {
    return new Response(JSON.stringify({ 
      error: { message: "无效的API密钥" } 
    }), {
      status: 401,
      headers: { "Content-Type": "application/json" }
    });
  }
  
  // 获取所有有效密钥用于负载均衡
  const allKeys = await getAllKeys();
  const validKeys = allKeys.filter(k => k.balance > 0);
  
  if (validKeys.length === 0) {
    return new Response(JSON.stringify({ 
      error: { message: "没有可用的API密钥" } 
    }), {
      status: 503,
      headers: { "Content-Type": "application/json" }
    });
  }
  
  // 负载均衡 - 随机选择一个密钥
  const randomIndex = Math.floor(Math.random() * validKeys.length);
  const selectedKey = validKeys[randomIndex].key;
  
  // 克隆请求并修改头信息
  const newHeaders = new Headers(request.headers);
  newHeaders.set("Authorization", `Bearer ${selectedKey}`);
  
  // 移除host头以避免冲突
  newHeaders.delete("host");
  
  // 创建新请求
  const newRequest = new Request(`https://api.siliconflow.cn${path}`, {
    method: request.method,
    headers: newHeaders,
    body: request.body,
    redirect: 'follow'
  });
  
  // 转发请求
  const response = await fetch(newRequest);
  
  // 创建一个新的响应用于流式传输（如果需要）
  const newResponse = new Response(response.body, response);
  
  // 添加完整的CORS头
  newResponse.headers.set("Access-Control-Allow-Origin", "*");
  newResponse.headers.set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
  newResponse.headers.set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Requested-With");
  newResponse.headers.set("Access-Control-Allow-Credentials", "true");
  newResponse.headers.set("Access-Control-Max-Age", "86400");
  
  // 禁用缓存以支持流式传输
  newResponse.headers.set("Cache-Control", "no-store, no-cache, must-revalidate, proxy-revalidate");
  newResponse.headers.set("Pragma", "no-cache");
  newResponse.headers.set("Expires", "0");
  
  return newResponse;
}

// KV工具函数
async function getAllKeys() {
  try {
    // 从KV获取所有密钥
    const keysJson = await SILICONFLOW_KEY.get("keys", "json") || [];
    return keysJson;
  } catch (error) {
    console.error("获取密钥出错:", error);
    return [];
  }
}

async function addKey(key, balance = 0) {
  // 检查密钥是否已存在
  const keys = await getAllKeys();
  const existingKeyIndex = keys.findIndex(k => k.key === key);
  
  if (existingKeyIndex !== -1) {
    // 更新现有密钥
    keys[existingKeyIndex].balance = balance;
  } else {
    // 添加新密钥
    keys.push({ key, balance, added: new Date().toISOString() });
  }
  
  await SILICONFLOW_KEY.put("keys", JSON.stringify(keys));
}

// 新增批量添加函数
async function addKeys(keys, balance = 0) {
// 检查密钥是否已存在
const allKeys = await getAllKeys();

keys.forEach(key => {
  const existingKeyIndex = allKeys.findIndex(k => k.key === key);

  if (existingKeyIndex !== -1) {
    // 更新现有密钥
    allKeys[existingKeyIndex].balance = balance;
  } else {
    // 添加新密钥
    allKeys.push({ key, balance, added: new Date().toISOString() });
  }
});
await SILICONFLOW_KEY.put("keys", JSON.stringify(allKeys));
}

async function deleteKey(key) {
  const keys = await getAllKeys();
  const updatedKeys = keys.filter(k => k.key !== key);
  await SILICONFLOW_KEY.put("keys", JSON.stringify(updatedKeys));
}

async function getConfiguration() {
  // 获取存储的配置或使用默认值
  return {
    apiKey: await SILICONFLOW_KEY.get("api_key") || CONFIG.API_KEY,
    adminUsername: await SILICONFLOW_KEY.get("admin_username") || CONFIG.ADMIN_USERNAME,
    adminPassword: await SILICONFLOW_KEY.get("admin_password") || CONFIG.ADMIN_PASSWORD,
    pageSize: parseInt(await SILICONFLOW_KEY.get("page_size") || CONFIG.PAGE_SIZE),
    accessControl: await SILICONFLOW_KEY.get("access_control") || CONFIG.ACCESS_CONTROL,
    guestPassword: await SILICONFLOW_KEY.get("guest_password") || CONFIG.GUEST_PASSWORD,
  };
}

async function updateConfiguration(config) {
  // 更新配置
  if (config.apiKey) await SILICONFLOW_KEY.put("api_key", config.apiKey);
  if (config.adminUsername) await SILICONFLOW_KEY.put("admin_username", config.adminUsername);
  if (config.adminPassword) await SILICONFLOW_KEY.put("admin_password", config.adminPassword);
  if (config.pageSize) await SILICONFLOW_KEY.put("page_size", config.pageSize.toString());
  if (config.accessControl) await SILICONFLOW_KEY.put("access_control", config.accessControl);
  if (config.guestPassword !== undefined) await SILICONFLOW_KEY.put("guest_password", config.guestPassword);
}

/**
 * 优化后的密钥验证和余额检测函数
 * 首先验证密钥是否有效，然后查询余额
 */
async function checkKeyValidity(key) {
  try {
    // 1. 验证密钥有效性
    const validationResponse = await fetch("https://api.siliconflow.cn/v1/chat/completions", {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${key}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        model: "Qwen/Qwen2.5-7B-Instruct",
        messages: [{ role: "user", content: "hi" }],
        max_tokens: 100,
        stream: false
      })
    });
    
    if (!validationResponse.ok) {
      const errorData = await validationResponse.json().catch(() => null);
      const errorMessage = errorData && errorData.error && errorData.error.message 
        ? errorData.error.message 
        : "密钥验证失败";
        
      return {
        isValid: false,
        balance: 0,
        message: errorMessage
      };
    }
    
    // 2. 查询余额
    const balanceResponse = await fetch("https://api.siliconflow.cn/v1/user/info", {
      method: "GET",
      headers: { "Authorization": `Bearer ${key}` }
    });
    
    if (!balanceResponse.ok) {
      const errorData = await balanceResponse.json().catch(() => null);
      const errorMessage = errorData && errorData.error && errorData.error.message 
        ? errorData.error.message 
        : "余额查询失败";
        
      return {
        isValid: false,
        balance: 0,
        message: errorMessage
      };
    }
    
    const data = await balanceResponse.json();
    const balance = data.data && data.data.totalBalance || 0;
    
    return {
      isValid: true,
      balance: balance,
      message: "验证成功"
    };
  } catch (error) {
    console.error("检测密钥时出错:", error);
    return {
      isValid: false,
      balance: 0,
      message: `网络错误: ${error.message || "未知错误"}`
    };
  }
}

// 主界面的HTML内容
const mainHtmlContent = `
<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>硅基API Key聚合管理系统</title>
  <link rel="icon" type="image/png" href="https://imgbed.killerbest.com/file/1742260658545_siliconcloud-color.png"/>
  <style>
    * {
      box-sizing: border-box;
    }
    body {
      margin: 0;
      padding: 0;
      background: linear-gradient(135deg, #f0f5fb, #c0d3ee);
      font-family: 'Inter', 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
      color: #333;
      min-height: 100vh;
      display: flex;
      flex-direction: column;
      -webkit-overflow-scrolling: touch;
    }
    .container {
      max-width: 1200px; 
      background-color: #fff;
      margin: 10px auto;
      padding: 30px; 
      border-radius: 16px; 
      box-shadow: 0 10px 25px rgba(0,0,0,0.1); 
      flex: 1;
      display: flex;           
      flex-direction: column; 
      overflow-y: auto;       
      height: calc(100vh - 40px);
      -webkit-overflow-scrolling: touch;
    }
    @media (max-width: 840px) {
      .container {
        margin: 20px;
        padding: 20px;
      }
    }
    .header {
      text-align: center;
      margin-bottom: 40px; 
      display: flex;
      flex-direction: column;
      align-items: center;
    }
    .logo {
      width: 80px;
      height: 80px;
      margin: 0 auto 15px;
      border-radius: 15px;
      box-shadow: 0 4px 8px rgba(0,0,0,0.1);
      padding: 5px;
      background: white;
    }
    h1 {
      margin: 0;
      font-size: 2rem;
      color: #2c3e50;
    }
    .subtitle {
      color: #7f8c8d;
      font-size: 1.1rem;
      margin-top: 10px;
    }


    .keys-container {
      flex: 1;        
      overflow-y: auto;  
      display: grid;
      grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
      gap: 20px;
      padding: 20px;
      max-width: 1200px;
      margin: 0 auto;
      -webkit-overflow-scrolling: touch;
      min-height: 390px;
    }

    .key-item {
      background: #ffffff;
      border: 1px solid rgba(225, 232, 240, 0.8);
      border-radius: 16px;
      padding: 18px;
      display: flex;
      align-items: center;
      justify-content: space-between;
      transition: all 0.35s cubic-bezier(0.21, 0.6, 0.35, 1);
      box-shadow: 0 4px 15px rgba(0, 0, 0, 0.04);
      min-height: 70px;
      max-height: 80px;
      position: relative;
      overflow: hidden;
      cursor: pointer;
    }

    .key-item::before {
      content: '';
      position: absolute;
      top: 0;
      left: 0;
      right: 0;
      height: 3px;
      background: linear-gradient(90deg, #3498db, #9b59b6);
      opacity: 0;
      transition: opacity 0.3s ease;
    }

    .key-item:hover {
      transform: translateY(-4px);
      border-color: rgba(52, 152, 219, 0.3);
    }

    .key-item:hover::before {
      opacity: 1;
    }

    .key-item::after {
      content: "复制";
      position: absolute;
      top: 50%;
      left: 40%;
      transform: translate(-50%, -50%) scale(0.85);
      background: rgba(52, 152, 219, 0.29); 
      color: white;
      padding: 8px 20px;
      border-radius: 30px;
      font-size: 0.9rem;
      font-weight: 500;
      opacity: 0;
      transition: all 0.3s cubic-bezier(0.16, 1, 0.3, 1);
      pointer-events: none;
      letter-spacing: 0.6px;
      backdrop-filter: blur(6px);
      -webkit-backdrop-filter: blur(6px);
      z-index: 10;
      border: 1px solid rgba(255, 255, 255, 0.2);
      text-shadow: 0 1px 2px rgba(0, 0, 0, 0.1);
      cursor: pointer;
    }

    .key-item:hover::after {
      opacity: 1;
      transform: translate(-50%, -50%) scale(1);
    }

    .key-text {
      font-family: 'JetBrains Mono', 'Monaco', 'Consolas', monospace;
      font-size: 0.9rem;
      color: #2c3e50;
      flex: 1;
      margin-right: 15px;
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
      position: relative;
      padding-left: 5px;
      letter-spacing: 0.5px;
    }

    .key-text::before {
      content: '';
      position: absolute;
      left: -5px;
      top: 50%;
      transform: translateY(-50%);
      width: 3px;
      height: 60%;
      background: #e1e8f0;
      border-radius: 3px;
      transition: background 0.3s ease;
    }

    .key-item:hover .key-text::before {
      background:rgb(86, 181, 183);
    }

    .key-balance {
      padding: 8px 14px;
      border-radius: 30px;
      font-weight: 600;
      font-size: 0.9rem;
      min-width: 80px;
      text-align: center;
      white-space: nowrap;
      background: linear-gradient(135deg, #defff0, #c6ffe4);
      color: #10875a;
      box-shadow: 0 3px 8px rgba(0, 179, 90, 0.12);
      transition: all 0.3s ease;
      position: relative;
      overflow: hidden;
    }

    .key-balance::before {
      content: '';
      position: absolute;
      top: 0;
      left: 0;
      right: 0;
      bottom: 0;
      background: linear-gradient(45deg, transparent, rgba(255, 255, 255, 0.8), transparent);
      transform: translateX(-100%);
      transition: transform 1s;
    }

    .key-item:hover .key-balance::before {
      transform: translateX(100%);
    }

    .key-balance.low {
      background: linear-gradient(135deg, #fff6f6, #ffe0e0);
      color: #e53e3e;
      box-shadow: 0 3px 8px rgba(229, 62, 62, 0.15);
    }

    .key-balance.zero {
      background: linear-gradient(135deg, #ffecec, #ffdbdb);
      color: #e53e3e;
      font-weight: 700;
      box-shadow: 0 3px 8px rgba(229, 62, 62, 0.15);
    }

    /* 添加时间显示样式 */
    .key-update-time {
      position: absolute;
      bottom: 8px;
      right: 8px;
      font-size: 0.7rem;
      color: #95a5a6;
      opacity: 0; 
      transition: opacity 0.3s ease; 
      pointer-events: none;
      text-shadow: 0 1px 2px rgba(255, 255, 255, 0.8);
      background: rgba(255, 255, 255, 0.8); 
      padding: 2px 6px;
      border-radius: 4px;
      backdrop-filter: blur(4px); 
      -webkit-backdrop-filter: blur(4px); 
      z-index: 2;
    }

    .key-item:hover .key-update-time {
      opacity: 1;
    }
    
    .pagination {
      display: flex;
      justify-content: center;
      margin: 15px 0;
      align-items: center;
      min-height: 60px;
    }
    .pagination button {
      background: rgba(52, 152, 219, 0.8);
      color: white;
      border: none;
      border-radius: 50px;
      padding: 12px 25px;
      margin: 0 8px;
      cursor: pointer;
      transition: all 0.3s cubic-bezier(0.25, 1, 0.5, 1);
      font-weight: 500;
      box-shadow: 0 4px 12px rgba(52, 152, 219, 0.2);
      backdrop-filter: blur(4px);
      -webkit-backdrop-filter: blur(4px);
      border: 1px solid rgba(255, 255, 255, 0.15);
      position: relative;
      overflow: hidden;
    }

    .pagination button::before {
      content: "";
      position: absolute;
      top: 0;
      left: 0;
      right: 0;
      bottom: 0;
      background: linear-gradient(120deg, rgba(255,255,255,0) 30%, rgba(255,255,255,0.2), rgba(255,255,255,0) 70%);
      transform: translateX(-100%);
      transition: transform 0.7s ease;
    }

    .pagination button:hover {
      background: rgba(52, 152, 219, 1);
      transform: translateY(-3px);
      box-shadow: 0 8px 20px rgba(52, 152, 219, 0.35);
    }

    .pagination button:hover::before {
      transform: translateX(100%);
    }

    .pagination button:disabled {
      background: rgba(149, 165, 166, 0.8);
      cursor: not-allowed;
      transform: none;
      box-shadow: 0 4px 8px rgba(149, 165, 166, 0.2);
    }

    .pagination-info {
      margin: 0 15px;
      display: flex;
      align-items: center;
      font-size: 1.1rem;
      font-weight: 500;
      color: #34495e;
    }
    .footer {
      text-align: center;
      margin-top: 30px;
      font-size: 0.9rem;
      color: #7f8c8d;
    }
    .counts {
      display: flex;
      justify-content: space-around;
      margin: 5px 0;
      padding: 5px;
      background: #f8f9fa;
      border-radius: 15px;
      box-shadow: 0 5px 15px rgba(0,0,0,0.05);
    }
    .count-item {
      text-align: center;
      flex: 1;
      padding: 5px 15px;
    }
    .count-item:not(:last-child) {
      border-right: 1px solid #e9ecef;
    }
    .count-label {
      font-size: 0.9rem;
      color: #7f8c8d;
      margin-bottom: 8px;
    }
    .count-value {
      font-size: 1.5rem;  
      font-weight: 600;   
      color: #e74c3c;   
    }

    .admin-link {
      display: flex;
      justify-content: center;
      align-items: center;
      margin: 20px 0;
    }

    .admin-link a {
      color: #3498db;
      text-decoration: none;
      font-size: 1rem;
      padding: 12px 28px;
      border: 1px solid rgba(52, 152, 219, 0.3);
      border-radius: 50px;
      transition: all 0.4s cubic-bezier(0.165, 0.84, 0.44, 1);
      background: rgba(255, 255, 255, 0.7);
      backdrop-filter: blur(4px);
      -webkit-backdrop-filter: blur(4px);
      box-shadow: 0 4px 10px rgba(0, 0, 0, 0.05);
      position: relative;
      overflow: hidden;
      display: inline-block;
    }

    .admin-link a::before {
      content: "";
      position: absolute;
      top: 0;
      left: 0;
      right: 0;
      height: 0;
      background: linear-gradient(to bottom, rgba(52, 152, 219, 0.8), rgba(52, 152, 219, 0.6));
      transition: height 0.4s cubic-bezier(0.165, 0.84, 0.44, 1);
      z-index: -1;
    }

    .admin-link a:hover {
      color: white;
      border-color: transparent;
      transform: translateY(-3px);
      box-shadow: 0 10px 20px rgba(52, 152, 219, 0.25);
    }

    .admin-link a:hover::before {
      height: 100%;
    }

    .admin-link a:active {
      transform: translateY(-1px);
    }

    .toast {
      position: fixed;
      bottom: 30px;
      left: 50%;
      transform: translateX(-50%) translateY(30px);
      background: rgba(46, 204, 113, 0.95);
      color: white;
      padding: 16px 30px;
      border-radius: 50px;
      font-size: 0.95rem;
      font-weight: 500;
      opacity: 0;
      transition: opacity 0.4s ease, transform 0.5s cubic-bezier(0.175, 0.885, 0.32, 1.275);
      pointer-events: none;
      box-shadow: 0 8px 20px rgba(0, 0, 0, 0.2);
      z-index: 9999;
      backdrop-filter: blur(8px);
      border: 1px solid rgba(255, 255, 255, 0.2);
      letter-spacing: 0.5px;
    }

    .toast.show {
      opacity: 1;
      transform: translateX(-50%) translateY(0);
    }

    .toast::before {
      content: '';
      display: inline-block;
      width: 18px;
      height: 18px;
      background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='white'%3E%3Cpath d='M9 16.17L4.83 12l-1.42 1.41L9 19 21 7l-1.41-1.41z'/%3E%3C/svg%3E");
      background-size: contain;
      margin-right: 8px;
      vertical-align: -3px;
    }

    .toast.error::before {
      background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='white'%3E%3Cpath d='M12 2C6.47 2 2 6.47 2 12s4.47 10 10 10 10-4.47 10-10S17.53 2 12 2zm5 13.59L15.59 17 12 13.41 8.41 17 7 15.59 10.59 12 7 8.41 8.41 7 12 10.59 15.59 7 17 8.41 13.41 12 17 15.59z'/%3E%3C/svg%3E");
    }
    .empty-state {
      display: flex;
      flex-direction: column;
      justify-content: center;
      align-items: center;
      text-align: center;
      padding: 40px 0;
      color: #7f8c8d;
      width: 100%;
      min-height: 200px;
      font-size: 1.2rem;
      /* 添加以下属性确保在grid布局中居中 */
      grid-column: 1 / -1; /* 跨越所有列 */
      margin: 0 auto; /* 水平居中 */
      max-width: 100%;
      box-sizing: border-box;
    }
    /* 针对空状态特别处理keys-container */
    .keys-container:has(.empty-state) {
      display: flex;
      justify-content: center;
      align-items: center;
    }
    .loading {
      position: absolute;
      top: 0;
      left: 0;
      width: 100%;
      height: 100%;
      display: flex;
      justify-content: center;
      align-items: center;
      background-color: rgba(255, 255, 255, 0.8);
      z-index: 10;
    }

    .loading > div {
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 20px 35px;
      background-color: white;
      border-radius: 12px;
      box-shadow: 0 4px 15px rgba(0, 0, 0, 0.08);
    }

    .loader {
      display: inline-block;
      width: 24px;
      height: 24px;
      border: 3px solid rgba(52, 152, 219, 0.2);
      border-radius: 50%;
      border-top-color: #3498db;
      animation: spin 1s ease-in-out infinite;
      margin-right: 15px;
      vertical-align: middle;
    }

    @keyframes spin {
      to { transform: rotate(360deg); }
    }

    /* 优化移动端显示 */
    @media (max-width: 768px) {
      .keys-container {
        grid-template-columns: 1fr;
        padding: 10px;
      }
      
      .key-item {
        padding: 12px;
      }
      
      .key-text {
        font-size: 0.85rem;
        max-width: 65%;
      }
    }
    @media (max-width: 640px) {
      .keys-container {
        grid-template-columns: 1fr; // 在小屏幕上改回单列
      }
    }
    /* 优化移动端滚动条样式 */
    .keys-container::-webkit-scrollbar {
      width: 6px;
    }

    .keys-container::-webkit-scrollbar-track {
      background: #f1f1f1;
      border-radius: 3px;
    }

    .keys-container::-webkit-scrollbar-thumb {
      background: #c0d3ee;
      border-radius: 3px;
    }

    .keys-container::-webkit-scrollbar-thumb:hover {
      background: #3498db;
    }

    @media (max-width: 840px) {
      .body {
        overflow-y: auto;
      }

      .container {
        margin: 10px;        
        padding: 15px;  
        height: calc(100vh - 20px);
      }
    }
    /* 优化移动端显示 */
    @media (max-width: 768px) {
      .keys-container {
        grid-template-columns: 1fr;
        padding: 10px;
        min-height: 350px;
      }
      
      .key-item {
        padding: 12px;
        min-height: 60px;
        height: 60px;
      }
      
      .key-text {
        font-size: 0.85rem;
        max-width: 65%;
      }

      /* 改善移动端滚动体验 */
      body, .container {
        -webkit-overflow-scrolling: touch;
        touch-action: manipulation;
      }
      
      .counts{
        display: inline;
      }

      .pagination button{
        padding: 4px 8px;
      }
    }

    /* 悬浮API按钮 */
    .float-api-btn {
      position: fixed;
      right: 25px;
      bottom: 25px;
      padding: 14px 24px;
      background: rgba(52, 152, 219, 0.85);
      color: white;
      border-radius: 50px;
      font-size: 0.95rem;
      font-weight: 500;
      box-shadow: 0 6px 18px rgba(52, 152, 219, 0.35);
      cursor: pointer;
      transition: all 0.4s cubic-bezier(0.19, 1, 0.22, 1);
      z-index: 900;
      border: none;
      display: flex;
      align-items: center;
      gap: 10px;
      border: 1px solid rgba(255, 255, 255, 0.15);
      backdrop-filter: blur(6px);
      -webkit-backdrop-filter: blur(6px);
      overflow: hidden;
      letter-spacing: 0.3px;
    }

    .float-api-btn::before {
      content: "";
      position: absolute;
      top: 0;
      left: 0;
      width: 100%;
      height: 100%;
      background: linear-gradient(120deg, 
        rgba(255, 255, 255, 0) 0%, 
        rgba(255, 255, 255, 0.1) 10%, 
        rgba(255, 255, 255, 0.25) 20%, 
        rgba(255, 255, 255, 0.1) 30%, 
        rgba(255, 255, 255, 0) 40%);
      transform: translateX(-100%);
      transition: transform 1s cubic-bezier(0.19, 1, 0.22, 1);
    }

    .float-api-btn:hover {
      transform: translateY(-4px) scale(1.03);
      box-shadow: 0 10px 25px rgba(52, 152, 219, 0.5);
      background: rgba(41, 128, 185, 0.9);
    }

    .float-api-btn:hover::before {
      transform: translateX(100%);
    }

    .float-api-btn:active {
      transform: translateY(-1px) scale(0.98);
      box-shadow: 0 8px 16px rgba(52, 152, 219, 0.4);
    }

    .float-api-btn svg {
      filter: drop-shadow(0 1px 2px rgba(0, 0, 0, 0.2));
      transition: transform 0.3s ease;
    }

    .float-api-btn:hover svg {
      transform: rotate(15deg) scale(1.1);
    }


    .api-modal {
      position: fixed;
      top: 0;
      left: 0;
      right: 0;
      bottom: 0;
      background: rgba(0, 0, 0, 0.7);
      backdrop-filter: blur(10px);
      display: flex;
      justify-content: center;
      align-items: center;
      z-index: 1000;
      opacity: 0;
      visibility: hidden;
      transition: all 0.4s cubic-bezier(0.19, 1, 0.22, 1);
    }

    .api-modal.show {
      opacity: 1;
      visibility: visible;
    }

    .api-modal-content {
      width: 90%;
      max-width: 750px;
      max-height: 85vh;
      background: #fff;
      border-radius: 20px;
      box-shadow: 0 25px 50px rgba(0, 0, 0, 0.25);
      overflow: hidden;
      transform: scale(0.9);
      opacity: 0;
      transition: all 0.5s cubic-bezier(0.19, 1, 0.22, 1);
      display: flex;
      flex-direction: column;
    }

    .api-modal.show .api-modal-content {
      transform: scale(1);
      opacity: 1;
    }

    .api-modal-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding: 24px 30px;
      background: linear-gradient(135deg, #3498db, #2c3e50);
      color: white;
      position: relative;
      z-index: 5;
      box-shadow: 0 2px 15px rgba(0, 0, 0, 0.1);
    }

    .api-modal-header:before {
      content: '';
      position: absolute;
      top: 0;
      left: 0;
      width: 100%;
      height: 100%;
      background: url("data:image/svg+xml,%3Csvg width='100' height='100' viewBox='0 0 100 100' xmlns='http://www.w3.org/2000/svg'%3E%3Cpath d='M11 18c3.866 0 7-3.134 7-7s-3.134-7-7-7-7 3.134-7 7 3.134 7 7 7zm48 25c3.866 0 7-3.134 7-7s-3.134-7-7-7-7 3.134-7 7 3.134 7 7 7zm-43-7c1.657 0 3-1.343 3-3s-1.343-3-3-3-3 1.343-3 3 1.343 3 3 3zm63 31c1.657 0 3-1.343 3-3s-1.343-3-3-3-3 1.343-3 3 1.343 3 3 3zM34 90c1.657 0 3-1.343 3-3s-1.343-3-3-3-3 1.343-3 3 1.343 3 3 3zm56-76c1.657 0 3-1.343 3-3s-1.343-3-3-3-3 1.343-3 3 1.343 3 3 3zM12 86c2.21 0 4-1.79 4-4s-1.79-4-4-4-4 1.79-4 4 1.79 4 4 4zm28-65c2.21 0 4-1.79 4-4s-1.79-4-4-4-4 1.79-4 4 1.79 4 4 4zm23-11c2.76 0 5-2.24 5-5s-2.24-5-5-5-5 2.24-5 5 2.24 5 5 5zm-6 60c2.21 0 4-1.79 4-4s-1.79-4-4-4-4 1.79-4 4 1.79 4 4 4zm29 22c2.76 0 5-2.24 5-5s-2.24-5-5-5-5 2.24-5 5 2.24 5 5 5zM32 63c2.76 0 5-2.24 5-5s-2.24-5-5-5-5 2.24-5 5 2.24 5 5 5zm57-13c2.76 0 5-2.24 5-5s-2.24-5-5-5-5 2.24-5 5 2.24 5 5 5zm-9-21c1.105 0 2-.895 2-2s-.895-2-2-2-2 .895-2 2 .895 2 2 2zM60 91c1.105 0 2-.895 2-2s-.895-2-2-2-2 .895-2 2 .895 2 2 2zM35 41c1.105 0 2-.895 2-2s-.895-2-2-2-2 .895-2 2 .895 2 2 2zM12 60c1.105 0 2-.895 2-2s-.895-2-2-2-2 .895-2 2 .895 2 2 2z' fill='rgba(255,255,255,0.05)' fill-rule='evenodd'/%3E%3C/svg%3E");
      z-index: -1;
    }

    .api-modal-title {
      font-size: 1.6rem;
      font-weight: 600;
      margin: 0;
      display: flex;
      align-items: center;
    }

    .api-modal-title svg {
      margin-right: 12px;
      height: 24px;
      width: 24px;
    }

    .api-modal-close {
      width: 36px;
      height: 36px;
      background: rgba(255, 255, 255, 0.15);
      border: none;
      border-radius: 50%;
      display: flex;
      align-items: center;
      justify-content: center;
      color: white;
      font-size: 1.4rem;
      cursor: pointer;
      transition: all 0.3s;
      outline: none;
    }

    .api-modal-close:hover {
      background: rgba(255, 255, 255, 0.3);
      transform: rotate(90deg);
    }

    .api-modal-body {
      padding: 30px;
      max-height: calc(85vh - 80px);
      overflow-y: auto;
      overflow-x: hidden;
    }

    .api-tutorial h3 {
      color: #2c3e50;
      margin-top: 30px;
      margin-bottom: 15px;
      font-size: 1.3rem;
      position: relative;
      padding-left: 15px;
      font-weight: 600;
    }

    .api-tutorial h3::before {
      content: '';
      position: absolute;
      left: 0;
      top: 0;
      bottom: 0;
      width: 4px;
      background: linear-gradient(to bottom, #3498db, #2980b9);
      border-radius: 4px;
    }

    .api-tutorial p {
      color: #34495e;
      line-height: 1.7;
      margin-bottom: 18px;
      font-size: 1.02rem;
    }

    .code-block {
      margin: 25px 0;
      border-radius: 12px;
      overflow: hidden;
      box-shadow: 0 4px 20px rgba(0, 0, 0, 0.08);
      background: #f8f9fa;
    }

    .code-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      background: #e9ecef;
      padding: 12px 20px;
      border-bottom: 1px solid #dee2e6;
    }

    .code-header span {
      font-size: 0.9rem;
      color: #495057;
      font-weight: 500;
    }

    .copy-btn {
      background: rgba(255, 255, 255, 0.7);
      border: none;
      border-radius: 4px;
      padding: 6px 12px;
      font-size: 0.85rem;
      color: #3498db;
      cursor: pointer;
      transition: all 0.2s ease;
      display: flex;
      align-items: center;
      gap: 5px;
    }

    .copy-btn::before {
      content: '';
      display: inline-block;
      width: 14px;
      height: 14px;
      background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='24' height='24' viewBox='0 0 24 24' fill='none' stroke='%233498db' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'%3E%3Crect x='9' y='9' width='13' height='13' rx='2' ry='2'%3E%3C/rect%3E%3Cpath d='M5 15H4a2 2 0 01-2-2V4a2 2 0 012-2h9a2 2 0 012 2v1'%3E%3C/path%3E%3C/svg%3E");
      background-size: contain;
      background-repeat: no-repeat;
      background-position: center;
    }

    .copy-btn:hover {
      background: rgba(255, 255, 255, 0.9);
      color: #2980b9;
      transform: translateY(-1px);
    }

    .copy-btn.copied {
      background: #2ecc71;
      color: white;
    }

    .copy-btn.copied::before {
      background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='24' height='24' viewBox='0 0 24 24' fill='none' stroke='white' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'%3E%3Cpolyline points='20 6 9 17 4 12'%3E%3C/polyline%3E%3C/svg%3E");
    }

    .api-code {
      background: #282c34;
      color: #abb2bf;
      margin: 0;
      padding: 20px;
      border-radius: 0;
      font-family: 'JetBrains Mono', 'Fira Code', 'Monaco', 'Consolas', monospace;
      font-size: 0.9rem;
      line-height: 1.6;
      overflow-x: auto;
      white-space: pre-wrap;
      word-break: break-word;
    }

    .api-code .comment {
      color: #98c379;
      opacity: 0.8;
    }

    .api-code .keyword {
      color: #c678dd;
    }

    .api-code .string {
      color: #e5c07b;
    }

    .api-tutorial .contact-info {
      background: linear-gradient(135deg, #e7f5fd, #d1e8f8);
      padding: 20px;
      border-radius: 12px;
      border: 1px solid #bbd8ed;
      margin-top: 25px;
      margin-bottom: 25px;
      text-align: center;
      color: #2c3e50;
      font-weight: 500;
      box-shadow: 0 4px 10px rgba(41, 128, 185, 0.1);
    }

    .api-tutorial .contact-info a {
      color: #3498db;
      text-decoration: none;
      font-weight: 600;
      position: relative;
      display: inline-block;
      padding-bottom: 2px;
    }

    .api-tutorial .contact-info a::after {
      content: '';
      position: absolute;
      left: 0;
      right: 0;
      bottom: 0;
      height: 2px;
      background: #3498db;
      transform: scaleX(0);
      transform-origin: right;
      transition: transform 0.3s ease;
    }

    .api-tutorial .contact-info a:hover::after {
      transform: scaleX(1);
      transform-origin: left;
    }

    .api-tutorial ul {
      padding-left: 20px;
      margin: 20px 0;
    }

    .api-tutorial li {
      margin-bottom: 10px;
      position: relative;
      padding-left: 5px;
      line-height: 1.6;
      color: #34495e;
    }

    .api-tutorial li::marker {
      color: #3498db;
      font-weight: bold;
    }

    /* 添加自定义滚动条 */
    .api-modal-body::-webkit-scrollbar {
      width: 8px;
    }

    .api-modal-body::-webkit-scrollbar-track {
      background: #f1f1f1;
      border-radius: 6px;
    }

    .api-modal-body::-webkit-scrollbar-thumb {
      background: #cbd5e0;
      border-radius: 6px;
    }

    .api-modal-body::-webkit-scrollbar-thumb:hover {
      background: #a0aec0;
    }

    /* 改善移动端适配 */
    @media (max-width: 768px) {
      .api-modal-content {
        width: 95%;
        max-height: 90vh;
      }
      
      .api-modal-header {
        padding: 16px 20px;
      }
      
      .api-modal-body {
        padding: 20px;
        max-height: calc(90vh - 60px);
      }
      
      .api-tutorial h3 {
        font-size: 1.2rem;
      }
      
      .api-tutorial p {
        font-size: 0.95rem;
      }
      
      .api-code {
        font-size: 0.75rem;
        padding: 15px;
      }
      
      .code-header {
        padding: 10px 15px;
      }
      
      .copy-btn {
        padding: 4px 8px;
        font-size: 0.8rem;
      }
      
      .float-api-btn {
        right: 20px;
        bottom: 20px;
        padding: 12px 18px;
        font-size: 0.9rem;
      }
    }

    /* 复制按钮 */
    .copy-btn {
      background: #e9f0f7;
      border: none;
      border-radius: 4px;
      padding: 5px 10px;
      font-size: 0.8rem;
      color: #3498db;
      cursor: pointer;
      margin-left: 10px;
      transition: all 0.2s;
    }

    .copy-btn:hover {
      background: #d4e6f7;
    }

    .copy-btn:active {
      transform: scale(0.95);
    }

    .code-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 8px;
    }

    .code-header span {
      color: #7f8c8d;
      font-size: 0.9rem;
    }

    /* 复制成功动画 */
    .copy-success {
      position: relative;
    }

    .copy-success::after {
      content: '✓';
      position: absolute;
      top: 50%;
      left: 40%;
      transform: translate(-50%, -50%);
      color: #fff;
      font-size: 1.5rem;
      font-weight: bold;
      opacity: 0;
      animation: successPop 1.5s ease forwards;
    }

    @keyframes successPop {
      0% {
        opacity: 0;
        transform: translate(-50%, -50%) scale(0.5);
      }
      15% {
        opacity: 1;
        transform: translate(-50%, -50%) scale(1.2);
      }
      30% {
        transform: translate(-50%, -50%) scale(1);
      }
      70% {
        opacity: 1;
      }
      100% {
        opacity: 0;
      }
    }

    /* 响应式调整 */
    @media (max-width: 768px) {
      .keys-container {
        grid-template-columns: 1fr;
        padding: 15px;
        gap: 16px;
      }
      
      .key-item {
        padding: 16px;
        min-height: 65px;
      }
      
      .key-balance {
        padding: 6px 12px;
        min-width: 70px;
      }
    }
    
    /* 进度条样式增强 */
    .progress-stats {
      display: flex;
      justify-content: space-between;
      font-size: 0.85rem;
      color: #718096;
    }
    
    .progress-details {
      margin-top: 10px;
      font-size: 0.8rem;
      color: #718096;
      display: flex;
      justify-content: space-between;
    }
    
    .progress-speed {
      color: #3498db;
    }
    
    .progress-eta {
      color: #e67e22;
    }


    /* 余额多样化显示 */
    .key-balance.normal {
      background: linear-gradient(135deg, #defff0, #c6ffe4);
      color: #10875a;
      box-shadow: 0 3px 8px rgba(0, 179, 90, 0.12);
    }

    .key-balance.medium {
      background: linear-gradient(135deg, #f3e7ff, #e4d0ff);
      color: #6b10c4;
      box-shadow: 0 3px 8px rgba(107, 16, 196, 0.15);
    }

    .key-balance.high {
      background: linear-gradient(135deg, #fff8e0, #ffe7a0);
      color: #b7860b;
      box-shadow: 0 3px 8px rgba(183, 134, 11, 0.25);
      text-shadow: 0 0 5px rgba(255, 215, 0, 0.3);
    }

    .key-balance.low {
      background: linear-gradient(135deg, #fff3e0, #ffdcaf);
      color: #d35400;
      box-shadow: 0 3px 8px rgba(211, 84, 0, 0.15);
    }

    .key-balance.zero {
      background: linear-gradient(135deg, #ffecec, #ffcbcb);
      color: #e53e3e;
      font-weight: 700;
      box-shadow: 0 3px 8px rgba(229, 62, 62, 0.15);
    }

    /* 认证弹窗样式 */
    .api-modal-footer {
      padding: 15px 20px;
      border-top: 1px solid #e9ecef;
      display: flex;
      justify-content: flex-end;
      gap: 10px;
    }

    #guest-password {
      width: 100%;
      padding: 12px;
      border-radius: 8px;
      border: 1px solid #ddd;
      font-size: 16px;
      transition: border-color 0.2s, box-shadow 0.2s;
      margin-top: 10px;
    }

    #guest-password:focus {
      border-color: #3498db;
      box-shadow: 0 0 0 3px rgba(52, 152, 219, 0.2);
      outline: none;
    }

    #auth-error {
      color: #e74c3c;
      margin-top: 8px;
      font-size: 0.9rem;
      font-weight: 500;
      display: none;
    }

    #verify-guest-btn {
      background: #3498db;
      color: white;
      border: none;
      border-radius: 6px;
      padding: 10px 20px;
      font-size: 15px;
      cursor: pointer;
      transition: all 0.2s ease;
    }

    #verify-guest-btn:hover {
      background: #2980b9;
      transform: translateY(-2px);
    }

    #verify-guest-btn:active {
      transform: translateY(0);
    }

    /* 版权样式 */
    #copyright-text {
      position: fixed;
      bottom: 10px;
      left: 50%;
      transform: translateX(-50%);
      font-size: 0.85rem;
      color: rgba(120, 120, 120, 0.85);
      font-weight: 700;
      text-shadow: 0 0 10px rgba(255, 255, 255, 0.5);
      z-index: 9999;
      pointer-events: none;
      user-select: none;
      letter-spacing: 0.5px;
      opacity: 0.75;
      transition: opacity 0.3s ease;
      white-space: nowrap; 
      text-align: center;
    }

    #copyright-text:hover {
      opacity: 1;
    }

    @media (max-width: 768px) {
      #copyright-text {
        font-size: 0.75rem;
        bottom: 8px;
      }
    }

    /* 添加GitHub链接样式 */
    .github-link {
      display: flex;
      align-items: center;
      gap: 6px;
      text-decoration: none;
      color: #333;
      background: #f1f1f1;
      border: 1px solid #ddd;
      border-radius: 4px;
      padding: 6px 10px;
      font-size: 0.9rem;
      margin-right: 10px;
      transition: all 0.2s;
      position: absolute;
      right: 15px;
      top: 15px;
    }
    
    .github-link:hover {
      background: #333;
      color: white;
      border-color: #333;
    }
    
    .github-link svg {
      transition: transform 0.2s;
    }
    
    .github-link:hover svg {
      transform: rotate(360deg);
    }
    
    @media (max-width: 768px) {
      .github-link {
        position: static;
        margin: 10px auto;
        width: fit-content;
      }
    }

  </style>
</head>
  <body>
  <div class="container">
      <div class="header">
        <img src="https://imgbed.killerbest.com/file/1742260658545_siliconcloud-color.png" alt="logo" class="logo"/>
        <h1>硅基流动API Key Sharing</h1>
        <div class="subtitle">API密钥共享与负载均衡服务</div>
        <a href="https://github.com/Dr-Ai-0018/Siliconflow-API-Management" target="_blank" class="github-link">
          <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <path d="M9 19c-5 1.5-5-2.5-7-3m14 6v-3.87a3.37 3.37 0 0 0-.94-2.61c3.14-.35 6.44-1.54 6.44-7A5.44 5.44 0 0 0 20 4.77 5.07 5.07 0 0 0 19.91 1S18.73.65 16 2.48a13.38 13.38 0 0 0-7 0C6.27.65 5.09 1 5.09 1A5.07 5.07 0 0 0 5 4.77a5.44 5.44 0 0 0-1.5 3.78c0 5.42 3.3 6.61 6.44 7A3.37 3.37 0 0 0 9 18.13V22"></path>
          </svg>
          GitHub
        </a>
      </div>
      
      <div id="keys-container" class="keys-container">
        <div class="loading">
          <div>
            <span class="loader"></span>
            <span>加载中...</span>
          </div>
        </div>
      </div>
      
      <div class="pagination">
        <button id="prev-page" disabled>&laquo; 上一页</button>
        <div class="pagination-info">
            <span id="page-info">第 1 页</span>
        </div>
        <button id="next-page" disabled>下一页 &raquo;</button>
      </div>
      
      <div class="counts">
        <div class="count-item">
          <div class="count-label">总API Keys</div>
          <div id="total-count" class="count-value">0</div>
        </div>
        <div class="count-item">
          <div class="count-label">有效API Keys</div>
          <div id="valid-count" class="count-value">0</div>
        </div>
        <div class="count-item">
          <div class="count-label">总额度</div>
          <div id="total-balance" class="count-value">0</div>
        </div>
      </div>
      
      <div class="admin-link">
        <a href="/admin">管理员入口</a>
      </div>
  </div>
  
  <div id="toast" class="toast"></div>

  <div id="auth-modal" class="api-modal">
    <div class="api-modal-content" style="max-width: 400px;">
      <div class="api-modal-header">
        <h3 class="api-modal-title">需要访客认证</h3>
        <button id="authModalClose" class="api-modal-close">&times;</button>
      </div>
      <div class="api-modal-body">
        <p>此页面受到保护，请输入访客密码继续访问：</p>
        <div style="margin: 20px 0;">
          <input type="password" id="guest-password" placeholder="请输入访客密码" style="width: 100%; padding: 10px; border-radius: 4px; border: 1px solid #ddd;">
          <div id="auth-error" style="color: #e74c3c; margin-top: 8px; font-size: 0.9rem; display: none;">密码不正确，请重试</div>
        </div>
      </div>
      <div class="api-modal-footer" style="padding: 15px 20px; text-align: right; display: flex; justify-content: flex-end;">
        <button id="verify-guest-btn" class="action-button" style="background: #3498db; color: white;">
          验证
        </button>
      </div>
    </div>
  </div>
  
  <!-- 悬浮API按钮 -->
  <button id="floatApiBtn" class="float-api-btn">
    <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
      <path d="M20 14.66V20a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2h5.34"></path>
      <polygon points="18 2 22 6 12 16 8 16 8 12 18 2"></polygon>
    </svg>
    API 调用文档
  </button>
  
  <!-- API教程弹窗 -->
  <div id="apiModal" class="api-modal">
    <div class="api-modal-content">
      <div class="api-modal-header">
        <h3 class="api-modal-title">API 调用教程</h3>
        <button id="apiModalClose" class="api-modal-close">&times;</button>
      </div>
      <div class="api-modal-body">
        <div class="api-tutorial">
          <p>硅基流动API负载均衡服务让您可以通过统一的入口访问基于 API Key 的服务，自动为您选择可用的 API Key，实现负载均衡与高可用。</p>
          
          <h3>基本使用</h3>
          <p>调用方式与原始API完全相同，只需将请求地址修改为我们的代理地址，并在请求头中使用您的专属API Key。</p>
          
          <div>
            <div class="code-header">
              <span>示例请求</span>
              <button class="copy-btn" data-copy=
"
curl -X POST '<your-project-domain>/v1/chat/completions' \\
-H 'Content-Type: application/json' \\
-H 'Authorization: Bearer your-api-key-here' \\
-d '{'model': 'Qwen/Qwen2.5-7B-Instruct', 'messages': [{'role': 'user', 'content': '你好'}], 'stream': true}'
">复制</button>
            </div>
            
            <div class="api-code">
    <span class="comment"># 向负载均衡服务发送请求</span>
    curl -X POST '<your-project-domain>/v1/chat/completions' \\
      -H 'Content-Type: application/json' \\
      -H 'Authorization: Bearer <span class="keyword">your-api-key-here</span>' \\
      -d '{
        <span class="string">"model"</span>: <span class="string">"Qwen/Qwen2.5-7B-Instruct"</span>,
        <span class="string">"messages"</span>: [{<span class="string">"role"</span>: <span class="string">"user"</span>, <span class="string">"content"</span>: <span class="string">"你好"</span>}],
        <span class="string">"stream"</span>: true
      }'
            </div>
          </div>
          
          <h3>支持的端点</h3>
          <p>我们支持硅基流动的所有API端点，您只需将原始API地址替换为我们的代理地址即可：</p>
          
          <div>
            <div class="code-header">
              <span>端点替换示例</span>
              <button class="copy-btn" data-copy="# 原始API地址
  https://api.siliconflow.cn/v1/...

  # 替换为
  <your-project-domain>/v1/...">复制</button>
            </div>
            <div class="api-code">
    <span class="comment"># 原始API地址</span>
    https://api.siliconflow.cn/v1/...

    <span class="comment"># 替换为</span>
    <your-project-domain>/v1/...
            </div>
          </div>
          
          <h3>获取访问授权</h3>
          <p>要使用该服务，您需要申请专属的API Key。请联系管理员获取访问权限：</p>
          
          <div class="contact-info">
            管理员邮箱：<a href="mailto:admin@killerbest.com">admin@killerbest.com</a>
          </div>
          
          <h3>主要优势</h3>
          <ul>
            <li>自动负载均衡 - 系统自动选择有效的API Key</li>
            <li>提高可用性 - 单个Key故障不影响整体服务</li>
            <li>简化管理 - 无需手动切换API Key</li>
            <li>统一入口 - 使用一个API Key访问所有服务</li>
          </ul>
        </div>
      </div>
    </div>
  </div>

  <div id="copyright-text">版权所有 &copy; 2025 KillerBest</div>

  <script>
    // 全局变量
    let allKeys = [];
    let currentPage = 1;
    let pageSize = 12;
    let authToken = localStorage.getItem('guestToken') || '';
    let accessControlMode = 'open';
    
    // DOM元素
    const keysContainer = document.getElementById('keys-container');
    const prevPageBtn = document.getElementById('prev-page');
    const nextPageBtn = document.getElementById('next-page');
    const pageInfo = document.getElementById('page-info');
    const totalCountEl = document.getElementById('total-count');
    const validCountEl = document.getElementById('valid-count');
    const totalBalanceEl = document.getElementById('total-balance');
    const toast = document.getElementById('toast');
    
    // API按钮和弹窗
    const floatApiBtn = document.getElementById('floatApiBtn');
    const apiModal = document.getElementById('apiModal');
    const apiModalClose = document.getElementById('apiModalClose');
    
    // 显示API弹窗
    floatApiBtn.addEventListener('click', () => {
        apiModal.classList.add('show');
        document.body.style.overflow = 'hidden'; // 防止背景滚动
        
        // 添加媒体查询适配动画
        if (window.innerWidth <= 768) {
          document.querySelector('.api-modal-content').style.transform = 'translateY(0)';
        }
    });
    
    // 关闭API弹窗
    apiModalClose.addEventListener('click', () => {
      apiModal.classList.remove('show');
      document.body.style.overflow = ''; // 恢复滚动
    });
    
    // 点击弹窗外部关闭
    apiModal.addEventListener('click', (e) => {
      if (e.target === apiModal) {
        apiModal.classList.remove('show');
        document.body.style.overflow = '';
      }
    });
    
    // 代码复制功能
    document.querySelectorAll('.copy-btn').forEach(btn => {
      btn.addEventListener('click', function() {
        const codeText = this.getAttribute('data-copy');
        
        // 使用异步剪贴板API
        navigator.clipboard.writeText(codeText)
          .then(() => {
            // 成功复制后的视觉反馈
            this.classList.add('copied');
            this.innerText = '已复制';
            
            // 恢复原始状态
            setTimeout(() => {
              this.classList.remove('copied');
              this.innerHTML = '复制代码';
              this.insertAdjacentHTML('afterbegin', '<span></span>');
            }, 2000);
            
            // 显示全局通知
            showToast('代码已复制到剪贴板');
          })
          .catch(err => {
            console.error('复制失败:', err);
            showToast('复制失败，请手动复制', true);
          });
      });
    });
    
    // 从服务器加载密钥
    async function loadKeys(retryCount = 3, retryDelay = 1500) {
      try {
        // 显示加载状态
        if (!keysContainer.querySelector('.loading')) {
          keysContainer.innerHTML = \`
            <div class="loading">
              <div>
                <span class="loader"></span>
                <span>加载中...</span>
              </div>
            </div>
          \`;
        }

        // 构建请求头，添加认证信息
        const headers = {};
        if (authToken) {
          headers['Authorization'] = \`Bearer \${authToken}\`;
        }
        
        const response = await fetch('/admin/api/keys', { headers });
        
        // 处理未认证的情况
        if (response.status === 401) {
          const result = await response.json();
          if (result.requireAuth) {
            // 清除失效的token
            localStorage.removeItem('guestToken');
            authToken = '';
            
            // 根据访问控制模式显示不同内容
            if (result.accessControl === 'private') {
              keysContainer.innerHTML = '<div class="empty-state">此页面仅限管理员访问<br><a href="/admin" style="color: #3498db;">前往管理员登录</a></div>';
            } else {
              showAuthModal();
            }
            return;
          }
        }
        
        if (!response.ok) {
          throw new Error(\`服务器响应错误: \${response.status}\`);
        }
        
        const result = await response.json();
        if (result.success) {
          allKeys = result.data;
          pageSize = await getPageSize();
          renderKeys();
          updateCountsWithAnimation();
        } else {
          throw new Error(result.message || '加载密钥失败');
        }
      } catch (error) {
        console.error('加载密钥时出错:', error);
        
        if (retryCount > 0) {
          // 显示重试消息
          keysContainer.innerHTML = \`
            <div class="empty-state">
              <p>加载失败: \${error.message}</p>
              <p>正在重试... (剩余 \${retryCount} 次)</p>
              <div class="loader" style="display: inline-block; margin-top: 10px; border-top-color: #3498db;"></div>
            </div>
          \`;
          
          // 延迟后重试
          setTimeout(() => loadKeys(retryCount - 1, retryDelay * 1.5), retryDelay);
        } else {
          // 所有重试都失败了，显示最终错误并提供刷新按钮
          keysContainer.innerHTML = \`
            <div class="empty-state">
              <p>加载失败: \${error.message}</p>
              <button id="retry-button" style="margin-top: 15px; background: #3498db; color: white; border: none; border-radius: 4px; padding: 10px 20px; cursor: pointer;">
                刷新重试
              </button>
            </div>
          \`;
          
          // 为刷新按钮添加事件监听器
          setTimeout(() => {
            const retryButton = document.getElementById('retry-button');
            if (retryButton) {
              retryButton.addEventListener('click', () => {
                // 显示加载状态
                keysContainer.innerHTML = \`
                  <div class="loading">
                    <div>
                      <span class="loader"></span>
                      <span>加载中...</span>
                    </div>
                  </div>
                \`;
                
                // 短暂延迟后重新加载
                setTimeout(() => loadKeys(3, 1500), 300);
              });
            }
          }, 0);
        }
      }
    }
    
    // 获取页面大小配置
    async function getPageSize(retryCount = 2) {
      try {
        const response = await fetch('/admin/api/pageSize');
        if (!response.ok) {
          throw new Error(\`服务器响应错误: \${response.status}\`);
        }
        
        const result = await response.json();
        if (result.success) {
          return parseInt(result.data) || 12; // 确保有默认值
        } else {
          throw new Error(result.message || '无法获取页面配置');
        }
      } catch (error) {
        console.warn('加载页面大小配置时出错:', error);
        
        // 尝试重试
        if (retryCount > 0) {
          console.log(\`尝试重新获取页面大小... 剩余尝试次数: \${retryCount}\`);
          await new Promise(resolve => setTimeout(resolve, 1000)); // 延迟1秒
          return getPageSize(retryCount - 1);
        }
        
        // 返回默认值
        return 12;
      }
    }
    
    // 渲染当前页面的密钥
    function renderKeys() {
      // 格式化日期 
      function formatDate(dateString) {
        try {
          const date = new Date(dateString);
          // 检查日期是否有效
          if (isNaN(date.getTime())) {
            return '时间未知';
          }
          // 指定使用24小时制格式
          return date.toLocaleString('zh-CN', { 
            year: 'numeric',
            month: '2-digit',
            day: '2-digit',
            hour: '2-digit',
            minute: '2-digit',
            second: '2-digit',
            hour12: false // 使用24小时制
          });
        } catch (e) {
          console.error('日期格式化错误:', e);
          return '时间未知';
        }
      }

      if (allKeys.length === 0) {
          keysContainer.innerHTML = '<div class="empty-state">暂无API Keys</div>';
          prevPageBtn.disabled = true;
          nextPageBtn.disabled = true;
          pageInfo.textContent = '第 0 页';
          return;
      }
      
      // 按余额从高到低排序
      const sortedKeys = [...allKeys].sort((a, b) => {
        // 转换为数字进行比较，确保是数值比较
        const balanceA = parseFloat(a.balance) || 0;
        const balanceB = parseFloat(b.balance) || 0;
        return balanceB - balanceA; // 从高到低排序
      });
      
      // 计算分页
      const totalPages = Math.ceil(sortedKeys.length / pageSize);
      if (currentPage > totalPages) {
          currentPage = totalPages;
      }
      
      const startIndex = (currentPage - 1) * pageSize;
      const endIndex = Math.min(startIndex + pageSize, sortedKeys.length);
      const currentKeys = sortedKeys.slice(startIndex, endIndex);
      
      // 更新分页控件
      prevPageBtn.disabled = currentPage === 1;
      nextPageBtn.disabled = currentPage === totalPages;
      pageInfo.textContent = \`第 \${currentPage} / \${totalPages} 页\`;
      
      // 渲染密钥
      let html = '';
      for (const keyObj of currentKeys) {
          // 省略显示密钥：保留前10位和后5位，中间用...替代
          const displayKey = keyObj.key.length > 20 
          ? \`\${keyObj.key.substring(0, 10)}...\${keyObj.key.substring(keyObj.key.length - 5)}\`
          : keyObj.key;
          
          // 根据余额确定类名和显示文本
          let balanceClass = '';
          let balanceText = '';
          const balance = parseFloat(keyObj.balance) || 0;
          
          if (balance <= 0) {
              balanceClass = 'zero';
              balanceText = '无效';
          } else if (balance > 0 && balance <= 7) {
              balanceClass = 'low';
              balanceText = balance;
          } else if (balance > 7 && balance <= 14) {
              balanceClass = 'normal';
              balanceText = balance;
          } else if (balance > 14 && balance <= 100) {
              balanceClass = 'medium';
              balanceText = balance;
          } else if (balance > 100) {
              balanceClass = 'high';
              balanceText = balance;
          }
          
          html += \`
            <div class="key-item" onclick="copyKey('\${keyObj.key}')" title="\${keyObj.key}">
                <div class="key-text">\${displayKey}</div>
                <div class="key-balance \${balanceClass}">\${balanceText}</div>
                <div class="key-update-time">
                  \${keyObj.lastUpdated ? '更新于 ' + formatDate(keyObj.lastUpdated) : '未更新'}
                </div>
            </div>
          \`;

      }
      
      keysContainer.innerHTML = html;
    }
    
    // 更新计数显示
    function updateCountsWithAnimation() {
      // 获取实际数据
      const total = allKeys.length;
      const valid = allKeys.filter(k => k.balance > 0).length;
      const totalBalance = allKeys.reduce((sum, key) => {
        return sum + (parseFloat(key.balance) || 0);
      }, 0).toFixed(2);
      
      // 为三个数字添加动画
      animateCounter(totalCountEl, total);
      animateCounter(validCountEl, valid);
      animateCounter(document.getElementById('total-balance'), totalBalance, '￥', true);
    }
    
    // 页面加载时初始化数字显示样式
    document.addEventListener('DOMContentLoaded', () => {
      // 确保初始状态为红色小字体
      const countValues = document.querySelectorAll('.count-value');
      countValues.forEach(el => {
        el.style.fontSize = '1.5rem';
        el.style.fontWeight = '600';
        el.style.color = '#e74c3c';
      });

      // 初始加载时首先检查访问控制状态，而不是直接加载密钥
      checkAccessControl();
      
      // 访客验证按钮事件
      document.getElementById('verify-guest-btn').addEventListener('click', verifyGuestPassword);
      
      // 关闭认证弹窗按钮
      document.getElementById('authModalClose').addEventListener('click', () => {
        document.getElementById('auth-modal').classList.remove('show');
        
        // 如果是受限模式且没有token，确保显示认证按钮
        if (accessControlMode === 'restricted' && !authToken) {
          keysContainer.innerHTML = \`
            <div class="empty-state">
              <p>需要访客密码才能查看内容</p>
              <button id="show-auth-button" style="margin-top: 20px; background: #3498db; color: white; border: none; border-radius: 6px; padding: 10px 20px; cursor: pointer; font-size: 14px; transition: all 0.3s ease;">
                点击认证
              </button>
            </div>
          \`;
          
          // 添加认证按钮点击事件
          setTimeout(() => {
            const authButton = document.getElementById('show-auth-button');
            if (authButton) {
              authButton.addEventListener('click', showAuthModal);
            }
          }, 0);
        }
      });
      
      // 密码输入框回车事件
      document.getElementById('guest-password').addEventListener('keypress', (e) => {
        if (e.key === 'Enter') {
          verifyGuestPassword();
        }
      });
    });

    // 数字动画函数
    function animateCounter(element, targetValue, prefix = '', isBalance = false) {
      // 确保目标是数字
      const target = parseFloat(targetValue) || 0;
      const isInteger = !isBalance && Number.isInteger(target);
      let current = 0;
      
      // 动画持续时间和帧率
      const duration = 5000; // 5秒动画
      const framesPerSecond = 60;
      const frames = duration / 1000 * framesPerSecond;
      
      // 使用easeOutExpo缓动函数以获得非线性的动画效果
      const easeOutExpo = t => t === 1 ? 1 : 1 - Math.pow(2, -10 * t);
      
      // 停止现有的动画
      if (element._animationFrame) {
        cancelAnimationFrame(element._animationFrame);
      }
      
      const startTime = performance.now();
      
      // 动画函数
      const animate = (timestamp) => {
        // 计算已经过去的时间比例
        const elapsed = timestamp - startTime;
        const progress = Math.min(elapsed / duration, 1);
        
        // 使用缓动函数
        const easedProgress = easeOutExpo(progress);
        
        // 计算当前值
        current = easedProgress * target;
        
        // 格式化
        let displayValue = prefix;
        if (isInteger) {
          displayValue += Math.round(current);
        } else if (isBalance) {
          displayValue += current.toFixed(2);
        } else {
          displayValue += Math.round(current * 100) / 100;
        }
        
        // 根据数值大小设置样式
        const numValue = parseFloat(current);
        
        // 计算字体大小: 1-9: 1.5rem, 10-99: 1.8rem, 100-999: 2.2rem, 1000+: 2.8rem
        let fontSize = '1.5rem';
        if (numValue >= 1000) {
          fontSize = '2.8rem';
        } else if (numValue >= 100) {
          fontSize = '2.2rem';
        } else if (numValue >= 10) {
          fontSize = '1.8rem';
        }
        
        // 计算颜色: 个位数红色, 十位数黑色, 百位数绿色, 千位数及以上彩色
        let color = '#e74c3c'; // 红色(个位数)
        
        if (numValue >= 1000) {
          // 千位数及以上: 渐变彩色
          const hue = (numValue % 360) || 50;
          color = \`linear-gradient(135deg, purple, #3498db, #f39c12)\`;
          element.style.webkitBackgroundClip = 'text';
          element.style.backgroundClip = 'text';
          element.style.color = 'transparent';
          element.style.backgroundImage = color;
          element.style.textShadow = '0 0 8px rgba(255,255,255,0.6)';
        } else if (numValue >= 120) {
          // 120以上: 完全绿色
          color = '#27ae60';
          element.style.backgroundImage = 'none';
          element.style.color = color;
          element.style.textShadow = 'none';
        } else if (numValue >= 80) {
          // 80-120: 从黑到绿的渐变 - 压缩到这个区间
          const greenIntensity = Math.min((numValue - 80) / 40, 1); // 40是区间宽度(120-80)
          const red = Math.round(44 - (44 * greenIntensity)); // 44->0
          const green = Math.round(44 + (130 * greenIntensity)); // 44->174
          const blue = Math.round(80 - (20 * greenIntensity)); // 80->60
          color = \`rgb(\${red}, \${green}, \${blue})\`;
          element.style.backgroundImage = 'none';
          element.style.color = color;
          element.style.textShadow = 'none';
        } else if (numValue >= 10) {
          // 十位数: 从红到黑的渐变
          const blackIntensity = Math.min((numValue - 10) / 70, 1); // 压缩到10-80区间
          const red = Math.round(231 - (231 - 44) * blackIntensity);
          const green = Math.round(76 - (76 - 44) * blackIntensity);
          const blue = Math.round(60 - (60 - 80) * blackIntensity);
          color = \`rgb(\${red}, \${green}, \${blue})\`;
          element.style.backgroundImage = 'none';
          element.style.color = color;
          element.style.textShadow = 'none';
        } else {
          // 个位数: 红色
          element.style.backgroundImage = 'none';
          element.style.color = '#e74c3c';
          element.style.textShadow = 'none';
        }
        
        // 应用样式
        element.style.fontSize = fontSize;
        element.style.fontWeight = numValue >= 100 ? '700' : '600';
        element.style.transition = 'all 0.2s ease';
        
        // 更新显示的值
        element.textContent = displayValue;
        
        // 判断是否继续动画
        if (progress < 1) {
          element._animationFrame = requestAnimationFrame(animate);
        }
      };
      
      // 启动动画
      element._animationFrame = requestAnimationFrame(animate);
    }
    
    // 将密钥复制到剪贴板
    function copyKey(key) {
      navigator.clipboard.writeText(key)
        .then(() => {
          // 找到被点击的元素
          const elements = document.querySelectorAll('.key-item');
          let targetElement;
          
          elements.forEach(el => {
            if (el.getAttribute('title') === key) {
              targetElement = el;
            }
          });
          
          if (targetElement) {
            // 添加复制成功动画类
            targetElement.classList.add('copy-success');
            
            // 显示通知
            showToast('已复制到剪贴板');
            
            // 一段时间后移除动画类
            setTimeout(() => {
              targetElement.classList.remove('copy-success');
            }, 1500);
          } else {
            showToast('已复制到剪贴板');
          }
        })
        .catch(err => {
          console.error('复制失败: ', err);
          showToast('复制失败', true);
        });
    }
    
    // 显示通知消息
    function showToast(message, isError = false) {
      toast.textContent = message;
      toast.style.background = isError ? 'rgba(231, 76, 60, 0.95)' : 'rgba(46, 204, 113, 0.95)';
      
      // 添加/移除错误类以显示正确的图标
      if (isError) {
        toast.classList.add('error');
      } else {
        toast.classList.remove('error');
      }
      
      toast.classList.add('show');
      
      setTimeout(() => {
        toast.classList.remove('show');
      }, 2500);
    }
    
    // 显示错误消息
    function showError(message) {
      keysContainer.innerHTML = \`<div class="empty-state">\${message}</div>\`;
    }
    
    // 处理分页
    prevPageBtn.addEventListener('click', () => {
      if (currentPage > 1) {
        currentPage--;
        renderKeys();
      }
    });
    
    nextPageBtn.addEventListener('click', () => {
      const totalPages = Math.ceil(allKeys.length / pageSize);
      if (currentPage < totalPages) {
        currentPage++;
        renderKeys();
      }
    });

    // 检查访问控制状态
    async function checkAccessControl() {
      try {
        // 显示正在检查权限的状态
        keysContainer.innerHTML = \`
          <div class="loading">
            <div>
              <span class="loader"></span>
              <span>检查访问权限...</span>
            </div>
          </div>
        \`;

        const response = await fetch('/admin/api/access-control');
        if (response.ok) {
          const data = await response.json();
          if (data.success) {
            accessControlMode = data.data.accessControl;
            
            // 根据访问控制模式执行不同操作
            if (accessControlMode === 'open') {
              // 完全开放，直接加载
              loadKeys();
            } else if (accessControlMode === 'private') {
              // 完全私有，显示管理员登录
              keysContainer.innerHTML = '<div class="empty-state">此页面仅限管理员访问<br><a href="/admin" style="color: #3498db;">前往管理员登录</a></div>';
            } else if (accessControlMode === 'restricted') {
              // 部分开放，检查是否已有token
              if (authToken) {
                // 尝试使用现有token加载
                loadKeys();
              } else {
                // 显示访客认证弹窗
                showAuthModal();
                // 清空加载中显示，同时添加一个认证按钮
                keysContainer.innerHTML = \`
                  <div class="empty-state">
                    <p>请输入访客密码继续访问</p>
                    <button id="show-auth-button" style="margin-top: 20px; background: #3498db; color: white; border: none; border-radius: 6px; padding: 10px 20px; cursor: pointer; font-size: 14px; transition: all 0.3s ease;">
                      点击认证
                    </button>
                  </div>
                \`;
                
                // 添加认证按钮的点击事件监听器
                setTimeout(() => {
                  const authButton = document.getElementById('show-auth-button');
                  if (authButton) {
                    authButton.addEventListener('click', showAuthModal);
                  }
                }, 0);
              }
            }
          }
        }
      } catch (error) {
        console.error('检查访问控制状态时出错:', error);
        showToast('无法获取页面访问状态', true);
        // 显示错误信息
        keysContainer.innerHTML = '<div class="empty-state">无法获取访问控制状态<br>请刷新页面重试</div>';
      }
    }

    // 显示认证弹窗
    function showAuthModal() {
      const authModal = document.getElementById('auth-modal');
      authModal.classList.add('show');
      
      // 聚焦到密码输入框
      setTimeout(() => {
        document.getElementById('guest-password').focus();
      }, 300);
    }

    // 验证访客密码
    async function verifyGuestPassword() {
      const passwordInput = document.getElementById('guest-password');
      const password = passwordInput.value.trim();
      const errorMsg = document.getElementById('auth-error');
      
      if (!password) {
        errorMsg.textContent = '请输入密码';
        errorMsg.style.display = 'block';
        return;
      }
      
      try {
        const response = await fetch('/admin/api/verify-guest', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ password })
        });
        
        const data = await response.json();
        
        if (data.success) {
          // 认证成功，保存token并加载密钥
          authToken = data.token;
          localStorage.setItem('guestToken', authToken);
          document.getElementById('auth-modal').classList.remove('show');
          loadKeys();
        } else {
          // 认证失败
          errorMsg.textContent = data.message || '密码不正确';
          errorMsg.style.display = 'block';
          passwordInput.focus();
        }
      } catch (error) {
        console.error('验证访客密码时出错:', error);
        errorMsg.textContent = '验证失败，请重试';
        errorMsg.style.display = 'block';
      }
    }
  </script>
</body>
</html>
`;

// 管理员界面的HTML内容
const adminHtmlContent = `
<!DOCTYPE html>
  <html lang="zh-CN">
  <head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>硅基流动Token管理 - 管理员</title>
  <link rel="icon" type="image/png" href="https://imgbed.killerbest.com/file/1742260658545_siliconcloud-color.png"/>
  <style>
    * {
      box-sizing: border-box;
    }
    body {
      margin: 0;
      padding: 0;
      background: linear-gradient(135deg, #f0f5fb, #c0d3ee);
      font-family: 'Inter', 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
      color: #333;
      min-height: 100vh;
    }
    .container {
      max-width: 1200px;
      background-color: #fff;
      margin: 20px auto;
      padding: 30px;
      border-radius: 12px;
      box-shadow: 0 6px 16px rgba(0,0,0,0.1);
    }
    @media (max-width: 1040px) {
      .container {
        margin: 15px;
        padding: 20px;
      }
    }
    .header {
      display: flex;
      align-items: center;
      margin-bottom: 30px;
      padding-bottom: 15px;
      border-bottom: 1px solid #e9ecef;
    }
    .logo {
      width: 48px;
      height: 48px;
      margin-right: 15px;
    }
    h1 {
      margin: 0;
      font-size: 1.8rem;
      color: #2c3e50;
      flex: 1;
    }
    .action-button {
      display: flex;
      align-items: center;
      gap: 8px;
      padding: 8px 16px;
      font-weight: 500;
      border-radius: 6px;
      transition: all 0.2s ease;
      position: relative;
      overflow: hidden;
    }

    .action-button svg {
      transition: transform 0.3s ease;
    }

    .action-button::before {
      content: '';
      position: absolute;
      top: 0;
      left: 0;
      width: 100%;
      height: 100%;
      background: linear-gradient(120deg, transparent, rgba(255, 255, 255, 0.3), transparent);
      transform: translateX(-100%);
      transition: transform 0.6s;
    }

    .action-button:hover::before {
      transform: translateX(100%);
    }

    .action-button:hover svg {
      transform: rotate(15deg);
    }

    /* API Key添加区域样式 */
    .key-management-container {
      display: flex;
      gap: 24px;
      margin-bottom: 25px;
    }

    .key-panel {
      flex: 1;
      display: flex;
      flex-direction: column;
    }

    .input-button-group {
      display: flex;
      gap: 10px;
      margin-bottom: 15px;
    }

    .input-button-group input {
      flex: 1;
    }

    .action-button.primary-btn {
      background: #3498db;
      color: white;
      border: none;
      border-radius: 6px;
      padding: 10px 18px;
      font-size: 15px;
      font-weight: 500;
      cursor: pointer;
      transition: all 0.2s ease;
      display: inline-flex;
      align-items: center;
      justify-content: center;
      gap: 8px;
      height: 42px;
      min-width: 90px;
    }

    .action-button.primary-btn:hover {
      background: #2980b9;
      transform: translateY(-2px);
      box-shadow: 0 3px 8px rgba(41, 128, 185, 0.3);
    }

    .action-button.primary-btn:active {
      transform: translateY(0);
    }

    .action-button.full-width {
      width: 100%;
      margin-top: 14px;
    }

    .form-group textarea {
      margin-bottom: 0;
      min-height: 120px;
    }

    .selection-controls {
      display: flex;
      align-items: center;
      justify-content: space-between;
      background: #f8f9fa;
      padding: 10px 14px;
      border-radius: 8px;
      margin-top: 5px;
      border: 1px solid #edf2f7;
    }

    .selection-count {
      font-size: 0.9rem;
      color: #495057;
      font-weight: 500;
    }

    .select-all-container {
      display: flex;
      align-items: center;
      gap: 8px;
      cursor: pointer;
      font-size: 0.9rem;
      color: #495057;
    }

    .select-all-container input {
      width: 16px;
      height: 16px;
    }

    /* 响应式调整 */
    @media (max-width: 768px) {
      .key-management-container {
        flex-direction: column;
        gap: 20px;
      }
      
      .selection-controls {
        margin-top: 10px;
      }
    }

    /* 优化设置按钮 */
    #toggle-batch-config {
      position: relative;
      z-index: 5;
    }

    #toggle-batch-config.active {
      background:rgb(0, 227, 182);
      border-bottom-left-radius: 0;
      border-bottom-right-radius: 0;
      border-bottom: 1px solid #f8f9fa;
      margin-bottom: -1px;
    }
    .home-link {
      text-decoration: none;
      color: #3498db;
      border: 1px solid #3498db;
      border-radius: 4px;
      padding: 8px 12px;
      font-size: 0.9rem;
      display: flex;
      align-items: center;
      transition: all 0.2s;
    }
    .home-link:hover {
      background: #3498db;
      color: white;
    }
    .tab-container {
      margin-bottom: 20px;
    }
    .tabs {
      display: flex;
      border-bottom: 1px solid #e9ecef;
      margin-bottom: 20px;
    }
    .tab {
      padding: 10px 20px;
      cursor: pointer;
      border-bottom: 3px solid transparent;
      transition: all 0.2s;
    }
    .tab.active {
      border-bottom-color: #3498db;
      color: #3498db;
      font-weight: 500;
    }
    .tab:hover:not(.active) {
      border-bottom-color: #bdc3c7;
    }
    .tab-content {
      display: none;
    }
    .tab-content.active {
      display: block;
    }

    /* 表单组样式优化 */
    .form-group {
      margin-bottom: 28px;
      padding: 22px 25px;
      background: #f8fafb;
      border-radius: 12px;
      box-shadow: 0 2px 10px rgba(0, 0, 0, 0.03);
      transition: all 0.3s ease;
      border: 1px solid #edf2f7;
    }

    .form-group:hover {
      box-shadow: 0 4px 15px rgba(52, 152, 219, 0.1);
      border-color: rgba(52, 152, 219, 0.2);
    }

    .form-group label {
      display: block;
      margin-bottom: 12px;
      font-weight: 600;
      color: #2c3e50;
      font-size: 1.05rem;
      letter-spacing: 0.3px;
    }

    /* 美化下拉菜单 */
    .form-control {
      display: block;
      width: 100%;
      padding: 12px 16px;
      font-size: 16px;
      font-weight: 500;
      color: #34495e;
      background-color: #fff;
      background-clip: padding-box;
      border: 1px solid #dde6ed;
      border-radius: 8px;
      transition: all 0.2s ease-in-out;
      box-shadow: 0 1px 3px rgba(0, 0, 0, 0.05);
      -webkit-appearance: none;
      -moz-appearance: none;
      appearance: none;
      background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='16' height='16' viewBox='0 0 24 24' fill='none' stroke='%233498db' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'%3E%3Cpolyline points='6 9 12 15 18 9'%3E%3C/polyline%3E%3C/svg%3E");
      background-repeat: no-repeat;
      background-position: right 15px center;
      background-size: 16px;
      cursor: pointer;
    }

    .form-control:focus {
      border-color: #3498db;
      outline: none;
      box-shadow: 0 0 0 4px rgba(52, 152, 219, 0.15);
    }

    .form-control:hover {
      border-color: #3498db;
    }

    /* 选项高亮样式 */
    .form-control option {
      padding: 12px;
      font-weight: 500;
    }

    /* 描述文本样式 */
    .form-group small {
      display: block;
      margin-top: 12px;
      padding: 12px 16px;
      color: #596775;
      font-size: 0.9rem;
      line-height: 1.6;
      background-color: rgba(236, 240, 245, 0.6);
      border-radius: 8px;
      border-left: 4px solid #3498db;
      box-shadow: inset 0 0 0 1px rgba(0, 0, 0, 0.03);
    }

    /* 强调各个模式 */
    .form-group small br {
      margin-bottom: 5px;
      content: "";
      display: block;
    }

    /* 增加可访问性 */
    .form-control:focus-visible {
      outline: 2px solid #3498db;
      outline-offset: 1px;
    }

    label {
      display: block;
      margin-bottom: 8px;
      font-weight: 500;
      color: #2c3e50;
    }
    input[type="text"],
    input[type="password"],
    input[type="number"],
    textarea {
      width: 100%;
      padding: 10px 12px;
      border: 1px solid #ddd;
      border-radius: 4px;
      font-size: 16px;
      transition: border-color 0.2s, box-shadow 0.2s;
    }
    input:focus,
    textarea:focus {
      border-color: #3498db;
      box-shadow: 0 0 0 3px rgba(52, 152, 219, 0.2);
      outline: none;
    }
    textarea {
      min-height: 150px;
      resize: vertical;
    }
    button {
      background: #3498db;
      color: white;
      border: none;
      border-radius: 4px;
      padding: 10px 20px;
      font-size: 16px;
      cursor: pointer;
      transition: background 0.2s, transform 0.1s;
    }
    button:hover {
      background: #2980b9;
    }
    button:active {
      transform: translateY(1px);
    }
    button.secondary {
      background: #95a5a6;
    }
    button.secondary:hover {
      background: #7f8c8d;
    }
    button.danger {
      background: #e74c3c;
    }
    button.danger:hover {
      background: #c0392b;
    }
    button.success {
      background: #2ecc71;
    }
    button.success:hover {
      background: #27ae60;
    }
    button:disabled {
      background: #bdc3c7;
      cursor: not-allowed;
    }
    .table-container {
      overflow-x: auto;
      margin-bottom: 20px;
    }
    table {
      width: 100%;
      border-collapse: collapse;
    }
    th, td {
      padding: 12px 15px;
      text-align: left;
      border-bottom: 1px solid #e9ecef;
    }
    th {
      background-color: #f8f9fa;
      font-weight: 600;
      color: #2c3e50;
    }
    tbody tr:hover {
      background-color: #f8f9fa;
    }
    .key-column {
      max-width: 300px;
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
      font-family: monospace;
      font-size: 0.85rem;
    }
    .actions-column {
      text-align: right;
      white-space: nowrap;
    }
    .action-icon {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      width: 32px;
      height: 32px;
      border-radius: 4px;
      background: #f1f2f6;
      margin-left: 5px;
      cursor: pointer;
      transition: background 0.2s;
    }
    .action-icon:hover {
      background: #dfe4ea;
    }
    .action-icon.delete:hover {
      background: #ff6b6b;
      color: white;
    }
    .toast {
      position: fixed;
      bottom: 20px;
      left: 50%;
      transform: translateX(-50%);
      background: rgba(46, 204, 113, 0.9);
      color: white;
      padding: 10px 20px;
      border-radius: 4px;
      font-size: 0.9rem;
      opacity: 0;
      transition: opacity 0.3s;
      pointer-events: none;
      z-index: 1000;
    }
    .toast.show {
      opacity: 1;
    }
    .stats-grid {
      display: grid;
      grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
      gap: 20px;
      margin-bottom: 30px;
    }
    .stat-card {
      background: #f8f9fa;
      border-radius: 8px;
      padding: 15px;
      display: flex;
      flex-direction: column;
      align-items: center;
      text-align: center;
    }
    .stat-value {
      font-size: 2rem;
      font-weight: 600;
      color: #2c3e50;
      margin: 10px 0;
    }
    .stat-label {
      color: #7f8c8d;
      font-size: 0.9rem;
    }
    .loader {
      display: inline-block;
      width: 20px;
      height: 20px;
      border: 3px solid rgba(255,255,255,.3);
      border-radius: 50%;
      border-top-color: white;
      animation: spin 1s ease-in-out infinite;
      margin-right: 10px;
    }
    @keyframes spin {
      to { transform: rotate(360deg); }
    }
    .empty-state {
      text-align: center;
      padding: 40px 0;
      color: #7f8c8d;
    }
    /* 添加错误信息显示样式 */
    .error-message {
      color: #e74c3c;
      font-size: 0.85rem;
      margin-top: 5px;
      display: block;
    }
    /* 密钥错误标记样式 */
    .key-error-icon {
      color: #e74c3c;
      margin-left: 5px;
      cursor: help;
    }
    .tooltip {
      position: relative;
      display: inline-block;
    }
    .tooltip .tooltip-text {
      visibility: hidden;
      width: 250px;
      background-color: #34495e;
      color: #fff;
      text-align: center;
      border-radius: 6px;
      padding: 10px;
      position: absolute;
      z-index: 1;
      bottom: 125%;
      left: 50%;
      transform: translateX(-50%);
      opacity: 0;
      transition: opacity 0.3s;
      font-size: 0.85rem;
      pointer-events: none;
    }
    .tooltip .tooltip-text::after {
      content: "";
      position: absolute;
      top: 100%;
      left: 50%;
      margin-left: -5px;
      border-width: 5px;
      border-style: solid;
      border-color: #34495e transparent transparent transparent;
    }
    .tooltip:hover .tooltip-text {
      visibility: visible;
      opacity: 1;
    }

    /* 自定义弹窗样式 */
    .modal-backdrop {
        position: fixed;
        top: 0;
        left: 0;
        right: 0;
        bottom: 0;
        background: rgba(0, 0, 0, 0.5);
        display: flex;
        align-items: center;
        justify-content: center;
        z-index: 1001;
        opacity: 0;
        visibility: hidden;
        transition: opacity 0.3s, visibility 0.3s;
    }
    
    .modal-backdrop.show {
        opacity: 1;
        visibility: visible;
    }
    
    .modal-content {
        background: white;
        border-radius: 8px;
        width: 90%;
        max-width: 500px;
        box-shadow: 0 10px 25px rgba(0, 0, 0, 0.2);
        overflow: hidden;
        transform: translateY(-20px);
        transition: transform 0.3s;
    }
    
    .modal-backdrop.show .modal-content {
        transform: translateY(0);
    }
    
    .modal-header {
        padding: 15px 20px;
        border-bottom: 1px solid #e9ecef;
        display: flex;
        justify-content: space-between;
        align-items: center;
    }
    
    .modal-title {
        margin: 0;
        font-size: 1.2rem;
        color: #2c3e50;
    }
    
    .modal-close {
        background: none;
        border: none;
        font-size: 1.5rem;
        cursor: pointer;
        color: #95a5a6;
        padding: 0;
    }
    
    .modal-body {
        padding: 20px;
    }
    
    .modal-footer {
        padding: 15px 20px;
        border-top: 1px solid #e9ecef;
        display: flex;
        justify-content: flex-end;
        gap: 10px;
    }
    
    .modal-input {
        width: 100%;
        padding: 10px 12px;
        border: 1px solid #ddd;
        border-radius: 4px;
        font-size: 16px;
        margin-bottom: 15px;
    }
    
    .modal-input:focus {
        border-color: #3498db;
        box-shadow: 0 0 0 3px rgba(52, 152, 219, 0.2);
        outline: none;
    }

    /* 进度条容器现代化样式 */
    .progress-container {
      position: fixed;
      bottom: 20px;
      right: 20px;
      width: 350px;
      background: rgba(255, 255, 255, 0.98);
      border-radius: 12px;
      padding: 22px;
      box-shadow: 0 10px 30px rgba(0,0,0,0.15), 0 0 0 1px rgba(52, 152, 219, 0.1);
      z-index: 1000;
      transition: transform 0.4s cubic-bezier(0.19, 1, 0.22, 1), opacity 0.3s ease;
      transform: translateY(150%);
      opacity: 0;
      display: flex;
      flex-direction: column;
      backdrop-filter: blur(10px);
      -webkit-backdrop-filter: blur(10px);
    }

    .progress-container.active {
      transform: translateY(0);
      opacity: 1;
    }

    .progress-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 15px;
    }

    .progress-title {
      font-weight: 600;
      color: #2c3e50;
      font-size: 1.1rem;
    }

    .progress-bar-container {
      height: 10px;
      background: #edf2f7;
      border-radius: 20px;
      overflow: hidden;
      margin-bottom: 12px;
      position: relative;
    }

    .progress-fill {
      height: 100%;
      background: linear-gradient(90deg, #3498db, #2ecc71);
      width: 0%;
      transition: width 0.5s cubic-bezier(0.19, 1, 0.22, 1);
      border-radius: 20px;
      position: relative;
    }


    /* 扫光动画 */
    .progress-fill::after {
      content: '';
      position: absolute;
      top: 0;
      left: 0;
      right: 0;
      bottom: 0;
      background: linear-gradient(
        90deg,
        rgba(255,255,255,0) 0%,
        rgba(255,255,255,0.4) 50%,
        rgba(255,255,255,0) 100%
      );
      transform: translateX(-100%);
      animation: scanLight 2s infinite;
    }

    @keyframes scanLight {
      0% {
        transform: translateX(-100%);
      }
      100% {
        transform: translateX(100%);
      }
    }

    .progress-stats {
      display: flex;
      justify-content: space-between;
      margin-bottom: 12px;
    }

    .progress-text {
      font-size: 0.9rem;
      color: #4a5568;
      font-weight: 500;
    }

    .progress-success-rate {
      font-size: 0.9rem;
      color: #2ecc71;
      font-weight: 600;
    }

    .progress-details {
      background: #f8fafc;
      border-radius: 8px;
      padding: 12px 15px;
      margin-top: 5px;
      margin-bottom: 15px;
      border: 1px solid #edf2f7;
    }

    .progress-details-row {
      display: flex;
      justify-content: space-between;
      margin-bottom: 5px;
      font-size: 0.85rem;
    }

    .progress-details-label {
      color: #718096;
      font-weight: 500;
    }

    .progress-details-value {
      color: #4a5568;
      font-weight: 600;
    }

    .progress-details-value.speed {
      color: #3498db;
    }

    .progress-details-value.eta {
      color: #e67e22;
    }

    .progress-close {
      background: rgba(237, 242, 247, 0.8);
      border: none;
      color: #718096;
      cursor: pointer;
      width: 28px;
      height: 28px;
      border-radius: 50%;
      display: flex;
      align-items: center;
      justify-content: center;
      font-size: 1.2rem;
      padding: 0;
      transition: all 0.2s ease;
    }

    .progress-close:hover {
      background: rgba(226, 232, 240, 1);
      color: #4a5568;
      transform: rotate(90deg);
    }

    .admin-normal-status {
      color: #2ecc71; 
      text-shadow: 0 0 5px rgba(46, 204, 113, 0.7);
    }

    /* 增加多选功能样式 */
    .key-checkbox {
      position: absolute;
      top: 10px;
      right: 10px;
      width: 18px;
      height: 18px;
      cursor: pointer;
      z-index: 5;
      opacity: 0.7;
      transition: all 0.2s ease;
    }
    
    .key-checkbox:hover,
    .key-checkbox:checked {
      opacity: 1;
    }
    
    .key-item.selected {
      border: 2px solid #3498db;
      background-color: rgba(52, 152, 219, 0.05);
    }
    
    /* 批量操作面板 */
    .batch-actions {
      background: #fff;
      border-radius: 12px;
      padding: 20px;
      margin-bottom: 20px;
      box-shadow: 0 4px 12px rgba(0,0,0,0.06);
      display: flex;
      flex-wrap: wrap;
      justify-content: space-between;
      align-items: center;
      gap: 15px;
    }

    .batch-actions-title {
      font-weight: 600;
      color: #2c3e50;
      margin: 0;
      font-size: 1.1rem;
    }

    .batch-actions-controls {
      display: flex;
      gap: 10px;
      align-items: center;
    }

    .action-button {
      display: flex;
      align-items: center;
      gap: 8px;
      padding: 8px 16px;
      font-weight: 500;
      border-radius: 6px;
      transition: all 0.2s ease;
    }

    .action-button svg {
      transition: transform 0.3s ease;
    }

    .action-button:hover svg {
      transform: scale(1.1);
    }

    .batch-config-panel {
      width: 100%;
      max-height: 0;
      overflow: hidden;
      padding: 0 18px;
      background: #f8f9fa;
      border-radius: 8px;
      margin-top: 15px;
      border: 1px solid transparent;
      transition: all 0.3s ease, max-height 0.5s ease;
      opacity: 0;
    }

    .batch-config-panel.show {
      max-height: 500px;
      padding: 18px;
      border-color: #e9ecef;
      opacity: 1;
    }

    .config-section {
      margin-bottom: 18px;
    }

    .config-section-title {
      font-weight: 600;
      font-size: 0.95rem;
      color: #495057;
      margin-bottom: 12px;
      padding-bottom: 6px;
      border-bottom: 1px solid #e9ecef;
    }

    .config-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
      gap: 15px;
    }
    
    .batch-config-item {
      display: flex;
      flex-direction: column;
    }

    .batch-config-item label {
      font-size: 0.85rem;
      margin-bottom: 6px;
      color: #495057;
    }

    .batch-config-item input,
    .batch-config-item select {
      padding: 9px 12px;
      border: 1px solid #ced4da;
      border-radius: 6px;
      font-size: 0.9rem;
      transition: all 0.2s ease;
      background-color: #fff;
      box-shadow: 0 1px 3px rgba(0,0,0,0.04);
    }

    .batch-config-item input:focus,
    .batch-config-item select:focus {
      border-color: #3498db;
      box-shadow: 0 0 0 3px rgba(52, 152, 219, 0.15);
      outline: none;
    }

    
    .batch-config-button {
      margin-top: auto;
      align-self: flex-end;
    }
    
    /* 选择计数和全选控件 */

    .select-wrapper {
      position: relative;
      display: flex;
      background-color: #fff;
      border-radius: 6px;
      overflow: hidden;
      border: 1px solid #ced4da;
      box-shadow: 0 1px 3px rgba(0,0,0,0.04);
    }

    .select-wrapper select {
      appearance: none;
      width: 100%;
      padding: 9px 32px 9px 12px;
      background: transparent;
      border: none;
      font-size: 0.9rem;
      color: #495057;
      cursor: pointer;
      outline: none;
    }

    .select-wrapper:hover {
      border-color: #adb5bd;
    }

    .select-wrapper:focus-within {
      border-color: #3498db;
      box-shadow: 0 0 0 3px rgba(52, 152, 219, 0.15);
    }

    .select-wrapper svg {
      position: absolute;
      right: 10px;
      top: 50%;
      transform: translateY(-50%);
      pointer-events: none;
      color: #6c757d;
      transition: transform 0.2s ease;
    }

    .select-wrapper:focus-within svg {
      transform: translateY(-50%) rotate(180deg);
      color: #3498db;
    }

    /* 响应式调整 */
    @media (max-width: 768px) {
      .config-grid {
        grid-template-columns: 1fr;
      }
      
      .batch-actions {
        flex-direction: column;
        align-items: stretch;
      }
      
      .batch-actions-controls {
        justify-content: flex-start;
        flex-wrap: wrap;
      }
    }

    /* 下拉菜单样式 */
    .dropdown {
      position: relative;
      display: inline-block;
    }
    
    .dropdown-content {
      display: none;
      position: absolute;
      right: 0;
      min-width: 160px;
      background-color: #fff;
      border-radius: 8px;
      box-shadow: 0 8px 20px rgba(0, 0, 0, 0.15);
      z-index: 1;
      overflow: hidden;
      transition: all 0.2s ease;
      transform-origin: top right;
      transform: scale(0.95);
      opacity: 0;
    }
    
    .dropdown-content.show {
      display: block;
      transform: scale(1);
      opacity: 1;
    }
    
    .dropdown-content a {
      color: #2c3e50;
      padding: 12px 16px;
      text-decoration: none;
      display: block;
      transition: background-color 0.2s;
      font-size: 0.9rem;
    }
    
    .dropdown-content a:hover {
      background-color: #f1f1f1;
      color: #3498db;
    }
    
    .dropdown-content a:not(:last-child) {
      border-bottom: 1px solid #f1f1f1;
    }

    /* 更多菜单按钮活跃状态样式 */
    #more-actions.active {
      background-color:rgb(29, 215, 209);
      color: white;
      box-shadow: 0 4px 8px rgba(52, 152, 219, 0.25);
    }

    #more-actions.active svg {
      transform: rotate(90deg);
    }

    /* 停止按钮样式 */
    .stop-batch-button {
      margin-top: 5px;
      width: 100%;
      padding: 10px 0;
      background: #e74c3c;
      color: white;
      border: none;
      border-radius: 8px;
      font-weight: 500;
      cursor: pointer;
      transition: all 0.2s ease;
      box-shadow: 0 2px 5px rgba(231, 76, 60, 0.25);
      position: relative;
      overflow: hidden;
    }

    .stop-batch-button:hover {
      background: #c0392b;
      transform: translateY(-2px);
      box-shadow: 0 4px 8px rgba(231, 76, 60, 0.3);
    }

    .stop-batch-button:active {
      transform: translateY(0);
    }

    .stop-batch-button:disabled {
      background: #bdc3c7;
      cursor: not-allowed;
      transform: none;
      box-shadow: none;
    }


    /* 扫光动画 */
    .stop-batch-button::after {
      content: "";
      position: absolute;
      top: 0;
      left: 0;
      width: 100%;
      height: 100%;
      background: linear-gradient(
        90deg,
        rgba(255,255,255,0) 0%,
        rgba(255,255,255,0.2) 50%,
        rgba(255,255,255,0) 100%
      );
      transform: translateX(-100%);
      transition: transform 0.5s ease;
    }

    .stop-batch-button:hover::after:not(:disabled) {
      transform: translateX(100%);
    }

    /* 排序相关样式 */
    .sort-header {
      cursor: pointer;
      user-select: none;
      position: relative;
    }
    
    .sort-header:hover {
      background: #f1f5f9;
    }
    
    .sort-icon {
      position: relative;
      display: inline-block;
      margin-left: 4px;
      opacity: 0.3;
      transition: all 0.2s ease;
      vertical-align: middle;
    }
    
    .sort-icon.active {
      opacity: 1;
      color: #3498db;
    }
    
    .sort-icon.asc .sort-arrow {
      transform: rotate(180deg);
    }
    
    .row-number {
      font-weight: 600;
      text-align: center;
      color: #64748b;
      font-family: monospace;
      font-size: 0.9rem;
    }
    
    /* 高亮选中行 */
    #all-keys-table tbody tr.selected-row {
      background: rgba(52, 152, 219, 0.1);
      box-shadow: 0 0 8px rgba(52, 152, 219, 0.3);
      position: relative;
    }

    #all-keys-table tbody tr.selected-row td {
      border-bottom-color: rgba(52, 152, 219, 0.3);
    }

    #all-keys-table tbody tr.selected-row .row-number {
      color: #3498db;
      font-weight: 700;
    }


    /* 图表相关样式 */
    .charts-control {
      display: flex;
      align-items: center;
      justify-content: space-between;
      margin: 25px 0 15px;
      padding: 15px;
      background: #f8f9fa;
      border-radius: 10px;
      box-shadow: 0 2px 8px rgba(0,0,0,0.04);
    }
    
    .charts-period-selector {
      display: flex;
      align-items: center;
      gap: 10px;
    }
    
    .charts-period-selector select {
      padding: 8px 12px;
      border: 1px solid #ddd;
      border-radius: 6px;
      background-color: white;
      font-size: 0.9rem;
      cursor: pointer;
    }
    
    .charts-grid {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 20px;
      margin-bottom: 25px;
    }
    
    .chart-container {
      background: white;
      border-radius: 12px;
      padding: 20px;
      box-shadow: 0 4px 15px rgba(0,0,0,0.05);
      border: 1px solid #edf2f7;
      position: relative;
      height: 340px;
      transition: transform 0.3s ease, box-shadow 0.3s ease;
    }
    
    .chart-container:hover {
      transform: translateY(-3px);
      box-shadow: 0 8px 20px rgba(0,0,0,0.08);
    }
    
    .chart-container h3 {
      margin-top: 0;
      margin-bottom: 15px;
      font-size: 1.1rem;
      color: #2c3e50;
      text-align: center;
    }
    
    .chart-full-container {
      background: white;
      border-radius: 12px;
      padding: 20px;
      box-shadow: 0 4px 15px rgba(0,0,0,0.05);
      border: 1px solid #edf2f7;
      margin-bottom: 30px;
      height: 350px;
      position: relative;
    }
    
    .chart-full-container h3 {
      margin-top: 0;
      margin-bottom: 15px;
      font-size: 1.1rem;
      color: #2c3e50;
    }
    
    .chart-options {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 15px;
    }
    
    .chart-option-btn {
      padding: 6px 12px;
      background: #f1f8ff;
      border: 1px solid #b3d7ff;
      border-radius: 4px;
      color: #3498db;
      font-size: 0.85rem;
      cursor: pointer;
      transition: all 0.2s;
    }
    
    .chart-option-btn:hover {
      background: #e1f0ff;
    }
    
    .chart-range-selector {
      display: flex;
      align-items: center;
      gap: 8px;
      font-size: 0.9rem;
    }
    
    .chart-range-selector select {
      padding: 6px 10px;
      border: 1px solid #ddd;
      border-radius: 4px;
      font-size: 0.85rem;
    }
    
    .balance-stats-container {
      display: grid;
      grid-template-columns: repeat(4, 1fr);
      gap: 20px;
      margin-bottom: 30px;
    }
    
    .balance-stat-card {
      background: white;
      border-radius: 12px;
      padding: 20px;
      box-shadow: 0 4px 12px rgba(0,0,0,0.04);
      border: 1px solid #edf2f7;
      display: flex;
      align-items: center;
      transition: all 0.3s ease;
    }
    
    .balance-stat-card:hover {
      transform: translateY(-3px);
      box-shadow: 0 8px 20px rgba(0,0,0,0.08);
    }
    
    .balance-stat-icon {
      width: 48px;
      height: 48px;
      border-radius: 12px;
      display: flex;
      align-items: center;
      justify-content: center;
      margin-right: 16px;
      flex-shrink: 0;
    }
    
    .balance-stat-icon.max {
      background: linear-gradient(45deg, #4ade80, #22c55e);
      color: white;
    }
    
    .balance-stat-icon.min {
      background: linear-gradient(45deg, #fb7185, #e11d48);
      color: white;
    }
    
    .balance-stat-icon.median {
      background: linear-gradient(45deg, #818cf8, #4f46e5);
      color: white;
    }
    
    .balance-stat-icon.total {
      background: linear-gradient(45deg, #facc15, #eab308);
      color: white;
    }
    
    .balance-stat-content {
      flex: 1;
    }
    
    .balance-stat-value {
      font-size: 1.6rem;
      font-weight: 700;
      color: #1e293b;
      margin-bottom: 4px;
      line-height: 1;
    }
    
    .balance-stat-label {
      font-size: 0.9rem;
      color: #64748b;
    }
    
    /* 响应式调整 */
    @media (max-width: 992px) {
      .charts-grid,
      .balance-stats-container {
        grid-template-columns: 1fr;
      }
      
      .chart-container,
      .chart-full-container {
        height: 300px;
        width: 100%;
      }
    }
    
    @media (max-width: 768px) {
      .charts-control {
        flex-direction: column;
        gap: 12px;
        align-items: flex-start;
      }
      
      .charts-period-selector {
        width: 100%;
        justify-content: flex-end;
      }
      
      .chart-options {
        flex-direction: column;
        align-items: flex-start;
        gap: 10px;
      }
    }

    /* 分隔符控制样式 */
    .delimiter-control {
      display: flex;
      align-items: center;
      margin-left: 15px;
      padding: 8px 12px;
      background: linear-gradient(to right, #f8f9fa, #f1f3f5);
      border-radius: 8px;
      font-size: 0.9rem;
      box-shadow: 0 1px 3px rgba(0,0,0,0.05);
      border: 1px solid #edf2f7;
      transition: all 0.2s ease;
    }

    .delimiter-control:hover {
      box-shadow: 0 2px 5px rgba(0,0,0,0.08);
      border-color: #dbe4f0;
    }

    .delimiter-control label {
      margin: 0 10px 0 0;
      font-weight: 500;
      color: #3c4858;
      white-space: nowrap;
    }

    .form-control-sm {
      padding: 5px 10px;
      font-size: 0.85rem;
      height: 30px;
      border-radius: 5px;
      border: 1px solid #cbd5e0;
      background-color: #fff;
      box-shadow: inset 0 1px 2px rgba(0,0,0,0.05);
      transition: all 0.2s ease;
      width: auto;
      min-width: 120px;
    }

    .form-control-sm:focus {
      border-color: #4299e1;
      box-shadow: 0 0 0 3px rgba(66, 153, 225, 0.15);
      outline: none;
    }

    .delimiter-preview {
      margin-left: 10px;
      padding: 4px 10px;
      background: #e2e8f0;
      border-radius: 6px;
      font-family: 'Fira Code', 'Consolas', monospace;
      color: #2d3748;
      font-size: 0.9rem;
      font-weight: 600;
      letter-spacing: 0.5px;
      border: 1px solid rgba(0,0,0,0.05);
      box-shadow: inset 0 1px 2px rgba(0,0,0,0.04);
      transition: all 0.2s ease;
      display: inline-flex;
      align-items: center;
    }

    .delimiter-preview::before {
      content: "预览:";
      font-size: 0.75rem;
      font-weight: normal;
      color: #718096;
      margin-right: 5px;
      opacity: 0.7;
    }

    #custom-delimiter {
      width: 80px;
      margin-left: 8px;
      text-align: center;
      font-family: monospace;
      font-weight: 600;
      transition: all 0.3s ease;
      border-color: #4299e1;
    }

    /* Github 链接样式 */
    .github-link {
      display: flex;
      align-items: center;
      gap: 6px;
      text-decoration: none;
      color: #333;
      background: #f1f1f1;
      border: 1px solid #ddd;
      border-radius: 4px;
      padding: 6px 10px;
      font-size: 0.9rem;
      margin-right: 10px;
      transition: all 0.2s;
    }
    
    .github-link:hover {
      background: #333;
      color: white;
      border-color: #333;
    }
    
    .github-link svg {
      transition: transform 0.2s;
    }
    
    .github-link:hover svg {
      transform: rotate(360deg);
    }

    .action-buttons {
      display: flex;
      align-items: center;
      gap: 10px;
    }

    @media (max-width: 768px) {
      .action-buttons {
        margin-top: 10px;
        justify-content: center;
      }
    }

  </style>
  <!-- 添加Chart.js库 -->
  <script src="https://cdn.jsdelivr.net/npm/chart.js@3.9.1/dist/chart.min.js"></script>
  <script src="https://cdn.jsdelivr.net/npm/chartjs-adapter-date-fns@2.0.0/dist/chartjs-adapter-date-fns.bundle.min.js"></script>
</head>
<body>
  <div class="container">
    <div class="header">
      <img src="https://imgbed.killerbest.com/file/1742260658545_siliconcloud-color.png" alt="logo" class="logo"/>
      <h1>硅基流动Token管理 - 管理员</h1>
      <div class="action-buttons">
        <a href="https://github.com/Dr-Ai-0018/Siliconflow-API-Management" target="_blank" class="github-link">
          <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <path d="M9 19c-5 1.5-5-2.5-7-3m14 6v-3.87a3.37 3.37 0 0 0-.94-2.61c3.14-.35 6.44-1.54 6.44-7A5.44 5.44 0 0 0 20 4.77 5.07 5.07 0 0 0 19.91 1S18.73.65 16 2.48a13.38 13.38 0 0 0-7 0C6.27.65 5.09 1 5.09 1A5.07 5.07 0 0 0 5 4.77a5.44 5.44 0 0 0-1.5 3.78c0 5.42 3.3 6.61 6.44 7A3.37 3.37 0 0 0 9 18.13V22"></path>
          </svg>
          GitHub
        </a>
        <a href="/" class="home-link">返回主页</a>
      </div>
    </div>
    
    <div class="tab-container">
      <div class="tabs">
        <div class="tab active" data-tab="dashboard">仪表盘</div>
        <div class="tab" data-tab="keys">管理API Keys</div>
        <div class="tab" data-tab="settings">系统设置</div>
      </div>
      
      <!-- Dashboard Tab -->
      <div class="tab-content active" id="dashboard">
        <div class="stats-grid">
          <div class="stat-card">
            <div class="stat-label">总API Keys</div>
            <div id="total-keys-stat" class="stat-value">-</div>
          </div>
          <div class="stat-card">
            <div class="stat-label">有效API Keys</div>
            <div id="valid-keys-stat" class="stat-value">-</div>
          </div>
          <div class="stat-card">
            <div class="stat-label">无效API Keys</div>
            <div id="invalid-keys-stat" class="stat-value">-</div>
          </div>
          <div class="stat-card">
            <div class="stat-label">平均余额</div>
            <div id="avg-balance-stat" class="stat-value">-</div>
          </div>
        </div>
        
        <h2>最近添加的API Keys</h2>
        <div class="table-container">
          <table id="recent-keys-table">
            <thead>
              <tr>
                <th>API Key</th>
                <th>余额</th>
                <th>添加时间</th>
                <th>状态</th>
              </tr>
            </thead>
            <tbody>
              <tr>
                <td colspan="4" class="empty-state">加载中...</td>
              </tr>
            </tbody>
          </table>
        </div>

        <!-- 新增: 图表控制区域 -->
        <div class="charts-control">
          <button id="refresh-stats-btn" class="success">刷新统计</button>
          <button id="update-balances-btn" style="margin-left: 15px;">更新所有余额</button>
          <div class="charts-period-selector">
            <label>数据周期: </label>
            <select id="chart-period">
              <option value="all" selected>全部数据</option>
              <option value="week">最近7天</option>
              <option value="month">最近30天</option>
            </select>
          </div>
        </div>
        
        <!-- 新增: 图表区域 -->
        <div class="charts-grid">
          <div class="chart-container">
            <h3>余额分布</h3>
            <canvas id="balance-distribution-chart"></canvas>
          </div>
          <div class="chart-container">
            <h3>密钥状态分布</h3>
            <canvas id="key-status-chart"></canvas>
          </div>
        </div>
        
        <!-- 新增: 余额统计信息 -->
        <div class="balance-stats-container">
          <div class="balance-stat-card">
            <div class="balance-stat-icon max">
              <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <polyline points="18 15 12 9 6 15"></polyline>
              </svg>
            </div>
            <div class="balance-stat-content">
              <div class="balance-stat-value" id="max-balance">-</div>
              <div class="balance-stat-label">最高余额</div>
            </div>
          </div>
          <div class="balance-stat-card">
            <div class="balance-stat-icon min">
              <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <polyline points="6 9 12 15 18 9"></polyline>
              </svg>
            </div>
            <div class="balance-stat-content">
              <div class="balance-stat-value" id="min-balance">-</div>
              <div class="balance-stat-label">最低有效余额</div>
            </div>
          </div>
          <div class="balance-stat-card">
            <div class="balance-stat-icon median">
              <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <line x1="18" y1="20" x2="18" y2="10"></line>
                <line x1="12" y1="20" x2="12" y2="4"></line>
                <line x1="6" y1="20" x2="6" y2="14"></line>
              </svg>
            </div>
            <div class="balance-stat-content">
              <div class="balance-stat-value" id="median-balance">-</div>
              <div class="balance-stat-label">中位数余额</div>
            </div>
          </div>
          <div class="balance-stat-card">
            <div class="balance-stat-icon total">
              <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <rect x="2" y="7" width="20" height="14" rx="2" ry="2"></rect>
                <path d="M16 21V5a2 2 0 0 0-2-2h-4a2 2 0 0 0-2 2v16"></path>
              </svg>
            </div>
            <div class="balance-stat-content">
              <div class="balance-stat-value" id="total-balance">-</div>
              <div class="balance-stat-label">总余额</div>
            </div>
          </div>
        </div>
        
        <!-- 新增: 使用趋势图 -->
        <div class="chart-full-container">
          <h3>余额趋势</h3>
          <div class="chart-options">
            <button id="toggle-trend-view" class="chart-option-btn">显示/隐藏异常值</button>
            <div class="chart-range-selector">
              <label>显示范围:</label>
              <select id="trend-range">
                <option value="10">前10项</option>
                <option value="20" selected>前20项</option>
                <option value="50">前50项</option>
                <option value="all">全部</option>
              </select>
            </div>
          </div>
          <canvas id="balance-trend-chart"></canvas>
        </div>

      </div>
      
      <!-- Keys Management Tab -->
      <div class="tab-content" id="keys">
        <div class="batch-actions">
          <h3 class="batch-actions-title">API Key 管理</h3>

          <div class="delimiter-control">
            <label for="delimiter-select">分隔符:</label>
            <select id="delimiter-select" class="form-control-sm">
              <option value="newline" selected>换行符</option>
              <option value="comma">逗号</option>
              <option value="space">空格</option>
              <option value="semicolon">分号</option>
              <option value="tab">制表符</option>
              <option value="custom">自定义...</option>
            </select>
            <span id="delimiter-display" class="delimiter-preview">"\\n"</span>
            <input type="text" id="custom-delimiter" class="form-control-sm" style="display:none; width:60px; margin-left:5px;" maxlength="10" placeholder="自定义">
          </div>

          <div class="batch-actions-controls">
            <button id="toggle-batch-config" class="secondary action-button">
              <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <circle cx="12" cy="12" r="3"></circle>
                <path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z"></path>
              </svg>
              <span>设置</span>
            </button>
            <button id="check-selected-keys" class="action-button" disabled>
              <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <circle cx="12" cy="12" r="10"></circle>
                <path d="M12 6v6l4 2"></path>
              </svg>
              <span>检测</span>
            </button>
            <button id="delete-selected-keys" class="danger action-button" disabled>
              <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <polyline points="3 6 5 6 21 6"></polyline>
                <path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path>
              </svg>
              <span>删除</span>
            <!-- 导出密钥 -->
            </button>
            <button id="export-selected-keys" class="action-button" disabled>
              <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path>
                <polyline points="7 10 12 15 17 10"></polyline>
                <line x1="12" y1="15" x2="12" y2="3"></line>
              </svg>
              <span>导出</span>
            </button>
            <div class="dropdown">
              <button id="more-actions" class="secondary action-button">
                <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                  <circle cx="12" cy="12" r="1"></circle>
                  <circle cx="19" cy="12" r="1"></circle>
                  <circle cx="5" cy="12" r="1"></circle>
                </svg>
                <span>更多</span>
              </button>
              <div class="dropdown-content">
                <a href="#" id="clear-invalid-keys">一键清除无效密钥</a>
                <a href="#" id="export-valid-keys">导出所有有效密钥</a>
                <a href="#" id="export-balance-keys">导出高余额密钥</a>
                <a href="#" id="copy-all-keys">复制所有密钥</a>
                <a href="#" id="copy-selected-keys">复制所选密钥</a>
              </div>
            </div>
          </div>

          <!-- 添加余额过滤导出模态框 -->
          <div id="balance-filter-modal" class="modal-backdrop">
            <div class="modal-content">
              <div class="modal-header">
                <h3 class="modal-title">导出高于指定余额的密钥</h3>
                <button class="modal-close" onclick="closeBalanceFilterModal()">&times;</button>
              </div>
              <div class="modal-body">
                <p>请输入最低余额阈值，将导出所有余额高于该值的密钥：</p>
                <div class="form-group">
                  <input type="number" id="min-balance-input" class="modal-input" value="10" min="0" step="0.01" placeholder="最低余额">
                </div>
                <div class="form-group">
                  <label>
                    <input type="checkbox" id="include-balances" checked> 包含余额值
                  </label>
                </div>
              </div>
              <div class="modal-footer">
                <button class="secondary" onclick="closeBalanceFilterModal()">取消</button>
                <button id="export-filtered-keys" class="success">导出</button>
              </div>
            </div>
          </div>
                  
          <!-- 批量检测设置 -->
          <div id="batch-config-panel" class="batch-config-panel">
            <div class="config-section">
              <div class="config-section-title">批量测试-高级设置</div>
              <div class="config-grid">
              <div class="batch-config-item">
                <label for="interval-type">间隔类型</label>
                <div class="select-wrapper">
                  <select id="interval-type" class="enhanced-select">
                    <option value="fixed">固定间隔</option>
                    <option value="random" selected>随机间隔</option>
                  </select>
                  <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="6 9 12 15 18 9"></polyline></svg>
                </div>
              </div>
                
                <div class="batch-config-item">
                  <label for="min-interval">最小间隔 (ms)</label>
                  <input type="number" id="min-interval" value="500" min="100" max="10000">
                </div>
                
                <div class="batch-config-item">
                  <label for="max-interval">最大间隔 (ms)</label>
                  <input type="number" id="max-interval" value="1500" min="100" max="10000">
                </div>
              </div>
            </div>
            
            <div class="config-section">
              <div class="config-section-title">请求间隔与重试</div>
              <div class="config-grid">
                <div class="batch-config-item">
                  <label for="concurrency">固定间隔秒数</label>
                  <input type="number" id="concurrency" value="1" min="0" step="0.1" max="100">
                </div>
                
                <div class="batch-config-item">
                  <label for="retry-count">重试次数</label>
                  <input type="number" id="retry-count" value="1" min="0" max="5">
                </div>
                
                <div class="batch-config-item">
                  <label for="retry-interval">重试间隔 (ms)</label>
                  <input type="number" id="retry-interval" value="2000" min="0" max="10000">
                </div>
              </div>
            </div>
          </div>
        </div>
        
        <div class="key-management-container">
          <!-- 左侧：添加单个Key -->
          <div class="key-panel">
            <div class="form-group">
              <label for="add-key-input">添加单个API Key</label>
              <div class="input-button-group">
                <input type="text" id="add-key-input" placeholder="输入API Key">
                <button id="add-key-btn" class="action-button primary-btn">
                  <span>添加</span>
                </button>
              </div>
            </div>
            
            <!-- 选择控件 -->
            <div class="selection-controls">
              <span id="selection-count" class="selection-count">已选择 0 个 Key</span>
              <label class="select-all-container">
                <input type="checkbox" id="select-all-keys">
                <span>全选/取消全选</span>
              </label>
            </div>
          </div>
          
          <!-- 右侧：批量添加Keys -->
          <div class="key-panel">
            <div class="form-group">
              <label for="bulk-keys-input">批量添加API Keys（每行一个）</label>
              <textarea id="bulk-keys-input" placeholder="每行输入一个API Key"></textarea>
              <button id="add-bulk-keys-btn" class="action-button primary-btn full-width">
                <span>批量添加</span>
              </button>
            </div>
          </div>
        </div>
        
        <h2>所有API Keys</h2>
        <div class="table-container">
          <table id="all-keys-table">
            <thead>
              <tr>
                <th width="50px">序号</th>
                <th width="30px"><input type="checkbox" id="select-all-table"></th>
                <th>API Key</th>
                <th>余额</th>
                <th>最后更新时间</th>
                <th>添加时间</th>
                <th>状态</th>
                <th>操作</th>
              </tr>
            </thead>
            <tbody>
              <tr>
                <td colspan="6" class="empty-state">加载中...</td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
      
      <!-- Settings Tab -->
      <div class="tab-content" id="settings">
      <form id="settings-form" onsubmit="saveSettings(event)">
        <div class="form-group">
          <label for="api-key-input">API代理密钥</label>
          <input type="text" id="api-key-input" placeholder="设置API代理密钥">
          <small style="display: block; margin-top: 5px; color: #7f8c8d;">用于API代理请求的鉴权密钥</small>

          <div style="margin-top: 20px;">
            <label for="admin-username-input">管理员用户名</label>
            <input type="text" id="admin-username-input" placeholder="设置管理员用户名">
          </div>

          <div style="margin-top: 20px;">
            <label for="admin-password-input">管理员密码</label>
            <input type="password" id="admin-password-input" placeholder="设置管理员密码" autocomplete="new-password">
          </div>

          <div style="margin-top: 20px;">
            <label for="page-size-input">每页显示数量</label>
            <input type="number" id="page-size-input" placeholder="设置每页显示数量" min="1" max="100">
          </div>

          <div style="margin-top: 20px;">
            <label for="access-control-select">访问控制模式</label>
            <select id="access-control-select" class="form-control">
              <option value="open">完全开放</option>
              <option value="restricted">部分开放</option>
              <option value="private">完全私有</option>
            </select>
            <small style="display: block; margin-top: 5px; color: #7f8c8d;">
              完全开放：所有访客都可以查看密钥列表<br>
              部分开放：需要输入访客密码才能查看<br>
              完全私有：只有管理员登录后才能查看
            </small>
          </div>
        </div>

          <div class="form-group" id="guest-password-group" style="display: none;">
            <label for="guest-password-input">访客密码</label>
            <input type="password" id="guest-password-input" placeholder="设置访客密码" autocomplete="new-password">
            <small style="display: block; margin-top: 5px; color: #7f8c8d;">当选择"部分开放"模式时，访客需要输入此密码才能查看密钥列表</small>
          </div>
          
          <button type="submit" id="save-settings-btn">保存设置</button>
      </form>
      </div>
    </div>
  </div>


  <div id="custom-modal" class="modal-backdrop">
    <div class="modal-content">
        <div class="modal-header">
        <h3 class="modal-title">提示</h3>
        <button class="modal-close" onclick="closeModal()">&times;</button>
        </div>
        <div class="modal-body">
        <p id="modal-message">内容</p>
        <div id="modal-input-container" style="display: none;">
            <input type="text" id="modal-input" class="modal-input">
        </div>
        </div>
        <div class="modal-footer">
        <button id="modal-cancel" class="secondary" onclick="closeModal()">取消</button>
        <button id="modal-confirm" onclick="handleModalConfirm()">确认</button>
        </div>
    </div>
  </div>

  <div id="progress-container" class="progress-container">
    <div class="progress-header">
      <span class="progress-title">更新密钥余额中</span>
      <button class="progress-close" onclick="hideProgress()">&times;</button>
    </div>
    <div class="progress-bar-container">
      <div id="progress-fill" class="progress-fill"></div>
    </div>
    <div class="progress-stats">
      <span id="progress-text" class="progress-text">0/0 (0%)</span>
      <span id="progress-success-rate" class="progress-success-rate">成功: 0</span>
    </div>
    <div id="progress-details" class="progress-details">
      <div class="progress-details-row">
        <span class="progress-details-label">处理速度:</span>
        <span id="progress-speed" class="progress-details-value speed">计算中...</span>
      </div>
      <div class="progress-details-row">
        <span class="progress-details-label">预计剩余时间:</span>
        <span id="progress-eta" class="progress-details-value eta">计算中...</span>
      </div>
      <div class="progress-details-row">
        <span class="progress-details-label">已用时间:</span>
        <span id="progress-elapsed" class="progress-details-value">0秒</span>
      </div>
    </div>
    <button id="stop-batch-process" class="stop-batch-button">停止检测</button>
  </div>

  <div id="toast" class="toast"></div>
  
  <script>
    // 标签功能
    const tabs = document.querySelectorAll('.tab');
    const tabContents = document.querySelectorAll('.tab-content');

    // 弹窗功能
    let modalCallback = null;
    let modalInputType = 'text';

    // 选中key
    let selectedKeys = new Set();

    // 停止检测
    let isBatchProcessingStopped = false;

    // 排序变量
    let currentSortField = 'added'; // 默认按添加时间排序
    let currentSortOrder = 'desc'; // 默认降序(最新添加的在前面)

    
    // 打开弹窗
      function showModal(options = {}) {
      const modal = document.getElementById('custom-modal');
      const title = document.getElementById('modal-title');
      const message = document.getElementById('modal-message');
      const confirmBtn = document.getElementById('modal-confirm');
      const cancelBtn = document.getElementById('modal-cancel');
      const inputContainer = document.getElementById('modal-input-container');
      const input = document.getElementById('modal-input');
      
      // 设置标题
      if (options.title) {
          document.querySelector('.modal-title').textContent = options.title;
      } else {
          document.querySelector('.modal-title').textContent = '提示';
      }
      
      // 设置消息
      message.textContent = options.message || '';
      
      // 设置按钮文本
      confirmBtn.textContent = options.confirmText || '确认';
      cancelBtn.textContent = options.cancelText || '取消';
      
      // 设置按钮颜色
      confirmBtn.className = options.confirmClass || '';
      
      // 处理输入框
      if (options.input) {
          inputContainer.style.display = 'block';
          input.placeholder = options.placeholder || '';
          input.value = options.value || '';
          modalInputType = options.inputType || 'text';
          input.type = modalInputType;
      } else {
          inputContainer.style.display = 'none';
      }
      
      // 显示/隐藏取消按钮
      if (options.showCancel === false) {
          cancelBtn.style.display = 'none';
      } else {
          cancelBtn.style.display = 'inline-block';
      }
      
      // 保存回调
      modalCallback = options.callback;
      
      // 显示弹窗
      modal.classList.add('show');
      
      // 如果有输入框，聚焦它
      if (options.input) {
          setTimeout(() => input.focus(), 100);
      }
      }

      // 关闭弹窗
      function closeModal() {
      const modal = document.getElementById('custom-modal');
      modal.classList.remove('show');
      modalCallback = null;
      }

      // 处理弹窗确认
      function handleModalConfirm() {
      const input = document.getElementById('modal-input');
      const value = input.value;
      
      if (modalCallback) {
          modalCallback(value);
      }
      
      closeModal();
      }

      // 确认对话框
      function confirmDialog(message, callback, options = {}) {
      showModal({
          title: options.title || '确认操作',
          message: message,
          confirmText: options.confirmText || '确认',
          cancelText: options.cancelText || '取消',
          confirmClass: options.confirmClass || 'danger',
          callback: (result) => {
          if (callback) callback(true);
          },
          showCancel: true
      });
      }
    
    tabs.forEach(tab => {
      tab.addEventListener('click', () => {
        const tabId = tab.getAttribute('data-tab');
        
        // 更新活动标签
        tabs.forEach(t => t.classList.remove('active'));
        tab.classList.add('active');
        
        // 更新活动内容
        tabContents.forEach(content => {
          content.classList.remove('active');
          if (content.id === tabId) {
            content.classList.add('active');
          }
        });
        
        // 基于标签加载内容
        if (tabId === 'dashboard') {
          loadDashboard();
        } else if (tabId === 'keys') {
          loadAllKeys();
        } else if (tabId === 'settings') {
          loadSettings();
        }
      });
    });
    
    // 通知消息
    const toast = document.getElementById('toast');
    
    function showToast(message, isError = false) {
      toast.textContent = message;
      toast.style.background = isError ? 'rgba(231, 76, 60, 0.9)' : 'rgba(46, 204, 113, 0.9)';
      toast.classList.add('show');
      
      setTimeout(() => {
        toast.classList.remove('show');
      }, 3000); // 延长显示时间
    }
    
    // 图表实例对象
    let balanceDistChart, keyStatusChart, balanceTrendChart;
    
    // 增强的仪表盘加载函数
    function loadDashboard() {
      loadStats();
      loadRecentKeys();
      
      // 添加图表数据加载和渲染
      loadChartData();
    }

    // 加载并处理图表数据
    async function loadChartData() {
      try {
        const response = await fetch('/admin/api/keys');
        if (!response.ok) throw new Error('加载密钥失败');
        
        const result = await response.json();
        if (result.success) {
          const keys = result.data;
          
          // 处理余额分布数据
          renderBalanceDistributionChart(keys);
          
          // 处理密钥状态数据
          renderKeyStatusChart(keys);
          
          // 处理余额趋势数据
          renderBalanceTrendChart(keys);
          
          // 更新余额统计信息
          updateBalanceStats(keys);
        }
      } catch (error) {
        console.error('加载图表数据失败:', error);
        showToast('加载图表数据失败', true);
      }
    }
    
    // 渲染余额分布图表
    function renderBalanceDistributionChart(keys) {
      const ctx = document.getElementById('balance-distribution-chart').getContext('2d');
      
      // 定义余额区间
      const ranges = [
        { min: 0, max: 10, label: '0-10' },
        { min: 10, max: 12, label: '10-12' },
        { min: 12, max: 13, label: '12-13' },
        { min: 13, max: 14, label: '13-14' },
        { min: 14, max: 100, label: '14-100' },
        { min: 100, max: 1000, label: '100-1000' },
        { min: 1000, max: Infinity, label: '1000+' }
      ];
      
      // 计算每个区间的密钥数量
      const distribution = ranges.map(range => {
        return keys.filter(key => {
          const balance = parseFloat(key.balance) || 0;
          return balance > range.min && balance <= range.max;
        }).length;
      });
      
      // 销毁旧图表
      if (balanceDistChart) {
        balanceDistChart.destroy();
      }
      
      // 创建新图表
      balanceDistChart = new Chart(ctx, {
        type: 'bar',
        data: {
          labels: ranges.map(r => r.label),
          datasets: [{
            label: '密钥数量',
            data: distribution,
            backgroundColor: [
              'rgba(52, 152, 219, 0.7)',
              'rgba(46, 204, 113, 0.7)',
              'rgba(155, 89, 182, 0.7)',
              'rgba(52, 73, 94, 0.7)',
              'rgba(22, 160, 133, 0.7)',
              'rgba(241, 196, 15, 0.7)'
            ],
            borderColor: [
              'rgba(52, 152, 219, 1)',
              'rgba(46, 204, 113, 1)',
              'rgba(155, 89, 182, 1)',
              'rgba(52, 73, 94, 1)',
              'rgba(22, 160, 133, 1)',
              'rgba(241, 196, 15, 1)'
            ],
            borderWidth: 1,
            borderRadius: 5,
            maxBarThickness: 50
          }]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          plugins: {
            legend: {
              display: false
            },
            tooltip: {
              callbacks: {
                title: function(tooltipItems) {
                  return \`余额范围: \${tooltipItems[0].label}\`;
                },
                label: function(context) {
                  return \`数量: \${context.raw} 个密钥\`;
                }
              }
            }
          },
          scales: {
            y: {
              beginAtZero: true,
              ticks: {
                precision: 0
              },
              title: {
                display: true,
                text: '密钥数量'
              }
            },
            x: {
              title: {
                display: true,
                text: '余额范围'
              }
            }
          }
        }
      });
    }
    
    // 渲染密钥状态图表
    function renderKeyStatusChart(keys) {
      const ctx = document.getElementById('key-status-chart').getContext('2d');
      
      // 计算状态分布
      const valid = keys.filter(k => parseFloat(k.balance) > 0 && !k.lastError).length;
      const noBalance = keys.filter(k => parseFloat(k.balance) <= 0 && !k.lastError).length;
      const hasError = keys.filter(k => k.lastError).length;
      
      // 销毁旧图表
      if (keyStatusChart) {
        keyStatusChart.destroy();
      }
      
      // 创建新图表
      keyStatusChart = new Chart(ctx, {
        type: 'doughnut',
        data: {
          labels: ['有效', '余额不足', '错误'],
          datasets: [{
            data: [valid, noBalance, hasError],
            backgroundColor: [
              'rgba(46, 204, 113, 0.8)',
              'rgba(241, 196, 15, 0.8)',
              'rgba(231, 76, 60, 0.8)'
            ],
            borderColor: [
              'rgba(46, 204, 113, 1)',
              'rgba(241, 196, 15, 1)',
              'rgba(231, 76, 60, 1)'
            ],
            borderWidth: 1,
            hoverOffset: 4
          }]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          cutout: '65%',
          plugins: {
            legend: {
              position: 'bottom',
              labels: {
                padding: 15,
                usePointStyle: true,
                pointStyle: 'circle'
              }
            },
            tooltip: {
              callbacks: {
                label: function(context) {
                  const label = context.label || '';
                  const value = context.raw;
                  const total = context.dataset.data.reduce((a, b) => a + b, 0);
                  const percentage = Math.round((value / total) * 100);
                  return \`\${label}: \${value} (\${percentage}%)\`;
                }
              }
            }
          }
        }
      });
    }
    
    // 渲染余额趋势图表
    function renderBalanceTrendChart(keys) {
      const ctx = document.getElementById('balance-trend-chart').getContext('2d');
      
      // 获取有效密钥并按余额排序
      const validKeys = keys
        .filter(k => parseFloat(k.balance) > 0)
        .sort((a, b) => parseFloat(b.balance) - parseFloat(a.balance));
      
      // 获取选定范围
      const rangeSelect = document.getElementById('trend-range');
      const range = rangeSelect ? rangeSelect.value : '20';
      
      // 根据范围选择数据
      let displayKeys;
      if (range === 'all') {
        displayKeys = validKeys;
      } else {
        displayKeys = validKeys.slice(0, parseInt(range));
      }
      
      // 准备数据
      const labels = displayKeys.map((_, index) => \`密钥 \${index + 1}\`);
      const balances = displayKeys.map(k => parseFloat(k.balance) || 0);
      
      // 销毁旧图表
      if (balanceTrendChart) {
        balanceTrendChart.destroy();
      }
      
      // 创建新图表
      balanceTrendChart = new Chart(ctx, {
        type: 'bar',
        data: {
          labels: labels,
          datasets: [{
            label: '余额',
            data: balances,
            backgroundColor: balances.map(balance => {
              if (balance >= 50) return 'rgba(46, 204, 113, 0.7)'; // 高余额
              if (balance >= 10) return 'rgba(52, 152, 219, 0.7)'; // 中等余额
              return 'rgba(241, 196, 15, 0.7)';                    // 低余额
            }),
            borderColor: balances.map(balance => {
              if (balance >= 50) return 'rgba(46, 204, 113, 1)';
              if (balance >= 10) return 'rgba(52, 152, 219, 1)';
              return 'rgba(241, 196, 15, 1)';
            }),
            borderWidth: 1,
            borderRadius: 4,
            maxBarThickness: 40
          }]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          plugins: {
            legend: {
              display: false
            },
            tooltip: {
              callbacks: {
                title: function(tooltipItems) {
                  const keyIndex = tooltipItems[0].dataIndex;
                  return \`密钥: \${displayKeys[keyIndex].key}\`;
                },
                label: function(context) {
                  return \`余额: \${context.raw}\`;
                },
                afterLabel: function(context) {
                  const keyIndex = context.dataIndex;
                  const key = displayKeys[keyIndex];
                  if (key.lastUpdated) {
                    return \`最后更新: \${new Date(key.lastUpdated).toLocaleString()}\`;
                  }
                  return '';
                }
              }
            }
          },
          scales: {
            y: {
              beginAtZero: true,
              title: {
                display: true,
                text: '余额'
              }
            },
            x: {
              ticks: {
                autoSkip: true,
                maxTicksLimit: 20
              },
              title: {
                display: true,
                text: '密钥编号'
              }
            }
          }
        }
      });
      
      // 添加点击事件，显示详细信息
      ctx.canvas.onclick = function(evt) {
        const points = balanceTrendChart.getElementsAtEventForMode(evt, 'nearest', { intersect: true }, true);
        if (points.length) {
          const firstPoint = points[0];
          const keyIndex = firstPoint.index;
          const key = displayKeys[keyIndex];
          
          // 显示详细信息
          showKeyDetail(key);
        }
      };
    }
    
    // 显示密钥详细信息
    function showKeyDetail(key) {
      showModal({
        title: '密钥详细信息',
        message: \`余额: \${key.balance || 0}\\n添加时间: \${new Date(key.added).toLocaleString()}\${key.lastUpdated ? '\\n最后更新: ' + new Date(key.lastUpdated).toLocaleString() : ''}\${key.lastError ? '\\n错误: ' + key.lastError : ''}\`,
        confirmText: '复制密钥',
        callback: () => {
          navigator.clipboard.writeText(key.key)
            .then(() => showToast('密钥已复制到剪贴板'))
            .catch(() => showToast('复制失败', true));
        }
      });
    }
    
    // 更新余额统计信息
    function updateBalanceStats(keys) {
      // 过滤有效键（余额大于0）
      const validBalances = keys
        .map(k => parseFloat(k.balance) || 0)
        .filter(balance => balance > 0);
      
      if (validBalances.length > 0) {
        // 计算最大值、最小值、中位数和总和
        const max = Math.max(...validBalances);
        const min = Math.min(...validBalances);
        const total = validBalances.reduce((sum, b) => sum + b, 0);
        
        // 计算中位数
        const sorted = [...validBalances].sort((a, b) => a - b);
        let median;
        if (sorted.length % 2 === 0) {
          // 偶数个，取中间两个值的平均
          median = (sorted[sorted.length / 2 - 1] + sorted[sorted.length / 2]) / 2;
        } else {
          // 奇数个，取中间值
          median = sorted[Math.floor(sorted.length / 2)];
        }
        
        // 更新显示
        document.getElementById('max-balance').textContent = max.toFixed(2);
        document.getElementById('min-balance').textContent = min.toFixed(2);
        document.getElementById('median-balance').textContent = median.toFixed(2);
        document.getElementById('total-balance').textContent = total.toFixed(2);
      } else {
        // 没有有效数据
        document.getElementById('max-balance').textContent = '0.00';
        document.getElementById('min-balance').textContent = '0.00';
        document.getElementById('median-balance').textContent = '0.00';
        document.getElementById('total-balance').textContent = '0.00';
      }
    }
    
    // 设置图表切换事件
    document.addEventListener('DOMContentLoaded', function() {
      // 初始化图表范围选择器
      const rangeSelector = document.getElementById('trend-range');
      if (rangeSelector) {
        rangeSelector.addEventListener('change', function() {
          // 更新余额趋势图
          loadChartData();
        });
      }
      
      // 初始化图表周期选择器
      const periodSelector = document.getElementById('chart-period');
      if (periodSelector) {
        periodSelector.addEventListener('change', function() {
          // 更新所有图表
          loadChartData();
        });
      }
      
      // 初始化趋势图显示切换按钮
      const trendViewToggle = document.getElementById('toggle-trend-view');
      if (trendViewToggle) {
        trendViewToggle.addEventListener('click', function() {
          // 切换异常值显示
          if (balanceTrendChart) {
            const hideOutliers = !balanceTrendChart.options.scales.y.max;
            
            if (hideOutliers) {
              // 计算一个合理的最大值 (去除异常值)
              const data = balanceTrendChart.data.datasets[0].data;
              const sortedData = [...data].sort((a, b) => a - b);
              const q3Index = Math.floor(sortedData.length * 0.75);
              const q3 = sortedData[q3Index];
              const maxNormal = q3 * 2; // 一个简单的启发式计算正常范围的最大值
              
              balanceTrendChart.options.scales.y.max = maxNormal;
              trendViewToggle.textContent = '显示异常值';
            } else {
              // 恢复自动缩放
              balanceTrendChart.options.scales.y.max = undefined;
              trendViewToggle.textContent = '隐藏异常值';
            }
            
            balanceTrendChart.update();
          }
        });
      }
    });


    
    async function loadStats() {
      try {
          const response = await fetch('/admin/api/keys');
          if (!response.ok) throw new Error('加载密钥失败');
          
          const result = await response.json();
          if (result.success) {
          const keys = result.data;
          
          // 计算统计数据
          const totalKeys = keys.length;
          const validKeys = keys.filter(k => k.balance > 0).length;
          const invalidKeys = totalKeys - validKeys;
          
          // 修正计算平均余额的方式
          const validBalances = keys
              .map(k => parseFloat(k.balance) || 0)
              .filter(balance => balance > 0);
              
          const avgBalance = validBalances.length > 0 
              ? (validBalances.reduce((a, b) => a + b, 0) / validBalances.length).toFixed(2)
              : '0.00';
          
          // 更新UI
          document.getElementById('total-keys-stat').textContent = totalKeys;
          document.getElementById('valid-keys-stat').textContent = validKeys;
          document.getElementById('invalid-keys-stat').textContent = invalidKeys;
          document.getElementById('avg-balance-stat').textContent = avgBalance;
          }
      } catch (error) {
          console.error('加载统计数据时出错:', error);
          showToast('加载统计数据失败', true);
      }
    }
    
    async function loadRecentKeys() {
      try {
        const response = await fetch('/admin/api/keys');
        if (!response.ok) throw new Error('加载密钥失败');
        
        const result = await response.json();
        if (result.success) {
          const keys = result.data;
          
          // 按添加时间排序（最新的在前面）并获取前5个
          const recentKeys = [...keys]
            .sort((a, b) => new Date(b.added) - new Date(a.added))
            .slice(0, 5);
          
          const tableBody = document.querySelector('#recent-keys-table tbody');
          
          if (recentKeys.length === 0) {
            tableBody.innerHTML = '<tr><td colspan="4" class="empty-state">暂无数据</td></tr>';
            return;
          }
          
          let html = '';
          recentKeys.forEach(key => {
            const addedDate = new Date(key.added).toLocaleString();
            const balance = parseFloat(key.balance) || 0;
            
            // 检查是否有错误信息或余额不足
            let statusHtml = '<td><span class="admin-normal-status">正常</span></td>';
            if (balance <= 0 || key.lastError) {
              const errorMsg = key.lastError || (balance <= 0 ? '余额不足' : '未知错误');
              statusHtml = \`<td>
                <span class="tooltip">
                  <span style="color: #e74c3c;">错误</span>
                  <span class="tooltip-text">\${errorMsg}</span>
                </span>
              </td>\`;
            }
            
            html += \`
              <tr>
                <td class="key-column">\${key.key}</td>
                <td>\${key.balance || 0}</td>
                <td>\${addedDate}</td>
                \${statusHtml}
              </tr>
            \`;
          });
          
          tableBody.innerHTML = html;
        }
      } catch (error) {
        console.error('加载最近密钥时出错:', error);
        const tableBody = document.querySelector('#recent-keys-table tbody');
        tableBody.innerHTML = '<tr><td colspan="4" class="empty-state">加载失败</td></tr>';
      }
    }
    
    // 密钥管理功能
    async function loadAllKeys() {
      try {
        const response = await fetch('/admin/api/keys');
        if (!response.ok) throw new Error('加载密钥失败');
        
        const result = await response.json();
        if (result.success) {
          const keys = result.data;
          
          const tableBody = document.querySelector('#all-keys-table tbody');
          
          if (keys.length === 0) {
            tableBody.innerHTML = '<tr><td colspan="6" class="empty-state">暂无API Keys</td></tr>';
            return;
          }
          
          // 应用排序逻辑
          const sortedKeys = sortKeys(keys, currentSortField, currentSortOrder);
      
          // 更新表头以支持排序
          const tableHeader = document.querySelector('#all-keys-table thead tr');
          tableHeader.innerHTML = \`
            <th width="50px">序号</th>
            <th width="30px"><input type="checkbox" id="select-all-table"></th>
            <th>API Key</th>
            <th class="sort-header" data-sort="balance">
              余额 
              <span class="sort-icon" id="sort-balance">
                <svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="sort-arrow"><path d="M7 10l5 5 5-5"></path></svg>
              </span>
            </th>
            <th class="sort-header" data-sort="lastUpdated">
              最后更新时间
              <span class="sort-icon" id="sort-lastUpdated">
                <svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="sort-arrow"><path d="M7 10l5 5 5-5"></path></svg>
              </span>
            </th>
            <th class="sort-header" data-sort="added">
              添加时间
              <span class="sort-icon" id="sort-added">
                <svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="sort-arrow"><path d="M7 10l5 5 5-5"></path></svg>
              </span>
            </th>
            <th>状态</th>
            <th>操作</th>
          \`;
          
          // 更新排序图标状态
          updateSortIcons();
          
          // 为表头添加事件
          document.querySelectorAll('.sort-header').forEach(header => {
            header.addEventListener('click', () => {
              const sortField = header.getAttribute('data-sort');
              
              // 如果点击当前排序列，切换排序顺序
              if (sortField === currentSortField) {
                currentSortOrder = currentSortOrder === 'asc' ? 'desc' : 'asc';
              } else {
                // 如果点击新列，设置为新排序字段并默认降序
                currentSortField = sortField;
                currentSortOrder = 'desc';
              }
              
              // 更新排序图标并重新加载数据
              loadAllKeys();
            });
          });
          
          let html = '';
          sortedKeys.forEach((key, index) => {
            // 序号从1开始
            const rowNumber = index + 1;
            
            // 使用最后更新时间，如果没有则使用添加时间
            const updateTime = key.lastUpdated ? new Date(key.lastUpdated) : new Date(key.added);
            const timeLabel = key.lastUpdated ? '更新于' : '添加于';
            const displayTime = updateTime.toLocaleString();
            
            // 添加时间格式化
            const addedTime = new Date(key.added).toLocaleString();
            
            // 检查是否在选中集合中
            const isChecked = selectedKeys.has(key.key) ? 'checked' : '';

            // 检查余额是否为负数或0，或者有错误信息
            const balance = parseFloat(key.balance) || 0;
            let statusHtml = '';
                
            if (balance <= 0 || key.lastError) {
              // 确定显示的错误消息
              const errorMsg = key.lastError || (balance <= 0 ? '余额不足' : '未知错误');
              statusHtml = \`<td>
                <span class="tooltip">
                  <span style="color: #e74c3c;">错误</span>
                  <span class="tooltip-text">\${errorMsg}</span>
                </span>
              </td>\`;
            } else {
              statusHtml = '<td><span class="admin-normal-status">正常</span></td>';
            }
            
            html += \`
            <tr data-key="\${key.key}" class="\${isChecked ? 'selected-row' : ''}">
                <td class="row-number">\${rowNumber}</td>
                <td><input type="checkbox" class="key-selector" data-key="\${key.key}" \${isChecked}></td>
                <td class="key-column">\${key.key}</td>
                <td>\${key.balance || 0}</td>
                <td><small>\${timeLabel} \${displayTime}</small></td>
                <td><small>\${addedTime}</small></td>
                \${statusHtml}
                <td class="actions-column">
                  <span class="action-icon check" title="检测余额" onclick="checkKeyBalance('\${key.key}')">⟳</span>
                  <span class="action-icon delete" title="删除" onclick="deleteKey('\${key.key}')">🗑️</span>
                </td>
            </tr>
            \`;
          });
          
          tableBody.innerHTML = html;
          
          // 添加事件监听器
          attachKeySelectors();
          updateSelectionStatus();
        }
      } catch (error) {
        console.error('加载所有密钥时出错:', error);
        const tableBody = document.querySelector('#all-keys-table tbody');
        tableBody.innerHTML = '<tr><td colspan="8" class="empty-state">加载失败</td></tr>';
      }
    }

    // 添加多选框事件监听器
    function attachKeySelectors() {
      // 为每个密钥选择器添加事件
      document.querySelectorAll('.key-selector').forEach(checkbox => {
        checkbox.addEventListener('change', function() {
          const key = this.getAttribute('data-key');
          const row = this.closest('tr');
          
          if (this.checked) {
            selectedKeys.add(key);
            row.classList.add('selected-row');
          } else {
            selectedKeys.delete(key);
            row.classList.remove('selected-row');
          }
          
          updateSelectionStatus();
        });
      });
      
      // 表头全选/取消全选功能
      document.getElementById('select-all-table').addEventListener('change', function() {
        const checkboxes = document.querySelectorAll('.key-selector');
        checkboxes.forEach(cb => {
          cb.checked = this.checked;
          const key = cb.getAttribute('data-key');
          const row = cb.closest('tr');
          
          if (this.checked) {
            selectedKeys.add(key);
            row.classList.add('selected-row');
          } else {
            selectedKeys.delete(key);
            row.classList.remove('selected-row');
          }
        });
        
        updateSelectionStatus();
      });
      
      // 行选择功能 - 点击行也可以选择
      document.querySelectorAll('#all-keys-table tbody tr').forEach(row => {
        row.addEventListener('click', function(e) {
          // 忽略操作按钮的点击
          if (e.target.closest('.action-icon') || e.target.type === 'checkbox') {
            return;
          }
          
          // 切换选择状态
          const checkbox = this.querySelector('.key-selector');
          checkbox.checked = !checkbox.checked;
          
          // 触发change事件
          const event = new Event('change');
          checkbox.dispatchEvent(event);
        });
      });
    }

    // 更新选择状态显示
    function updateSelectionStatus() {
      const count = selectedKeys.size;
      document.getElementById('selection-count').textContent = \`已选择 \${count} 个 Key\`;
      
      // 设置批量操作按钮状态
      document.getElementById('check-selected-keys').disabled = count === 0;
      document.getElementById('delete-selected-keys').disabled = count === 0;
      
      // 设置全选框状态
      const allCheckboxes = document.querySelectorAll('.key-selector');
      const allChecked = allCheckboxes.length > 0 && count === allCheckboxes.length;
      document.getElementById('select-all-table').checked = allChecked;
      document.getElementById('select-all-keys').checked = allChecked;
    }

    // 处理批量检测密钥余额
    async function batchCheckSelectedKeys() {
      
      const processedKeysSet = new Set(); // 用于跟踪已经处理过的密钥

      // 如果没有选择任何密钥，直接返回
      if (selectedKeys.size === 0) {
        showToast('请选择至少一个API Key', true);
        return;
      }
      
      // 获取配置
      const intervalType = document.getElementById('interval-type').value;
      const minInterval = parseInt(document.getElementById('min-interval').value) || 500;
      const maxInterval = parseInt(document.getElementById('max-interval').value) || 1500;
      const retryCount = parseInt(document.getElementById('retry-count').value) || 1;
      const retryInterval = parseInt(document.getElementById('retry-interval').value) || 2000;

      // 获取固定间隔秒数并转换为毫秒
      const fixedIntervalSeconds = parseFloat(document.getElementById('concurrency').value) || 1;
      const fixedInterval = Math.max(0, Math.round(fixedIntervalSeconds * 1000)); // 保证非负

      // 确保最小间隔不大于最大间隔，可取0s
      const effectiveMinInterval = Math.max(0, minInterval);
      if (minInterval > maxInterval) {
        showToast('最小间隔不能大于最大间隔', true);
        return;
      }
      
      try {
        // 准备进度显示
        showProgress("批量检测密钥余额");
        
        // 将选中的密钥转换为数组
        const keysToCheck = Array.from(selectedKeys);
        const total = keysToCheck.length;
        
        let processed = 0;
        let successful = 0;
        let failed = 0;
        let startTime = Date.now();
        
        // 创建任务队列
        const queue = [...keysToCheck];
        const running = new Set(); // 用于跟踪当前运行的任务
        const results = new Map(); // 存储结果
        
        // 更新进度显示
        function updateProgressDisplay() {
          const percentComplete = Math.floor((processed / total) * 100);
          const elapsed = Date.now() - startTime;
          const speed = processed > 0 ? elapsed / processed : 0; // 每个key平均处理时间(ms)
          const remaining = (total - processed) * speed; // 估计剩余时间(ms)
          
          // 更新进度条
          updateProgress(processed, total, successful);

          // 格式化剩余时间，精确到秒
          const remainingText = formatTime(remaining);
          const elapsedText = formatTime(elapsed);

          // 格式化速度
          const speedText = (speed / 1000).toFixed(2) + '秒/项';
  
          // 更新详细信息
          document.getElementById('progress-speed').textContent = speedText;
          document.getElementById('progress-eta').textContent = remainingText;
          document.getElementById('progress-elapsed').textContent = elapsedText;
  
          // 更新表格行状态
          results.forEach((result, key) => {
            const row = document.querySelector(\`tr[data-key="\${key}"]\`);
            if (row) {
              // 更新余额
              row.querySelector('td:nth-child(4)').textContent = result.balance || 0;
              
              // 更新时间
              const updateTime = result.lastUpdated ? new Date(result.lastUpdated).toLocaleString('zh-CN', {
                year: 'numeric',
                month: '2-digit',
                day: '2-digit',
                hour: '2-digit',
                minute: '2-digit',
                second: '2-digit',
                hour12: false // 使用24小时制
              }) : new Date().toLocaleString('zh-CN', {
                year: 'numeric',
                month: '2-digit',
                day: '2-digit',
                hour: '2-digit',
                minute: '2-digit',
                second: '2-digit',
                hour12: false // 使用24小时制
              });

              row.querySelector('td:nth-child(5)').innerHTML = \`<small>更新于 \${updateTime}</small>\`;
            

              // 更新状态 - 判断是否成功且余额大于0
              if (result.success && result.balance > 0) {
                row.querySelector('td:nth-child(7)').innerHTML = '<span class="admin-normal-status">正常</span>';
              } else {
                row.querySelector('td:nth-child(7)').innerHTML = \`
                  <span class="tooltip">
                    <span style="color: #e74c3c;">错误</span>
                    <span class="tooltip-text">\${result.message || '未知错误'}</span>
                  </span>
                \`;
              }
            }
          });
        }
        
        const pendingTimeUpdates = []; // 用于收集需要更新的时间

        // 处理单个键
        async function processKey(key, attempts = 0) {
          try {
            // 如果密钥已处理，直接返回，不重复计算进度
            if (processedKeysSet.has(key)) {
              return;
            }
                        
            running.add(key);
            // 标记该密钥已被处理
            processedKeysSet.add(key);
            
            const response = await fetch('/admin/api/update-key-balance', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ key })
            });
            
            if (!response.ok) throw new Error('检测余额失败');
            
            const result = await response.json();

            // 收集时间更新信息
            if (result.success) {
              pendingTimeUpdates.push({
                key,
                lastUpdated: result.lastUpdated || new Date().toISOString()
              });
            }
            
            // 保存结果
            results.set(key, result);
            processed++;
            
            if (result.success) {
              successful++;
            } else {
              failed++;
            }
            
            running.delete(key);
            updateProgressDisplay();
            
            return result;
          } catch (error) {
            console.error(\`检测密钥\${key}时出错:\`, error);
            
            // 重试逻辑
            if (attempts < retryCount) {
              console.log(\`重试密钥\${key}, 尝试次数: \${attempts + 1}/\${retryCount}\`);
              await new Promise(resolve => setTimeout(resolve, retryInterval));
              return processKey(key, attempts + 1);
            }
            
            // 重试失败，标记为错误
            results.set(key, { 
              success: false, 
              balance: 0, 
              message: \`检测失败: \${error.message}\` 
            });

            // 即使出错也要标记为已处理，避免重复计算
            if (!processedKeysSet.has(key)) {
              processedKeysSet.add(key);
              processed++; // 仍然计入已处理数量
              failed++;
            }
              
            running.delete(key);
            updateProgressDisplay();
            
            return { success: false, message: error.message };
          }
        }
        
        // 串行处理所有密钥
        for (let i = 0; i < keysToCheck.length; i++) {
          // 检查是否收到停止信号
          if (isBatchProcessingStopped) {
            hideProgress();
            showToast(\`批量检测已停止！已完成: \${processed}/\${total}\`);
            return;
          }
          
          // 获取请求延迟时间
          let delay;
          if (i > 0) { // 第一个请求不需要延迟
            const intervalType = document.getElementById('interval-type').value;
            const effectiveMinInterval = Math.max(500, parseInt(document.getElementById('min-interval').value) || 500);
            const maxInterval = parseInt(document.getElementById('max-interval').value) || 1500;
            
            // 根据间隔类型计算延迟
            if (intervalType === 'fixed') {
              const fixedIntervalSeconds = parseFloat(document.getElementById('concurrency').value) || 1;
              delay = Math.max(500, Math.round(fixedIntervalSeconds * 1000));
            } else {
              delay = Math.floor(Math.random() * (maxInterval - effectiveMinInterval + 1)) + effectiveMinInterval;
            }
            
            // 在处理下一个密钥前添加延迟
            await new Promise(resolve => setTimeout(resolve, delay));
          }
          
          // 处理当前密钥
          const key = keysToCheck[i];
          await processKey(key);
        }
        
        // 处理完成
        setTimeout(() => {
          hideProgress();
          showToast(\`批量检测完成！成功: \${successful}, 失败: \${failed}\`);
        }, 1000);
        
      } catch (error) {
        hideProgress();
        console.error('批量检测失败:', error);
        showToast(\`批量检测失败: \${error.message}\`, true);
      }
    }

    // 添加时间格式化函数
    function formatTime(milliseconds) {
      if (isNaN(milliseconds) || milliseconds <= 0) {
        return "计算中...";
      }
      
      const seconds = Math.floor(milliseconds / 1000);
      
      if (seconds < 60) {
        return \`\${seconds}秒\`;
      } else if (seconds < 3600) {
        const minutes = Math.floor(seconds / 60);
        const remainingSeconds = seconds % 60;
        return \`\${minutes}分\${remainingSeconds}秒\`;
      } else {
        const hours = Math.floor(seconds / 3600);
        const minutes = Math.floor((seconds % 3600) / 60);
        const remainingSeconds = seconds % 60;
        return \`\${hours}小时\${minutes}分\${remainingSeconds}秒\`;
      }
    }

    // 批量删除选中的密钥
    function batchDeleteSelectedKeys() {
      if (selectedKeys.size === 0) {
        showToast('请选择至少一个API Key', true);
        return;
      }
      
      confirmDialog(\`确定要删除这些API Key吗？此操作不可撤销，将删除 \${selectedKeys.size} 个密钥。\`, async (confirmed) => {
        if (!confirmed) return;
        
        try {
          showProgress("正在批量删除密钥");
          
          const keysToDelete = Array.from(selectedKeys);
          const total = keysToDelete.length;
          let processed = 0;
          let successful = 0;
          // 添加开始时间记录
          let startTime = Date.now();
          
          for (const key of keysToDelete) {
            // 添加检查是否收到停止信号
            if (isBatchProcessingStopped) {
              hideProgress();
              showToast(\`批量删除已停止！已完成: \${processed}/\${total}\`);
              loadAllKeys();
              return;
            }
            
            try {
              const response = await fetch('/admin/api/delete-key', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ key })
              });
              
              if (!response.ok) throw new Error('删除失败');
              
              const result = await response.json();
              if (result.success) {
                successful++;
                selectedKeys.delete(key); // 从选中集合中移除
              }
              
            } catch (error) {
              console.error(\`删除密钥 \${key} 失败:\`, error);
            } finally {
              processed++;
              
              // 计算时间指标
              const elapsed = Date.now() - startTime;
              const speed = processed > 0 ? elapsed / processed : 0; // 每个key平均处理时间(ms)
              const remaining = (total - processed) * speed; // 估计剩余时间(ms)
              
              // 格式化时间文本
              const remainingText = formatTime(remaining);
              const elapsedText = formatTime(elapsed);
              const speedText = (speed / 1000).toFixed(2) + '秒/项';
              
              // 更新更详细的进度信息
              updateProgress(processed, total, successful);
              
              // 更新详细信息
              document.getElementById('progress-speed').textContent = speedText;
              document.getElementById('progress-eta').textContent = remainingText;
              document.getElementById('progress-elapsed').textContent = elapsedText;
            }
            
            // 添加短暂延迟避免请求过快
            await new Promise(resolve => setTimeout(resolve, 100));
          }
          
          // 重新加载数据
          setTimeout(() => {
            hideProgress();
            loadAllKeys();
            setTimeout(loadDashboard, 500);
            showToast(\`成功删除 \${successful} 个API Key\`);
            updateSelectionStatus(); // 更新选择状态
          }, 1000);
          
        } catch (error) {
          hideProgress();
          console.error('批量删除失败:', error);
          showToast(\`批量删除失败: \${error.message}\`, true);
        }
      }, {
        confirmClass: 'danger',
        confirmText: '批量删除',
        title: '批量删除确认'
      });
    }


    // 检测单个密钥余额的函数
    window.checkKeyBalance = async function(key) {
      const rows = document.querySelectorAll('#all-keys-table tbody tr');
      let targetRow;
      
      // 找到对应的行
      rows.forEach(row => {
        const keyCell = row.querySelector('.key-column');
        if (keyCell && keyCell.textContent === key) {
          targetRow = row;
        }
      });
      
      if (!targetRow) return;
      
      // 序号td:nth-child(1), 复选框td:nth-child(2), API Key td:nth-child(3)
      // 余额td:nth-child(4), 最后更新时间td:nth-child(5), 添加时间td:nth-child(6), 状态td:nth-child(7)
      const balanceCell = targetRow.querySelector('td:nth-child(4)');
      const timeCell = targetRow.querySelector('td:nth-child(5)');
      const statusCell = targetRow.querySelector('td:nth-child(7)');
      
      if (!balanceCell || !timeCell || !statusCell) return;
      
      // 显示加载中状态
      const originalBalanceText = balanceCell.textContent;
      const originalStatusHtml = statusCell.innerHTML;
      const originalTimeHtml = timeCell.innerHTML;
      
      balanceCell.innerHTML = '<span class="loader" style="border-top-color: #3498db;"></span> 检测中';
      statusCell.innerHTML = '<span style="color: #3498db;">检测中...</span>';
      
      try {
        const response = await fetch('/admin/api/update-key-balance', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ key })
        });
        
        if (!response.ok) throw new Error('检测余额失败');
        
        const result = await response.json();
        const updateTime = result.lastUpdated ? new Date(result.lastUpdated).toLocaleString() : new Date().toLocaleString();
        
        // 更新时间
        timeCell.innerHTML = \`<small>更新于 \${updateTime}</small>\`;
        
        // 判断余额是否有效（大于0）
        const balance = parseFloat(result.balance) || 0;
        balanceCell.textContent = balance;
        
        if (result.success && balance > 0) {
          // 余额正常
          statusCell.innerHTML = '<span class="admin-normal-status">正常</span>';
          showToast('余额检测成功');
        } else {
          // API成功但余额为0或负数，也视为错误
          const errorMsg = result.message || (balance <= 0 ? '余额不足' : '未知错误');
          statusCell.innerHTML = \`
            <span class="tooltip">
              <span style="color: #e74c3c;">错误</span>
              <span class="tooltip-text">\${errorMsg}</span>
            </span>
          \`;
          showToast(errorMsg || '密钥余额不足', true);
        }
      } catch (error) {
        console.error('检测余额时出错:', error);
        balanceCell.textContent = originalBalanceText;
        statusCell.innerHTML = originalStatusHtml;
        timeCell.innerHTML = originalTimeHtml;
        showToast('检测失败: ' + error.message, true);
      }
    };
    
    // 添加密钥
    async function addKey() {
      const keyInput = document.getElementById('add-key-input');
      const key = keyInput.value.trim();
      
      if (!key) {
          showToast('请输入API Key', true);
          return;
      }
      
      try {
          const response = await fetch('/admin/api/add-key', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ key })
          });
          
          if (!response.ok) throw new Error('添加密钥失败');
          
          const result = await response.json();
          if (result.success) {
          showToast('API Key添加成功，正在检测余额...');
          keyInput.value = '';
          
          // 添加成功后自动检测余额
          try {
              await fetch('/admin/api/update-key-balance', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ key })
              });
              // 不管检测结果如何，都重新加载数据
          } catch (error) {
              console.error('添加后检测余额失败:', error);
          }
          
          loadAllKeys();
          setTimeout(loadDashboard, 500);
          } else {
          showToast(result.message || '添加失败', true);
          }
      } catch (error) {
          console.error('添加密钥时出错:', error);
          showToast('添加失败: ' + error.message, true);
      }
    }
    
    // 批量添加keys
    async function addBulkKeys() {
      const textarea = document.getElementById('bulk-keys-input');
      const keysText = textarea.value.trim();
      
      if (!keysText) {
          showToast('请输入API Keys', true);
          return;
      }
      
      try {
          const response = await fetch('/admin/api/add-keys-bulk', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ keys: keysText })
          });
          
          if (!response.ok) throw new Error('添加密钥失败');
          
          const result = await response.json();
          if (result.success) {
            showToast(\`成功添加 \${result.count} 个API Keys，正在检测余额...\`);
            textarea.value = '';
            
            // 修改这里：后端应直接返回添加的key字符串数组
            if (result.addedKeys && result.addedKeys.length > 0) {
              // 清除以前的选择
              selectedKeys.clear();
              
              // 直接添加API Key字符串到selectedKeys集合
              result.addedKeys.forEach(key => {
                selectedKeys.add(key);
              });
              
              // 更新选择状态
              updateSelectionStatus();
              
              // 如果需要自动检测
              if (result.autoCheck) {
                // 调用批量检查
                batchCheckSelectedKeys();
              }
            }
            
            // 刷新密钥列表
            await loadAllKeys();
            setTimeout(loadDashboard, 500);
          } else {
            throw new Error(result.message || '添加密钥失败');
          }
      } catch (error) {
          console.error('添加密钥失败', error);
          showToast(\`添加密钥失败: \${error.message}\`, true);
      }
    }
    
    // 全局删除密钥函数
    window.deleteKey = async function(key) {
      confirmDialog('确定要删除这个API Key吗？', async (confirmed) => {
          if (!confirmed) return;
          
          try {
          const response = await fetch('/admin/api/delete-key', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ key })
          });
          
          if (!response.ok) throw new Error('删除密钥失败');
          
          const result = await response.json();
          if (result.success) {
              showToast('API Key已删除');
              loadAllKeys();
              setTimeout(loadDashboard, 500);
          } else {
              showToast(result.message || '删除失败', true);
          }
          } catch (error) {
          console.error('删除密钥时出错:', error);
          showToast('删除失败: ' + error.message, true);
          }
      }, {
          confirmClass: 'danger',
          confirmText: '删除'
      });
    };
    
      // 增强批量操作面板的视觉反馈
      function enhanceBatchConfigPanelVisibility() {
        const configPanel = document.getElementById('batch-config-panel');
        const toggleBtn = document.getElementById('toggle-batch-config');
        
        // 初始状态检查
        if (configPanel.classList.contains('show')) {
          toggleBtn.classList.add('active');
          toggleBtn.querySelector('span').textContent = '点击收起';
        } else {
          toggleBtn.classList.remove('active');
          toggleBtn.querySelector('span').textContent = '高级设置';
        }
        
        // 添加过渡结束事件监听器
        configPanel.addEventListener('transitionend', function(e) {
          if (e.propertyName === 'max-height') {
            if (!configPanel.classList.contains('show')) {
              configPanel.style.overflow = 'hidden';
            } else {
              configPanel.style.overflow = 'visible';
            }
          }
        });
      }

      // 设置功能
      async function loadSettings(attempts = 3) {
      try {
          // 添加一个随机参数防止缓存
          const timestamp = new Date().getTime();
          const response = await fetch(\`/admin/api/config?_=\${timestamp}\`, {
            // 添加超时处理
            signal: AbortSignal.timeout(10000) // 10秒超时
          });
          
          if (!response.ok) {
            throw new Error(\`加载配置失败: 状态码 \${response.status}\`);
          }
          
          const result = await response.json();
          if (result.success) {
            const config = result.data;
            document.getElementById('api-key-input').value = config.apiKey || '';
            document.getElementById('admin-username-input').value = config.adminUsername || '';
            document.getElementById('admin-password-input').value = ''; // 不预填密码
            document.getElementById('page-size-input').value = config.pageSize || 10;
            // 设置访问控制选项
            const accessControlSelect = document.getElementById('access-control-select');
            accessControlSelect.value = config.accessControl || 'open';
            // 显示/隐藏访客密码输入框
            toggleGuestPasswordField(accessControlSelect.value);
            
            // 后端不返回访客密码明文，仅返回是否已设置
            if (config.hasGuestPassword) {
              document.getElementById('guest-password-input').value = '';  // 出于安全考虑，不预填真实密码
              document.getElementById('guest-password-input').placeholder = '已设置访客密码 (不显示)';
            } else {
              document.getElementById('guest-password-input').placeholder = '设置访客密码';
            }
    
          } else {
            throw new Error(result.message || '未知错误');
          }
      } catch (error) {
          console.error('加载设置时出错:', error);
          
          // 如果还有重试次数，尝试重试
          if (attempts > 0) {
            console.log(\`尝试重新加载设置，剩余尝试次数: \${attempts-1}\`);
            await new Promise(resolve => setTimeout(resolve, 1000)); // 等待1秒再重试
            return loadSettings(attempts - 1);
          }
          
          // 显示错误提示
          showToast(\`加载设置失败: \${error.message}\`, true);
      }
    }

    // 根据访问控制模式显示/隐藏访客密码字段
    function toggleGuestPasswordField(mode) {
      const guestPasswordGroup = document.getElementById('guest-password-group');
      guestPasswordGroup.style.display = mode === 'restricted' ? 'block' : 'none';
    }

    // 排序辅助函数
    function sortKeys(keys, field, order) {
      return [...keys].sort((a, b) => {
        let valueA, valueB;
        
        // 根据字段类型获取对应的值
        switch (field) {
          case 'balance':
            valueA = parseFloat(a.balance) || 0;
            valueB = parseFloat(b.balance) || 0;
            break;
          case 'lastUpdated':
            // 如果没有lastUpdated，则使用added时间
            valueA = a.lastUpdated ? new Date(a.lastUpdated).getTime() : new Date(a.added).getTime();
            valueB = b.lastUpdated ? new Date(b.lastUpdated).getTime() : new Date(b.added).getTime();
            break;
          case 'added':
          default:
            valueA = new Date(a.added).getTime();
            valueB = new Date(b.added).getTime();
            break;
        }
        
        // 应用排序方向
        return order === 'asc' 
          ? valueA - valueB  // 升序
          : valueB - valueA; // 降序
      });
    }

    // 更新排序图标状态
    function updateSortIcons() {
      document.querySelectorAll('.sort-icon').forEach(icon => {
        icon.classList.remove('active', 'asc', 'desc');
      });
      
      const activeIcon = document.getElementById(\`sort-\${currentSortField}\`);
      if (activeIcon) {
        activeIcon.classList.add('active', currentSortOrder);
      }
    }
    
    async function saveSettings(event) {
      // 阻止表单默认提交
      if (event) event.preventDefault();
      
      const apiKey = document.getElementById('api-key-input').value.trim();
      const adminUsername = document.getElementById('admin-username-input').value.trim();
      const adminPassword = document.getElementById('admin-password-input').value.trim();
      const pageSize = parseInt(document.getElementById('page-size-input').value) || 10;
      const accessControl = document.getElementById('access-control-select').value;
      const guestPassword = document.getElementById('guest-password-input').value;
  
      
      const config = {};
      if (apiKey) config.apiKey = apiKey;
      if (adminUsername) config.adminUsername = adminUsername;
      if (adminPassword) config.adminPassword = adminPassword;
      if (pageSize) config.pageSize = pageSize;
      
      // 添加访问控制设置
      config.accessControl = accessControl;

      // 只有在有值或模式为restricted时设置访客密码
      if (accessControl === 'restricted') {
        // 如果密码字段非空，则更新密码
        if (guestPassword) {
          config.guestPassword = guestPassword;
        }
        // 否则保持原密码不变
      } else {
        // 其他模式下，显式设置为空字符串
        config.guestPassword = '';
      }

      try {
          const response = await fetch('/admin/api/update-config', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(config)
          });
          
          if (!response.ok) throw new Error('更新配置失败');
          
          const result = await response.json();
          if (result.success) {
          showToast('设置已保存');
          document.getElementById('admin-password-input').value = '';
          } else {
          showToast(result.message || '保存设置失败', true);
          }
      } catch (error) {
          console.error('保存设置时出错:', error);
          showToast('保存设置失败: ' + error.message, true);
      }
    }

    // 停止批量处理函数
    function stopBatchProcessing() {
      isBatchProcessingStopped = true;
      showToast('正在停止批量检测，请等待当前任务完成...');
      document.getElementById('stop-batch-process').disabled = true;
      document.getElementById('stop-batch-process').textContent = '正在停止...';
    }

    // 进度条控制函数
    function showProgress(title) {
      const container = document.getElementById('progress-container');
      const titleElement = container.querySelector('.progress-title');
      const progressFill = document.getElementById('progress-fill');
      const progressText = document.getElementById('progress-text');
      const successRate = document.getElementById('progress-success-rate');

      // 重置停止标记
      isBatchProcessingStopped = false;
      
      titleElement.textContent = title || "操作进行中";
      progressFill.style.width = '0%';
      progressText.textContent = "0/0 (0%)";
      successRate.textContent = "成功: 0";
      
      container.classList.add('active');
    }

    // 更新进度函数
    function updateProgress(current, total, success) {
      const percent = total > 0 ? Math.round((current / total) * 100) : 0;
      const progressFill = document.getElementById('progress-fill');
      const progressText = document.getElementById('progress-text');
      const successRate = document.getElementById('progress-success-rate');
      
      progressFill.style.width = \`\${percent}%\`;
      progressText.textContent = \`\${current}/\${total} (\${percent}%)\`;
      successRate.textContent = \`成功: \${success}\`;
    }

    function hideProgress() {
      const container = document.getElementById('progress-container');
      container.classList.remove('active');
      
      // 重置停止按钮状态
      const stopButton = document.getElementById('stop-batch-process');
      stopButton.disabled = false;
      stopButton.textContent = '停止检测';
      
      // 重置停止标记
      isBatchProcessingStopped = false;
    }

    // 更新所有密钥余额
    async function updateAllBalances() {
      const btn = document.getElementById('update-balances-btn');
      const originalText = btn.textContent;
      
      confirmDialog('确定要更新所有密钥的余额吗？这可能需要几分钟时间完成。', async (confirmed) => {
        if (!confirmed) return;

        btn.disabled = true;
        btn.innerHTML = '<span class="loader"></span>更新中...';
        
        try {
          // 获取所有密钥并全选
          const response = await fetch('/admin/api/keys');
          if (!response.ok) throw new Error('获取密钥失败');
          
          const result = await response.json();
          if (!result.success) throw new Error('获取密钥数据失败');
          
          const allKeys = result.data;
          
          if (allKeys.length === 0) {
            showToast('没有可更新的密钥');
            return;
          }
          
          // 清除现有选择
          selectedKeys.clear();
          
          // 将所有密钥添加到选中集合
          allKeys.forEach(key => selectedKeys.add(key.key));
          
          // 更新选择状态UI
          updateSelectionStatus();
          
          // 调用批量检测功能
          await batchCheckSelectedKeys();
          
          // 更新完成后刷新仪表盘数据
          setTimeout(loadDashboard, 500);
          
        } catch (error) {
          hideProgress();
          showToast(\`更新失败: \${error.message}\`, true);
        } finally {
          btn.disabled = false;
          btn.textContent = originalText;
        }
      }, {
        title: '更新所有密钥',
        confirmText: '开始更新',
        confirmClass: 'success'
      });
    }

    // 关闭余额过滤模态框
    function closeBalanceFilterModal() {
      document.getElementById('balance-filter-modal').classList.remove('show');
    }
    
    // 显示余额过滤模态框
    function showBalanceFilterModal() {
      document.getElementById('balance-filter-modal').classList.add('show');
    }
    
    // 导出选中的密钥
    function exportSelectedKeys() {
      if (selectedKeys.size === 0) {
        showToast('请先选择要导出的密钥', true);
        return;
      }
      
      exportKeys(Array.from(selectedKeys), '已选密钥');
    }

    // 复制所选密钥
    async function copySelectedKeys() {
      if (selectedKeys.size === 0) {
        showToast('请先选择要复制的密钥', true);
        return;
      }
      
      try {
        // 获取分隔符
        const delimiter = getSelectedDelimiter();
        
        // 复制到剪贴板
        const keysText = Array.from(selectedKeys).join(delimiter);
        await navigator.clipboard.writeText(keysText);
        
        showToast(\`成功复制 \${selectedKeys.size} 个密钥到剪贴板\`);
        
      } catch (error) {
        console.error('复制所选密钥失败:', error);
        showToast(\`复制失败: \${error.message}\`, true);
      }
    }

    // 获取当前选择的分隔符
    function getSelectedDelimiter() {
      const delimiterType = document.getElementById('delimiter-select').value;
      
      switch (delimiterType) {
        case 'newline':
          return '\\n';
        case 'comma':
          return ',';
        case 'space':
          return ' ';
        case 'semicolon':
          return ';';
        case 'tab':
          return '\\t';
        case 'custom':
          return document.getElementById('custom-delimiter').value || ','; // 默认逗号
        default:
          return '\\n'; // 默认换行符
      }
    }

    // 更新分隔符文本显示
    function updateDelimiterDisplay() {
      const delimiterType = document.getElementById('delimiter-select').value;
      const displayElement = document.getElementById('delimiter-display');
      const customDelimiterInput = document.getElementById('custom-delimiter');
      
      // 显示/隐藏自定义分隔符输入框
      if (delimiterType === 'custom') {
        customDelimiterInput.style.display = 'inline-block';
        customDelimiterInput.focus();
        
        // 为自定义分隔符添加change事件
        customDelimiterInput.onchange = function() {
          displayElement.textContent = \`"\${this.value}"\`;
        };
        
        // 显示当前自定义值
        const currentCustomValue = customDelimiterInput.value || '';
        displayElement.textContent = \`"\${currentCustomValue}"\`;
      } else {
        customDelimiterInput.style.display = 'none';
        
        // 显示选定的分隔符
        switch (delimiterType) {
          case 'newline':
            displayElement.textContent = '"\\n"';
            break;
          case 'comma':
            displayElement.textContent = '","';
            break;
          case 'space':
            displayElement.textContent = '" "';
            break;
          case 'semicolon':
            displayElement.textContent = '";"';
            break;
          case 'tab':
            displayElement.textContent = '"\\t"';
            break;
        }
      }
    }
    
    // 清除无效密钥
    function clearInvalidKeys() {
      confirmDialog('确定要删除所有无效密钥吗？此操作不可撤销。', async (confirmed) => {
        if (!confirmed) return;
        
        try {
          // 获取所有密钥
          const response = await fetch('/admin/api/keys');
          if (!response.ok) throw new Error('获取密钥失败');
          
          const result = await response.json();
          if (!result.success) throw new Error('获取密钥失败');
          
          const keys = result.data;
          const invalidKeys = keys.filter(k => k.balance <= 0 || k.lastError).map(k => k.key);
          
          if (invalidKeys.length === 0) {
            showToast('没有找到无效密钥');
            return;
          }
          
          // 显示进度条
          showProgress("正在删除无效密钥");
          
          // 批量删除
          let processed = 0;
          let successful = 0;
          
          for (const key of invalidKeys) {
            try {
              const deleteResponse = await fetch('/admin/api/delete-key', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ key })
              });
              
              if (deleteResponse.ok) {
                const deleteResult = await deleteResponse.json();
                if (deleteResult.success) successful++;
              }
            } catch (e) {
              console.error(\`删除密钥 \${key} 失败:\`, e);
            } finally {
              processed++;
              updateProgress(processed, invalidKeys.length, successful);
              
              // 添加短暂延迟避免请求过快
              await new Promise(resolve => setTimeout(resolve, 100));
            }
          }
          
          // 完成后重新加载数据
          setTimeout(() => {
            hideProgress();
            loadAllKeys();
            setTimeout(loadDashboard, 500);
            showToast(\`成功删除 \${successful} 个无效密钥\`);
          }, 1000);
          
        } catch (error) {
          hideProgress();
          console.error('清除无效密钥失败:', error);
          showToast(\`操作失败: \${error.message}\`, true);
        }
      }, {
        confirmText: '删除无效密钥',
        confirmClass: 'danger'
      });
    }
    
    // 导出所有有效密钥
    async function exportValidKeys() {
      try {
        // 获取所有密钥
        const response = await fetch('/admin/api/keys');
        if (!response.ok) throw new Error('获取密钥失败');
        
        const result = await response.json();
        if (!result.success) throw new Error('获取密钥失败');
        
        const keys = result.data;
        const validKeys = keys.filter(k => k.balance > 0 && !k.lastError).map(k => k.key);
        
        if (validKeys.length === 0) {
          showToast('没有找到有效密钥', true);
          return;
        }
        
        exportKeys(validKeys, '有效密钥');
        
      } catch (error) {
        console.error('导出有效密钥失败:', error);
        showToast(\`导出失败: \${error.message}\`, true);
      }
    }
    
    // 导出高余额密钥
    async function exportFilteredKeys() {
      try {
        // 获取最低余额阈值
        const minBalance = parseFloat(document.getElementById('min-balance-input').value) || 0;
        const includeBalances = document.getElementById('include-balances').checked;
        
        // 关闭模态框
        closeBalanceFilterModal();
        
        // 获取所有密钥
        const response = await fetch('/admin/api/keys');
        if (!response.ok) throw new Error('获取密钥失败');
        
        const result = await response.json();
        if (!result.success) throw new Error('获取密钥失败');
        
        const keys = result.data;
        const filteredKeys = keys.filter(k => parseFloat(k.balance) >= minBalance && !k.lastError);
        
        if (filteredKeys.length === 0) {
          showToast(\`没有找到余额高于 \${minBalance} 的密钥\`, true);
          return;
        }
        
        if (includeBalances) {
          // 导出格式: key|balance
          const keysWithBalances = filteredKeys.map(k => \`\${k.key}|\${k.balance}\`);
          exportKeys(keysWithBalances, \`余额≥\${minBalance}密钥\`, true);
        } else {
          // 仅导出密钥
          const keysOnly = filteredKeys.map(k => k.key);
          exportKeys(keysOnly, \`余额≥\${minBalance}密钥\`);
        }
        
      } catch (error) {
        console.error('导出高余额密钥失败:', error);
        showToast(\`导出失败: \${error.message}\`, true);
      }
    }
    
    // 复制所有密钥
    async function copyAllKeys() {
      try {
        // 获取所有密钥
        const response = await fetch('/admin/api/keys');
        if (!response.ok) throw new Error('获取密钥失败');
        
        const result = await response.json();
        if (!result.success) throw new Error('获取密钥失败');
        
        const keys = result.data.map(k => k.key);
        
        if (keys.length === 0) {
          showToast('没有找到可复制的密钥', true);
          return;
        }
        
        // 获取分隔符
        const delimiter = getSelectedDelimiter();
        
        // 复制到剪贴板
        const keysText = keys.join(delimiter);
        await navigator.clipboard.writeText(keysText);
        
        showToast(\`成功复制 \${keys.length} 个密钥到剪贴板\`);
        
      } catch (error) {
        console.error('复制所有密钥失败:', error);
        showToast(\`复制失败: \${error.message}\`, true);
      }
    }
    
    // 通用导出密钥函数
    function exportKeys(keys, description, isFormatted = false) {
      if (!keys || keys.length === 0) {
        showToast('没有可导出的密钥', true);
        return;
      }
      
      try {
        // 获取用户指定的分隔符
        const delimiter = getSelectedDelimiter();
        
        // 创建Blob对象
        const keysText = keys.join(delimiter);
        const blob = new Blob([keysText], { type: 'text/plain' });
        
        // 创建下载链接
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        
        // 设置文件名
        const date = new Date().toISOString().replace(/[:.]/g, '-').substring(0, 19);
        const formattedType = isFormatted ? '(带余额)' : '';
        a.download = \`siliconflow-\${description}\${formattedType}-\${date}.txt\`; // 导出文件名
        
        // 模拟点击
        document.body.appendChild(a);
        a.click();
        
        // 清理
        setTimeout(() => {
          document.body.removeChild(a);
          URL.revokeObjectURL(url);
        }, 100);
        
        showToast(\`成功导出 \${keys.length} 个\${description}\`);
        
      } catch (error) {
        console.error('导出密钥失败:', error);
        showToast(\`导出失败: \${error.message}\`, true);
      }
    }

    // 添加隐藏进度条函数
    window.hideProgress = hideProgress;
    
    // 事件监听器
    document.addEventListener('DOMContentLoaded', () => {

      // 全局多选控件
      document.getElementById('select-all-keys').addEventListener('change', function() {
        const tableCheckbox = document.getElementById('select-all-table');
        tableCheckbox.checked = this.checked;
        
        // 触发表格全选按钮的change事件
        const event = new Event('change');
        tableCheckbox.dispatchEvent(event);
      });
      
      // 显示/隐藏批量配置面板
      document.getElementById('toggle-batch-config').addEventListener('click', function() {
        const configPanel = document.getElementById('batch-config-panel');
        configPanel.classList.toggle('show');
        this.classList.toggle('active');
        
        // 使用平滑动画效果更新按钮文本
        const btnText = this.querySelector('span');
        const btnIcon = this.querySelector('svg');
        
        if (configPanel.classList.contains('show')) {
          // 配置面板显示状态
          btnIcon.style.transform = 'rotate(180deg)';
          btnText.textContent = '点击收起';
          
          // 平滑滚动到配置面板
          setTimeout(() => {
            configPanel.scrollIntoView({behavior: 'smooth', block: 'nearest'});
          }, 100);
        } else {
          // 配置面板隐藏状态
          btnIcon.style.transform = 'rotate(0)';
          btnText.textContent = '高级设置';
        }
      });
      
      // 批量检测按钮
      document.getElementById('check-selected-keys').addEventListener('click', async () => {
        try {
          await batchCheckSelectedKeys();
        } catch (error) {
          console.error("批量检测出错:", error);
        }
      });
      // 批量删除按钮
      document.getElementById('delete-selected-keys').addEventListener('click', batchDeleteSelectedKeys);

      // 回车按钮检测
      const modalInput = document.getElementById('modal-input');
      modalInput.addEventListener('keypress', (e) => {
          if (e.key === 'Enter') {
          handleModalConfirm();
          }
      });

      // 仪表盘
      document.getElementById('refresh-stats-btn').addEventListener('click', loadDashboard);
      document.getElementById('update-balances-btn').addEventListener('click', updateAllBalances);
      
      // 密钥
      document.getElementById('add-key-btn').addEventListener('click', addKey);
      document.getElementById('add-bulk-keys-btn').addEventListener('click', addBulkKeys);
      
      // 按Enter键添加单个密钥
      document.getElementById('add-key-input').addEventListener('keypress', (event) => {
        if (event.key === 'Enter') {
          addKey();
        }
      });

      // 添加间隔类型切换逻辑
      const intervalTypeSelect = document.getElementById('interval-type');
      
      // 初始化输入框状态
      updateIntervalFields();
      
      // 监听间隔类型变化
      intervalTypeSelect.addEventListener('change', updateIntervalFields);
      
      function updateIntervalFields() {
        const intervalType = intervalTypeSelect.value;
        const minIntervalInput = document.getElementById('min-interval');
        const maxIntervalInput = document.getElementById('max-interval');
        const fixedIntervalInput = document.getElementById('concurrency');
        
        if (intervalType === 'fixed') {
          // 启用固定间隔，禁用随机间隔
          fixedIntervalInput.disabled = false;
          minIntervalInput.disabled = true;
          maxIntervalInput.disabled = true;
          
          // 视觉反馈
          fixedIntervalInput.style.opacity = '1';
          minIntervalInput.style.opacity = '0.5';
          maxIntervalInput.style.opacity = '0.5';
        } else {
          // 启用随机间隔，禁用固定间隔
          fixedIntervalInput.disabled = true;
          minIntervalInput.disabled = false;
          maxIntervalInput.disabled = false;
          
          // 视觉反馈
          fixedIntervalInput.style.opacity = '0.5';
          minIntervalInput.style.opacity = '1';
          maxIntervalInput.style.opacity = '1';
        }
      }


      // 增强批量配置面板可见性
      enhanceBatchConfigPanelVisibility();

      // 下拉菜单控制
      const moreActionsBtn = document.getElementById('more-actions');
      const dropdownContent = document.querySelector('.dropdown-content');
      
      moreActionsBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        dropdownContent.classList.toggle('show');
        
        // 添加或移除活跃状态样式
        moreActionsBtn.classList.toggle('active', dropdownContent.classList.contains('show'));
      });
      
      // 点击其他地方关闭下拉菜单
      document.addEventListener('click', (e) => {
        if (!moreActionsBtn.contains(e.target)) {
          dropdownContent.classList.remove('show');
          moreActionsBtn.classList.remove('active');
        }
      });
      
      // 导出选中密钥
      document.getElementById('export-selected-keys').addEventListener('click', exportSelectedKeys);
      
      // 清除无效密钥
      document.getElementById('clear-invalid-keys').addEventListener('click', clearInvalidKeys);
      
      // 导出有效密钥
      document.getElementById('export-valid-keys').addEventListener('click', exportValidKeys);
      
      // 导出高余额密钥
      document.getElementById('export-balance-keys').addEventListener('click', showBalanceFilterModal);
      
      // 复制所有密钥
      document.getElementById('copy-all-keys').addEventListener('click', copyAllKeys);
      
      // 复制所选密钥
      document.getElementById('copy-selected-keys').addEventListener('click', copySelectedKeys);
      
      // 导出过滤后的密钥按钮
      document.getElementById('export-filtered-keys').addEventListener('click', exportFilteredKeys);
      
      // 停止批量处理按钮点击事件
      document.getElementById('stop-batch-process').addEventListener('click', stopBatchProcessing);
      
      // 更新分隔符文本显示
      document.getElementById('delimiter-select').addEventListener('change', updateDelimiterDisplay);

      // 更新导出按钮状态
      function updateExportButtonState() {
        document.getElementById('export-selected-keys').disabled = selectedKeys.size === 0;
      }

      // 初始化分隔符显示
      updateDelimiterDisplay();
      
      // 添加事件监听器
      document.getElementById('delimiter-select').addEventListener('change', updateDelimiterDisplay);
      document.getElementById('custom-delimiter').addEventListener('input', updateDelimiterDisplay);
      
      // 扩展更新选择状态函数
      const originalUpdateSelectionStatus = updateSelectionStatus;
      window.updateSelectionStatus = function() {
        originalUpdateSelectionStatus();
        updateExportButtonState();
      };

      // 访问控制选择变化时
      document.getElementById('access-control-select').addEventListener('change', function() {
        toggleGuestPasswordField(this.value);
      });
                
      // 初始加载
      loadDashboard();
    });
  </script>
</body>
</html>
`;
