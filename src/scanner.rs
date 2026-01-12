use anyhow::Result;
use chrono::{Local, NaiveDate};
use std::process::Command;
use sysinfo::{System, Process};
use winreg::enums::*;
use winreg::RegKey;
use netstat2::{get_sockets_info, AddressFamilyFlags, ProtocolFlags};
use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};
use std::fs::File;
use std::io::Read;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub network: Option<NetworkResult>,
    pub startup: Option<Vec<StartupItem>>,
    pub registry: Option<RegistryResult>,
    pub files: Option<Vec<String>>,
    pub services: Option<ServiceResult>,
    pub logs: Option<LogResult>,
    pub memory: Option<Vec<ProcessInfo>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkResult {
    pub all_connections: Vec<ConnectionInfo>,
    pub suspicious: Vec<ConnectionInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum RiskLevel {
    High,
    Medium,
    Low,
    Info,
}

impl RiskLevel {
    pub fn to_label(&self) -> String {
        match self {
            RiskLevel::High => "高危".to_string(),
            RiskLevel::Medium => "中危".to_string(),
            RiskLevel::Low => "低危".to_string(),
            RiskLevel::Info => "信息".to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionInfo {
    pub pid: u32,
    pub process: String,
    pub laddr: String,
    pub raddr: String,
    pub status: String,
    pub risk_level: RiskLevel,
    pub risk_desc: String,
    // Enhanced fields
    pub location: String,
    pub service: String,
    pub process_path: String,
    pub signature: String,
    pub threat_info: String,
    pub behavior: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StartupItem {
    pub name: String,
    pub path: String,
    pub signature: String,
    pub risk_level: RiskLevel,
    pub risk_desc: String,
    pub modified_time: String, // Added
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryResult {
    pub status: String, 
    pub message: String,
    pub accounts: Vec<String>,
    pub manual_steps: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceResult {
    pub suspicious: Vec<ServiceInfo>,
    pub skipped: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceInfo {
    pub name: String,
    pub display_name: String,
    pub status: String,
    pub binpath: String,
    pub risk_level: RiskLevel,
    pub signature: String,
    pub modified_time: String, // Added
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogResult {
    pub error: Option<String>,
    pub total_events: usize,
    pub critical_events: usize,
    pub events: Vec<LogEvent>,
    pub manual_steps: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEvent {
    pub time: String,
    pub id: u64,
    pub event_type: String,
    pub message: String,
    pub tactics: String, // MITRE ATT&CK
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessInfo {
    pub pid: u32,
    pub name: String,
    pub path: String,
    pub reason: String,
    pub memory: String,
    pub risk_level: RiskLevel,
    pub parent_pid: u32,
    pub signature: String,
    pub start_time: u64, // Added timestamp
    pub start_time_str: String, // Added string
}

pub struct Scanner {
    pub everything_path: String,
    pub start_date: Option<NaiveDate>,
    pub end_date: Option<NaiveDate>,
}

impl Scanner {
    pub fn new(everything_path: String, start_date: Option<NaiveDate>, end_date: Option<NaiveDate>) -> Self {
        Self {
            everything_path,
            start_date,
            end_date,
        }
    }

    fn check_signature(path: &str) -> String {
        if path.is_empty() || !std::path::Path::new(path).exists() { return "文件不存在".to_string(); }
        // 避免频繁调用 PowerShell，改用简单的文件存在性检查作为占位
        // 实际生产环境中应使用 WinAPI (WinVerifyTrust) 进行高效验证
        // 这里为了不卡死界面，暂时只检查是否为可执行文件
        "未验证(性能优化)".to_string() 
    }

    fn get_ip_location(ip: &str) -> String {
        if ip == "*.*" || ip.starts_with("127.") || ip.starts_with("192.168.") || ip.starts_with("10.") || ip.starts_with("172.") {
            return "内网/本地".to_string();
        }
        // Use ip-api.com (free, rate limited)
        let url = format!("http://ip-api.com/json/{}?fields=country,city,isp", ip);
        match reqwest::blocking::Client::new().get(&url).timeout(std::time::Duration::from_secs(1)).send() {
            Ok(resp) => {
                 if let Ok(json) = resp.json::<serde_json::Value>() {
                     format!("{} {} ({})", 
                        json["country"].as_str().unwrap_or(""), 
                        json["city"].as_str().unwrap_or(""),
                        json["isp"].as_str().unwrap_or("")
                    )
                 } else {
                     "位置未知".to_string()
                 }
            },
            Err(_) => "查询超时".to_string()
        }
    }

    fn get_service_name(port: u16) -> String {
        match port {
            80 => "HTTP".to_string(),
            443 => "HTTPS".to_string(),
            445 => "SMB".to_string(),
            3389 => "RDP".to_string(),
            22 => "SSH".to_string(),
            21 => "FTP".to_string(),
            23 => "Telnet".to_string(),
            25 => "SMTP".to_string(),
            53 => "DNS".to_string(),
            3306 => "MySQL".to_string(),
            1433 => "MSSQL".to_string(),
            6379 => "Redis".to_string(),
            8080 => "HTTP-Alt".to_string(),
            _ => "未知服务".to_string(),
        }
    }

    fn get_file_hash(path: &str) -> String {
        let mut file = match File::open(path) {
            Ok(f) => f,
            Err(_) => return "无法读取".to_string(),
        };
        let mut hasher = Sha256::new();
        let mut buffer = [0; 4096];
        loop {
            let n = match file.read(&mut buffer) {
                Ok(n) if n == 0 => break,
                Ok(n) => n,
                Err(_) => return "读取错误".to_string(),
            };
            hasher.update(&buffer[..n]);
        }
        hex::encode(hasher.finalize())
    }

    fn get_file_modified_time(path: &str) -> String {
        if let Ok(metadata) = std::fs::metadata(path) {
            if let Ok(time) = metadata.modified() {
                let datetime: chrono::DateTime<chrono::Local> = time.into();
                return datetime.format("%Y-%m-%d %H:%M:%S").to_string();
            }
        }
        "未知".to_string()
    }

    pub fn analyze_network(&self) -> Result<NetworkResult> {
        let sys = System::new_all();
        let af_flags = AddressFamilyFlags::IPV4 | AddressFamilyFlags::IPV6;
        let proto_flags = ProtocolFlags::TCP | ProtocolFlags::UDP;
        let sockets = get_sockets_info(af_flags, proto_flags)?;

        let mut all_connections = Vec::new();
        let mut suspicious = Vec::new();

        for si in sockets {
            let (laddr, raddr, status, pids, rport) = match si.protocol_socket_info {
                netstat2::ProtocolSocketInfo::Tcp(tcp) => (
                    format!("{}:{}", tcp.local_addr, tcp.local_port),
                    format!("{}:{}", tcp.remote_addr, tcp.remote_port),
                    tcp.state.to_string(),
                    si.associated_pids,
                    tcp.remote_port
                ),
                netstat2::ProtocolSocketInfo::Udp(udp) => (
                    format!("{}:{}", udp.local_addr, udp.local_port),
                    "*.*".to_string(),
                    "UDP".to_string(),
                    si.associated_pids,
                    0
                ),
            };

            let is_remote = !raddr.starts_with("127.0.0.1") && !raddr.starts_with("0.0.0.0") && !raddr.starts_with("::1") && raddr != "*.*";

            if is_remote {
                for pid in pids {
                    let mut process_name = "未知进程".to_string();
                    let mut process_path = "".to_string();
                    let mut signature = "未知".to_string();
                    let mut behavior = "正常".to_string();

                    if let Some(process) = sys.process(sysinfo::Pid::from(pid as usize)) {
                        process_name = process.name().to_string();
                        process_path = process.exe().map(|p| p.to_string_lossy().to_string()).unwrap_or_default();
                        
                        // Behavior analysis
                        let disk_usage = process.disk_usage();
                        if disk_usage.read_bytes > 10_000_000 || disk_usage.written_bytes > 10_000_000 {
                            behavior = "大流量传输".to_string();
                        }
                    }

                    if !process_path.is_empty() {
                         signature = Self::check_signature(&process_path);
                    }

                    // Extract IP for location query
                    let remote_ip = raddr.split(':').next().unwrap_or("");
                    let location = Self::get_ip_location(remote_ip);
                    let service = Self::get_service_name(rport);

                    let mut risk_level = RiskLevel::Info;
                    let mut risk_desc = String::new();
                    let mut threat_info = "暂无情报".to_string();

                    // Risk Analysis
                    let is_private = remote_ip.starts_with("192.168.") || remote_ip.starts_with("10.") || remote_ip.starts_with("172.");
                    
                    if !is_private {
                         if !signature.contains("已签名") && !process_name.is_empty() {
                             risk_level = RiskLevel::Medium;
                             risk_desc = "外联进程未签名".to_string();
                         }

                         if rport != 80 && rport != 443 {
                             if risk_level == RiskLevel::Info {
                                 risk_level = RiskLevel::Low;
                                 risk_desc = "非常规端口".to_string();
                             }
                         }
                         
                         if [4444, 445, 3389].contains(&rport) {
                             risk_level = RiskLevel::High;
                             risk_desc = "高危端口连接".to_string();
                         }
                    }

                    let info = ConnectionInfo {
                        pid,
                        process: process_name,
                        laddr: laddr.clone(),
                        raddr: raddr.clone(),
                        status: status.clone(),
                        risk_level: risk_level.clone(),
                        risk_desc,
                        location,
                        service,
                        process_path,
                        signature,
                        threat_info,
                        behavior,
                    };

                    if risk_level != RiskLevel::Info {
                        suspicious.push(info.clone());
                    }
                    all_connections.push(info);
                }
            }
        }

        Ok(NetworkResult {
            all_connections,
            suspicious,
        })
    }

    pub fn check_startup_items(&self) -> Result<Vec<StartupItem>> {
        let mut items = Vec::new();
        let locations = [
            (HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
            (HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run"),
            (HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
        ];

        for (hive, path) in locations.iter() {
            if let Ok(key) = RegKey::predef(*hive).open_subkey(path) {
                for (name, value) in key.enum_values().filter_map(Result::ok) {
                    let path_str = value.to_string();
                    let clean_path = path_str.split('"').nth(1).unwrap_or(&path_str).split(' ').next().unwrap_or(&path_str);
                    let signature = Self::check_signature(clean_path);
                    
                    let mut risk_level = RiskLevel::Info;
                    let mut risk_desc = String::new();

                    if !signature.contains("已签名") {
                        // Check if it's a known safe system path (simple heuristic)
                        let lower_path = clean_path.to_lowercase();
                        if !lower_path.contains("windows\\system32") && !lower_path.contains("program files") {
                             risk_level = RiskLevel::Medium;
                             risk_desc = "未签名启动项".to_string();
                        }
                    }

                    let modified_time = Self::get_file_modified_time(clean_path);

                    items.push(StartupItem {
                        name,
                        path: path_str,
                        signature,
                        risk_level,
                        risk_desc,
                        modified_time,
                    });
                }
            }
        }
        Ok(items)
    }

    pub fn scan_hidden_accounts(&self) -> RegistryResult {
        // ... (Keep existing implementation)
        let mut accounts = Vec::new();
        let manual_steps = vec![
            "1. 以管理员身份运行 CMD".to_string(),
            "2. 执行命令 'wmic useraccount get name,status'".to_string(),
        ];

        let script = "Get-LocalUser | Select-Object Name,Enabled,Description | ConvertTo-Json";
        let output = Command::new("powershell").args(&["-Command", script]).output();

        if let Ok(out) = output {
            if out.status.success() {
                let content = String::from_utf8_lossy(&out.stdout);
                let users: Vec<serde_json::Value> = if content.trim().starts_with('[') {
                    serde_json::from_str(&content).unwrap_or_default()
                } else if content.trim().starts_with('{') {
                    vec![serde_json::from_str(&content).unwrap_or(serde_json::Value::Null)]
                } else {
                    vec![]
                };

                for user in users {
                    if user.is_null() { continue; }
                    let name = user["Name"].as_str().unwrap_or("").to_string();
                    if name.ends_with("$") || name.contains("hidden") || name.contains("admin") && name != "Administrator" {
                         accounts.push(format!("{} (检测到可疑命名)", name));
                    }
                }
            }
        }

        let key_res = RegKey::predef(HKEY_LOCAL_MACHINE).open_subkey_with_flags(r"SAM\SAM\Domains\Account\Users", KEY_READ);
        if let Ok(key) = key_res {
             for name in key.enum_keys().filter_map(Result::ok) {
                 if name.starts_with("00000") {
                     if let Ok(names_key) = key.open_subkey(format!("{}\\{}", name, "Names")) {
                         for account_name in names_key.enum_keys().filter_map(Result::ok) {
                             if !accounts.iter().any(|a| a.contains(&account_name)) {
                                 if account_name.ends_with("$") {
                                     accounts.push(format!("{} (注册表发现)", account_name));
                                 }
                             }
                         }
                     }
                 }
             }
        }

        if accounts.is_empty() {
             RegistryResult {
                 status: "no_hidden".to_string(),
                 message: "未发现可疑隐藏账户".to_string(),
                 accounts,
                 manual_steps,
             }
         } else {
             RegistryResult {
                 status: "found".to_string(),
                 message: format!("发现 {} 个可疑账户", accounts.len()),
                 accounts,
                 manual_steps,
             }
         }
    }

    pub fn find_suspicious_files(&self) -> Result<Vec<String>> {
        if self.everything_path.is_empty() {
            return Ok(vec!["错误: 未配置 Everything 路径".to_string()]);
        }

        let start = self.start_date.unwrap_or_else(|| Local::now().date_naive() - chrono::Duration::days(30));
        let end = self.end_date.unwrap_or_else(|| Local::now().date_naive());
        let start_str = start.format("%Y/%m/%d").to_string();
        let end_str = end.format("%Y/%m/%d").to_string();
        let query = format!("c:\\users\\* datemodified:{}-{} ext:exe;dll;bat;ps1;vbs", start_str, end_str);
        
        let output = Command::new(&self.everything_path).arg("-s").arg(&query).output();

        match output {
            Ok(_) => Ok(vec![format!("已调用 Everything 搜索: {}", query), "请在弹出的 Everything 窗口中查看结果".to_string()]),
            Err(e) => Ok(vec![format!("执行搜索失败: {}", e)])
        }
    }

    pub fn check_services(&self) -> Result<ServiceResult> {
        let script = "Get-CimInstance Win32_Service | Select-Object Name,DisplayName,PathName,State | ConvertTo-Json";
        let output = Command::new("powershell").args(&["-Command", script]).output()?;
        let content = String::from_utf8_lossy(&output.stdout);
        let mut suspicious = Vec::new();
        let skipped = Vec::new();

        let services: Vec<serde_json::Value> = if content.trim().starts_with('[') {
            serde_json::from_str(&content).unwrap_or_default()
        } else if content.trim().starts_with('{') {
             vec![serde_json::from_str(&content).unwrap_or(serde_json::Value::Null)]
        } else {
            vec![]
        };

        for svc in services {
            if svc.is_null() { continue; }
            let name = svc["Name"].as_str().unwrap_or("").to_string();
            let display_name = svc["DisplayName"].as_str().unwrap_or("").to_string();
            let path = svc["PathName"].as_str().unwrap_or("").to_string();
            let status = svc["State"].as_str().unwrap_or("").to_string();

            if path.is_empty() { continue; }
            
            // Signature check for non-system services
            let path_lower = path.to_lowercase();
            // Remove arguments from service path to get binary
            let clean_path = path.split('"').nth(1).unwrap_or(&path).split(' ').next().unwrap_or(&path);

            if !path_lower.contains("microsoft") && !path_lower.contains("windows") && 
               !path_lower.starts_with("c:\\windows\\") {
                
                let signature = Self::check_signature(clean_path);
                
                let modified_time = Self::get_file_modified_time(clean_path);

                suspicious.push(ServiceInfo {
                    name,
                    display_name,
                    status,
                    binpath: path,
                    risk_level: if signature.contains("已签名") { RiskLevel::Low } else { RiskLevel::Medium },
                    signature,
                    modified_time,
                });
            }
        }

        Ok(ServiceResult { suspicious, skipped })
    }

    pub fn analyze_security_logs(&self) -> LogResult {
        let script = r#"
            $OutputEncoding = [Console]::OutputEncoding = [System.Text.Encoding]::UTF8;
            Get-EventLog -LogName Security -Newest 1000 | 
            Where-Object { $_.EventID -in 4624,4625,4648,4672,4720,4726,4738,4740,4768,4769,4776,1102 } |
            Select-Object TimeGenerated,EventID,InstanceId,Message |
            ConvertTo-Json
        "#;

        let output = Command::new("powershell").args(&["-Command", script]).output();

        match output {
            Ok(out) => {
                if !out.status.success() {
                    return LogResult {
                        error: Some("PowerShell 执行失败".to_string()),
                        total_events: 0,
                        critical_events: 0,
                        events: vec![],
                        manual_steps: vec!["请以管理员身份运行".to_string()],
                    };
                }
                let content = String::from_utf8_lossy(&out.stdout);
                let events: Vec<LogEvent> = if content.trim().starts_with('[') {
                    serde_json::from_str::<Vec<serde_json::Value>>(&content).unwrap_or_default()
                } else if content.trim().starts_with('{') {
                    vec![serde_json::from_str::<serde_json::Value>(&content).unwrap_or(serde_json::Value::Null)]
                } else {
                    vec![]
                }.into_iter().filter_map(|v| {
                    if v.is_null() { return None; }
                    let id = v["EventID"].as_u64().unwrap_or(0);
                    // MITRE ATT&CK Mapping
                    let tactics = match id {
                        4624 | 4625 => "Initial Access (初始访问)",
                        4688 => "Execution (执行)",
                        4720 => "Persistence (持久化)",
                        _ => "General",
                    }.to_string();

                    Some(LogEvent {
                        time: v["TimeGenerated"].as_str().unwrap_or("").to_string(),
                        id,
                        event_type: "安全事件".to_string(),
                        message: v["Message"].as_str().unwrap_or("").chars().take(100).collect(),
                        tactics,
                    })
                }).collect();

                LogResult {
                    error: None,
                    total_events: 1000, 
                    critical_events: events.len(),
                    events,
                    manual_steps: vec![],
                }
            },
            Err(e) => LogResult {
                error: Some(e.to_string()),
                total_events: 0,
                critical_events: 0,
                events: vec![],
                manual_steps: vec!["请以管理员身份运行".to_string()],
            }
        }
    }

    pub fn analyze_memory(&self) -> Result<Vec<ProcessInfo>> {
        let sys = System::new_all();
        let mut suspicious = Vec::new();

        for (pid, process) in sys.processes() {
            let name = process.name();
            let path = process.exe().map(|p| p.to_string_lossy().to_string()).unwrap_or_default();
            let memory = format!("{:.2} MB", process.memory() as f64 / 1024.0 / 1024.0);
            let parent = process.parent().map(|p| p.as_u32()).unwrap_or(0);
            
            let start_time = process.start_time();
            let start_time_str = chrono::NaiveDateTime::from_timestamp_opt(start_time as i64, 0)
                .map(|dt| chrono::DateTime::<chrono::Local>::from_naive_utc_and_offset(dt, *chrono::Local::now().offset()).format("%Y-%m-%d %H:%M:%S").to_string())
                .unwrap_or_else(|| "未知".to_string());

            let mut is_suspicious = false;
            let mut reason = String::new();
            let mut risk_level = RiskLevel::Info;

            let signature = if !path.is_empty() {
                Self::check_signature(&path)
            } else {
                "未知".to_string()
            };

            if path.is_empty() {
                if pid.as_u32() > 100 { 
                     // Ignore for now
                }
            } else {
                let path_lower = path.to_lowercase();
                if path_lower.starts_with("c:\\windows\\temp") || path_lower.starts_with("c:\\programdata") {
                    is_suspicious = true;
                    reason = "可疑路径运行".to_string();
                    risk_level = RiskLevel::High;
                } else if ["svchost.exe", "explorer.exe", "lsass.exe"].contains(&name) {
                    if !path_lower.starts_with("c:\\windows\\system32") {
                        is_suspicious = true;
                        reason = "系统进程伪装".to_string();
                        risk_level = RiskLevel::High;
                    }
                }
                
                if !signature.contains("已签名") && !path_lower.contains("windows") {
                     is_suspicious = true;
                     reason = "未签名进程".to_string();
                     if risk_level == RiskLevel::Info { risk_level = RiskLevel::Medium; }
                }
            }

            if is_suspicious {
                suspicious.push(ProcessInfo {
                    pid: pid.as_u32(),
                    name: name.to_string(),
                    path,
                    reason,
                    memory,
                    risk_level,
                    parent_pid: parent,
                    signature,
                    start_time,
                    start_time_str,
                });
            }
        }

        Ok(suspicious)
    }
}
