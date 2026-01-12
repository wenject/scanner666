#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod scanner;

use eframe::egui;
use egui_plot::{Bar, BarChart, Plot};
use scanner::{Scanner, ScanResult, RiskLevel};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::thread;
use chrono::NaiveDate;
use std::fs::File;
use std::io::Write;

fn main() -> Result<(), eframe::Error> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1000.0, 700.0])
            .with_title("Wenject Security Scanner - Wenject安全扫描"),
        ..Default::default()
    };
    eframe::run_native(
        "Wenject Security Scanner",
        options,
        Box::new(|cc| Box::new(SecurityApp::new(cc))),
    )
}

#[derive(PartialEq)]
enum AppTab {
    Config,
    Dashboard,
    Timeline,
    Results,
    Report,
}

struct SecurityApp {
    // UI State
    current_tab: AppTab,
    is_dark_mode: bool,

    // Configuration
    everything_path: String,
    start_date: NaiveDate,
    end_date: NaiveDate,

    // Toggles
    check_network: bool,
    check_startup: bool,
    check_registry: bool,
    check_files: bool,
    check_services: bool,
    check_logs: bool,
    check_memory: bool,

    // State
    is_scanning: bool,
    progress: f32,
    logs: String,
    results: Option<ScanResult>,
    
    // Concurrency
    rx: Receiver<ScanUpdate>,
    tx: Sender<ScanUpdate>, // Keep a clone to pass to thread
}

enum ScanUpdate {
    Log(String),
    Progress(f32),
    Result(ScanResult),
    Finished,
}

impl SecurityApp {
    fn new(cc: &eframe::CreationContext<'_>) -> Self {
        // 配置字体以支持中文
        let mut fonts = egui::FontDefinitions::default();
        
        // 尝试读取系统字体：优先微软雅黑，其次黑体
        let font_data = std::fs::read("C:\\Windows\\Fonts\\msyh.ttf")
            .or_else(|_| std::fs::read("C:\\Windows\\Fonts\\simhei.ttf"));
            
        if let Ok(data) = font_data {
            fonts.font_data.insert(
                "ChineseFont".to_owned(),
                egui::FontData::from_owned(data),
            );
            
            // 将中文字体插入到字体列表的首位
            if let Some(vec) = fonts.families.get_mut(&egui::FontFamily::Proportional) {
                vec.insert(0, "ChineseFont".to_owned());
            }
            if let Some(vec) = fonts.families.get_mut(&egui::FontFamily::Monospace) {
                vec.insert(0, "ChineseFont".to_owned());
            }
            
            cc.egui_ctx.set_fonts(fonts);
        }

        // Default to dark mode visuals initially
        cc.egui_ctx.set_visuals(egui::Visuals::dark());

        let (tx, rx) = channel();

        Self {
            current_tab: AppTab::Config,
            is_dark_mode: true,
            everything_path: "C:\\Program Files\\Everything\\Everything.exe".to_owned(),
            start_date: chrono::Local::now().date_naive() - chrono::Duration::days(30),
            end_date: chrono::Local::now().date_naive(),
            
            check_network: true,
            check_startup: true,
            check_registry: true,
            check_files: false, // Default off as it requires config
            check_services: true,
            check_logs: true,
            check_memory: true,

            is_scanning: false,
            progress: 0.0,
            logs: String::new(),
            results: None,

            rx,
            tx,
        }
    }
    
    fn set_theme(&self, ctx: &egui::Context) {
        if self.is_dark_mode {
             ctx.set_visuals(egui::Visuals::dark());
        } else {
             ctx.set_visuals(egui::Visuals::light());
        }
    }

    fn start_scan(&mut self) {
        self.is_scanning = true;
        self.progress = 0.0;
        self.logs.clear();
        self.results = None;
        self.current_tab = AppTab::Dashboard; // Switch to dashboard
        self.logs.push_str("开始扫描...\n");

        let tx = self.tx.clone();
        let scanner = Scanner::new(
            self.everything_path.clone(),
            Some(self.start_date),
            Some(self.end_date),
        );
        
        let checks = (
            self.check_network,
            self.check_startup,
            self.check_registry,
            self.check_files,
            self.check_services,
            self.check_logs,
            self.check_memory
        );

        thread::spawn(move || {
            let mut results = ScanResult {
                network: None,
                startup: None,
                registry: None,
                files: None,
                services: None,
                logs: None,
                memory: None,
            };

            let total_steps = [checks.0, checks.1, checks.2, checks.3, checks.4, checks.5, checks.6]
                .iter().filter(|&&x| x).count() as f32;
            let mut current_step = 0.0;

            if checks.0 {
                let _ = tx.send(ScanUpdate::Log("正在分析网络连接...".into()));
                match scanner.analyze_network() {
                    Ok(res) => results.network = Some(res),
                    Err(e) => { let _ = tx.send(ScanUpdate::Log(format!("网络分析错误: {}", e))); }
                }
                current_step += 1.0;
                let _ = tx.send(ScanUpdate::Progress(current_step / total_steps));
            }

            if checks.1 {
                let _ = tx.send(ScanUpdate::Log("正在检查启动项...".into()));
                match scanner.check_startup_items() {
                    Ok(res) => results.startup = Some(res),
                    Err(e) => { let _ = tx.send(ScanUpdate::Log(format!("启动项检查错误: {}", e))); }
                }
                current_step += 1.0;
                let _ = tx.send(ScanUpdate::Progress(current_step / total_steps));
            }

            if checks.2 {
                let _ = tx.send(ScanUpdate::Log("正在扫描注册表...".into()));
                results.registry = Some(scanner.scan_hidden_accounts());
                current_step += 1.0;
                let _ = tx.send(ScanUpdate::Progress(current_step / total_steps));
            }

            if checks.3 {
                let _ = tx.send(ScanUpdate::Log("正在调用 Everything 搜索文件...".into()));
                match scanner.find_suspicious_files() {
                    Ok(res) => results.files = Some(res),
                    Err(e) => { let _ = tx.send(ScanUpdate::Log(format!("文件搜索错误: {}", e))); }
                }
                current_step += 1.0;
                let _ = tx.send(ScanUpdate::Progress(current_step / total_steps));
            }

            if checks.4 {
                let _ = tx.send(ScanUpdate::Log("正在审查系统服务...".into()));
                match scanner.check_services() {
                    Ok(res) => results.services = Some(res),
                    Err(e) => { let _ = tx.send(ScanUpdate::Log(format!("服务检查错误: {}", e))); }
                }
                current_step += 1.0;
                let _ = tx.send(ScanUpdate::Progress(current_step / total_steps));
            }

            if checks.5 {
                let _ = tx.send(ScanUpdate::Log("正在分析安全日志...".into()));
                results.logs = Some(scanner.analyze_security_logs());
                current_step += 1.0;
                let _ = tx.send(ScanUpdate::Progress(current_step / total_steps));
            }

            if checks.6 {
                let _ = tx.send(ScanUpdate::Log("正在分析内存进程...".into()));
                match scanner.analyze_memory() {
                    Ok(res) => results.memory = Some(res),
                    Err(e) => { let _ = tx.send(ScanUpdate::Log(format!("内存分析错误: {}", e))); }
                }
                current_step += 1.0;
                let _ = tx.send(ScanUpdate::Progress(current_step / total_steps));
            }

            let _ = tx.send(ScanUpdate::Result(results));
            let _ = tx.send(ScanUpdate::Finished);
        });
    }

    fn generate_report(&mut self) {
        if let Some(results) = &self.results {
            if let Some(path) = rfd::FileDialog::new().set_file_name("security_report.txt").save_file() {
                let content = serde_json::to_string_pretty(results).unwrap_or_else(|e| format!("序列化失败: {}", e));
                match File::create(&path).and_then(|mut f| f.write_all(content.as_bytes())) {
                    Ok(_) => self.logs.push_str(&format!("报告已成功保存至: {}\n", path.display())),
                    Err(e) => self.logs.push_str(&format!("保存失败: {}\n", e)),
                }
            }
        } else {
             self.logs.push_str("暂无扫描结果，无法生成报告。\n");
        }
    }
}

impl eframe::App for SecurityApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.set_theme(ctx);
        
        // Handle updates from thread
        while let Ok(update) = self.rx.try_recv() {
            match update {
                ScanUpdate::Log(msg) => {
                    self.logs.push_str(&format!("{}\n", msg));
                }
                ScanUpdate::Progress(p) => self.progress = p,
                ScanUpdate::Result(res) => self.results = Some(res),
                ScanUpdate::Finished => {
                    self.is_scanning = false;
                    self.logs.push_str("扫描完成.\n");
                }
            }
        }

        egui::TopBottomPanel::top("top_panel").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.heading("Wenject 安全扫描仪表盘");
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                     if ui.button(if self.is_dark_mode { "☀ 浅色模式" } else { "🌙 深色模式" }).clicked() {
                         self.is_dark_mode = !self.is_dark_mode;
                     }
                });
            });
            
            ui.separator();
            
            ui.horizontal(|ui| {
                ui.selectable_value(&mut self.current_tab, AppTab::Config, "🛠️ 配置与扫描");
                ui.selectable_value(&mut self.current_tab, AppTab::Dashboard, "📊 风险仪表盘");
                ui.selectable_value(&mut self.current_tab, AppTab::Timeline, "⏱️ 应急时间线");
                ui.selectable_value(&mut self.current_tab, AppTab::Results, "📝 详细发现");
                ui.selectable_value(&mut self.current_tab, AppTab::Report, "📄 报告导出");
            });
        });

        egui::CentralPanel::default().show(ctx, |ui| {
            if self.is_scanning {
                ui.add(egui::ProgressBar::new(self.progress).show_percentage().text("扫描进行中..."));
                ui.add_space(10.0);
            }

            match self.current_tab {
                AppTab::Config => self.show_config_tab(ui),
                AppTab::Dashboard => self.show_dashboard_tab(ui),
                AppTab::Timeline => self.show_timeline_tab(ui),
                AppTab::Results => self.show_results_tab(ui),
                AppTab::Report => self.show_report_tab(ui),
            }
        });
        
        // Request repaint if scanning
        if self.is_scanning {
            ctx.request_repaint();
        }
    }
}

impl SecurityApp {
    fn show_config_tab(&mut self, ui: &mut egui::Ui) {
        egui::ScrollArea::vertical().show(ui, |ui| {
            ui.group(|ui| {
                ui.heading("扫描配置");
                ui.horizontal(|ui| {
                    ui.label("Everything 路径:");
                    ui.text_edit_singleline(&mut self.everything_path);
                    if ui.button("浏览").clicked() {
                        if let Some(path) = rfd::FileDialog::new().add_filter("exe", &["exe"]).pick_file() {
                            self.everything_path = path.display().to_string();
                        }
                    }
                });
                
                ui.add_space(5.0);
                
                ui.horizontal(|ui| {
                    ui.label("修改时间范围:");
                    let mut start_str = self.start_date.format("%Y-%m-%d").to_string();
                    if ui.add(egui::TextEdit::singleline(&mut start_str).desired_width(100.0)).changed() {
                        if let Ok(date) = NaiveDate::parse_from_str(&start_str, "%Y-%m-%d") {
                            self.start_date = date;
                        }
                    }
                    ui.label(" 至 ");
                    let mut end_str = self.end_date.format("%Y-%m-%d").to_string();
                    if ui.add(egui::TextEdit::singleline(&mut end_str).desired_width(100.0)).changed() {
                        if let Ok(date) = NaiveDate::parse_from_str(&end_str, "%Y-%m-%d") {
                            self.end_date = date;
                        }
                    }
                });
            });

            ui.add_space(10.0);

            ui.group(|ui| {
                ui.heading("功能模块");
                ui.horizontal_wrapped(|ui| {
                    ui.checkbox(&mut self.check_network, "网络连接分析");
                    ui.checkbox(&mut self.check_startup, "启动项检查");
                    ui.checkbox(&mut self.check_registry, "注册表隐藏账户");
                    ui.checkbox(&mut self.check_files, "文件搜索 (Everything)");
                    ui.checkbox(&mut self.check_services, "系统服务审查");
                    ui.checkbox(&mut self.check_logs, "安全日志分析");
                    ui.checkbox(&mut self.check_memory, "内存进程分析");
                });
            });

            ui.add_space(20.0);
            
            if ui.add_enabled(!self.is_scanning, egui::Button::new("🚀 开始全盘扫描").min_size(egui::vec2(200.0, 40.0))).clicked() {
                self.start_scan();
            }
            
            ui.add_space(20.0);
            ui.heading("运行日志");
            egui::ScrollArea::vertical().id_source("config_logs").max_height(200.0).show(ui, |ui| {
                ui.code(&self.logs);
            });
        });
    }

    fn show_dashboard_tab(&mut self, ui: &mut egui::Ui) {
        if let Some(res) = &self.results {
            ui.heading("🛡️ 风险可视化仪表盘");
            ui.separator();
            
            let mut high_count = 0;
            let mut medium_count = 0;
            let mut low_count = 0;
            
            // Count risks
            if let Some(startup) = &res.startup {
                for s in startup {
                    match s.risk_level {
                        RiskLevel::High => high_count += 1,
                        RiskLevel::Medium => medium_count += 1,
                        _ => low_count += 1,
                    }
                }
            }
            if let Some(net) = &res.network {
                for c in &net.suspicious {
                    match c.risk_level {
                        RiskLevel::High => high_count += 1,
                        RiskLevel::Medium => medium_count += 1,
                        _ => low_count += 1,
                    }
                }
            }
            if let Some(srv) = &res.services {
                for s in &srv.suspicious {
                     match s.risk_level {
                        RiskLevel::High => high_count += 1,
                        RiskLevel::Medium => medium_count += 1,
                        _ => low_count += 1,
                    }
                }
            }
            if let Some(mem) = &res.memory {
                for m in mem {
                    match m.risk_level {
                        RiskLevel::High => high_count += 1,
                        RiskLevel::Medium => medium_count += 1,
                        _ => low_count += 1,
                    }
                }
            }
            
            // Layout Charts
            ui.columns(2, |columns| {
                columns[0].heading("风险等级分布");
                // Simplified Pie Chart using basic shapes since PieChart widget might not be available or stable
                // We'll use a BarChart for now as it is reliable
                let risk_bars = vec![
                    Bar::new(1.0, high_count as f64).name("高危").fill(egui::Color32::RED),
                    Bar::new(2.0, medium_count as f64).name("中危").fill(egui::Color32::YELLOW),
                    Bar::new(3.0, low_count as f64).name("低危").fill(egui::Color32::BLUE),
                ];
                
                Plot::new("risk_dist").view_aspect(1.5).show(&mut columns[0], |plot_ui| {
                    plot_ui.bar_chart(BarChart::new(risk_bars).width(0.5));
                });

                columns[1].heading("模块风险统计");
                let net_count = res.network.as_ref().map(|n| n.suspicious.len()).unwrap_or(0) as f64;
                let startup_count = res.startup.as_ref().map(|s| s.len()).unwrap_or(0) as f64;
                let srv_count = res.services.as_ref().map(|s| s.suspicious.len()).unwrap_or(0) as f64;
                let mem_count = res.memory.as_ref().map(|m| m.len()).unwrap_or(0) as f64;
                let reg_count = res.registry.as_ref().map(|r| r.accounts.len()).unwrap_or(0) as f64;

                let bars = vec![
                    Bar::new(1.0, net_count).name("网络").fill(egui::Color32::LIGHT_BLUE),
                    Bar::new(2.0, startup_count).name("启动项").fill(egui::Color32::LIGHT_GRAY),
                    Bar::new(3.0, srv_count).name("服务").fill(egui::Color32::LIGHT_GREEN),
                    Bar::new(4.0, mem_count).name("内存").fill(egui::Color32::LIGHT_RED),
                    Bar::new(5.0, reg_count).name("注册表").fill(egui::Color32::LIGHT_YELLOW),
                ];
                
                Plot::new("module_bar").view_aspect(1.5).show(&mut columns[1], |plot_ui| {
                    plot_ui.bar_chart(BarChart::new(bars).width(0.5));
                });
            });
            
        } else {
            ui.centered_and_justified(|ui| {
                ui.label("请先进行扫描以生成数据");
            });
        }
    }

    fn show_timeline_tab(&mut self, ui: &mut egui::Ui) {
        if let Some(res) = &self.results {
            ui.heading("⏱️ 应急响应时间线");
            ui.label("自动整合所有模块的关键事件，按时间顺序还原攻击路径。");
            ui.separator();

            let mut events = Vec::new();

            // 1. Logs
            if let Some(logs) = &res.logs {
                for event in &logs.events {
                    // Try to parse time
                    // PowerShell time format: usually "M/d/yyyy h:mm:ss tt" or ISO
                    // We'll just use string sort for simplicity if parsing fails, or try basic parsing
                    // For now, let's trust the log order is roughly correct or use string
                    events.push((event.time.clone(), format!("[安全日志] {} - {}", event.tactics, event.message), RiskLevel::High));
                }
            }

            // 2. Processes (Start Time)
            if let Some(mem) = &res.memory {
                for proc in mem {
                     if proc.start_time > 0 {
                         events.push((proc.start_time_str.clone(), format!("[进程启动] {} (PID: {}) - {}", proc.name, proc.pid, proc.reason), proc.risk_level.clone()));
                     }
                }
            }

            // 3. Files (Modified Time) - Not fully implemented in backend yet, but if we had
            // Startup Items
            if let Some(startup) = &res.startup {
                for item in startup {
                    if item.modified_time != "未知" {
                        events.push((item.modified_time.clone(), format!("[启动项修改] {} - {}", item.name, item.path), item.risk_level.clone()));
                    }
                }
            }
             // Services
            if let Some(srv) = &res.services {
                for s in &srv.suspicious {
                    if s.modified_time != "未知" {
                        events.push((s.modified_time.clone(), format!("[服务修改] {} - {}", s.name, s.binpath), s.risk_level.clone()));
                    }
                }
            }

            // Sort events by time string (ISO-like format YYYY-MM-DD HH:MM:SS sorts correctly)
            events.sort_by(|a, b| b.0.cmp(&a.0)); // Newest first

            egui::ScrollArea::vertical().show(ui, |ui| {
                for (time, desc, risk) in events {
                    ui.group(|ui| {
                        ui.horizontal(|ui| {
                            ui.label(egui::RichText::new(&time).strong().monospace());
                            self.risk_badge(ui, &risk);
                        });
                        ui.label(desc);
                    });
                }
            });

        } else {
             ui.centered_and_justified(|ui| {
                ui.label("请先进行扫描以生成数据");
            });
        }
    }

    fn show_results_tab(&mut self, ui: &mut egui::Ui) {
        if let Some(res) = &self.results {
            ui.heading("详细发现列表");
            ui.separator();
            
            egui::ScrollArea::vertical().show(ui, |ui| {
                if let Some(net) = &res.network {
                    ui.collapsing(format!("网络连接 ({} 可疑)", net.suspicious.len()), |ui| {
                        if net.suspicious.is_empty() {
                            ui.label("未发现可疑连接");
                        } else {
                            for conn in &net.suspicious {
                                ui.group(|ui| {
                                    ui.horizontal(|ui| {
                                        self.risk_badge(ui, &conn.risk_level);
                                        ui.label(format!("PID: {} | {} -> {}", conn.pid, conn.laddr, conn.raddr));
                                    });
                                    ui.label(format!("进程: {}", conn.process));
                                    ui.label(format!("路径: {}", conn.process_path));
                                    ui.horizontal(|ui| {
                                        ui.label(format!("归属地: {}", conn.location));
                                        ui.label(format!("服务: {}", conn.service));
                                    });
                                    ui.horizontal(|ui| {
                                        ui.label(format!("签名: {}", conn.signature));
                                        ui.label(format!("威胁情报: {}", conn.threat_info));
                                    });
                                    ui.label(format!("行为: {}", conn.behavior));
                                    ui.label(format!("说明: {}", conn.risk_desc));
                                }).response.on_hover_text("建议：检查该IP信誉，或使用任务管理器结束进程");
                            }
                        }
                    });
                }
                
                if let Some(startup) = &res.startup {
                    ui.collapsing(format!("启动项 ({} 个)", startup.len()), |ui| {
                         for item in startup {
                             ui.group(|ui| {
                                 ui.horizontal(|ui| {
                                     self.risk_badge(ui, &item.risk_level);
                                     ui.label(format!("名称: {}", item.name));
                                 });
                                 ui.label(format!("路径: {}", item.path));
                                 ui.label(format!("签名: {}", item.signature));
                                 if !item.risk_desc.is_empty() {
                                     ui.label(format!("说明: {}", item.risk_desc));
                                 }
                             });
                         }
                    });
                }

                if let Some(files) = &res.files {
                    ui.collapsing(format!("文件系统 ({} 个结果)", files.len()), |ui| {
                        if files.is_empty() {
                            ui.label("未发现相关文件");
                        } else {
                            for file in files {
                                ui.label(file);
                            }
                        }
                    });
                }

                if let Some(mem) = &res.memory {
                    ui.collapsing(format!("内存进程 ({} 可疑)", mem.len()), |ui| {
                        for proc in mem {
                             ui.group(|ui| {
                                ui.horizontal(|ui| {
                                    self.risk_badge(ui, &proc.risk_level);
                                    ui.label(format!("{} (PID: {})", proc.name, proc.pid));
                                });
                                ui.label(format!("路径: {}", proc.path));
                                ui.label(format!("签名: {}", proc.signature));
                                ui.label(format!("父进程PID: {}", proc.parent_pid));
                                ui.label(format!("原因: {}", proc.reason));
                            });
                        }
                    });
                }
                
                if let Some(srv) = &res.services {
                     ui.collapsing(format!("系统服务 ({} 可疑)", srv.suspicious.len()), |ui| {
                        for s in &srv.suspicious {
                             ui.group(|ui| {
                                ui.horizontal(|ui| {
                                    self.risk_badge(ui, &s.risk_level);
                                    ui.label(format!("{} ({})", s.name, s.display_name));
                                });
                                ui.label(format!("路径: {}", s.binpath));
                                ui.label(format!("签名: {}", s.signature));
                            });
                        }
                    });
                }

                if let Some(reg) = &res.registry {
                    ui.collapsing("注册表/账户检查", |ui| {
                        ui.label(&reg.message);
                        if !reg.accounts.is_empty() {
                            for acc in &reg.accounts {
                                ui.colored_label(egui::Color32::RED, format!("发现账户: {}", acc));
                            }
                        }
                    });
                }
                
                if let Some(logs) = &res.logs {
                    ui.collapsing(format!("安全日志 ({} 关键事件)", logs.critical_events), |ui| {
                         for event in &logs.events {
                             ui.group(|ui| {
                                 ui.label(format!("[{}] {}", event.time, event.event_type));
                                 ui.label(format!("Event ID: {}", event.id));
                                 ui.label(format!("战术: {}", event.tactics));
                                 ui.label(format!("消息: {}", event.message));
                             });
                         }
                    });
                }
            });
        } else {
             ui.centered_and_justified(|ui| {
                ui.label("暂无详细结果");
            });
        }
    }

    fn show_report_tab(&mut self, ui: &mut egui::Ui) {
        ui.heading("报告导出");
        ui.label("扫描结果已自动保存为 JSON 格式。");
        if ui.button("导出为 JSON 报告").clicked() {
            self.generate_report();
        }
        ui.separator();
        ui.heading("原始日志");
        egui::ScrollArea::vertical().show(ui, |ui| {
            ui.code(&self.logs);
        });
    }

    fn risk_badge(&self, ui: &mut egui::Ui, level: &RiskLevel) {
        let (text, color) = match level {
            RiskLevel::High => ("高危", egui::Color32::RED),
            RiskLevel::Medium => ("中危", egui::Color32::YELLOW),
            RiskLevel::Low => ("低危", egui::Color32::BLUE),
            RiskLevel::Info => ("信息", egui::Color32::GRAY),
        };
        ui.add(egui::Label::new(egui::RichText::new(text).color(egui::Color32::WHITE).background_color(color)));
    }
}
