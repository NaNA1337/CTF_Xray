
"""
CTF-XRay GUI界面
"""

import sys
from PySide6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
                               QPushButton, QTextEdit, QTableWidget, QTableWidgetItem,
                               QTabWidget, QFileDialog, QLabel, QLineEdit, QListWidget,
                               QMessageBox, QGroupBox, QSplitter, QHeaderView, QDialog)
from PySide6.QtCore import Qt, QThread, Signal
from analyzers.pcap_analyzer import PcapAnalyzer
from analyzers.log_analyzer import LogAnalyzer
from analyzers.file_analyzer import FileAnalyzer
from ai_coordinator import AICoordinator
import json


class CTFXRayMainWindow(QMainWindow):
    """CTF-XRay主窗口类"""

    def __init__(self):
        super().__init__()
        # 初始化对话历史
        self.conversation_history = []
        self.last_ai_request_context = None
        self.init_ui()
        self.setup_analyzers()
        # 检查AI状态
        self.check_ai_status()
        
    def init_ui(self):
        """初始化UI界面"""
        self.setWindowTitle("CTF-XRay - CTF专用AI辅助分析工具")
        self.setGeometry(100, 100, 1200, 800)
        
        # 创建标签页
        self.tabs = QTabWidget()
        self.setCentralWidget(self.tabs)
        
        # 创建各个标签页
        self.create_network_tab()
        self.create_log_tab()
        self.create_file_tab()
        self.create_ai_tab()
        
        # 状态栏
        self.statusBar().showMessage("就绪")
        
    def create_network_tab(self):
        """创建网络流量分析标签页 - 拆分为两个独立步骤"""
        self.network_tab = QWidget()
        main_layout = QVBoxLayout()
        
        # ========== 步骤 1：PCAP 分析（生成 all_packets.json）==========
        step1_group = QGroupBox("步骤 1️⃣：分析 PCAP 文件生成数据包 JSON（all_packets.json）")
        step1_layout = QVBoxLayout()
        
        # 文件选择
        file_select_layout = QHBoxLayout()
        self.pcap_file_btn = QPushButton("选择 PCAP 文件")
        self.pcap_file_btn.clicked.connect(self.select_pcap_file)
        self.network_file_label = QLabel("未选择文件")
        
        self.start_capture_btn = QPushButton("或开始实时抓包")
        self.start_capture_btn.clicked.connect(self.start_capture)
        
        file_select_layout.addWidget(self.pcap_file_btn)
        file_select_layout.addWidget(self.network_file_label)
        file_select_layout.addWidget(self.start_capture_btn)
        file_select_layout.addStretch()
        
        step1_layout.addLayout(file_select_layout)
        
        # 分析按钮和状态
        analyze_btn_layout = QHBoxLayout()
        self.network_analyze_btn = QPushButton("▶ 分析 PCAP 文件")
        self.network_analyze_btn.clicked.connect(self.analyze_network)
        self.network_analyze_btn.setEnabled(False)
        self.network_analyze_btn.setStyleSheet("background-color: #4CAF50; color: white; font-weight: bold;")
        
        self.pcap_status_label = QLabel("状态：请选择 PCAP 文件")
        self.pcap_status_label.setStyleSheet("color: #FFA500;")
        
        analyze_btn_layout.addWidget(self.network_analyze_btn)
        analyze_btn_layout.addWidget(self.pcap_status_label)
        analyze_btn_layout.addStretch()
        
        step1_layout.addLayout(analyze_btn_layout)
        step1_group.setLayout(step1_layout)
        main_layout.addWidget(step1_group)
        
        # ========== 步骤 2：AI 初筛（基于题目和文件名）==========
        step2_group = QGroupBox("步骤 2️⃣：AI 初筛（根据题目描述和文件名生成建议）")
        step2_layout = QVBoxLayout()
        
        problem_label = QLabel("请输入题目要求和关键词（AI 将只根据题目描述和文件名进行初筛，不读取实际数据包）：")
        self.network_problem_input = QTextEdit()
        self.network_problem_input.setPlaceholderText(
            "例如：\n"
            "题目：在 HTTP 流量中找到 flag\n"
            "关键词：password、secret、flag、admin\n"
            "提示：可能是隐藏的文件或特殊编码的数据"
        )
        self.network_problem_input.setMaximumHeight(80)
        
        # AI初筛按钮和状态
        initial_btn_layout = QHBoxLayout()
        self.network_initial_analyze_btn = QPushButton("▶ 执行 AI 初筛")
        self.network_initial_analyze_btn.clicked.connect(self.network_initial_analyze)
        self.network_initial_analyze_btn.setEnabled(False)
        self.network_initial_analyze_btn.setStyleSheet("background-color: #2196F3; color: white; font-weight: bold;")

        self.ai_status_label = QLabel("状态：请先完成步骤 1️⃣ 的 PCAP 分析")
        self.ai_status_label.setStyleSheet("color: #FFA500;")

        initial_btn_layout.addWidget(self.network_initial_analyze_btn)
        initial_btn_layout.addWidget(self.ai_status_label)
        initial_btn_layout.addStretch()

        # 初筛补充提示（正则不理想时重试）
        refine_layout = QHBoxLayout()
        refine_label = QLabel("补充提示（初筛未筛出结果时填写）：")
        self.network_refine_input = QLineEdit()
        self.network_refine_input.setPlaceholderText("例如：关注210-240号包，可能有base64/zip/图片传输等")
        self.network_refine_btn = QPushButton("补充后重新生成正则")
        self.network_refine_btn.clicked.connect(self.rerun_initial_with_feedback)
        self.network_refine_btn.setEnabled(False)
        refine_layout.addWidget(refine_label)
        refine_layout.addWidget(self.network_refine_input)
        refine_layout.addWidget(self.network_refine_btn)
        refine_layout.addStretch()

        step2_layout.addWidget(problem_label)
        step2_layout.addWidget(self.network_problem_input)
        step2_layout.addLayout(initial_btn_layout)
        step2_layout.addLayout(refine_layout)
        
        step2_group.setLayout(step2_layout)
        main_layout.addWidget(step2_group)
        
        # ========== 步骤 3：初筛结果展示 ==========
        step3_group = QGroupBox("步骤 3️⃣：AI 初筛结果")
        step3_layout = QVBoxLayout()
        
        # 创建标签页来展示不同的结果
        self.network_result_tabs = QTabWidget()
        
        # 分析方向
        self.analysis_direction_display = QTextEdit()
        self.analysis_direction_display.setReadOnly(True)
        self.network_result_tabs.addTab(self.analysis_direction_display, "📊 分析方向")
        
        # Wireshark 正则
        self.wireshark_regex_display = QTextEdit()
        self.wireshark_regex_display.setReadOnly(True)
        self.network_result_tabs.addTab(self.wireshark_regex_display, "🔍 Wireshark 正则")

        step3_layout.addWidget(self.network_result_tabs)

        # 二次研判：根据用户在 Wireshark 中缩小的包范围，提取对应 JSON 并发送到 AI 协同
        packet_range_layout = QHBoxLayout()
        packet_range_label = QLabel("数据包范围（如 210-240 或 123, 100, 17）：")
        self.packet_range_input = QLineEdit()
        self.packet_range_input.setPlaceholderText("可用逗号分隔多个编号，支持区间")
        self.packet_range_btn = QPushButton("➡ 发送选定数据包到 AI 协同研判")
        self.packet_range_btn.clicked.connect(self.send_packet_range_to_ai)
        self.packet_range_btn.setEnabled(False)
        self.packet_range_status = QLabel("状态：等待 PCAP 分析生成 all_packets.json")
        self.packet_range_status.setStyleSheet("color: #FFA500;")

        packet_range_layout.addWidget(packet_range_label)
        packet_range_layout.addWidget(self.packet_range_input)
        packet_range_layout.addWidget(self.packet_range_btn)
        packet_range_layout.addWidget(self.packet_range_status)
        packet_range_layout.addStretch()

        step3_layout.addLayout(packet_range_layout)

        step3_group.setLayout(step3_layout)
        main_layout.addWidget(step3_group)
        
        self.network_tab.setLayout(main_layout)
        self.tabs.addTab(self.network_tab, "流量分析")
        
    def create_log_tab(self):
        """创建日志分析标签页"""
        self.log_tab = QWidget()
        layout = QVBoxLayout()
        
        # 控制区域
        control_group = QGroupBox("控制面板")
        control_layout = QHBoxLayout()
        
        self.log_file_btn = QPushButton("选择日志文件")
        self.log_file_btn.clicked.connect(self.select_log_file)
        
        self.log_analyze_btn = QPushButton("分析")
        self.log_analyze_btn.clicked.connect(self.analyze_logs)
        self.log_analyze_btn.setEnabled(False)
        
        control_layout.addWidget(self.log_file_btn)
        control_layout.addWidget(self.log_analyze_btn)
        control_layout.addStretch()
        
        control_group.setLayout(control_layout)
        layout.addWidget(control_group)
        
        # 文件信息显示
        self.log_file_label = QLabel("未选择文件")
        layout.addWidget(self.log_file_label)
        
        # 结果显示区域
        self.log_results = QTableWidget()
        self.log_results.setColumnCount(3)
        self.log_results.setHorizontalHeaderLabels(["行号", "内容", "匹配项"])
        self.log_results.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        layout.addWidget(self.log_results)
        
        # 添加查看分析过程按钮
        self.view_log_process_btn = QPushButton("查看分析过程")
        self.view_log_process_btn.clicked.connect(self.view_log_process)
        self.view_log_process_btn.setEnabled(False)
        layout.addWidget(self.view_log_process_btn)
        
        self.log_tab.setLayout(layout)
        self.tabs.addTab(self.log_tab, "日志分析")
        
    def create_file_tab(self):
        """创建文件/内存分析标签页"""
        self.file_tab = QWidget()
        layout = QVBoxLayout()
        
        # 控制区域
        control_group = QGroupBox("控制面板")
        control_layout = QHBoxLayout()
        
        self.file_select_btn = QPushButton("选择文件/目录")
        self.file_select_btn.clicked.connect(self.select_file_or_directory)
        
        self.file_analyze_btn = QPushButton("分析")
        self.file_analyze_btn.clicked.connect(self.analyze_files)
        self.file_analyze_btn.setEnabled(False)
        
        control_layout.addWidget(self.file_select_btn)
        control_layout.addWidget(self.file_analyze_btn)
        control_layout.addStretch()
        
        control_group.setLayout(control_layout)
        layout.addWidget(control_group)
        
        # 文件信息显示
        self.file_label = QLabel("未选择文件或目录")
        layout.addWidget(self.file_label)
        
        # 结果显示区域
        self.file_results = QTableWidget()
        self.file_results.setColumnCount(3)
        self.file_results.setHorizontalHeaderLabels(["文件路径", "类型", "发现内容"])
        self.file_results.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        layout.addWidget(self.file_results)
        
        # 添加查看分析过程按钮
        self.view_file_process_btn = QPushButton("查看分析过程")
        self.view_file_process_btn.clicked.connect(self.view_file_process)
        self.view_file_process_btn.setEnabled(False)
        layout.addWidget(self.view_file_process_btn)
        
        self.file_tab.setLayout(layout)
        self.tabs.addTab(self.file_tab, "文件/内存分析")
        
    def create_ai_tab(self):
        """创建AI协同研判标签页"""
        self.ai_tab = QWidget()
        layout = QHBoxLayout()
        
        # 左侧：候选Flag列表
        left_panel = QVBoxLayout()
        left_group = QGroupBox("候选Flag列表")
        left_layout = QVBoxLayout()
        
        self.flag_list = QListWidget()
        self.flag_list.currentRowChanged.connect(self.on_flag_selected)
        left_layout.addWidget(self.flag_list)
        
        # 操作按钮
        button_layout = QHBoxLayout()
        self.accept_btn = QPushButton("接受")
        self.reject_btn = QPushButton("拒绝")
        self.edit_btn = QPushButton("编辑")
        self.reask_btn = QPushButton("用此上下文重新问AI")
        
        self.accept_btn.clicked.connect(self.accept_flag)
        self.reject_btn.clicked.connect(self.reject_flag)
        self.edit_btn.clicked.connect(self.edit_flag)
        self.reask_btn.clicked.connect(self.reask_ai)
        
        button_layout.addWidget(self.accept_btn)
        button_layout.addWidget(self.reject_btn)
        button_layout.addWidget(self.edit_btn)
        button_layout.addWidget(self.reask_btn)
        left_layout.addLayout(button_layout)
        
        left_group.setLayout(left_layout)
        left_panel.addWidget(left_group)
        
        # 右侧：详细信息和操作区域
        right_panel = QVBoxLayout()
        
        # API设置区域
        api_group = QGroupBox("API设置")
        api_layout = QHBoxLayout()
        
        api_layout.addWidget(QLabel("API密钥:"))
        self.api_key_input = QLineEdit()
        self.api_key_input.setEchoMode(QLineEdit.Password)
        api_layout.addWidget(self.api_key_input)
        
        api_group.setLayout(api_layout)
        right_panel.addWidget(api_group)
        
        # 模型选择区域
        model_group = QGroupBox("模型设置")
        model_layout = QHBoxLayout()
        
        model_layout.addWidget(QLabel("模型名称:"))
        self.model_input = QLineEdit()
        self.model_input.setPlaceholderText("留空使用默认模型")
        model_layout.addWidget(self.model_input)
        
        model_group.setLayout(model_layout)
        right_panel.addWidget(model_group)
        
        # AI推理过程
        process_group = QGroupBox("AI推理过程")
        process_layout = QVBoxLayout()
        self.reasoning_display = QTextEdit()
        self.reasoning_display.setReadOnly(True)
        process_layout.addWidget(self.reasoning_display)
        process_group.setLayout(process_layout)
        right_panel.addWidget(process_group)
        
        # 对话历史
        history_group = QGroupBox("对话历史")
        history_layout = QVBoxLayout()
        self.conversation_display = QTextEdit()
        self.conversation_display.setReadOnly(True)
        history_layout.addWidget(self.conversation_display)
        
        # 清除历史按钮
        clear_history_btn = QPushButton("清除对话历史")
        clear_history_btn.clicked.connect(self.clear_conversation_history)
        history_layout.addWidget(clear_history_btn)
        
        history_group.setLayout(history_layout)
        right_panel.addWidget(history_group)
        
        # 原始数据
        data_group = QGroupBox("原始数据")
        data_layout = QVBoxLayout()
        self.raw_data_display = QTextEdit()
        self.raw_data_display.setReadOnly(True)
        data_layout.addWidget(self.raw_data_display)
        data_group.setLayout(data_layout)
        right_panel.addWidget(data_group)
        
        # 用户提示
        prompt_group = QGroupBox("用户提示")
        prompt_layout = QVBoxLayout()
        self.user_prompt_input = QTextEdit()
        self.user_prompt_input.setMaximumHeight(60)
        prompt_layout.addWidget(self.user_prompt_input)
        
        self.ask_ai_btn = QPushButton("询问AI")
        self.ask_ai_btn.clicked.connect(self.ask_ai)
        prompt_layout.addWidget(self.ask_ai_btn)
        
        # 添加查看完整响应过程按钮
        self.view_full_response_btn = QPushButton("查看完整响应过程")
        self.view_full_response_btn.clicked.connect(self.view_full_response)
        self.view_full_response_btn.setEnabled(False)
        prompt_layout.addWidget(self.view_full_response_btn)
        
        prompt_group.setLayout(prompt_layout)
        right_panel.addWidget(prompt_group)
        
        # 添加到主布局
        splitter = QSplitter(Qt.Horizontal)
        left_widget = QWidget()
        left_widget.setLayout(left_panel)
        right_widget = QWidget()
        right_widget.setLayout(right_panel)
        splitter.addWidget(left_widget)
        splitter.addWidget(right_widget)
        splitter.setSizes([300, 900])
        
        layout.addWidget(splitter)
        self.ai_tab.setLayout(layout)
        self.tabs.addTab(self.ai_tab, "AI协同研判")
        
    def setup_analyzers(self):
        """设置分析器"""
        try:
            self.pcap_analyzer = PcapAnalyzer()
            self.log_analyzer = LogAnalyzer()
            self.file_analyzer = FileAnalyzer()
            self.ai_coordinator = AICoordinator()
            
            # 连接信号
            self.pcap_analyzer.analysis_finished.connect(self.on_network_analysis_finished)
            self.log_analyzer.analysis_finished.connect(self.on_log_analysis_finished)
            self.file_analyzer.analysis_finished.connect(self.on_file_analysis_finished)
            
            # AI协调器信号连接
            self.ai_coordinator.analysis_finished.connect(self.on_ai_analysis_finished)
            self.ai_coordinator.analysis_error.connect(self.on_ai_analysis_error)
        except Exception as e:
            QMessageBox.critical(self, "错误", f"初始化分析器失败: {str(e)}")
    
    def check_ai_status(self):
        """检查AI状态"""
        # 不再需要检查Ollama状态
        self.statusBar().showMessage("请配置心流API密钥以启用AI功能")
    
    # 网络分析相关方法
    def select_pcap_file(self):
        """选择 PCAP 文件"""
        file_path, _ = QFileDialog.getOpenFileName(
            self, "选择 PCAP 文件", "", "PCAP 文件 (*.pcap *.pcapng);;所有文件 (*)")
        if file_path:
            self.network_file_label.setText(f"已选择：{file_path}")
            self.selected_pcap_file = file_path

            # 启用"分析 PCAP"按钮
            self.network_analyze_btn.setEnabled(True)
            self.pcap_status_label.setText("状态：已选择文件，点击'分析 PCAP 文件'开始分析")
            self.pcap_status_label.setStyleSheet("color: #2196F3;")

            # 禁用 AI 初筛按钮（需要先完成 PCAP 分析）
            self.network_initial_analyze_btn.setEnabled(False)
            self.ai_status_label.setText("状态：请先完成步骤 1️⃣ 的 PCAP 分析")
            self.ai_status_label.setStyleSheet("color: #FFA500;")

            # 禁用二次研判按钮，等待新的 JSON 生成
            self.packet_range_btn.setEnabled(False)
            self.packet_range_status.setText("状态：等待 PCAP 分析生成 all_packets.json")
            self.packet_range_status.setStyleSheet("color: #FFA500;")
            self.network_refine_btn.setEnabled(False)
            self.network_refine_input.clear()

            self.statusBar().showMessage("✅ PCAP 文件已选择！点击'分析 PCAP 文件'按钮开始分析")
            
    def start_capture(self):
        """开始实时抓包"""
        QMessageBox.information(self, "提示", "实时抓包功能将在后续版本中实现")
    
    def _cleanup_analysis_data(self):
        """清理旧的分析数据：删除tmp文件夹和对话历史"""
        from pathlib import Path
        import shutil
        
        # 删除tmp文件夹及其内容
        tmp_dir = Path("tmp")
        if tmp_dir.exists():
            try:
                shutil.rmtree(tmp_dir)
                print("[清理] 已删除tmp文件夹及其内容")
            except Exception as e:
                print(f"[清理] 删除tmp文件夹失败: {e}")
        
        # 清空对话历史
        self.conversation_history = []
        print("[清理] 已清空对话历史")

        # 清空二次研判选定数据
        self.selected_packets_for_ai = []
        self.selected_packet_range = None
        if hasattr(self, 'network_refine_input'):
            self.network_refine_input.clear()
    
    def analyze_network(self):
        """【步骤 1】分析 PCAP 文件并生成 all_packets.json"""
        if not hasattr(self, 'selected_pcap_file') or not self.selected_pcap_file:
            QMessageBox.warning(self, "警告", "请先选择 PCAP 文件")
            return
        
        # 禁用按钮，防止重复点击
        self.network_analyze_btn.setEnabled(False)
        self.pcap_status_label.setText("状态：正在分析 PCAP 文件...")
        self.pcap_status_label.setStyleSheet("color: #FFA500;")
        self.statusBar().showMessage("正在分析 PCAP 文件，请稍候...")
        self.packet_range_btn.setEnabled(False)
        self.packet_range_status.setText("状态：正在生成 all_packets.json")
        self.packet_range_status.setStyleSheet("color: #FFA500;")
        self.network_refine_btn.setEnabled(False)

        # 清除旧的分析数据
        self._cleanup_analysis_data()
        
        # 调用 PCAP 分析器
        self.pcap_analyzer.analyze(self.selected_pcap_file)
    
    def network_initial_analyze(self):
        """【步骤 2】AI 初筛：根据文件名和题目描述进行初筛"""
        # 检查是否已完成步骤 1
        if not hasattr(self, 'network_analysis_results') or not self.network_analysis_results:
            QMessageBox.warning(self, "警告", "请先完成步骤 1️⃣ 的 PCAP 分析")
            return
        
        # 检查题目描述
        problem_desc = self.network_problem_input.toPlainText().strip()
        if not problem_desc:
            QMessageBox.warning(self, "警告", "请输入题目描述")
            return
        
        # 禁用按钮，防止重复点击
        self.network_initial_analyze_btn.setEnabled(False)
        self.network_refine_btn.setEnabled(False)
        self.ai_status_label.setText("状态：正在执行 AI 初筛...")
        self.ai_status_label.setStyleSheet("color: #FFA500;")
        self.statusBar().showMessage("正在执行 AI 初筛，请稍候...")

        # 保存题目描述供后续使用
        self.network_problem_description = problem_desc
        
        # 调用 AI 初筛
        self._do_ai_initial_screening()
            
    def on_network_analysis_finished(self, results):
        """【步骤 1 完成】PCAP 分析完成回调 - 现在等待用户输入题目并执行 AI 初筛"""
        # 保存分析结果（包括 json_file 路径）
        self.network_analysis_results = results
        
        # 清空显示区域
        self.analysis_direction_display.setPlainText("")
        self.wireshark_regex_display.setPlainText("")
        
        # 检查是否有 JSON 文件
        json_files = [r.get('json_file') for r in results if r.get('json_file')]
        
        if not json_files:
            QMessageBox.warning(self, "错误", "未能生成 JSON 分析文件，请检查 PCAP 文件是否有效")
            self.network_analyze_btn.setEnabled(True)
            self.pcap_status_label.setText("状态：分析失败，请检查 PCAP 文件")
            self.pcap_status_label.setStyleSheet("color: #F44336;")
            self.packet_range_btn.setEnabled(False)
            self.packet_range_status.setText("状态：未生成 all_packets.json")
            self.packet_range_status.setStyleSheet("color: #F44336;")
            return

        # PCAP 分析成功
        print(f"[GUI] ✅ PCAP 分析完成，{len(json_files)} 个 JSON 文件已生成")
        self.pcap_status_label.setText(f"✅ 状态：PCAP 分析完成（{len(json_files)} 个数据包）")
        self.pcap_status_label.setStyleSheet("color: #4CAF50;")
        
        # 启用 AI 初筛按钮
        self.network_initial_analyze_btn.setEnabled(True)
        self.ai_status_label.setText("状态：请输入题目描述后点击'执行 AI 初筛'")
        self.ai_status_label.setStyleSheet("color: #2196F3;")

        # 启用二次研判按钮
        self.packet_range_btn.setEnabled(True)
        self.packet_range_status.setText("状态：all_packets.json 已生成，可输入数据包范围")
        self.packet_range_status.setStyleSheet("color: #4CAF50;")
        self.network_refine_btn.setEnabled(False)

        self.statusBar().showMessage("✅ PCAP 分析完成！请输入题目描述后进行 AI 初筛")
        
        # 重新启用分析按钮（允许用户重新分析其他文件）
        self.network_analyze_btn.setEnabled(True)
    
    def _build_initial_screening_prompt(self, extra_hint=None):
        """构建初筛提示 - 只包含题目、文件名，可附带补充信息"""
        problem = self.network_problem_description
        pcap_filename = self.selected_pcap_file.split('\\')[-1] if hasattr(self, 'selected_pcap_file') else "unknown.pcap"

        extra_block = ""
        if extra_hint:
            extra_block = f"\n【用户补充信息】\n{extra_hint}\n\n"

        return f"""你是一个CTF网络流量分析专家。仅根据PCAP文件名和题目描述（不读取实际数据包），给出可直接落地的筛选方案。

【PCAP文件名】
{pcap_filename}

【题目描述】
{problem}
{extra_block}【任务】
输出两部分内容：
1. 分析方向：结合题目背景推断可能的协议、端口、主机、传输方式、登录/文件操作等，并给出检查步骤（2-4条）。
2. Wireshark过滤表达式：提供至少3条可直接粘贴到Wireshark“显示过滤器”的过滤表达式，包含具体字段和值（IP/端口/Host/URI/方法/关键字符串等），必要时给出窄-宽两级筛选。

【必须的输出格式】
【分析方向】
- ...
- ...

【Wireshark正则】
1) <显示过滤器> # 用途/预期命中
2) <显示过滤器> # 用途/预期命中
3) <显示过滤器> # 兜底或更宽的筛选

【注意】
- 只返回Wireshark显示过滤器，不要抓包过滤器或伪代码
- 尽量替换为具体值，避免占位符（请把题目中出现的IP/域名/端口/路径直接写入表达式）
- 若信息不足，可给出最可能的值与假设，并说明筛选目的
"""

    def _do_ai_initial_screening(self, extra_hint=None):
        """执行AI初筛 - 仅基于题目和文件名，可附加补充信息"""
        if not hasattr(self, 'network_problem_description'):
            QMessageBox.warning(self, "错误", "找不到题目描述")
            return

        self.last_ai_request_context = "initial_screening"
        initial_screening_prompt = self._build_initial_screening_prompt(extra_hint=extra_hint)

        # 禁用按钮，防止重复点击
        self.network_initial_analyze_btn.setEnabled(False)
        self.network_refine_btn.setEnabled(False)
        self.ai_status_label.setText("状态：正在执行 AI 初筛...")
        self.ai_status_label.setStyleSheet("color: #FFA500;")
        self.statusBar().showMessage("正在执行 AI 初筛，请稍候...")

        # 调用 AI 协调器，但只传递用户提示词（不传数据包）
        # 使用空的 prompt_data 列表，这样 AI 不会尝试分析任何数据
        self.ai_coordinator.analyze(
            prompt_data=[],  # 空数据，避免 AI 分析任何内容
            user_prompt=initial_screening_prompt,  # 提示词作为 user_prompt
            api_key=self.api_key_input.text(),
            model=self.model_input.text(),
            conversation_history=self.conversation_history
        )

    def rerun_initial_with_feedback(self):
        """用户补充信息后重新生成正则"""
        if not hasattr(self, 'network_problem_description'):
            QMessageBox.warning(self, "错误", "请先填写题目描述并完成初次初筛")
            return

        feedback = self.network_refine_input.text().strip()
        if not feedback:
            QMessageBox.warning(self, "提示", "请先填写补充提示后再重试")
            return

        self._do_ai_initial_screening(extra_hint=feedback)
    
    def network_ai_analyze(self):
        """使用AI对网络流量进行深度分析"""
        # 此方法已由新流程替代
        pass

    # 日志分析相关方法
    def select_log_file(self):
        """选择日志文件"""
        file_path, _ = QFileDialog.getOpenFileName(
            self, "选择日志文件", "", "日志文件 (*.log *.txt);;所有文件 (*)")
        if file_path:
            self.log_file_label.setText(file_path)
            self.log_analyze_btn.setEnabled(True)
            self.selected_log_file = file_path
            
    def analyze_logs(self):
        """分析日志"""
        if hasattr(self, 'selected_log_file'):
            self.statusBar().showMessage("正在分析日志...")
            self.log_analyze_btn.setEnabled(False)
            self.log_analyzer.analyze(self.selected_log_file)
            
    def on_log_analysis_finished(self, results):
        """日志分析完成回调"""
        # 提取分析过程信息
        analysis_process = None
        clean_results = []
        for result in results:
            if result.get("type") == "ANALYSIS_PROCESS":
                analysis_process = result.get("content", "")
            else:
                clean_results.append(result)
        
        # 保存分析过程
        self.log_analysis_process = analysis_process
        
        # 启用查看按钮
        self.view_log_process_btn.setEnabled(analysis_process is not None)
        
        # 显示结果
        self.log_results.setRowCount(0)  # 清空现有结果
        
        for result in clean_results:
            row_position = self.log_results.rowCount()
            self.log_results.insertRow(row_position)
            
            self.log_results.setItem(row_position, 0, QTableWidgetItem(str(result.get("line_number", ""))))
            self.log_results.setItem(row_position, 1, QTableWidgetItem(result.get("content", "")))
            self.log_results.setItem(row_position, 2, QTableWidgetItem(result.get("match", "")))
            
        self.statusBar().showMessage(f"日志分析完成，发现{len(clean_results)}条匹配记录")
        self.log_analyze_btn.setEnabled(True)
        
    # 文件分析相关方法
    def select_file_or_directory(self):
        """选择文件或目录"""
        file_dialog = QFileDialog(self)
        file_dialog.setFileMode(QFileDialog.ExistingFiles)
        file_dialog.setOption(QFileDialog.ShowDirsOnly, False)
        
        if file_dialog.exec():
            selected = file_dialog.selectedFiles()
            if selected:
                self.file_label.setText("; ".join(selected))
                self.file_analyze_btn.setEnabled(True)
                self.selected_files = selected
                
    def analyze_files(self):
        """分析文件"""
        if hasattr(self, 'selected_files'):
            self.statusBar().showMessage("正在分析文件...")
            self.file_analyze_btn.setEnabled(False)
            self.file_analyzer.analyze(self.selected_files)
            
    def on_file_analysis_finished(self, results):
        """文件分析完成回调"""
        # 提取分析过程信息
        analysis_process = None
        clean_results = []
        for result in results:
            if result.get("type") == "ANALYSIS_PROCESS":
                analysis_process = result.get("content", "")
            else:
                clean_results.append(result)
        
        # 保存分析过程
        self.file_analysis_process = analysis_process
        
        # 启用查看按钮
        self.view_file_process_btn.setEnabled(analysis_process is not None)
        
        # 显示结果
        self.file_results.setRowCount(0)  # 清空现有结果
        
        for result in clean_results:
            row_position = self.file_results.rowCount()
            self.file_results.insertRow(row_position)
            
            self.file_results.setItem(row_position, 0, QTableWidgetItem(result.get("path", "")))
            self.file_results.setItem(row_position, 1, QTableWidgetItem(result.get("type", "")))
            self.file_results.setItem(row_position, 2, QTableWidgetItem(result.get("content", "")))
            
        self.statusBar().showMessage(f"文件分析完成，处理了{len(clean_results)}个文件")
        self.file_analyze_btn.setEnabled(True)
        
    # AI协同相关方法
    def on_flag_selected(self, row):
        """当选中某个Flag时"""
        if row >= 0:
            # 显示相关信息（此处应从数据模型中获取）
            item = self.flag_list.item(row)
            if item:
                self.raw_data_display.setPlainText(f"选中的Flag: {item.text()}")
            
    def accept_flag(self):
        """接受选中的Flag"""
        current_row = self.flag_list.currentRow()
        if current_row >= 0:
            QMessageBox.information(self, "提示", "已接受该Flag")
            # 在实际应用中，这里应该保存Flag到结果中
            
    def reject_flag(self):
        """拒绝选中的Flag"""
        current_row = self.flag_list.currentRow()
        if current_row >= 0:
            self.flag_list.takeItem(current_row)
            QMessageBox.information(self, "提示", "已拒绝该Flag")
            
    def edit_flag(self):
        """编辑选中的Flag"""
        current_row = self.flag_list.currentRow()
        if current_row >= 0:
            QMessageBox.information(self, "提示", "编辑功能将在后续版本中实现")
            
    def reask_ai(self):
        """用当前上下文重新问AI"""
        if not self.conversation_history:
            QMessageBox.warning(self, "警告", "没有对话历史，请先进行AI分析")
            return
        
        # 获取新的用户提示
        new_prompt = self.user_prompt_input.toPlainText()
        if not new_prompt:
            QMessageBox.warning(self, "警告", "请输入新的问题或提示")
            return
        
        # 获取API设置
        api_key = self.api_key_input.text()
        model = self.model_input.text()
        
        current_data = {
            "type": "USER_SELECTED",
            "content": self.raw_data_display.toPlainText()
        }
        
        self.statusBar().showMessage("正在向AI发送新问题...")
        self.ask_ai_btn.setEnabled(False)
        # 传递现有的对话历史给AI分析
        self.last_ai_request_context = "collaboration"
        self.ai_coordinator.analyze([current_data], new_prompt, api_key, model,
                                   conversation_history=self.conversation_history)
        
    def ask_ai(self):
        """询问AI"""
        user_prompt = self.user_prompt_input.toPlainText()

        analysis_data = []

        # 优先使用用户选定的数据包范围（二次研判）
        if hasattr(self, 'selected_packets_for_ai') and self.selected_packets_for_ai:
            analysis_data = self.selected_packets_for_ai
            print(f"[AI分析] 使用选定数据包范围进行研判 ({len(analysis_data)} 条记录)")
        # 其次使用网络分析结果（完整数据）
        elif hasattr(self, 'network_analysis_results') and self.network_analysis_results:
            analysis_data = self.network_analysis_results
            print(f"[AI分析] 使用网络分析结果 ({len(analysis_data)} 条记录)")
        else:
            current_data = {
                "type": "USER_SELECTED",
                "content": self.raw_data_display.toPlainText()
            }
            analysis_data = [current_data]
        
        # 获取API设置
        api_key = self.api_key_input.text()
        model = self.model_input.text()
        
        if user_prompt or analysis_data:
            self.statusBar().showMessage("正在向AI发送请求...")
            self.ask_ai_btn.setEnabled(False)
            # 清空AI推理过程和Flag列表（新的询问开始）
            self.reasoning_display.setPlainText("")
            self.flag_list.clear()
            self.last_ai_request_context = "collaboration"
            # 传递原始分析结果给AI分析（包含json_file路径）
            self.ai_coordinator.analyze(analysis_data, user_prompt, api_key, model,
                                       conversation_history=self.conversation_history)
        else:
            QMessageBox.warning(self, "警告", "请输入提示内容或选择数据")
    
    def on_ai_analysis_finished(self, result):
        """AI分析完成回调 - 处理初筛结果或深度研判结果"""
        self.ask_ai_btn.setEnabled(True)

        context = self.last_ai_request_context
        if context == "initial_screening":
            self._handle_initial_screening_result(result)
        else:
            self._handle_ai_analysis_result(result)
        self.last_ai_request_context = None
    
    def _handle_initial_screening_result(self, result):
        """处理初筛结果 - 基于题目和文件名的初步建议"""
        print("[GUI] 处理初筛结果...")
        
        raw_response = result.get("raw_response", "")
        print(f"[GUI] AI 响应长度: {len(raw_response)}")
        
        # 清空显示
        self.analysis_direction_display.setPlainText("")
        self.wireshark_regex_display.setPlainText("")

        # 解析 AI 的初筛结果
        import re as re_lib

        # 提取分析方向
        analysis_section = re_lib.search(r'【分析方向】(.*?)(?=【|$)', raw_response, re_lib.DOTALL)
        if analysis_section:
            analysis_text = analysis_section.group(1).strip()
            self.analysis_direction_display.setPlainText(analysis_text)
            print(f"[GUI] ✓ 提取到分析方向 ({len(analysis_text)} 字符)")
        else:
            self.analysis_direction_display.setPlainText("（未找到分析方向信息）")
            print(f"[GUI] ⚠ 未找到【分析方向】标记")
        
        # 提取 Wireshark 正则/过滤表达式
        regex_section = re_lib.search(r'【Wireshark(?:正则|过滤表达式)】(.*?)(?=【|$)', raw_response, re_lib.DOTALL)
        if regex_section:
            regex_text = regex_section.group(1).strip()
            self.wireshark_regex_display.setPlainText(regex_text)
            print(f"[GUI] ✓ 提取到 Wireshark 过滤表达式 ({len(regex_text)} 字符)")
        else:
            self.wireshark_regex_display.setPlainText("（未找到 Wireshark 过滤表达式）")
            print(f"[GUI] ⚠ 未找到【Wireshark...】标记")

        # 输出完整响应便于调试
        print(f"[GUI] ===== AI 完整响应 =====")
        print(raw_response)
        print(f"[GUI] ===== 响应结束 =====")

        self.network_initial_analyze_btn.setEnabled(True)

        self.statusBar().showMessage(
            f"✅ AI 初筛完成！已生成分析方向和 Wireshark 过滤表达式。"
        )
        # 允许补充提示重新生成
        self.network_refine_btn.setEnabled(True)
        if not regex_section:
            self.ai_status_label.setText("状态：未生成有效正则，可补充提示后重试")
            self.ai_status_label.setStyleSheet("color: #FFA500;")
        else:
            self.ai_status_label.setText("状态：初筛完成，可根据需要补充提示重试")
            self.ai_status_label.setStyleSheet("color: #4CAF50;")

    def send_packet_range_to_ai(self):
        """根据用户在 Wireshark 中定位的数据包范围，提取对应 JSON 并发送到 AI 协同研判"""
        # 确保已有 PCAP 分析结果（all_packets.json）
        if not hasattr(self, 'network_analysis_results') or not self.network_analysis_results:
            QMessageBox.warning(self, "警告", "请先完成步骤 1️⃣ 的 PCAP 分析")
            return

        # 提取 all_packets.json 路径
        json_files = [r.get('json_file') for r in self.network_analysis_results if r.get('json_file')]
        if not json_files:
            QMessageBox.warning(self, "警告", "未找到 all_packets.json，请先运行 PCAP 分析")
            return

        all_packets_path = json_files[0]

        # 解析用户输入（支持逗号分隔的编号与范围）
        range_text = self.packet_range_input.text().strip().replace('，', ',')
        if not range_text:
            QMessageBox.warning(self, "警告", "请输入数据包范围，例如 210-240 或 123, 100, 17")
            return

        selected_ids = set()
        ranges = []
        tokens = [t.strip() for t in range_text.replace(' ', '').split(',') if t.strip()]
        try:
            for token in tokens:
                if '-' in token:
                    start_str, end_str = token.split('-', 1)
                    start_idx, end_idx = int(start_str), int(end_str)
                    if start_idx > end_idx:
                        start_idx, end_idx = end_idx, start_idx
                    ranges.append((start_idx, end_idx))
                else:
                    selected_ids.add(int(token))
        except ValueError:
            QMessageBox.warning(self, "警告", "数据包范围格式不正确，请输入数字或用'-'分隔的范围")
            return

        if not selected_ids and not ranges:
            QMessageBox.warning(self, "警告", "未解析到有效的数据包编号")
            return

        # 读取 all_packets.json
        try:
            with open(all_packets_path, 'r', encoding='utf-8') as f:
                all_packets = json.load(f)
        except Exception as e:
            QMessageBox.critical(self, "错误", f"读取 {all_packets_path} 失败：{e}")
            return

        if not isinstance(all_packets, list):
            all_packets = [all_packets]

        # 根据 packet_id 或列表索引过滤范围/编号
        selected_packets = []
        for idx, packet in enumerate(all_packets, 1):
            packet_id = None
            if isinstance(packet, dict) and 'packet_id' in packet:
                try:
                    packet_id = int(str(packet.get('packet_id')).split('.')[0])
                except Exception:
                    packet_id = None

            effective_id = packet_id if packet_id is not None else idx
            in_range = any(start <= effective_id <= end for start, end in ranges)
            if effective_id in selected_ids or in_range:
                selected_packets.append(packet)

        if not selected_packets:
            QMessageBox.warning(self, "提示", f"未在 all_packets.json 中找到编号 {range_text} 的数据包")
            return

        # 生成 JSON 文本（用于展示与传递给 AI）
        def normalize_text(value, max_len=4000):
            text = str(value) if value is not None else ""
            if len(text) > max_len:
                return text[:max_len] + "...(truncated)"
            return text

        def find_readable_payload(packet, source_name):
            readable = packet.get("readable_payloads")
            if isinstance(readable, list):
                for item in readable:
                    if isinstance(item, dict) and item.get("source") == source_name:
                        return item.get("text")
            return None

        def find_tcp_payload_text(packet):
            payload = packet.get("payload", {})
            if isinstance(payload, dict):
                layers = payload.get("layers_with_payload", [])
                if isinstance(layers, list):
                    for item in layers:
                        if isinstance(item, dict) and item.get("layer") == "TCP":
                            return item.get("text") or item.get("ascii")
            return None

        reduced_packets = []
        for packet in selected_packets:
            if not isinstance(packet, dict):
                continue
            segment_text = (
                find_readable_payload(packet, "TCP.segment_data")
                or find_readable_payload(packet, "TCP.reassembled_data")
                or ""
            )
            payload_text = (
                find_readable_payload(packet, "TCP.payload")
                or find_tcp_payload_text(packet)
                or ""
            )
            reduced_packets.append({
                "packet_id": packet.get("packet_id", ""),
                "segment_data": normalize_text(segment_text),
                "payload": normalize_text(payload_text)
            })

        selected_json = json.dumps(reduced_packets, ensure_ascii=False, indent=2)
        preview_text = selected_json if len(selected_json) <= 4000 else selected_json[:4000] + "\n...（预览已截断）"

        self.selected_packets_for_ai = [{
            "type": "PACKET_RANGE",
            "packet_range": range_text,
            "packets": reduced_packets,
            "content": preview_text
        }]
        self.selected_packet_range = range_text

        # 准备二次研判提示词
        secondary_prompt = f"""对 PCAP 数据包编号 {range_text} 进行二次研判（来源：tmp/all_packets.json，经 Wireshark 缩小范围）。
请提取所有可能的 flag/密钥/凭证，标出所在数据包编号和字段位置；若为编码/压缩/分片，请还原后给出 flag。
优先输出 flag{{...}} / FLAG{{...}} / ctf{{...}}，若无明确 flag，请提供最可疑片段和下一步建议。"""

        # 切换到 AI 协同标签页并填充上下文
        self.tabs.setCurrentWidget(self.ai_tab)
        self.raw_data_display.setPlainText(
            f"选定数据包范围：#{range_text}（共 {len(selected_packets)} 个）\n来源：{all_packets_path}\n\n{preview_text}"
        )
        self.user_prompt_input.setPlainText(secondary_prompt)
        self.reasoning_display.setPlainText("")
        self.conversation_display.setPlainText("")
        self.flag_list.clear()
        self.conversation_history = []

        self.packet_range_status.setText(f"状态：已准备 #{range_text} 发送到 AI")
        self.packet_range_status.setStyleSheet("color: #4CAF50;")
        self.statusBar().showMessage(f"已加载 #{range_text} 的数据包到 AI 协同，点击“询问AI”开始研判")
        self.ask_ai_btn.setEnabled(True)

    def _handle_ai_analysis_result(self, result):
        """处理AI协同页面的分析结果"""
        # 处理分析状态
        analysis_status = result.get("status", "")
        
        # 如果是正则匹配阶段
        if analysis_status == "regex_matched":
            self.statusBar().showMessage("✓ 正则筛选完成，已匹配到可疑flag")

            # 显示分析过程
            analysis_text = result.get("analysis", "")
            raw_response = result.get("raw_response", "")
            reasoning_text = f"【两阶段分析结果】\n\n{analysis_text}"
            if raw_response:
                reasoning_text += f"\n\n【AI 返回】\n{raw_response}"
            self.reasoning_display.setPlainText(reasoning_text)

            # 更新对话历史
            user_prompt = self.user_prompt_input.toPlainText()
            if user_prompt:
                self.conversation_history.append({
                    "role": "user",
                    "content": user_prompt
                })
            if raw_response:
                self.conversation_history.append({
                    "role": "assistant",
                    "content": raw_response
                })
            self.update_conversation_display()
            
            # 显示匹配的flag
            flags = result.get("flags", [])
            if flags:
                for flag in flags:
                    if flag:
                        self.flag_list.addItem(f"[正则匹配] {flag}")
                
                self.statusBar().showMessage(
                    f"✓ 正则匹配成功！发现 {len(flags)} 个可疑flag"
                )
        
        # 普通分析完成
        else:
            self.statusBar().showMessage("AI分析完成")
            
            # 保存完整响应过程数据
            self.full_response_data = result.get("full_response_process", {})
            
            # 启用查看完整响应过程按钮
            self.view_full_response_btn.setEnabled(bool(self.full_response_data))
            
            # 获取原始AI响应文本
            raw_response = result.get("raw_response", "")
            
            # 更新对话历史
            if raw_response:
                user_prompt = self.user_prompt_input.toPlainText()
                if user_prompt:
                    self.conversation_history.append({
                        "role": "user",
                        "content": user_prompt
                    })
                self.conversation_history.append({
                    "role": "assistant",
                    "content": raw_response
                })
            
            # 显示AI响应
            self.reasoning_display.setPlainText(raw_response)
            self.update_conversation_display()
            
            # 显示AI推理结果
            flags = result.get("flags", [])
            
            if flags:
                for flag in flags:
                    if flag:
                        self.flag_list.addItem(flag)
                self.statusBar().showMessage(f"AI分析完成，发现 {len(flags)} 个可能的flag")
            else:
                old_flag = result.get("flag", "")
                if old_flag:
                    self.flag_list.addItem(old_flag)
                    self.statusBar().showMessage("AI分析完成，发现1个可能的flag")
                else:
                    self.statusBar().showMessage("AI分析完成，未发现flag")

    def view_full_response(self):
        """查看完整响应过程"""
        if hasattr(self, 'full_response_data') and self.full_response_data:
            # 创建新窗口显示完整响应过程
            response_window = QDialog(self)
            response_window.setWindowTitle("AI完整响应过程")
            response_window.setGeometry(200, 200, 800, 600)
            
            layout = QVBoxLayout()
            
            # 添加标签页来分别显示请求和响应
            tab_widget = QTabWidget()
            
            # 请求详情
            request_widget = QWidget()
            request_layout = QVBoxLayout()
            request_text = QTextEdit()
            request_text.setReadOnly(True)
            
            request_info = self.full_response_data.get("request", {})
            request_text.setPlainText(
                f"URL: {request_info.get('url', '')}\n\n"
                f"Headers: {json.dumps(request_info.get('headers', {}), indent=2, ensure_ascii=False)}\n\n"
                f"Data: {json.dumps(request_info.get('data', {}), indent=2, ensure_ascii=False)}"
            )
            
            request_layout.addWidget(request_text)
            request_widget.setLayout(request_layout)
            tab_widget.addTab(request_widget, "请求详情")
            
            # 响应详情
            response_widget = QWidget()
            response_layout = QVBoxLayout()
            response_text = QTextEdit()
            response_text.setReadOnly(True)
            
            response_info = self.full_response_data.get("response", {})
            response_text.setPlainText(
                f"Status Code: {response_info.get('status_code', '')}\n\n"
                f"Headers: {json.dumps(response_info.get('headers', {}), indent=2, ensure_ascii=False)}\n\n"
                f"Response Body: {response_info.get('text', '')}"
            )
            
            response_layout.addWidget(response_text)
            response_widget.setLayout(response_layout)
            tab_widget.addTab(response_widget, "响应详情")
            
            layout.addWidget(tab_widget)
            
            # 添加关闭按钮
            close_button = QPushButton("关闭")
            close_button.clicked.connect(response_window.close)
            layout.addWidget(close_button)
            
            response_window.setLayout(layout)
            response_window.exec()
        else:
            QMessageBox.information(self, "提示", "暂无完整响应过程数据")
    
    def update_conversation_display(self):
        """更新对话历史显示"""
        conversation_text = ""
        for message in self.conversation_history:
            role = message.get("role", "")
            content = message.get("content", "")
            
            if role == "user":
                conversation_text += f"【用户】\n{content}\n\n"
            elif role == "assistant":
                conversation_text += f"【AI助手】\n{content}\n\n"
        
        self.conversation_display.setPlainText(conversation_text)
    
    def clear_conversation_history(self):
        """清除对话历史"""
        reply = QMessageBox.question(self, "确认", "确定要清除对话历史吗？",
                                    QMessageBox.Yes | QMessageBox.No)
        if reply == QMessageBox.Yes:
            self.conversation_history = []
            self.conversation_display.setPlainText("")
            self.flag_list.clear()
            self.statusBar().showMessage("对话历史已清除")
    
    def on_ai_analysis_error(self, error_msg):
        """AI分析错误回调"""
        self.ask_ai_btn.setEnabled(True)
        self.statusBar().showMessage("AI分析失败")
        QMessageBox.critical(self, "AI分析错误", error_msg)
    
    def view_network_process(self):
        """查看网络分析过程"""
        if hasattr(self, 'network_analysis_process') and self.network_analysis_process:
            self.view_analysis_process("网络分析过程", self.network_analysis_process)
        else:
            QMessageBox.information(self, "提示", "暂无网络分析过程数据")
    
    def view_log_process(self):
        """查看日志分析过程"""
        if hasattr(self, 'log_analysis_process') and self.log_analysis_process:
            self.view_analysis_process("日志分析过程", self.log_analysis_process)
        else:
            QMessageBox.information(self, "提示", "暂无日志分析过程数据")
    
    def view_file_process(self):
        """查看文件分析过程"""
        if hasattr(self, 'file_analysis_process') and self.file_analysis_process:
            self.view_analysis_process("文件分析过程", self.file_analysis_process)
        else:
            QMessageBox.information(self, "提示", "暂无文件分析过程数据")
    
    def view_analysis_process(self, title, process_data):
        """通用的查看分析过程方法"""
        try:
            # 解析JSON数据
            process_info = json.loads(process_data)
            
            # 创建新窗口显示分析过程
            process_window = QDialog(self)
            process_window.setWindowTitle(title)
            process_window.setGeometry(200, 200, 800, 600)
            
            layout = QVBoxLayout()
            
            # 创建文本框显示分析过程
            process_text = QTextEdit()
            process_text.setReadOnly(True)
            
            # 格式化显示分析过程
            formatted_text = ""
            for step_info in process_info:
                step = step_info.get("step", "")
                details = step_info.get("details", "")
                formatted_text += f"[{step}]\n{details}\n\n"
            
            process_text.setPlainText(formatted_text)
            layout.addWidget(process_text)
            
            # 添加关闭按钮
            close_button = QPushButton("关闭")
            close_button.clicked.connect(process_window.close)
            layout.addWidget(close_button)
            
            process_window.setLayout(layout)
            process_window.exec()
        except json.JSONDecodeError:
            QMessageBox.warning(self, "错误", "分析过程数据格式不正确")


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = CTFXRayMainWindow()
    window.show()
    sys.exit(app.exec())
