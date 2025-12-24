#!/usr/bin/env python3
# -*- coding: utf-8 -*-

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
        """创建网络流量分析标签页 - 新流程：导入→题目→初筛→展示"""
        self.network_tab = QWidget()
        main_layout = QVBoxLayout()
        
        # 第一步：文件导入区域
        import_group = QGroupBox("第一步：导入 PCAP 文件")
        import_layout = QHBoxLayout()
        
        self.pcap_file_btn = QPushButton("选择 PCAP 文件")
        self.pcap_file_btn.clicked.connect(self.select_pcap_file)
        self.network_file_label = QLabel("未选择文件")
        
        self.start_capture_btn = QPushButton("或开始实时抓包")
        self.start_capture_btn.clicked.connect(self.start_capture)
        
        import_layout.addWidget(self.pcap_file_btn)
        import_layout.addWidget(self.network_file_label)
        import_layout.addWidget(self.start_capture_btn)
        import_layout.addStretch()
        
        import_group.setLayout(import_layout)
        main_layout.addWidget(import_group)
        
        # 第二步：题目描述区域
        problem_group = QGroupBox("第二步：输入题目描述")
        problem_layout = QVBoxLayout()
        
        problem_label = QLabel("请输入题目要求和关键词（AI 将根据文件名和题目描述进行初筛）：")
        self.network_problem_input = QTextEdit()
        self.network_problem_input.setPlaceholderText(
            "例如：\n"
            "题目：在 HTTP 流量中找到 flag\n"
            "关键词：password、secret、flag\n"
            "文件类型：jpg、png、txt"
        )
        self.network_problem_input.setMaximumHeight(80)
        
        # AI初筛按钮
        self.network_initial_analyze_btn = QPushButton("开始 AI 初筛")
        self.network_initial_analyze_btn.clicked.connect(self.network_initial_analyze)
        self.network_initial_analyze_btn.setEnabled(False)
        
        problem_layout.addWidget(problem_label)
        problem_layout.addWidget(self.network_problem_input)
        problem_layout.addWidget(self.network_initial_analyze_btn)
        
        problem_group.setLayout(problem_layout)
        main_layout.addWidget(problem_group)
        
        # 第三步：分析结果展示区域
        result_group = QGroupBox("第三步：AI 初筛结果")
        result_layout = QVBoxLayout()
        
        # 创建标签页来展示不同的结果
        self.network_result_tabs = QTabWidget()
        
        # 高匹配数据包标签
        self.high_match_list = QListWidget()
        self.network_result_tabs.addTab(self.high_match_list, "高匹配数据包")
        
        # Wireshark 正则
        self.wireshark_regex_display = QTextEdit()
        self.wireshark_regex_display.setReadOnly(True)
        self.network_result_tabs.addTab(self.wireshark_regex_display, "Wireshark 正则")
        
        # 高频数据条目
        self.high_frequency_display = QTextEdit()
        self.high_frequency_display.setReadOnly(True)
        self.network_result_tabs.addTab(self.high_frequency_display, "高频数据条目")
        
        result_layout.addWidget(self.network_result_tabs)
        
        # 操作按钮
        action_layout = QHBoxLayout()
        
        self.network_export_json_btn = QPushButton("导出高频条目到 JSON")
        self.network_export_json_btn.clicked.connect(self.network_export_json)
        self.network_export_json_btn.setEnabled(False)
        
        self.network_secondary_analyze_btn = QPushButton("二次深度研判")
        self.network_secondary_analyze_btn.clicked.connect(self.network_secondary_analyze)
        self.network_secondary_analyze_btn.setEnabled(False)
        
        action_layout.addWidget(self.network_export_json_btn)
        action_layout.addWidget(self.network_secondary_analyze_btn)
        action_layout.addStretch()
        
        result_layout.addLayout(action_layout)
        
        result_group.setLayout(result_layout)
        main_layout.addWidget(result_group)
        
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
        """选择PCAP文件"""
        file_path, _ = QFileDialog.getOpenFileName(
            self, "选择PCAP文件", "", "PCAP文件 (*.pcap *.pcapng);;所有文件 (*)")
        if file_path:
            self.network_file_label.setText(f"已选择：{file_path}")
            self.selected_pcap_file = file_path
            # 启用题目输入和初筛按钮
            self.network_initial_analyze_btn.setEnabled(True)
            self.statusBar().showMessage("PCAP 文件已加载，请输入题目描述后进行初筛")
            
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
    
    def network_initial_analyze(self):
        """AI 初筛：根据文件名和题目描述进行初筛"""
        if not hasattr(self, 'selected_pcap_file'):
            QMessageBox.warning(self, "警告", "请先选择 PCAP 文件")
            return
        
        problem_desc = self.network_problem_input.toPlainText()
        if not problem_desc.strip():
            QMessageBox.warning(self, "警告", "请输入题目描述")
            return
        
        # 清除旧数据
        self._cleanup_analysis_data()
        
        # 首先分析PCAP文件
        self.statusBar().showMessage("正在分析 PCAP 文件...")
        self.network_initial_analyze_btn.setEnabled(False)
        
        # 保存题目描述供后续使用
        self.network_problem_description = problem_desc
        
        # 调用分析器
        self.pcap_analyzer.analyze(self.selected_pcap_file)
    
    def analyze_network(self):
        """分析网络流量（仅在PCAP分析完成后调用）"""
        # 此方法已由 network_initial_analyze 替代
        pass
            
    def on_network_analysis_finished(self, results):
        """网络分析完成回调 - 新流程：PCAP分析后立即进行AI初筛"""
        # 保存分析结果（包括json_file路径）
        self.network_analysis_results = results
        
        # 清空显示区域
        self.high_match_list.clear()
        self.wireshark_regex_display.setPlainText("")
        self.high_frequency_display.setPlainText("")
        
        # 检查是否有JSON文件
        json_files = [r.get('json_file') for r in results if r.get('json_file')]
        
        if not json_files:
            QMessageBox.warning(self, "错误", "未能生成JSON分析文件，请检查PCAP文件")
            self.network_initial_analyze_btn.setEnabled(True)
            return
        
        # 现在调用AI进行初筛
        print(f"[GUI] PCAP分析完成，{len(json_files)} 个JSON文件已生成")
        self.statusBar().showMessage("PCAP 分析完成，正在进行 AI 初筛...")
        
        # 调用AI协调器进行初筛
        self._do_ai_initial_screening()
    
    def _do_ai_initial_screening(self):
        """执行AI初筛"""
        if not hasattr(self, 'network_problem_description'):
            QMessageBox.warning(self, "错误", "找不到题目描述")
            return
        
        # 构建初筛提示
        problem = self.network_problem_description
        pcap_filename = self.selected_pcap_file.split('\\')[-1] if hasattr(self, 'selected_pcap_file') else "unknown.pcap"
        
        initial_screening_prompt = f"""【文件名】{pcap_filename}

【题目描述】
{problem}

【任务】
基于文件名、题目描述和数据包内容，执行初筛任务：
1. **识别高匹配数据包**：根据题目关键词找出最相关的数据包
2. **生成 Wireshark 正则**：输出可以在 Wireshark 中使用的正则表达式来快速过滤
3. **统计高频条目**：提取频繁出现的关键字段、URL、域名等

【输出格式】
分别输出：
1. 高匹配包（数据包号）
2. Wireshark 正则
3. 高频数据条目 JSON
"""
        
        # 使用分析数据作为上下文
        analysis_data = self.network_analysis_results
        
        # 直接调用AI协调器
        self.statusBar().showMessage("正在执行 AI 初筛...")
        self.ai_coordinator.analyze(
            analysis_data, 
            initial_screening_prompt,
            self.api_key_input.text(),
            self.model_input.text(),
            conversation_history=self.conversation_history
        )
    
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
        self.ai_coordinator.analyze([current_data], new_prompt, api_key, model,
                                   conversation_history=self.conversation_history)
        
    def ask_ai(self):
        """询问AI"""
        user_prompt = self.user_prompt_input.toPlainText()
        
        # 优先使用网络分析结果（如果存在）
        if hasattr(self, 'network_analysis_results') and self.network_analysis_results:
            # 直接传递原始分析结果给AI协调器
            analysis_data = self.network_analysis_results
            print(f"[AI分析] 使用网络分析结果 ({len(analysis_data)} 条记录)")
        else:
            # 降级：从表格读取
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
            # 传递原始分析结果给AI分析（包含json_file路径）
            self.ai_coordinator.analyze(analysis_data, user_prompt, api_key, model, 
                                       conversation_history=self.conversation_history)
        else:
            QMessageBox.warning(self, "警告", "请输入提示内容或选择数据")
    
    def on_ai_analysis_finished(self, result):
        """AI分析完成回调 - 处理初筛结果或深度研判结果"""
        self.ask_ai_btn.setEnabled(True)
        
        # 检查是否是流量分析页面的初筛
        if hasattr(self, 'network_problem_description') and 'network_initial_analyze_btn' in dir(self):
            # 这是初筛结果
            self._handle_initial_screening_result(result)
        else:
            # 这是AI协同页面的结果
            self._handle_ai_analysis_result(result)
    
    def _handle_initial_screening_result(self, result):
        """处理初筛结果"""
        print("[GUI] 处理初筛结果...")
        
        raw_response = result.get("raw_response", "")
        
        # 清空显示
        self.high_match_list.clear()
        self.wireshark_regex_display.setPlainText("")
        self.high_frequency_display.setPlainText("")
        
        # 解析AI的初筛结果
        # 预期格式：
        # 【高匹配包】...
        # 【Wireshark正则】...
        # 【高频数据条目】...JSON...
        
        import re as re_lib
        
        # 提取高匹配包
        high_match_section = re_lib.search(r'【高匹配包】(.*?)(?=【|$)', raw_response, re_lib.DOTALL)
        if high_match_section:
            high_match_text = high_match_section.group(1).strip()
            packages = re_lib.findall(r'#?\d+|数据包\s*#?\d+', high_match_text)
            for pkg in packages:
                self.high_match_list.addItem(pkg)
            print(f"[GUI] 提取到 {len(packages)} 个高匹配包")
        
        # 提取 Wireshark 正则
        regex_section = re_lib.search(r'【Wireshark正则|【Wireshark\s*正则】(.*?)(?=【|$)', raw_response, re_lib.DOTALL)
        if regex_section:
            regex_text = regex_section.group(1).strip()
            self.wireshark_regex_display.setPlainText(regex_text)
            print(f"[GUI] 提取到 Wireshark 正则")
        
        # 提取高频数据条目（JSON）
        freq_section = re_lib.search(r'【高频数据条目】(.*?)(?=【|$)', raw_response, re_lib.DOTALL)
        if freq_section:
            freq_text = freq_section.group(1).strip()
            # 尝试解析JSON
            try:
                import json as json_lib
                # 查找JSON部分
                json_match = re_lib.search(r'\{.*\}', freq_text, re_lib.DOTALL)
                if json_match:
                    freq_json = json_lib.loads(json_match.group(0))
                    # 保存到全局变量供后续使用
                    self.high_frequency_data = freq_json
                    self.high_frequency_display.setPlainText(json_lib.dumps(freq_json, indent=2, ensure_ascii=False))
                    print(f"[GUI] 提取到高频数据条目 JSON")
            except:
                # 如果JSON解析失败，直接显示文本
                self.high_frequency_display.setPlainText(freq_text)
        
        # 启用导出和二次研判按钮
        self.network_export_json_btn.setEnabled(True)
        self.network_secondary_analyze_btn.setEnabled(True)
        self.network_initial_analyze_btn.setEnabled(True)
        
        self.statusBar().showMessage(
            f"✓ AI 初筛完成！发现 {self.high_match_list.count()} 个高匹配包，"
            f"已生成 Wireshark 正则和高频数据条目。"
        )
    
    def network_export_json(self):
        """导出高频数据条目到 JSON"""
        if not hasattr(self, 'high_frequency_data'):
            QMessageBox.warning(self, "警告", "没有可导出的数据")
            return
        
        from pathlib import Path
        import json as json_lib
        
        # 创建 tmp 目录
        tmp_dir = Path("tmp")
        tmp_dir.mkdir(exist_ok=True)
        
        # 保存高频数据到 JSON
        output_file = tmp_dir / "high_frequency_items.json"
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                json_lib.dump(self.high_frequency_data, f, indent=2, ensure_ascii=False)
            
            QMessageBox.information(self, "成功", f"高频数据条目已导出到：\n{output_file}")
            self.statusBar().showMessage(f"高频数据已导出到 {output_file}")
        except Exception as e:
            QMessageBox.critical(self, "错误", f"导出失败：{e}")
    
    def network_secondary_analyze(self):
        """二次深度研判"""
        if not hasattr(self, 'high_frequency_data'):
            QMessageBox.warning(self, "警告", "请先完成初筛")
            return
        
        # 切换到AI协同页面
        self.tabs.setCurrentWidget(self.ai_tab)
        
        # 清空AI显示区域
        self.reasoning_display.setPlainText("")
        self.conversation_display.setPlainText("")
        self.flag_list.clear()
        self.conversation_history = []
        
        # 构建二次研判的提示
        import json as json_lib
        secondary_prompt = f"""根据以下初筛结果和高频数据条目，进行二次深度研判：

【高频数据条目】
{json_lib.dumps(self.high_frequency_data, ensure_ascii=False, indent=2)}

【任务】
1. 分析这些高频条目中是否包含明显的flag或关键信息
2. 提取所有可能的flag、hash值、密钥等敏感信息
3. 分析这些数据的含义和用途

【输出】
直接列出发现的所有flag和关键信息。
"""
        
        # 填充AI页面
        self.raw_data_display.setPlainText(f"高频数据条目：\n{json_lib.dumps(self.high_frequency_data, ensure_ascii=False, indent=2)}")
        self.user_prompt_input.setPlainText(secondary_prompt)
        
        self.statusBar().showMessage("已加载高频数据，请点击'询问AI'进行二次研判")
    
    def _handle_ai_analysis_result(self, result):
        """处理AI协同页面的分析结果"""
        # 处理分析状态
        analysis_status = result.get("status", "")
        
        # 如果是正则匹配阶段
        if analysis_status == "regex_matched":
            self.statusBar().showMessage("✓ 正则筛选完成，已匹配到可疑flag")
            
            # 显示分析过程
            analysis_text = result.get("analysis", "")
            self.reasoning_display.setPlainText(f"【两阶段分析结果】\n\n{analysis_text}")
            
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