#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
AI协同研判模块
负责与AI模型交互，进行Flag识别和分析
"""

import json
import requests
from PySide6.QtCore import QObject, Signal, QThread
import sys


class AICoordinatorWorker(QObject):
    """AI协调工作线程"""
    finished = Signal(dict)  # 发送AI分析结果
    error = Signal(str)      # 发送错误信息
    
    def __init__(self, prompt_data, user_prompt="", api_key="", model="", conversation_history=None):
        super().__init__()
        self.prompt_data = prompt_data
        self.user_prompt = user_prompt
        self.api_key = api_key
        self.model = model
        self.batch_analysis_results = []  # 存储分批分析结果
        self.conversation_history = conversation_history or []  # 对话历史
        
    def run(self):
        """执行AI分析任务"""
        try:
            # 首先检查数据中是否包含分块标记
            has_chunks = any(item.get('type') in ['CHUNK_START', 'CHUNK_COMPLETE', 'CHUNK_SUMMARY'] for item in self.prompt_data)
            
            if has_chunks:
                print("[AI分析] 检测到分块数据，使用分块模式处理...")
                result = self.process_chunked_data()
            else:
                # 检查数据量是否过大，需要分批处理
                total_content_length = sum(len(str(item.get('content', ''))) for item in self.prompt_data)
                
                # 如果内容超过50KB，使用分批处理
                if total_content_length > 50000:
                    print(f"[AI分析] 检测到大数据包({total_content_length}bytes)，使用分批处理...")
                    result = self.process_in_batches()
                else:
                    # 小数据量直接处理
                    prompt = self.construct_prompt()
                    api_result = self.call_iflow_model(prompt)
                    
                    # 规范化返回格式：转换flags_with_reasons为字符串列表
                    flags_list = []
                    if "flags" in api_result:
                        for flag_info in api_result["flags"]:
                            if isinstance(flag_info, dict):
                                flag_content = flag_info.get('flag', '').strip()
                            else:
                                flag_content = str(flag_info).strip()
                            if flag_content:
                                flags_list.append(flag_content)
                    
                    result = {
                        "flags": flags_list,  # ✅ 统一为字符串列表
                        "raw_response": api_result.get("raw_response", ""),
                        "status": api_result.get("status", "success"),
                        "analysis": f"单次处理完成，发现{len(flags_list)}个可疑flag"
                    }
            
            self.finished.emit(result)
        except Exception as e:
            self.error.emit(str(e))
    
    def process_chunked_data(self):
        """处理分块数据的AI分析"""
        print("[分块处理] 开始处理分块数据...")
        
        # 将数据按块分组
        chunks = {}
        chunk_order = []
        all_flags = []
        chunk_summaries = []
        
        for item in self.prompt_data:
            item_type = item.get('type', '')
            
            if item_type == 'CHUNK_START':
                chunk_id = item.get('chunk_id', 0)
                if chunk_id not in chunks:
                    chunks[chunk_id] = []
                    chunk_order.append(chunk_id)
            elif item_type == 'CHUNK_COMPLETE':
                continue  # 跳过标记
            elif item_type == 'CHUNK_SUMMARY':
                continue  # 跳过标记
            elif item_type not in ['ANALYSIS_PROCESS']:
                # 该项属于最近的块
                if chunk_order:
                    current_chunk = chunk_order[-1]
                    chunks[current_chunk].append(item)
        
        total_chunks = len(chunks)
        print(f"[分块处理] 检测到 {total_chunks} 块数据")
        
        # 逐块分析
        for block_num, chunk_id in enumerate(chunk_order, 1):
            chunk_items = chunks[chunk_id]
            
            if not chunk_items:
                continue
            
            print(f"[分块处理] 分析第 {block_num}/{total_chunks} 块...")
            
            # 为这一块构造提示词
            chunk_prompt = self._construct_chunk_prompt(chunk_items, chunk_id, total_chunks, chunk_summaries)
            
            try:
                api_result = self.call_iflow_model(chunk_prompt)
                flags = self.extract_flags_from_result(api_result)
                all_flags.extend(flags)
                
                # 保存块的总结（用于后续块的上下文）
                summary = api_result.get("raw_response", "")[:300]
                chunk_summaries.append(f"块{chunk_id}: 发现flag-{flags}，内容摘要-{summary}")
                
                print(f"[分块处理] 块 {chunk_id} 完成，发现 {len(flags)} 个flag")
                
            except Exception as e:
                print(f"[分块处理] 块 {chunk_id} 分析失败: {str(e)}")
                continue
        
        # 最后的综合分析
        synthesis_prompt = f"""
【综合分析总结】
已完成对所有 {total_chunks} 块数据包的逐块分析。

各块发现的内容：
{chr(10).join(chunk_summaries) if chunk_summaries else '暂无'}

目前发现的所有可疑flag/哈希值：
{', '.join(all_flags) if all_flags else '暂无'}

请给出最终的综合分析：
1. 确认的flag列表
2. 各flag的发现块号和理由
3. 是否有关联的流量特征
4. 最终建议
"""
        
        print("[分块处理] 执行最终综合分析...")
        
        try:
            final_result = self.call_iflow_model(synthesis_prompt)
            final_flags = self.extract_flags_from_result(final_result)
            
            # 合并所有发现的flag
            all_flags.extend(final_flags)
            unique_flags = list(set(all_flags))
            
            return {
                "flags": unique_flags,
                "raw_response": final_result.get("raw_response", ""),
                "status": "success_chunked",
                "total_chunks": total_chunks,
                "analysis": f"分块分析完成（{total_chunks}块），共发现 {len(unique_flags)} 个可疑flag"
            }
        except Exception as e:
            print(f"[分块处理] 综合分析失败: {str(e)}")
            return {
                "flags": all_flags,
                "raw_response": "",
                "status": "partial_success",
                "total_chunks": total_chunks,
                "analysis": f"分块分析部分完成，共发现 {len(all_flags)} 个可疑flag"
            }
    
    def _construct_chunk_prompt(self, chunk_items, chunk_id, total_chunks, previous_summaries):
        """为单个数据块构造AI分析提示词"""
        prompt = f"【数据块 {chunk_id}/{total_chunks}】\n"
        
        # 如果有前面块的信息，添加到上下文
        if previous_summaries:
            prompt += "\n【前面块的分析总结】\n"
            for summary in previous_summaries[-2:]:  # 只保留最近2块的总结
                prompt += f"- {summary}\n"
            prompt += "\n"
        
        # 添加当前块的数据
        prompt += "【当前块的原始数据】\n"
        
        # 按优先级显示数据
        flag_matches = [item for item in chunk_items if item.get('type') == 'FLAG_REGEX_MATCH']
        hex_dumps = [item for item in chunk_items if item.get('type') == 'HEX_DUMP']
        all_data = [item for item in chunk_items if item.get('type') == 'ALL_DATA']
        
        # 显示flag匹配结果（最重要）
        if flag_matches:
            prompt += f"\n正则匹配到的可疑内容（{len(flag_matches)}条）:\n"
            for item in flag_matches[:10]:  # 最多显示10条
                prompt += f"- {item.get('match', '')}\n"
        
        # 显示十六进制数据
        if hex_dumps:
            prompt += f"\n十六进制数据包（{len(hex_dumps)}条）:\n"
            for item in hex_dumps[:5]:  # 最多显示5条
                prompt += f"- {item.get('content', '')}\n"
        
        # 显示其他数据
        if all_data:
            prompt += f"\n其他提取的数据（{len(all_data)}条）:\n"
            for item in all_data[:5]:  # 最多显示5条
                prompt += f"- {item.get('content', '')}\n"
        
        # 添加分析任务
        prompt += f"\n【分析任务】\n"
        prompt += f"请分析这一块的数据，查找：\n"
        prompt += f"1. 所有的flag格式内容 (flag{{}}, FLAG{{}}, ctf{{}}, 等)\n"
        prompt += f"2. 可疑的哈希值或加密文本\n"
        prompt += f"3. 特殊的协议行为或数据流特征\n"
        prompt += f"4. 任何看起来异常的内容\n\n"
        
        if self.user_prompt:
            prompt += f"【用户要求】\n{self.user_prompt}\n"
        
        return prompt

        """分批处理大数据包"""
        # 按每个批次最多30KB计算分批数量
        batch_size = 30000
        batches = []
        current_batch = []
        current_size = 0
        
        for item in self.prompt_data:
            item_size = len(str(item.get('content', '')))
            
            # 如果当前批次加上这个item会超过限制，开始新批次
            if current_size + item_size > batch_size and current_batch:
                batches.append(current_batch)
                current_batch = [item]
                current_size = item_size
            else:
                current_batch.append(item)
                current_size += item_size
        
        # 添加最后一个批次
        if current_batch:
            batches.append(current_batch)
        
        print(f"数据已分成{len(batches)}个批次，准备逐批传输到AI...")
        
        # 逐批分析
        all_flags = []
        conversation_context = []  # 保存对话上下文
        last_raw_response = ""  # 保存最后一个批次的原始响应
        
        for batch_idx, batch_data in enumerate(batches):
            print(f"处理批次 {batch_idx + 1}/{len(batches)}...")
            
            # 临时替换prompt_data为当前批次
            original_data = self.prompt_data
            self.prompt_data = batch_data
            
            # 构造该批次的提示词
            if batch_idx == 0:
                # 第一批：普通提示
                prompt = self.construct_prompt()
                prefix = "这是第一批数据："
            else:
                # 后续批次：告知是后续数据
                prompt = self.construct_prompt()
                prefix = f"这是第{batch_idx + 1}批数据（共{len(batches)}批）。前面已分析过的flag：{', '.join(all_flags) if all_flags else '无'}。\n\n"
            
            prompt = prefix + prompt
            
            # 调用API分析该批次
            try:
                batch_result = self.call_iflow_model(prompt)
                
                # 提取这一批的flag
                batch_flags = self.extract_flags_from_result(batch_result)
                all_flags.extend(batch_flags)
                
                # 保存最后一个批次的原始响应（用于UI显示）
                last_raw_response = batch_result.get("raw_response", "")
                
                self.batch_analysis_results.append({
                    "batch": batch_idx + 1,
                    "result": batch_result,
                    "flags_found": batch_flags
                })
                
                print(f"批次{batch_idx + 1}分析完成，发现flag: {batch_flags}")
            except Exception as e:
                print(f"批次{batch_idx + 1}处理失败: {str(e)}")
                self.batch_analysis_results.append({
                    "batch": batch_idx + 1,
                    "error": str(e)
                })
            
            # 恢复原始数据
            self.prompt_data = original_data
        
        # 合并所有批次的结果
        combined_result = self.combine_batch_results(all_flags, last_raw_response)
        return combined_result
    
    def extract_flags_from_result(self, result):
        """从AI结果中提取flag"""
        flags = []
        
        # 直接从已解析的flags字段提取（call_iflow_model已经调用了parse_flags_from_response）
        if isinstance(result, dict):
            # 首先尝试从"flags"字段提取（推荐，已解析）
            if "flags" in result:
                flags_list = result["flags"]
                if isinstance(flags_list, list):
                    for flag_info in flags_list:
                        if isinstance(flag_info, dict):
                            flag_content = flag_info.get('flag', '').strip()
                            if flag_content:
                                flags.append(flag_content)
                                print(f"[批次提取] 找到flag: {flag_content}")
        
        return flags
    
    def combine_batch_results(self, all_flags, raw_response=""):
        """合并所有批次的结果"""
        # all_flags 是字符串列表 (["flag{...}", "flag{...}", ...])
        unique_flags = list(set(all_flags))  # 去重
        
        return {
            "flags": unique_flags,  # ✅ GUI期望的格式：字符串列表
            "raw_response": raw_response,  # ✅ 用于UI显示的原始AI响应
            "batch_count": len(self.batch_analysis_results),
            "batches": self.batch_analysis_results,
            "analysis": f"分批处理了{len(self.batch_analysis_results)}批数据，共发现{len(unique_flags)}个可疑flag",
            "status": "success" if unique_flags else "no_flags_found"
        }
    
    def parse_flags_from_response(self, response_text):
        """从AI的响应中解析flag和原因（支持JSON和纯文本格式）"""
        flags_with_reasons = []
        
        # 首先尝试解析JSON格式
        try:
            # 检查是否包含JSON块（{ 或 [）
            json_start = -1
            json_end = -1
            
            # 尝试找到第一个 { 或 [
            brace_pos = response_text.find('{')
            bracket_pos = response_text.find('[')
            
            if brace_pos != -1 or bracket_pos != -1:
                if brace_pos == -1:
                    json_start = bracket_pos
                    json_end = response_text.rfind(']') + 1
                elif bracket_pos == -1:
                    json_start = brace_pos
                    json_end = response_text.rfind('}') + 1
                else:
                    json_start = min(brace_pos, bracket_pos)
                    # 根据起始位置确定结束位置
                    if response_text[json_start] == '{':
                        json_end = response_text.rfind('}') + 1
                    else:
                        json_end = response_text.rfind(']') + 1
                
                if json_start != -1 and json_end > json_start:
                    json_str = response_text[json_start:json_end]
                    try:
                        result = json.loads(json_str)
                        
                        # 处理单个JSON对象
                        if isinstance(result, dict) and 'flag' in result:
                            flag_content = result.get('flag', '').strip()
                            reason = result.get('reason', '').strip()
                            confidence = result.get('confidence', '').strip()
                            
                            # 检查是否是有效的flag
                            if flag_content and "未发现" not in reason:
                                flags_with_reasons.append({
                                    "flag": flag_content,
                                    "reason": reason,
                                    "confidence": confidence
                                })
                                print(f"[JSON解析] 成功提取flag: {flag_content}")
                                return flags_with_reasons  # 返回找到的JSON结果
                        
                        # 处理JSON数组
                        elif isinstance(result, list):
                            for item in result:
                                if isinstance(item, dict) and 'flag' in item:
                                    flag_content = item.get('flag', '').strip()
                                    reason = item.get('reason', '').strip()
                                    confidence = item.get('confidence', '').strip()
                                    
                                    if flag_content and "未发现" not in reason:
                                        flags_with_reasons.append({
                                            "flag": flag_content,
                                            "reason": reason,
                                            "confidence": confidence
                                        })
                            
                            if flags_with_reasons:
                                print(f"[JSON解析] 成功提取{len(flags_with_reasons)}个flag")
                                return flags_with_reasons
                    except json.JSONDecodeError as e:
                        print(f"[JSON解析] JSON格式解析失败: {str(e)[:50]}，尝试纯文本格式...")
        except Exception as e:
            print(f"[JSON解析] 异常: {str(e)}，尝试纯文本格式...")
        
        # 如果JSON解析失败，尝试纯文本格式
        print("[文本解析] 使用纯文本格式解析...")
        
        # 策略1：查找flag{...}、FLAG{...}、ctf{...}等格式（最常见）
        import re
        flag_patterns = [
            r'flag\{[^}]+\}',
            r'FLAG\{[^}]+\}',
            r'ctf\{[^}]+\}',
            r'CTF\{[^}]+\}',
            r'Flag\{[^}]+\}',
        ]
        
        for pattern in flag_patterns:
            matches = re.findall(pattern, response_text, re.IGNORECASE)
            for match in matches:
                if match not in [f.get('flag', '') for f in flags_with_reasons]:
                    flags_with_reasons.append({
                        "flag": match,
                        "reason": "从响应文本中直接提取",
                        "confidence": "high"
                    })
                    print(f"[文本解析] 找到flag: {match}")
        
        # 策略2：查找MD5/SHA格式的哈希值（可能是flag）
        if not flags_with_reasons:
            hash_patterns = [
                (r'[a-f0-9]{32}', 'MD5'),
                (r'[a-f0-9]{40}', 'SHA1'),
                (r'[a-f0-9]{64}', 'SHA256'),
            ]
            
            for pattern, hash_type in hash_patterns:
                matches = re.findall(pattern, response_text, re.IGNORECASE)
                for match in matches:
                    # 构造flag格式
                    flag_text = f"flag{{{match}}}"
                    if flag_text not in [f.get('flag', '') for f in flags_with_reasons]:
                        flags_with_reasons.append({
                            "flag": flag_text,
                            "reason": f"提取的{hash_type}哈希值",
                            "confidence": "medium"
                        })
                        print(f"[文本解析] 找到{hash_type}哈希: {flag_text}")
        
        # 策略3：按key:value格式解析
        if not flags_with_reasons:
            blocks = response_text.split('---')
            
            for block in blocks:
                block = block.strip()
                if not block:
                    continue
                
                flag_content = ""
                reason = ""
                confidence = ""
                
                # 解析flag行
                lines = block.split('\n')
                for line in lines:
                    line = line.strip()
                    if line.startswith('flag:'):
                        flag_content = line.replace('flag:', '').strip()
                    elif line.startswith('reason:'):
                        reason = line.replace('reason:', '').strip()
                    elif line.startswith('confidence:'):
                        confidence = line.replace('confidence:', '').strip()
                
                # 如果找到flag和原因，添加到列表
                if flag_content or reason:
                    # 检查是否是"未发现"的情况
                    if flag_content or (reason and "未发现" not in reason):
                        flags_with_reasons.append({
                            "flag": flag_content,
                            "reason": reason,
                            "confidence": confidence
                        })
        
        if flags_with_reasons:
            print(f"[文本解析] 成功提取{len(flags_with_reasons)}个flag")
        else:
            print("[解析结果] 未找到任何flag")
        
        return flags_with_reasons
    
    def construct_prompt(self):
        """构造发送给AI的提示词（限制上下文窗口不超过256K字符）"""
        # 最大token限制（256K）
        MAX_CONTEXT_SIZE = 256000  # 约256K字符
        SYSTEM_PROMPT_SIZE = 1000  # 系统提示词的基础大小
        RESERVE_SIZE = 2000        # 为响应预留的大小
        MAX_DATA_SIZE = MAX_CONTEXT_SIZE - SYSTEM_PROMPT_SIZE - RESERVE_SIZE  # 数据部分的最大大小
        
        # 检查是否为网络流量分析数据
        is_network_data = any(item.get('type') in ['FLAG_SEARCH', 'HTTP', 'HTTP_CONTENT', 'DNS_FLAG', 'ICMP_DATA', 'ICMP_RAW', 'ALL_DATA'] 
                             for item in self.prompt_data)
        
        if is_network_data:
            prompt = "你是一名专业的CTF专家。以下是提取的数据包信息，请进行全面分析：\n\n"
            prompt += "流量数据：\n"
            
            # 分别处理不同类型的数据
            all_data_items = [item for item in self.prompt_data if item.get('type') == 'ALL_DATA']
            flag_items = [item for item in self.prompt_data if item.get('type') == 'FLAG_SEARCH']
            http_items = [item for item in self.prompt_data if item.get('type') == 'HTTP']
            http_content_items = [item for item in self.prompt_data if item.get('type') == 'HTTP_CONTENT']
            dns_items = [item for item in self.prompt_data if item.get('type') == 'DNS_FLAG']
            icmp_items = [item for item in self.prompt_data if item.get('type') in ['ICMP_DATA', 'ICMP_RAW']]
            
            # 跟踪当前提示词大小
            current_size = len(prompt)
            
            # 显示所有数据包信息（动态限制数量以控制token）
            if all_data_items and current_size < MAX_DATA_SIZE:
                items_to_show = min(20, len(all_data_items))  # 先尝试显示20条
                section_header = f"\n所有数据包信息（共{len(all_data_items)}条，显示前{items_to_show}条）:\n"
                prompt += section_header
                current_size += len(section_header)
                
                for i, item in enumerate(all_data_items[:items_to_show]):
                    if current_size > MAX_DATA_SIZE * 0.8:  # 当接近限制时停止
                        prompt += f"   ... 还有{len(all_data_items) - i}条数据包信息已省略 ...\n"
                        break
                    
                    line = f"{i+1}. [{item.get('type', 'UNKNOWN')}] {item.get('src', 'N/A')} -> {item.get('dst', 'N/A')}\n"
                    content = item.get('content', '')[:200]  # 限制单个内容长度
                    line += f"   内容: {content}\n"
                    
                    if current_size + len(line) > MAX_DATA_SIZE:
                        prompt += f"   ... 还有{len(all_data_items) - i}条数据包信息已省略 ...\n"
                        break
                    
                    prompt += line
                    current_size += len(line)
            
            # 显示HTTP内容（更精细的数据，限制数量和长度）
            if http_content_items and current_size < MAX_DATA_SIZE:
                items_to_show = min(10, len(http_content_items))
                section_header = f"\nHTTP详细内容（共{len(http_content_items)}条，显示前{items_to_show}条）:\n"
                prompt += section_header
                current_size += len(section_header)
                
                for i, item in enumerate(http_content_items[:items_to_show]):
                    if current_size > MAX_DATA_SIZE * 0.8:
                        prompt += f"   ... 还有{len(http_content_items) - i}条HTTP内容已省略 ...\n"
                        break
                    
                    content = item.get('content', '')[:300]  # 限制内容长度
                    line = f"{i+1}. HTTP详细内容\n   {content}\n"
                    
                    if current_size + len(line) > MAX_DATA_SIZE:
                        prompt += f"   ... 还有{len(http_content_items) - i}条HTTP内容已省略 ...\n"
                        break
                    
                    prompt += line
                    current_size += len(line)
            
            # 显示标记的Flag相关内容
            if flag_items and current_size < MAX_DATA_SIZE:
                items_to_show = min(10, len(flag_items))
                section_header = f"\n标记的Flag相关内容（共{len(flag_items)}条，显示前{items_to_show}条）:\n"
                prompt += section_header
                current_size += len(section_header)
                
                for i, item in enumerate(flag_items[:items_to_show]):
                    if current_size > MAX_DATA_SIZE * 0.8:
                        prompt += f"   ... 还有{len(flag_items) - i}条Flag内容已省略 ...\n"
                        break
                    
                    content = item.get('content', '')[:200]
                    line = f"{i+1}. [{item.get('type', 'UNKNOWN')}] {item.get('src', 'N/A')} -> {item.get('dst', 'N/A')}\n   内容: {content}\n"
                    
                    if current_size + len(line) > MAX_DATA_SIZE:
                        prompt += f"   ... 还有{len(flag_items) - i}条Flag内容已省略 ...\n"
                        break
                    
                    prompt += line
                    current_size += len(line)
            
            # 显示HTTP流信息
            if http_items and current_size < MAX_DATA_SIZE:
                items_to_show = min(15, len(http_items))
                section_header = f"\nHTTP流信息（共{len(http_items)}条，显示前{items_to_show}条）:\n"
                prompt += section_header
                current_size += len(section_header)
                
                for i, item in enumerate(http_items[:items_to_show]):
                    if current_size > MAX_DATA_SIZE * 0.8:
                        prompt += f"   ... 还有{len(http_items) - i}条HTTP流已省略 ...\n"
                        break
                    
                    content = item.get('content', '')[:150]
                    line = f"{i+1}. [{item.get('type', 'UNKNOWN')}] {item.get('src', 'N/A')} -> {item.get('dst', 'N/A')}\n   内容: {content}\n"
                    
                    if current_size + len(line) > MAX_DATA_SIZE:
                        prompt += f"   ... 还有{len(http_items) - i}条HTTP流已省略 ...\n"
                        break
                    
                    prompt += line
                    current_size += len(line)
            
            # 显示DNS查询信息
            if dns_items and current_size < MAX_DATA_SIZE:
                items_to_show = min(10, len(dns_items))
                section_header = f"\nDNS查询信息（共{len(dns_items)}条，显示前{items_to_show}条）:\n"
                prompt += section_header
                current_size += len(section_header)
                
                for i, item in enumerate(dns_items[:items_to_show]):
                    if current_size > MAX_DATA_SIZE * 0.8:
                        prompt += f"   ... 还有{len(dns_items) - i}条DNS查询已省略 ...\n"
                        break
                    
                    content = item.get('content', '')[:150]
                    line = f"{i+1}. [{item.get('type', 'UNKNOWN')}] {item.get('src', 'N/A')} -> {item.get('dst', 'N/A')}\n   内容: {content}\n"
                    
                    if current_size + len(line) > MAX_DATA_SIZE:
                        prompt += f"   ... 还有{len(dns_items) - i}条DNS查询已省略 ...\n"
                        break
                    
                    prompt += line
                    current_size += len(line)
            
            # 显示ICMP数据
            if icmp_items and current_size < MAX_DATA_SIZE:
                items_to_show = min(5, len(icmp_items))
                section_header = f"\nICMP数据（共{len(icmp_items)}条，显示前{items_to_show}条）:\n"
                prompt += section_header
                current_size += len(section_header)
                
                for i, item in enumerate(icmp_items[:items_to_show]):
                    if current_size > MAX_DATA_SIZE * 0.8:
                        prompt += f"   ... 还有{len(icmp_items) - i}条ICMP数据已省略 ...\n"
                        break
                    
                    content = item.get('content', '')[:150]
                    line = f"{i+1}. [{item.get('type', 'UNKNOWN')}] {item.get('src', 'N/A')} -> {item.get('dst', 'N/A')}\n   内容: {content}\n"
                    
                    if current_size + len(line) > MAX_DATA_SIZE:
                        prompt += f"   ... 还有{len(icmp_items) - i}条ICMP数据已省略 ...\n"
                        break
                    
                    prompt += line
                    current_size += len(line)
            
            # 添加分析指令
            analysis_instruction = f"\n用户提示：'{self.user_prompt}'\n\n" if self.user_prompt else "\n请快速扫描流量数据，寻找可疑的flag。\n\n"
            
            prompt += analysis_instruction
            
            # 记录实际的上下文大小
            print(f"[上下文大小] 当前提示词长度: {len(prompt)} 字符 (限制: {MAX_CONTEXT_SIZE})")
            if len(prompt) > MAX_CONTEXT_SIZE:
                print(f"[警告] 提示词超过限制！超出: {len(prompt) - MAX_CONTEXT_SIZE} 字符")

        else:
            # 保留原有的通用提示词
            prompt = "你是一名CTF专家。以下是从流量/日志中提取的可疑片段，请判断哪些是真实flag，并解释理由。\n\n"
            prompt += "候选片段：\n"
            
            for i, item in enumerate(self.prompt_data):
                prompt += f"{i+1}. [{item.get('type', 'UNKNOWN')}] {item.get('content', '')}\n"
            
            prompt += f"\n用户提示：'{self.user_prompt}'\n\n" if self.user_prompt else "\n"
            prompt += "请分析这些候选片段，找出真实的flag。\n"
        
        # 打印构造的提示词
        print("=" * 50)
        print("构造的提示词:")
        print(prompt)
        print("=" * 50)
        
        return prompt
    
    def call_iflow_model(self, prompt):
        """调用心流API模型（支持对话历史）"""
        if not self.api_key:
            raise Exception("心流API需要提供API密钥")
        
        # 如果没有指定模型，使用默认模型
        model = self.model if self.model else "TBStars2-200B-A13B"
        
        url = "https://apis.iflow.cn/v1/chat/completions"
        
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.api_key}"
        }
        
        # 构建对话消息列表：历史对话 + 当前提示
        messages = []
        
        # 添加对话历史
        if self.conversation_history:
            messages.extend(self.conversation_history)
        
        # 添加当前用户提示
        messages.append({"role": "user", "content": prompt})
        
        data = {
            "model": model,
            "messages": messages,
            "temperature": 0.7
        }
        
        # 打印请求信息
        print("=" * 50)
        print(f"发送到心流API的请求 (对话轮数: {len(messages)}):")
        print(f"URL: {url}")
        print(f"最后一条消息长度: {len(prompt)} 字符")
        print("=" * 50)
        
        response = requests.post(url, headers=headers, json=data, timeout=120)
        
        # 打印响应信息
        print("=" * 50)
        print("心流API的响应:")
        print(f"Status Code: {response.status_code}")
        print(f"Headers: {json.dumps(dict(response.headers), indent=2, ensure_ascii=False)}")
        print(f"Response Body: {response.text}")
        print("=" * 50)
        
        # 保存完整的响应过程用于调试和展示
        full_response_process = {
            "request": {
                "url": url,
                "headers": headers,
                "data": data
            },
            "response": {
                "status_code": response.status_code,
                "headers": dict(response.headers),
                "text": response.text
            }
        }
        
        if response.status_code == 200:
            response_data = response.json()
            try:
                result_text = response_data["choices"][0]["message"]["content"]
                
                # 打印AI返回的结果
                print("=" * 50)
                print("AI返回的结果:")
                print(result_text)
                print("=" * 50)
                
                # 将AI响应添加到对话历史
                self.conversation_history.append({
                    "role": "assistant",
                    "content": result_text
                })
                
                # 简化的解析方式：直接提取flag和reason
                flags_with_reasons = self.parse_flags_from_response(result_text)
                
                return {
                    "flags": flags_with_reasons,
                    "raw_response": result_text,
                    "status": "success" if flags_with_reasons else "no_flags_found",
                    "conversation_history": self.conversation_history
                }
            except KeyError:
                raise Exception("心流API返回格式不正确")
        elif response.status_code == 400:
            # 检查是否是token超限错误
            error_response = response.json()
            if "PromptExceedMaxTokens" in str(error_response):
                # 尝试减少请求的数据量
                print("检测到token超限错误，尝试减少数据量...")
                # 重新构造一个更精简的提示词
                reduced_prompt = self.construct_prompt_reduced()
                
                data_reduced = {
                    "model": model,
                    "messages": [
                        {"role": "user", "content": reduced_prompt}
                    ],
                    "temperature": 0.7
                }
                
                response_reduced = requests.post(url, headers=headers, json=data_reduced, timeout=120)
                
                if response_reduced.status_code == 200:
                    response_data_reduced = response_reduced.json()
                    result_text_reduced = response_data_reduced["choices"][0]["message"]["content"]
                    
                    # 使用简化的解析方式
                    flags_with_reasons = self.parse_flags_from_response(result_text_reduced)
                    
                    return {
                        "flags": flags_with_reasons,
                        "raw_response": result_text_reduced,
                        "status": "success_reduced" if flags_with_reasons else "no_flags_found"
                    }
                else:
                    raise Exception(f"减少数据量后的心流API调用失败，状态码: {response_reduced.status_code}")
            else:
                raise Exception(f"心流API调用失败，状态码: {response.status_code}, 错误信息: {error_response}")
        else:
            raise Exception(f"心流API调用失败，状态码: {response.status_code}")

    def construct_prompt_reduced(self):
        """构造精简版的提示词，用于处理token超限的情况（严格限制128K）"""
        # 更严格的限制（128K）
        MAX_CONTEXT_SIZE = 128000
        SYSTEM_PROMPT_SIZE = 800
        RESERVE_SIZE = 1500
        MAX_DATA_SIZE = MAX_CONTEXT_SIZE - SYSTEM_PROMPT_SIZE - RESERVE_SIZE
        
        # 检查是否为网络流量分析数据
        is_network_data = any(item.get('type') in ['FLAG_SEARCH', 'HTTP', 'HTTP_CONTENT', 'DNS_FLAG', 'ICMP_DATA', 'ICMP_RAW', 'ALL_DATA'] 
                             for item in self.prompt_data)
        
        if is_network_data:
            prompt = "你是CTF专家。快速分析以下流量数据，寻找flag。\n\n"
            prompt += "数据：\n"
            
            # 分别处理不同类型的数据，但只取最关键的部分
            all_data_items = [item for item in self.prompt_data if item.get('type') == 'ALL_DATA']
            flag_items = [item for item in self.prompt_data if item.get('type') == 'FLAG_SEARCH']
            http_content_items = [item for item in self.prompt_data if item.get('type') == 'HTTP_CONTENT']
            
            current_size = len(prompt)
            
            # 优先显示标记的Flag内容
            if flag_items and current_size < MAX_DATA_SIZE:
                items_to_show = min(5, len(flag_items))
                section_header = f"\nFlag内容（共{len(flag_items)}条，前{items_to_show}条）:\n"
                prompt += section_header
                current_size += len(section_header)
                
                for i, item in enumerate(flag_items[:items_to_show]):
                    if current_size > MAX_DATA_SIZE * 0.85:
                        break
                    
                    content = item.get('content', '')[:120]  # 严格限制长度
                    line = f"{i+1}. {content}\n"
                    
                    if current_size + len(line) > MAX_DATA_SIZE:
                        break
                    
                    prompt += line
                    current_size += len(line)
            
            # 次优先：HTTP内容
            if http_content_items and current_size < MAX_DATA_SIZE * 0.8:
                items_to_show = min(3, len(http_content_items))
                section_header = f"\nHTTP内容（共{len(http_content_items)}条，前{items_to_show}条）:\n"
                prompt += section_header
                current_size += len(section_header)
                
                for i, item in enumerate(http_content_items[:items_to_show]):
                    if current_size > MAX_DATA_SIZE * 0.85:
                        break
                    
                    content = item.get('content', '')[:120]
                    line = f"{i+1}. {content}\n"
                    
                    if current_size + len(line) > MAX_DATA_SIZE:
                        break
                    
                    prompt += line
                    current_size += len(line)
            
            # 其他数据包
            if all_data_items and current_size < MAX_DATA_SIZE * 0.7:
                items_to_show = min(2, len(all_data_items))
                section_header = f"\n其他数据（共{len(all_data_items)}条，前{items_to_show}条）:\n"
                prompt += section_header
                current_size += len(section_header)
                
                for i, item in enumerate(all_data_items[:items_to_show]):
                    if current_size > MAX_DATA_SIZE * 0.85:
                        break
                    
                    content = item.get('content', '')[:100]
                    line = f"{i+1}. {content}\n"
                    
                    if current_size + len(line) > MAX_DATA_SIZE:
                        break
                    
                    prompt += line
                    current_size += len(line)
            
            # 添加分析指令
            analysis_instruction = f"\n用户提示：{self.user_prompt}\n" if self.user_prompt else "\n"
            
            prompt += analysis_instruction
            
            print(f"[精简提示] 长度: {len(prompt)} 字符 (限制: {MAX_CONTEXT_SIZE})")
            return prompt

        
        else:
            # 保留原有的通用提示词（非网络数据类型）
            prompt = "你是一名CTF专家。以下是从流量/日志中提取的可疑片段，请判断哪些是真实flag，并解释理由。\n\n"
            prompt += "候选片段：\n"
            
            # 只取前20个片段
            for i, item in enumerate(self.prompt_data[:20]):
                content = item.get('content', '')
                if len(content) > 200:
                    content = content[:200] + "...(内容已截断)"
                prompt += f"{i+1}. [{item.get('type', 'UNKNOWN')}] {content}\n"
            
            prompt += f"\n用户提示：'{self.user_prompt}'\n" if self.user_prompt else "\n"
            
            print(f"[通用提示] 长度: {len(prompt)} 字符")
        
        return prompt
class AICoordinator(QObject):
    """AI协调器主类"""
    analysis_finished = Signal(dict)  # 发送AI分析结果
    analysis_error = Signal(str)      # 发送错误信息
    
    def __init__(self):
        super().__init__()
        self.thread = None
        self.worker = None
    
    def analyze(self, prompt_data, user_prompt="", api_key="", model="", conversation_history=None):
        """开始AI分析
        Args:
            prompt_data: 提示数据
            user_prompt: 用户提示
            api_key: API密钥 (心流API)
            model: 模型名称
            conversation_history: 对话历史列表
        """
        # 创建线程和工作对象
        self.thread = QThread()
        self.worker = AICoordinatorWorker(prompt_data, user_prompt, api_key, model, conversation_history)
        
        # 移动工作对象到线程
        self.worker.moveToThread(self.thread)
        
        # 连接信号和槽
        self.thread.started.connect(self.worker.run)
        self.worker.finished.connect(self.on_analysis_finished)
        self.worker.error.connect(self.on_analysis_error)
        self.worker.finished.connect(self.thread.quit)
        self.worker.error.connect(self.thread.quit)
        self.thread.finished.connect(self.thread.deleteLater)
        
        # 启动线程
        self.thread.start()
    
    def on_analysis_finished(self, result):
        """分析完成回调"""
        self.analysis_finished.emit(result)
        if self.worker:
            self.worker.deleteLater()
    
    def on_analysis_error(self, error_msg):
        """分析出错回调"""
        self.analysis_error.emit(error_msg)
        if self.worker:
            self.worker.deleteLater()

    def is_ollama_available(self):
        """检查Ollama是否可用"""
        try:
            response = requests.get("http://localhost:11434/api/tags", timeout=5)
            return response.status_code == 200
        except:
            return False

    def check_qwen_model(self):
        """检查qwen3:4b模型是否已下载"""
        try:
            response = requests.get("http://localhost:11434/api/tags", timeout=5)
            if response.status_code == 200:
                models = response.json()
                for model in models.get("models", []):
                    if "qwen3:4b" in model.get("name", ""):
                        return True
            return False
        except:
            return False