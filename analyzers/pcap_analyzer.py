#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
网络流量分析模块
用于分析pcap文件，提取可能包含flag的信息
"""

import re
from PySide6.QtCore import QObject, Signal, QThread
import json
import pyshark
import asyncio
import platform
import os


class PcapAnalyzerWorker(QObject):
    """PCAP分析工作线程"""
    finished = Signal(list)  # 发送分析结果
    error = Signal(str)      # 发送错误信息
    
    def __init__(self, pcap_file):
        super().__init__()
        self.pcap_file = pcap_file
        self.analysis_process = []  # 存储分析过程
        
    def run(self):
        """执行分析任务"""
        try:
            # 在Windows上创建新的事件循环，以处理pyshark的异步操作
            if platform.system() == 'Windows':
                asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
            
            # 为当前线程创建新的事件循环
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            
            print("=" * 50)
            print(f"开始分析PCAP文件: {self.pcap_file}")
            print("=" * 50)
            
            # 检查文件大小，决定是否使用分块模式
            file_size = os.path.getsize(self.pcap_file)
            print(f"文件大小: {file_size / 1024 / 1024:.2f} MB")
            
            # 如果文件超过5MB，使用分块分析
            if file_size > 5 * 1024 * 1024:
                print("检测到大文件，使用分块分析模式")
                results = self.analyze_pcap_chunked()
            else:
                print("使用标准分析模式")
                results = self.analyze_pcap()
            
            # 将分析过程添加到结果中
            results.append({"type": "ANALYSIS_PROCESS", "content": json.dumps(self.analysis_process, ensure_ascii=False)})
            
            print("=" * 50)
            print(f"PCAP分析完成，共发现{len(results)-1}条记录")  # -1是因为包含了ANALYSIS_PROCESS
            print("=" * 50)
            
            self.finished.emit(results)
        except Exception as e:
            print("=" * 50)
            print(f"PCAP分析出错: {str(e)}")
            import traceback
            traceback.print_exc()
            print("=" * 50)
            self.error.emit(str(e))
        finally:
            # 关闭事件循环
            try:
                loop = asyncio.get_event_loop()
                if loop and not loop.is_closed():
                    loop.close()
            except:
                pass
    
    def analyze_pcap(self):
        """
        分析PCAP文件
        返回包含发现的flag相关数据的列表
        """
        results = []
        cap = None
        
        # 记录分析步骤
        self.analysis_process.append({"step": "开始分析", "details": f"开始分析PCAP文件: {self.pcap_file}"})
        
        # 检查是否可以加载pcap文件
        try:
            # 在工作线程中创建pyshark.FileCapture，禁用异步以避免事件循环问题
            cap = pyshark.FileCapture(self.pcap_file, keep_packets=False, use_json=True)
            # 首先统计包的数量
            packet_count = 0
            try:
                packet_count = sum(1 for _ in cap)
            except Exception as count_e:
                print(f"统计数据包数量时出错（继续处理）: {str(count_e)}")
                packet_count = "未知"
            
            # 重新创建cap以进行分析
            cap = pyshark.FileCapture(self.pcap_file, keep_packets=False, use_json=True)
            self.analysis_process.append({"step": "环境检查", "details": f"pyshark库可用，成功加载PCAP文件，共{packet_count}个数据包"})
        except Exception as e:
            self.analysis_process.append({"step": "环境检查", "details": f"pyshark库不可用或无法加载PCAP文件: {str(e)}"})
            raise Exception(f"无法加载PCAP文件: {str(e)}")
        
        # 尝试使用pyshark进行分析
        # 优先级顺序：正则匹配FLAG > TCP流详情 > HTTP流 > 其他数据
        
        # 1. 查找包含flag的内容（正则匹配 - 优先级最高）
        flag_results = []
        try:
            flag_results = self.search_flag_in_pcap(cap)
            results.extend(flag_results)
        except Exception as e:
            print(f"搜索FLAG出错（继续处理）: {str(e)}")
            self.analysis_process.append({"step": "FLAG搜索", "details": f"FLAG搜索出错: {str(e)}"})
        
        # 2. 提取TCP流详细信息（提供详细的协议字段和完整内容）
        try:
            tcp_results = self.extract_tcp_streams_detailed(cap)
            results.extend(tcp_results)
        except Exception as e:
            print(f"提取TCP流出错（继续处理）: {str(e)}")
            self.analysis_process.append({"step": "TCP流提取", "details": f"TCP流提取出错: {str(e)}"})
        
        # 3. 获取HTTP流信息
        try:
            http_results = self.extract_http_streams(cap)
            results.extend(http_results)
        except Exception as e:
            print(f"提取HTTP流出错（继续处理）: {str(e)}")
            self.analysis_process.append({"step": "HTTP流提取", "details": f"HTTP流提取出错: {str(e)}"})
        
        # 4. 获取HTTP完整内容
        try:
            http_content_results = self.extract_http_content(cap)
            results.extend(http_content_results)
        except Exception as e:
            print(f"提取HTTP内容出错（继续处理）: {str(e)}")
            self.analysis_process.append({"step": "HTTP内容提取", "details": f"HTTP内容提取出错: {str(e)}"})
        
        # 5. 获取DNS查询信息
        try:
            dns_results = self.extract_dns_queries(cap)
            results.extend(dns_results)
        except Exception as e:
            print(f"提取DNS查询出错（继续处理）: {str(e)}")
            self.analysis_process.append({"step": "DNS查询提取", "details": f"DNS查询提取出错: {str(e)}"})
        
        # 6. 获取ICMP数据
        try:
            icmp_results = self.extract_icmp_data(cap)
            results.extend(icmp_results)
        except Exception as e:
            print(f"提取ICMP数据出错（继续处理）: {str(e)}")
            self.analysis_process.append({"step": "ICMP数据提取", "details": f"ICMP数据提取出错: {str(e)}"})
        
        # 7. 导出所有数据供AI参考分析（优先级最低，但包含所有数据）
        try:
            all_data_results = self.export_all_data(cap)
            results.extend(all_data_results)
        except Exception as e:
            print(f"导出所有数据出错（继续处理）: {str(e)}")
            self.analysis_process.append({"step": "导出数据", "details": f"导出数据出错: {str(e)}"})
        
        # 关闭capture对象
        try:
            if cap:
                cap.close()
        except Exception as e:
            print(f"关闭capture对象时出错: {str(e)}")
        
        self.analysis_process.append({"step": "分析完成", "details": f"分析完成，共发现{len(results)}条记录"})
        return results
    
    def analyze_pcap_chunked(self, chunk_size=50):
        """
        分块分析PCAP文件
        将大文件分成多个块，逐块分析以避免内存溢出和token超限
        """
        results = []
        cap = None
        
        self.analysis_process.append({"step": "分块分析开始", "details": f"开始分块分析PCAP文件，每块{chunk_size}个数据包"})
        
        try:
            # 首先加载所有数据包
            cap = pyshark.FileCapture(self.pcap_file, keep_packets=False, use_json=True)
            
            packets = []
            try:
                print("正在加载所有数据包...")
                for packet in cap:
                    packets.append(packet)
                    if len(packets) % 100 == 0:
                        print(f"已加载 {len(packets)} 个数据包")
            except Exception as e:
                print(f"加载数据包时出错: {str(e)}")
                self.analysis_process.append({"step": "数据包加载", "details": f"加载了{len(packets)}个数据包"})
            
            if cap:
                cap.close()
            
            if not packets:
                self.analysis_process.append({"step": "分块分析", "details": "没有找到任何数据包"})
                return results
            
            total_packets = len(packets)
            total_chunks = (total_packets + chunk_size - 1) // chunk_size
            
            self.analysis_process.append({"step": "分块分析", "details": f"总共{total_packets}个数据包，分为{total_chunks}块"})
            print(f"[分块分析] 总共 {total_packets} 个数据包，分为 {total_chunks} 块")
            
            # 逐块分析
            for chunk_id in range(total_chunks):
                start_idx = chunk_id * chunk_size
                end_idx = min((chunk_id + 1) * chunk_size, total_packets)
                chunk_packets = packets[start_idx:end_idx]
                
                print(f"[分块分析] 处理块 {chunk_id + 1}/{total_chunks} (包 #{start_idx + 1}-#{end_idx})")
                
                # 分析这一块
                chunk_results = self._analyze_chunk(chunk_packets, chunk_id + 1, total_chunks)
                results.extend(chunk_results)
                
                # 添加块完成的标记
                results.append({
                    "type": "CHUNK_COMPLETE",
                    "chunk_id": chunk_id + 1,
                    "total_chunks": total_chunks,
                    "packet_range": f"#{start_idx + 1}-#{end_idx}",
                    "content": f"块 {chunk_id + 1} 分析完成，处理 {end_idx - start_idx} 个数据包"
                })
            
            self.analysis_process.append({"step": "分块分析完成", "details": f"完成分块分析，共 {total_chunks} 块"})
            
        except Exception as e:
            self.analysis_process.append({"step": "分块分析错误", "details": f"分块分析出错: {str(e)}"})
            print(f"分块分析出错: {str(e)}")
            raise
        finally:
            try:
                if cap:
                    cap.close()
            except:
                pass
        
        return results
    
    def _analyze_chunk(self, chunk_packets, chunk_id, total_chunks):
        """
        分析单个数据块
        提取该块中所有可疑内容供AI分析
        """
        results = []
        
        # 添加块头
        results.append({
            "type": "CHUNK_START",
            "chunk_id": chunk_id,
            "total_chunks": total_chunks,
            "packet_count": len(chunk_packets),
            "content": f"\n{'='*60}\n【数据块 {chunk_id}/{total_chunks}】\n包含 {len(chunk_packets)} 个数据包\n{'='*60}\n"
        })
        
        # 对该块的数据包进行标准分析
        try:
            # 1. 查找flag（正则匹配）
            for packet in chunk_packets:
                try:
                    src_ip = getattr(packet.ip, 'src', 'N/A') if hasattr(packet, 'ip') else 'N/A'
                    dst_ip = getattr(packet.ip, 'dst', 'N/A') if hasattr(packet, 'ip') else 'N/A'
                    
                    # 收集所有可能包含数据的内容
                    packet_contents = []
                    
                    if hasattr(packet, 'tcp') and hasattr(packet.tcp, 'payload'):
                        packet_contents.append(str(getattr(packet.tcp, 'payload', '')))
                    elif hasattr(packet, 'udp') and hasattr(packet.udp, 'payload'):
                        packet_contents.append(str(getattr(packet.udp, 'payload', '')))
                    
                    if hasattr(packet, 'http'):
                        if hasattr(packet.http, 'file_data'):
                            packet_contents.append(str(getattr(packet.http, 'file_data', '')))
                        if hasattr(packet.http, 'request_uri'):
                            packet_contents.append(str(getattr(packet.http, 'request_uri', '')))
                    
                    if hasattr(packet, 'data'):
                        packet_contents.append(str(getattr(packet.data, 'data', '')))
                    
                    # 正则匹配
                    flag_patterns = [
                        r'flag\{[^}]+\}',
                        r'FLAG\{[^}]+\}',
                        r'ctf\{[^}]+\}',
                        r'CTF\{[^}]+\}',
                        r'[A-Za-z0-9_]{20,}',
                        r'[a-f0-9]{32}',
                        r'[a-f0-9]{40}',
                        r'[a-f0-9]{64}',
                    ]
                    
                    for content in packet_contents:
                        for pattern in flag_patterns:
                            matches = re.findall(pattern, content, re.IGNORECASE)
                            for match in matches:
                                decoded_match = match
                                try:
                                    if all(c in '0123456789abcdefABCDEF' for c in match.replace(':', '')):
                                        decoded_match = bytes.fromhex(match.replace(':', '')).decode('utf-8', errors='ignore')
                                except:
                                    pass
                                
                                results.append({
                                    "type": "FLAG_REGEX_MATCH",
                                    "src": src_ip,
                                    "dst": dst_ip,
                                    "match": decoded_match,
                                    "content": f"Frame {packet.frame_info.number}: 正则匹配到可能的flag: {decoded_match}"
                                })
                except:
                    continue
            
            # 2. 提取十六进制dump（完整的包数据）
            for i, packet in enumerate(chunk_packets):
                try:
                    src_ip = getattr(packet.ip, 'src', 'N/A') if hasattr(packet, 'ip') else 'N/A'
                    dst_ip = getattr(packet.ip, 'dst', 'N/A') if hasattr(packet, 'ip') else 'N/A'
                    src_port = 'N/A'
                    dst_port = 'N/A'
                    
                    if hasattr(packet, 'tcp'):
                        src_port = getattr(packet.tcp, 'srcport', 'N/A')
                        dst_port = getattr(packet.tcp, 'dstport', 'N/A')
                    elif hasattr(packet, 'udp'):
                        src_port = getattr(packet.udp, 'srcport', 'N/A')
                        dst_port = getattr(packet.udp, 'dstport', 'N/A')
                    
                    # 获取十六进制数据（限制大小）
                    hex_data = ""
                    try:
                        raw_packet = packet.get_raw_packet().hex()
                        hex_data = ' '.join([raw_packet[i:i+2] for i in range(0, min(len(raw_packet), 400), 2)])
                    except:
                        pass
                    
                    if hex_data:
                        results.append({
                            "type": "HEX_DUMP",
                            "src": f"{src_ip}:{src_port}",
                            "dst": f"{dst_ip}:{dst_port}",
                            "content": f"Frame {packet.frame_info.number} ({packet.frame_info.len} bytes): {hex_data}{'...' if len(raw_packet) > 400 else ''}"
                        })
                except:
                    continue
            
            # 3. 提取全部数据
            for packet in chunk_packets:
                try:
                    src_ip = getattr(packet.ip, 'src', 'N/A') if hasattr(packet, 'ip') else 'N/A'
                    dst_ip = getattr(packet.ip, 'dst', 'N/A') if hasattr(packet, 'ip') else 'N/A'
                    
                    data_content = 'N/A'
                    if hasattr(packet, 'data'):
                        data_content = getattr(packet.data, 'data', 'N/A')
                    elif hasattr(packet, 'tcp') and hasattr(packet.tcp, 'payload'):
                        data_content = getattr(packet.tcp, 'payload', 'N/A')
                    elif hasattr(packet, 'http') and hasattr(packet.http, 'file_data'):
                        data_content = getattr(packet.http, 'file_data', 'N/A')
                    
                    if data_content != 'N/A':
                        decoded_data = data_content
                        try:
                            if isinstance(data_content, str) and all(c in '0123456789abcdefABCDEF' for c in data_content.replace(':', '')):
                                decoded_data = bytes.fromhex(data_content.replace(':', '')).decode('utf-8', errors='ignore')
                        except:
                            pass
                        
                        results.append({
                            "type": "ALL_DATA",
                            "src": src_ip,
                            "dst": dst_ip,
                            "content": f"Frame {packet.frame_info.number}: {decoded_data[:200]}{'...' if len(decoded_data) > 200 else ''}"
                        })
                except:
                    continue
        
        except Exception as e:
            print(f"分析块 {chunk_id} 时出错: {str(e)}")
        
        # 添加块尾
        results.append({
            "type": "CHUNK_SUMMARY",
            "chunk_id": chunk_id,
            "content": f"【块 {chunk_id} 分析完成】 提取 {len([r for r in results if r['type'] in ['FLAG_REGEX_MATCH', 'HEX_DUMP', 'ALL_DATA']])} 条记录\n"
        })
        
        return results
    
    def export_all_data(self, cap):
        """导出所有数据包信息供AI参考分析"""
        results = []
        try:
            for packet_num, packet in enumerate(cap, 1):
                try:
                    # 获取基本的IP信息
                    src_ip = getattr(packet.ip, 'src', 'N/A') if hasattr(packet, 'ip') else 'N/A'
                    dst_ip = getattr(packet.ip, 'dst', 'N/A') if hasattr(packet, 'ip') else 'N/A'
                    
                    # 获取端口信息
                    src_port = 'N/A'
                    dst_port = 'N/A'
                    if hasattr(packet, 'tcp'):
                        src_port = getattr(packet.tcp, 'srcport', 'N/A')
                        dst_port = getattr(packet.tcp, 'dstport', 'N/A')
                    elif hasattr(packet, 'udp'):
                        src_port = getattr(packet.udp, 'srcport', 'N/A')
                        dst_port = getattr(packet.udp, 'dstport', 'N/A')
                    
                    # 获取数据内容
                    data_content = 'N/A'
                    if hasattr(packet, 'data'):
                        data_content = getattr(packet.data, 'data', 'N/A')
                    elif 'TCP' in packet and hasattr(packet.tcp, 'payload'):
                        data_content = packet.tcp.payload
                    elif 'UDP' in packet and hasattr(packet.udp, 'payload'):
                        data_content = packet.udp.payload
                    elif 'HTTP' in packet and hasattr(packet.http, 'file_data'):
                        data_content = packet.http.file_data
                    elif 'HTTP' in packet and hasattr(packet.http, 'request_uri'):
                        data_content = f"{getattr(packet.http, 'request_method', 'GET')} {getattr(packet.http, 'request_uri', '')}"
                    elif 'HTTP' in packet and hasattr(packet.http, 'response_code'):
                        data_content = f"Response Code: {getattr(packet.http, 'response_code', '')}"
                    
                    # 尝试解码数据
                    decoded_data = data_content
                    if data_content != 'N/A':
                        try:
                            # 尝试将十六进制字符串转换为可读文本
                            if isinstance(data_content, str) and all(c in '0123456789abcdefABCDEF' for c in data_content.replace(':', '')):
                                decoded_data = bytes.fromhex(data_content.replace(':', '')).decode('utf-8', errors='ignore')
                            else:
                                decoded_data = data_content
                        except:
                            decoded_data = data_content
                    
                    result_entry = {
                        "type": "ALL_DATA",
                        "src": f"{src_ip}:{src_port}" if src_port != 'N/A' else src_ip,
                        "dst": f"{dst_ip}:{dst_port}" if dst_port != 'N/A' else dst_ip,
                        "content": f"Frame {packet_num} Len:{len(str(packet))} Data:{decoded_data[:100]}{'...' if len(decoded_data) > 100 else ''}"
                    }
                    results.append(result_entry)
                    
                    print(f"导出数据: {result_entry['content']}")
                    
                except AttributeError:
                    # 某些数据包可能没有IP层
                    continue
                except Exception as e:
                    print(f"处理数据包 {packet_num} 时出错: {str(e)}")
                    continue
                        
        except Exception as e:
            self.analysis_process.append({"step": "pyshark处理错误", "details": f"pyshark处理失败: {str(e)}"})
            print(f"pyshark处理失败: {str(e)}")
            # 如果pyshark处理失败，则跳过这一步
            pass
            
        self.analysis_process.append({"step": "全部数据导出完成", "details": f"全部数据导出完成，导出{len(results)}条记录"})
        return results
    
    def search_flag_in_pcap(self, cap):
        """在pcap中搜索flag相关字符串，使用正则表达式进行精确匹配"""
        results = []
        # 常见的flag格式正则表达式
        flag_patterns = [
            r'flag\{[^}]+\}',  # flag{...}
            r'FLAG\{[^}]+\}',
            r'ctf\{[^}]+\}',
            r'CTF\{[^}]+\}',
            r'[A-Za-z0-9_]{20,}',  # 长字符串可能是加密的flag
            r'[a-f0-9]{32}',  # MD5可能的hash
            r'[a-f0-9]{40}',  # SHA1可能的hash
            r'[a-f0-9]{64}',  # SHA256可能的hash
        ]
        
        try:
            for packet_num, packet in enumerate(cap, 1):
                try:
                    # 获取完整的数据包信息
                    src_ip = getattr(packet.ip, 'src', 'N/A') if hasattr(packet, 'ip') else 'N/A'
                    dst_ip = getattr(packet.ip, 'dst', 'N/A') if hasattr(packet, 'ip') else 'N/A'
                    
                    # 收集所有可能包含数据的内容
                    packet_contents = []
                    
                    # 获取协议数据
                    if hasattr(packet, 'tcp') and hasattr(packet.tcp, 'payload'):
                        packet_contents.append(str(getattr(packet.tcp, 'payload', '')))
                    elif hasattr(packet, 'udp') and hasattr(packet.udp, 'payload'):
                        packet_contents.append(str(getattr(packet.udp, 'payload', '')))
                    
                    if hasattr(packet, 'http'):
                        if hasattr(packet.http, 'file_data'):
                            packet_contents.append(str(getattr(packet.http, 'file_data', '')))
                        if hasattr(packet.http, 'request_uri'):
                            packet_contents.append(str(getattr(packet.http, 'request_uri', '')))
                        if hasattr(packet.http, 'request_body'):
                            packet_contents.append(str(getattr(packet.http, 'request_body', '')))
                    
                    if hasattr(packet, 'data'):
                        packet_contents.append(str(getattr(packet.data, 'data', '')))
                    
                    # 对所有内容进行正则匹配
                    for content in packet_contents:
                        for pattern in flag_patterns:
                            matches = re.findall(pattern, content, re.IGNORECASE)
                            for match in matches:
                                # 解码十六进制数据
                                decoded_match = match
                                try:
                                    if all(c in '0123456789abcdefABCDEF' for c in match.replace(':', '')):
                                        decoded_match = bytes.fromhex(match.replace(':', '')).decode('utf-8', errors='ignore')
                                except:
                                    pass
                                
                                result_entry = {
                                    "type": "FLAG_REGEX_MATCH",
                                    "src": src_ip,
                                    "dst": dst_ip,
                                    "match": decoded_match,
                                    "content": f"Frame {packet_num}: 正则匹配到可能的flag: {decoded_match}"
                                }
                                results.append(result_entry)
                                print(f"[FLAG正则匹配] {decoded_match}")
                    
                except AttributeError:
                    continue
                except Exception as e:
                    print(f"处理数据包 {packet_num} 时出错: {str(e)}")
                    continue
                        
        except Exception as e:
            self.analysis_process.append({"step": "pyshark处理错误", "details": f"pyshark处理FLAG搜索失败: {str(e)}"})
            print(f"pyshark处理FLAG搜索失败: {str(e)}")
            # 如果pyshark处理失败，则跳过这一步
            pass
            
        self.analysis_process.append({"step": "FLAG搜索完成", "details": f"FLAG搜索完成，发现{len(results)}条记录"})
        return results
    
    def extract_tcp_streams_detailed(self, cap):
        """提取TCP流的详细信息，包括完整内容和协议字段"""
        results = []
        tcp_streams = {}  # 用于组合TCP流
        
        try:
            for packet_num, packet in enumerate(cap, 1):
                try:
                    if hasattr(packet, 'tcp'):
                        # 获取TCP基本信息
                        src_ip = getattr(packet.ip, 'src', 'N/A') if hasattr(packet, 'ip') else 'N/A'
                        dst_ip = getattr(packet.ip, 'dst', 'N/A') if hasattr(packet, 'ip') else 'N/A'
                        src_port = getattr(packet.tcp, 'srcport', 'N/A')
                        dst_port = getattr(packet.tcp, 'dstport', 'N/A')
                        seq = getattr(packet.tcp, 'seq', 'N/A')
                        ack = getattr(packet.tcp, 'ack', 'N/A')
                        flags = getattr(packet.tcp, 'flags', 'N/A')
                        
                        # 创建流标识符
                        stream_key = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}"
                        
                        # 提取payload内容
                        payload = 'N/A'
                        if hasattr(packet.tcp, 'payload'):
                            payload = getattr(packet.tcp, 'payload', '')
                        
                        # 尝试提取应用层数据
                        app_data = ''
                        if hasattr(packet, 'http'):
                            # HTTP数据
                            if hasattr(packet.http, 'file_data'):
                                app_data = getattr(packet.http, 'file_data', '')
                            elif hasattr(packet.http, 'request_line'):
                                app_data = f"HTTP {getattr(packet.http, 'request_method', '')} {getattr(packet.http, 'request_uri', '')}"
                        
                        # 构建详细内容
                        tcp_detail = {
                            "packet": packet_num,
                            "seq": seq,
                            "ack": ack,
                            "flags": flags,
                            "payload": payload[:200] if payload and payload != 'N/A' else 'N/A',  # 截断超长内容
                            "app_data": app_data
                        }
                        
                        # 累积TCP流
                        if stream_key not in tcp_streams:
                            tcp_streams[stream_key] = {
                                "src": f"{src_ip}:{src_port}",
                                "dst": f"{dst_ip}:{dst_port}",
                                "packets": [],
                                "all_payload": "",
                                "all_app_data": ""
                            }
                        
                        tcp_streams[stream_key]["packets"].append(tcp_detail)
                        if payload and payload != 'N/A':
                            tcp_streams[stream_key]["all_payload"] += str(payload)
                        if app_data:
                            tcp_streams[stream_key]["all_app_data"] += str(app_data) + "\n"
                
                except AttributeError:
                    continue
                except Exception as e:
                    print(f"处理TCP数据包 {packet_num} 时出错: {str(e)}")
                    continue
            
            # 输出TCP流信息
            for stream_key, stream_data in tcp_streams.items():
                # 生成详细的流摘要
                packet_count = len(stream_data["packets"])
                
                # 尝试解析payload
                decoded_payload = stream_data["all_payload"]
                try:
                    # 尝试从十六进制解码
                    if decoded_payload and all(c in '0123456789abcdefABCDEF:' for c in str(decoded_payload)):
                        decoded_payload = bytes.fromhex(decoded_payload.replace(':', '')).decode('utf-8', errors='ignore')
                except:
                    pass
                
                # 构建内容信息
                content_info = f"TCP流: {stream_data['src']} -> {stream_data['dst']}\n"
                content_info += f"数据包数: {packet_count}\n"
                content_info += f"完整Payload: {decoded_payload[:500]}\n" if decoded_payload else ""
                content_info += f"应用层数据: {stream_data['all_app_data'][:500]}" if stream_data['all_app_data'] else ""
                
                # 详细的协议字段
                protocol_details = []
                for pkt in stream_data["packets"]:
                    if pkt['flags'] != 'N/A':
                        protocol_details.append(f"Pkt{pkt['packet']}: seq={pkt['seq']}, ack={pkt['ack']}, flags={pkt['flags']}")
                
                result_entry = {
                    "type": "TCP_STREAM",
                    "src": stream_data['src'],
                    "dst": stream_data['dst'],
                    "content": content_info,
                    "protocol_details": "\n".join(protocol_details[:10]),  # 仅保留前10个数据包的详情
                    "packet_count": packet_count,
                    "payload": decoded_payload[:1000]  # 提供更多的payload用于分析
                }
                results.append(result_entry)
                
                print(f"发现TCP流: {stream_data['src']} -> {stream_data['dst']}, {packet_count}个数据包")
        
        except Exception as e:
            self.analysis_process.append({"step": "TCP流提取错误", "details": f"TCP流提取失败: {str(e)}"})
            print(f"TCP流提取失败: {str(e)}")
        
        self.analysis_process.append({"step": "TCP流提取完成", "details": f"TCP流提取完成，发现{len(results)}条流"})
        return results
    
    def extract_http_streams(self, cap):
        """提取HTTP流信息"""
        results = []
        try:
            for packet_num, packet in enumerate(cap, 1):
                try:
                    if 'HTTP' in packet:
                        src_ip = getattr(packet.ip, 'src', 'N/A') if hasattr(packet, 'ip') else 'N/A'
                        dst_ip = getattr(packet.ip, 'dst', 'N/A') if hasattr(packet, 'ip') else 'N/A'
                        
                        # 获取HTTP字段
                        method = getattr(packet.http, 'request_method', '') if hasattr(packet.http, 'request_method') else ''
                        uri = getattr(packet.http, 'request_uri', '') if hasattr(packet.http, 'request_uri') else ''
                        response_code = getattr(packet.http, 'response_code', '') if hasattr(packet.http, 'response_code') else ''
                        host = getattr(packet.http, 'host', '') if hasattr(packet.http, 'host') else ''
                        user_agent = getattr(packet.http, 'user_agent', '') if hasattr(packet.http, 'user_agent') else ''
                        content_type = getattr(packet.http, 'content_type', '') if hasattr(packet.http, 'content_type') else ''
                        
                        # 构建HTTP信息
                        http_info = f"HTTP {method} {uri}" if method else f"HTTP Response {response_code}"
                        if host:
                            http_info += f" Host:{host}"
                        if response_code and response_code != "":
                            http_info += f" Response:{response_code}"
                        if user_agent:
                            http_info += f" UA:{user_agent[:50]}{'...' if len(user_agent) > 50 else ''}"
                        if content_type:
                            http_info += f" Content-Type:{content_type}"
                        
                        result_entry = {
                            "type": "HTTP",
                            "src": src_ip,
                            "dst": dst_ip,
                            "content": http_info
                        }
                        results.append(result_entry)
                        
                        print(f"发现HTTP流: {result_entry['content']}")
                        
                except AttributeError:
                    continue
                except Exception as e:
                    print(f"处理HTTP数据包 {packet_num} 时出错: {str(e)}")
                    continue
                        
        except Exception as e:
            self.analysis_process.append({"step": "pyshark处理错误", "details": f"pyshark处理HTTP流提取失败: {str(e)}"})
            print(f"pyshark处理HTTP流提取失败: {str(e)}")
            # 如果pyshark处理失败，则跳过这一步
            pass
            
        self.analysis_process.append({"step": "HTTP流提取完成", "details": f"HTTP流提取完成，发现{len(results)}条记录"})
        return results
    
    def extract_http_content(self, cap):
        """提取HTTP内容，包括请求体和响应体"""
        results = []
        try:
            for packet_num, packet in enumerate(cap, 1):
                try:
                    if 'HTTP' in packet:
                        full_uri = getattr(packet.http, 'request_full_uri', '') if hasattr(packet.http, 'request_full_uri') else ''
                        method = getattr(packet.http, 'request_method', '') if hasattr(packet.http, 'request_method') else ''
                        query = getattr(packet.http, 'request_uri', '') if hasattr(packet.http, 'request_uri') else ''
                        req_body = getattr(packet.http, 'file_data', '') if hasattr(packet.http, 'file_data') else ''
                        resp_code = getattr(packet.http, 'response_code', '') if hasattr(packet.http, 'response_code') else ''
                        resp_phrase = getattr(packet.http, 'response_phrase', '') if hasattr(packet.http, 'response_phrase') else ''
                        resp_body = getattr(packet.http, 'file_data', '') if hasattr(packet.http, 'file_data') else ''
                        content_type = getattr(packet.http, 'content_type', '') if hasattr(packet.http, 'content_type') else ''
                        user_agent = getattr(packet.http, 'user_agent', '') if hasattr(packet.http, 'user_agent') else ''
                        referer = getattr(packet.http, 'referer', '') if hasattr(packet.http, 'referer') else ''
                        
                        # 构建HTTP内容信息
                        http_content = ""
                        if full_uri:
                            http_content += f"URI: {full_uri} | "
                        if method:
                            http_content += f"Method: {method} | "
                        if query:
                            http_content += f"Query: {query} | "
                        if user_agent:
                            http_content += f"User-Agent: {user_agent} | "
                        if referer:
                            http_content += f"Referer: {referer} | "
                        if content_type:
                            http_content += f"Content-Type: {content_type} | "
                        if req_body and req_body != resp_body:
                            http_content += f"RequestBody: {req_body} | "
                        if resp_code:
                            http_content += f"ResponseCode: {resp_code} | "
                        if resp_phrase:
                            http_content += f"ResponsePhrase: {resp_phrase} | "
                        if resp_body and req_body != resp_body:  # 避免重复
                            http_content += f"ResponseBody: {resp_body}"
                        
                        # 如果没有具体数据，至少包含基本的HTTP信息
                        if not http_content.strip():
                            http_content = f"HTTP {method} {query} Response: {resp_code}"
                        
                        result_entry = {
                            "type": "HTTP_CONTENT",
                            "src": getattr(packet.ip, 'src', 'N/A') if hasattr(packet, 'ip') else 'N/A',
                            "dst": getattr(packet.ip, 'dst', 'N/A') if hasattr(packet, 'ip') else 'N/A',
                            "content": http_content
                        }
                        results.append(result_entry)
                        
                        print(f"发现HTTP内容: {result_entry['content']}")
                        
                except AttributeError:
                    continue
                except Exception as e:
                    print(f"处理HTTP内容数据包 {packet_num} 时出错: {str(e)}")
                    continue
                        
        except Exception as e:
            self.analysis_process.append({"step": "pyshark处理错误", "details": f"pyshark处理HTTP内容提取失败: {str(e)}"})
            print(f"pyshark处理HTTP内容提取失败: {str(e)}")
            # 如果pyshark处理失败，则跳过这一步
            pass
            
        self.analysis_process.append({"step": "HTTP内容提取完成", "details": f"HTTP内容提取完成，发现{len(results)}条记录"})
        return results
    
    def extract_dns_queries(self, cap):
        """提取DNS查询信息"""
        results = []
        try:
            for packet_num, packet in enumerate(cap, 1):
                try:
                    if 'DNS' in packet and hasattr(packet, 'dns'):
                        src_ip = getattr(packet.ip, 'src', 'N/A') if hasattr(packet, 'ip') else 'N/A'
                        dst_ip = getattr(packet.ip, 'dst', 'N/A') if hasattr(packet, 'ip') else 'N/A'
                        
                        # 获取DNS字段
                        dns_query = getattr(packet.dns, 'qry_name', '') if hasattr(packet.dns, 'qry_name') else ''
                        dns_resp = getattr(packet.dns, 'resp_name', '') if hasattr(packet.dns, 'resp_name') else ''
                        dns_a = getattr(packet.dns, 'a', '') if hasattr(packet.dns, 'a') else ''
                        dns_qry_type = getattr(packet.dns, 'qry_type', '') if hasattr(packet.dns, 'qry_type') else ''
                        
                        # 构建DNS信息
                        dns_info = f"Query: {dns_query}"
                        if dns_qry_type:
                            dns_info += f" (Type: {dns_qry_type})"
                        if dns_resp:
                            dns_info += f" | Response: {dns_resp}"
                        if dns_a:
                            dns_info += f" | A-Record: {dns_a}"
                        
                        result_entry = {
                            "type": "DNS_FLAG",
                            "src": src_ip,
                            "dst": dst_ip,
                            "content": dns_info
                        }
                        results.append(result_entry)
                        
                        print(f"发现DNS: {result_entry['content']}")
                        
                except AttributeError:
                    continue
                except Exception as e:
                    print(f"处理DNS数据包 {packet_num} 时出错: {str(e)}")
                    continue
                        
        except Exception as e:
            self.analysis_process.append({"step": "pyshark处理错误", "details": f"pyshark处理DNS查询提取失败: {str(e)}"})
            print(f"pyshark处理DNS查询提取失败: {str(e)}")
            # 如果pyshark处理失败，则跳过这一步
            pass
            
        self.analysis_process.append({"step": "DNS查询提取完成", "details": f"DNS查询提取完成，发现{len(results)}条记录"})
        return results
    
    def extract_icmp_data(self, cap):
        """提取ICMP数据"""
        results = []
        try:
            for packet_num, packet in enumerate(cap, 1):
                try:
                    if 'ICMP' in packet or 'ICMPv6' in packet:
                        src_ip = getattr(packet.ip, 'src', 'N/A') if hasattr(packet, 'ip') else 'N/A'
                        dst_ip = getattr(packet.ip, 'dst', 'N/A') if hasattr(packet, 'ip') else 'N/A'
                        
                        # 获取ICMP数据
                        icmp_data = ''
                        if hasattr(packet, 'icmp'):
                            icmp_data = str(packet.icmp)
                            icmp_type = getattr(packet.icmp, 'type', '')
                            icmp_code = getattr(packet.icmp, 'code', '')
                            icmp_data_field = getattr(packet.icmp, 'data', '')
                            icmp_info = f"ICMP Type: {icmp_type}, Code: {icmp_code}"
                            if icmp_data_field:
                                icmp_info += f", Data: {icmp_data_field}"
                            icmp_data = icmp_info
                        elif hasattr(packet, 'icmpv6'):
                            icmp_data = str(packet.icmpv6)
                            icmpv6_type = getattr(packet.icmpv6, 'type', '')
                            icmpv6_code = getattr(packet.icmpv6, 'code', '')
                            icmpv6_data_field = getattr(packet.icmpv6, 'data', '')
                            icmpv6_info = f"ICMPv6 Type: {icmpv6_type}, Code: {icmpv6_code}"
                            if icmpv6_data_field:
                                icmpv6_info += f", Data: {icmpv6_data_field}"
                            icmp_data = icmpv6_info
                        
                        # 尝试解码ICMP数据
                        try:
                            decoded_data = icmp_data
                            if isinstance(icmp_data, str) and all(c in '0123456789abcdefABCDEF' for c in icmp_data.replace(':', '')):
                                decoded_data = bytes.fromhex(icmp_data.replace(':', '')).decode('utf-8', errors='ignore')
                            
                            result_entry = {
                                "type": "ICMP_DATA",
                                "src": src_ip,
                                "dst": dst_ip,
                                "content": decoded_data
                            }
                            results.append(result_entry)
                            
                            print(f"发现ICMP数据: {result_entry['content']}")
                            
                        except:
                            # 如果无法解码，仍然添加原始数据
                            result_entry = {
                                "type": "ICMP_RAW",
                                "src": src_ip,
                                "dst": dst_ip,
                                "content": icmp_data
                            }
                            results.append(result_entry)
                            
                            print(f"发现ICMP原始数据: {result_entry['content']}")
                            
                except AttributeError:
                    continue
                except Exception as e:
                    print(f"处理ICMP数据包 {packet_num} 时出错: {str(e)}")
                    continue
                        
        except Exception as e:
            self.analysis_process.append({"step": "pyshark处理错误", "details": f"pyshark处理ICMP数据提取失败: {str(e)}"})
            print(f"pyshark处理ICMP数据提取失败: {str(e)}")
            # 如果pyshark处理失败，则跳过这一步
            pass
            
        self.analysis_process.append({"step": "ICMP数据提取完成", "details": f"ICMP数据提取完成，发现{len(results)}条记录"})
        return results


class PcapAnalyzer(QObject):
    """PCAP分析器主类"""
    analysis_finished = Signal(list)  # 发送分析结果
    analysis_error = Signal(str)      # 发送错误信息
    
    def __init__(self):
        super().__init__()
        self.thread = None
        self.worker = None
    
    def analyze(self, pcap_file):
        """开始分析PCAP文件"""
        # 创建线程和工作对象
        self.thread = QThread()
        self.worker = PcapAnalyzerWorker(pcap_file)
        
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
    
    def on_analysis_finished(self, results):
        """分析完成回调"""
        self.analysis_finished.emit(results)
        if self.worker:
            self.worker.deleteLater()
    
    def on_analysis_error(self, error_msg):
        """分析出错回调"""
        self.analysis_error.emit(error_msg)
        if self.worker:
            self.worker.deleteLater()