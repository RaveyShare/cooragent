# /etc/sandbox/security_policies/__init__.py

"""
Cooragent Sandbox Security Policies
安全策略模块，提供命令过滤、文件访问控制、网络限制等安全功能
"""

import re
import os
import json
import yaml
import logging
from typing import Dict, List, Set, Optional, Union, Tuple
from pathlib import Path
from dataclasses import dataclass, field
from enum import Enum


class SecurityLevel(Enum):
    """安全级别枚举"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    STRICT = "strict"


class ActionType(Enum):
    """操作类型枚举"""
    COMMAND = "command"
    FILE_READ = "file_read"
    FILE_WRITE = "file_write"
    FILE_DELETE = "file_delete"
    NETWORK = "network"
    PROCESS = "process"
    SYSTEM = "system"


@dataclass
class SecurityRule:
    """安全规则数据类"""
    name: str
    action_type: ActionType
    pattern: str
    allow: bool = False
    description: str = ""
    severity: str = "medium"

    def matches(self, target: str) -> bool:
        """检查规则是否匹配目标"""
        try:
            return bool(re.search(self.pattern, target, re.IGNORECASE))
        except re.error:
            logging.error(f"Invalid regex pattern in rule {self.name}: {self.pattern}")
            return False


@dataclass
class SecurityPolicy:
    """安全策略配置"""
    level: SecurityLevel = SecurityLevel.MEDIUM
    rules: List[SecurityRule] = field(default_factory=list)
    allowed_commands: Set[str] = field(default_factory=set)
    blocked_commands: Set[str] = field(default_factory=set)
    allowed_paths: Set[str] = field(default_factory=set)
    blocked_paths: Set[str] = field(default_factory=set)
    allowed_domains: Set[str] = field(default_factory=set)
    blocked_domains: Set[str] = field(default_factory=set)
    max_file_size: int = 100 * 1024 * 1024  # 100MB
    max_process_count: int = 50
    enable_logging: bool = True


class SecurityPolicyManager:
    """安全策略管理器"""

    def __init__(self, config_path: str = "/etc/sandbox/security_policies"):
        self.config_path = Path(config_path)
        self.policies: Dict[str, SecurityPolicy] = {}
        self.logger = logging.getLogger(__name__)
        self._load_policies()

    def _load_policies(self):
        """加载安全策略配置"""
        try:
            # 加载默认策略
            self._load_default_policies()

            # 加载自定义策略文件
            config_files = [
                self.config_path / "command_policies.yaml",
                self.config_path / "file_policies.yaml",
                self.config_path / "network_policies.yaml",
                self.config_path / "custom_policies.yaml"
            ]

            for config_file in config_files:
                if config_file.exists():
                    self._load_policy_file(config_file)

        except Exception as e:
            self.logger.error(f"Failed to load security policies: {e}")
            # 使用默认的严格策略作为后备
            self._load_fallback_policy()

    def _load_default_policies(self):
        """加载默认安全策略"""
        # 严格安全策略
        strict_policy = SecurityPolicy(
            level=SecurityLevel.STRICT,
            rules=self._get_strict_rules(),
            blocked_commands=self._get_dangerous_commands(),
            blocked_paths=self._get_sensitive_paths(),
            allowed_domains={"api.openai.com", "github.com", "pypi.org"},
            max_file_size=10 * 1024 * 1024,  # 10MB
            max_process_count=10
        )

        # 中等安全策略
        medium_policy = SecurityPolicy(
            level=SecurityLevel.MEDIUM,
            rules=self._get_medium_rules(),
            blocked_commands=self._get_dangerous_commands(),
            blocked_paths=self._get_critical_paths(),
            allowed_domains={"*.openai.com", "github.com", "*.github.com", "pypi.org", "*.pypi.org"},
            max_file_size=50 * 1024 * 1024,  # 50MB
            max_process_count=25
        )

        # 低安全策略
        low_policy = SecurityPolicy(
            level=SecurityLevel.LOW,
            rules=self._get_basic_rules(),
            blocked_commands=self._get_critical_commands(),
            blocked_paths=self._get_system_paths(),
            max_file_size=100 * 1024 * 1024,  # 100MB
            max_process_count=50
        )

        self.policies = {
            "strict": strict_policy,
            "medium": medium_policy,
            "low": low_policy,
            "default": medium_policy
        }

    def _get_strict_rules(self) -> List[SecurityRule]:
        """获取严格安全规则"""
        return [
            # 命令规则
            SecurityRule("no_rm_rf", ActionType.COMMAND, r"rm\s+.*-rf?\s*/", False,
                         "禁止递归删除根目录", "critical"),
            SecurityRule("no_dd", ActionType.COMMAND, r"dd\s+", False,
                         "禁止使用dd命令", "high"),
            SecurityRule("no_format", ActionType.COMMAND, r"mkfs\.|format\s", False,
                         "禁止格式化命令", "critical"),
            SecurityRule("no_mount", ActionType.COMMAND, r"mount\s|umount\s", False,
                         "禁止挂载操作", "high"),
            SecurityRule("no_chmod_777", ActionType.COMMAND, r"chmod\s+777", False,
                         "禁止设置777权限", "medium"),
            SecurityRule("no_sudo", ActionType.COMMAND, r"sudo\s|su\s", False,
                         "禁止提权操作", "critical"),
            SecurityRule("no_wget_curl_unsafe", ActionType.COMMAND,
                         r"(wget|curl).*http://.*\.(sh|py|exe|bat)", False,
                         "禁止下载可执行文件", "high"),

            # 文件规则
            SecurityRule("no_passwd_access", ActionType.FILE_READ, r"/etc/passwd|/etc/shadow", False,
                         "禁止访问密码文件", "critical"),
            SecurityRule("no_ssh_keys", ActionType.FILE_READ, r"\.ssh/.*key", False,
                         "禁止访问SSH密钥", "critical"),
            SecurityRule("no_system_write", ActionType.FILE_WRITE, r"^/etc/|^/sys/|^/proc/", False,
                         "禁止写入系统目录", "critical"),

            # 网络规则
            SecurityRule("no_local_network", ActionType.NETWORK,
                         r"(127\.|192\.168\.|10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.)", False,
                         "禁止访问内网地址", "high"),
            SecurityRule("no_suspicious_domains", ActionType.NETWORK,
                         r"(malware|virus|hack|exploit)", False,
                         "禁止访问可疑域名", "critical"),
        ]

    def _get_medium_rules(self) -> List[SecurityRule]:
        """获取中等安全规则"""
        rules = self._get_strict_rules()
        # 中等级别允许一些操作，但仍保持核心安全
        return [r for r in rules if r.severity in ["critical", "high"]]

    def _get_basic_rules(self) -> List[SecurityRule]:
        """获取基础安全规则"""
        return [
            SecurityRule("no_rm_rf_root", ActionType.COMMAND, r"rm\s+.*-rf?\s*/\s*$", False,
                         "禁止删除根目录", "critical"),
            SecurityRule("no_format_system", ActionType.COMMAND, r"mkfs\.|format\s+[A-Z]:", False,
                         "禁止格式化系统盘", "critical"),
            SecurityRule("no_passwd_write", ActionType.FILE_WRITE, r"/etc/passwd|/etc/shadow", False,
                         "禁止修改密码文件", "critical"),
        ]

    def _get_dangerous_commands(self) -> Set[str]:
        """获取危险命令列表"""
        return {
            "rm", "rmdir", "shred", "dd", "fdisk", "mkfs", "format",
            "iptables", "ufw", "firewall-cmd", "systemctl", "service",
            "crontab", "at", "chroot", "mount", "umount", "fsck",
            "parted", "gparted", "lsof", "netstat", "ss", "tcpdump",
            "wireshark", "nmap", "nc", "netcat", "telnet", "ssh",
            "scp", "rsync", "wget", "curl", "lynx", "w3m"
        }

    def _get_critical_commands(self) -> Set[str]:
        """获取关键危险命令"""
        return {
            "rm", "shred", "dd", "fdisk", "mkfs", "format", "parted",
            "systemctl", "service", "mount", "umount", "chroot"
        }

    def _get_sensitive_paths(self) -> Set[str]:
        """获取敏感路径列表"""
        return {
            "/etc", "/sys", "/proc", "/dev", "/boot", "/root",
            "/var/log", "/usr/bin", "/usr/sbin", "/sbin", "/bin",
            "/.ssh", "/home/*/.ssh", "/tmp/.ssh"
        }

    def _get_critical_paths(self) -> Set[str]:
        """获取关键敏感路径"""
        return {
            "/etc/passwd", "/etc/shadow", "/etc/sudoers", "/etc/hosts",
            "/sys", "/proc", "/dev", "/boot/grub", "/root/.ssh"
        }

    def _get_system_paths(self) -> Set[str]:
        """获取系统路径"""
        return {
            "/etc/passwd", "/etc/shadow", "/etc/sudoers", "/sys", "/proc", "/dev"
        }

    def _load_policy_file(self, config_file: Path):
        """加载策略配置文件"""
        try:
            with open(config_file, 'r', encoding='utf-8') as f:
                if config_file.suffix == '.yaml' or config_file.suffix == '.yml':
                    config = yaml.safe_load(f)
                else:
                    config = json.load(f)

            # 解析配置并更新策略
            self._parse_config(config)

        except Exception as e:
            self.logger.error(f"Failed to load policy file {config_file}: {e}")

    def _parse_config(self, config: Dict):
        """解析配置文件"""
        # 这里可以实现复杂的配置解析逻辑
        pass

    def _load_fallback_policy(self):
        """加载后备安全策略"""
        fallback_policy = SecurityPolicy(
            level=SecurityLevel.STRICT,
            blocked_commands={"rm", "dd", "mkfs", "format", "mount", "sudo"},
            blocked_paths={"/etc", "/sys", "/proc", "/dev", "/boot", "/root"},
            max_file_size=1024 * 1024,  # 1MB
            max_process_count=5
        )
        self.policies = {"default": fallback_policy}

    def get_policy(self, policy_name: str = "default") -> SecurityPolicy:
        """获取指定的安全策略"""
        return self.policies.get(policy_name, self.policies["default"])

    def check_command(self, command: str, policy_name: str = "default") -> Tuple[bool, str]:
        """检查命令是否被允许"""
        policy = self.get_policy(policy_name)

        # 检查命令规则
        for rule in policy.rules:
            if rule.action_type == ActionType.COMMAND and rule.matches(command):
                if not rule.allow:
                    return False, f"命令被安全规则阻止: {rule.description}"

        # 检查命令黑名单
        cmd_parts = command.strip().split()
        if cmd_parts:
            base_cmd = cmd_parts[0]
            if base_cmd in policy.blocked_commands:
                return False, f"命令 '{base_cmd}' 在黑名单中"

        return True, "命令允许执行"

    def check_file_access(self, file_path: str, operation: str, policy_name: str = "default") -> Tuple[bool, str]:
        """检查文件访问是否被允许"""
        policy = self.get_policy(policy_name)

        # 确定操作类型
        action_type_map = {
            "read": ActionType.FILE_READ,
            "write": ActionType.FILE_WRITE,
            "delete": ActionType.FILE_DELETE
        }
        action_type = action_type_map.get(operation, ActionType.FILE_READ)

        # 检查文件规则
        for rule in policy.rules:
            if rule.action_type == action_type and rule.matches(file_path):
                if not rule.allow:
                    return False, f"文件访问被安全规则阻止: {rule.description}"

        # 检查路径黑名单
        for blocked_path in policy.blocked_paths:
            if file_path.startswith(blocked_path):
                return False, f"路径 '{file_path}' 在黑名单中"

        return True, "文件访问允许"

    def check_network_access(self, url_or_domain: str, policy_name: str = "default") -> Tuple[bool, str]:
        """检查网络访问是否被允许"""
        policy = self.get_policy(policy_name)

        # 检查网络规则
        for rule in policy.rules:
            if rule.action_type == ActionType.NETWORK and rule.matches(url_or_domain):
                if not rule.allow:
                    return False, f"网络访问被安全规则阻止: {rule.description}"

        # 检查域名白名单（如果配置了）
        if policy.allowed_domains:
            domain_allowed = False
            for allowed_domain in policy.allowed_domains:
                if self._domain_matches(url_or_domain, allowed_domain):
                    domain_allowed = True
                    break

            if not domain_allowed:
                return False, f"域名 '{url_or_domain}' 不在白名单中"

        # 检查域名黑名单
        for blocked_domain in policy.blocked_domains:
            if self._domain_matches(url_or_domain, blocked_domain):
                return False, f"域名 '{url_or_domain}' 在黑名单中"

        return True, "网络访问允许"

    def _domain_matches(self, url_or_domain: str, pattern: str) -> bool:
        """检查域名是否匹配模式"""
        # 提取域名
        if "://" in url_or_domain:
            domain = url_or_domain.split("://")[1].split("/")[0]
        else:
            domain = url_or_domain.split("/")[0]

        # 支持通配符匹配
        if pattern.startswith("*."):
            return domain.endswith(pattern[2:]) or domain == pattern[2:]
        else:
            return domain == pattern

    def validate_resource_usage(self, file_size: int = 0, process_count: int = 0,
                                policy_name: str = "default") -> Tuple[bool, str]:
        """验证资源使用是否在限制范围内"""
        policy = self.get_policy(policy_name)

        if file_size > policy.max_file_size:
            return False, f"文件大小 {file_size} 超过限制 {policy.max_file_size}"

        if process_count > policy.max_process_count:
            return False, f"进程数量 {process_count} 超过限制 {policy.max_process_count}"

        return True, "资源使用在限制范围内"


# 全局安全策略管理器实例
security_manager = SecurityPolicyManager()


def check_command_security(command: str, policy: str = "default") -> Tuple[bool, str]:
    """检查命令安全性的便捷函数"""
    return security_manager.check_command(command, policy)


def check_file_security(file_path: str, operation: str, policy: str = "default") -> Tuple[bool, str]:
    """检查文件访问安全性的便捷函数"""
    return security_manager.check_file_access(file_path, operation, policy)


def check_network_security(url: str, policy: str = "default") -> Tuple[bool, str]:
    """检查网络访问安全性的便捷函数"""
    return security_manager.check_network_access(url, policy)


# 装饰器：安全检查
def require_security_check(action_type: str):
    """安全检查装饰器"""

    def decorator(func):
        def wrapper(*args, **kwargs):
            # 根据action_type执行相应的安全检查
            # 这里可以根据具体需求实现
            return func(*args, **kwargs)

        return wrapper

    return decorator


if __name__ == "__main__":
    # 示例用法
    print("Cooragent Sandbox Security Policies Test")

    # 测试命令检查
    test_commands = [
        "ls -la",
        "rm -rf /",
        "dd if=/dev/zero of=/dev/sda",
        "python script.py",
        "sudo rm file.txt"
    ]

    for cmd in test_commands:
        allowed, reason = check_command_security(cmd)
        status = "✓ 允许" if allowed else "✗ 拒绝"
        print(f"{status}: {cmd} - {reason}")

    print("\n" + "=" * 50 + "\n")

    # 测试文件访问检查
    test_files = [
        ("/tmp/test.txt", "write"),
        ("/etc/passwd", "read"),
        ("/home/user/data.json", "read"),
        ("/sys/kernel/config", "write")
    ]

    for file_path, operation in test_files:
        allowed, reason = check_file_security(file_path, operation)
        status = "✓ 允许" if allowed else "✗ 拒绝"
        print(f"{status}: {operation} {file_path} - {reason}")

    print("\n" + "=" * 50 + "\n")

    # 测试网络访问检查
    test_urls = [
        "https://api.openai.com/v1/chat",
        "http://malware.example.com/payload.sh",
        "https://github.com/user/repo",
        "http://192.168.1.1/admin"
    ]

    for url in test_urls:
        allowed, reason = check_network_security(url)
        status = "✓ 允许" if allowed else "✗ 拒绝"
        print(f"{status}: {url} - {reason}")