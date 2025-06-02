# src/sandbox/sandbox_manager.py

from typing import Dict, Any, Optional, List
import os
import json
from .daytona_client import DaytonaClient


class SandboxManager:
    """Sandbox 管理器，用于管理 sandbox 生命周期"""

    def __init__(self, api_key: str = None, api_url: str = None):
        """初始化 Sandbox 管理器

        Args:
            api_key: Daytona API 密钥，默认从环境变量获取
            api_url: Daytona API URL，默认从环境变量获取
        """
        self.client = DaytonaClient(api_key, api_url)
        self.sandboxes = {}  # 本地缓存

    def create_sandbox(self, agent_id: str, resources: Dict[str, Any] = None) -> str:
        """为指定 agent 创建 sandbox

        Args:
            agent_id: Agent ID
            resources: 资源限制配置

        Returns:
            Sandbox ID
        """
        # 创建 sandbox
        sandbox = self.client.create_sandbox(resources=resources)
        sandbox_id = sandbox["id"]

        # 缓存 sandbox 信息
        self.sandboxes[sandbox_id] = {
            "agent_id": agent_id,
            "sandbox_id": sandbox_id,
            "status": "created",
            "details": sandbox
        }

        return sandbox_id

    def get_sandbox(self, sandbox_id: str) -> Dict[str, Any]:
        """获取 sandbox 信息

        Args:
            sandbox_id: Sandbox ID

        Returns:
            Sandbox 详细信息
        """
        # 如果本地缓存中没有，则从 Daytona 获取
        if sandbox_id not in self.sandboxes:
            sandbox = self.client.get_sandbox(sandbox_id)
            self.sandboxes[sandbox_id] = {
                "agent_id": "unknown",
                "sandbox_id": sandbox_id,
                "status": sandbox["status"],
                "details": sandbox
            }

        return self.sandboxes[sandbox_id]

    def list_sandboxes(self) -> List[Dict[str, Any]]:
        """列出所有 sandbox

        Returns:
            Sandbox 列表
        """
        # 从 Daytona 获取最新列表
        sandboxes = self.client.list_sandboxes()

        # 更新本地缓存
        for sandbox in sandboxes:
            sandbox_id = sandbox["id"]
            if sandbox_id in self.sandboxes:
                self.sandboxes[sandbox_id]["status"] = sandbox["status"]
                self.sandboxes[sandbox_id]["details"] = sandbox
            else:
                self.sandboxes[sandbox_id] = {
                    "agent_id": "unknown",
                    "sandbox_id": sandbox_id,
                    "status": sandbox["status"],
                    "details": sandbox
                }

        return list(self.sandboxes.values())

    def delete_sandbox(self, sandbox_id: str) -> bool:
        """删除 sandbox

        Args:
            sandbox_id: Sandbox ID

        Returns:
            是否成功删除
        """
        # 从 Daytona 删除
        success = self.client.delete_sandbox(sandbox_id)

        # 如果成功删除，则从本地缓存中移除
        if success and sandbox_id in self.sandboxes:
            del self.sandboxes[sandbox_id]

        return success

    def exec_command(self, sandbox_id: str, command: str) -> Dict[str, Any]:
        """在 sandbox 中执行命令

        Args:
            sandbox_id: Sandbox ID
            command: 要执行的命令

        Returns:
            命令执行结果
        """
        return self.client.exec_command(sandbox_id, command)

    def upload_file(self, sandbox_id: str, local_path: str, remote_path: str) -> bool:
        """上传文件到 sandbox

        Args:
            sandbox_id: Sandbox ID
            local_path: 本地文件路径
            remote_path: 远程文件路径

        Returns:
            是否成功上传
        """
        return self.client.upload_file(sandbox_id, local_path, remote_path)

    def download_file(self, sandbox_id: str, remote_path: str, local_path: str) -> bool:
        """从 sandbox 下载文件

        Args:
            sandbox_id: Sandbox ID
            remote_path: 远程文件路径
            local_path: 本地文件路径

        Returns:
            是否成功下载
        """
        return self.client.download_file(sandbox_id, remote_path, local_path)