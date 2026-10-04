"""Profile Package 存储模块"""

from typing import Optional, Dict, List
from dataclasses import dataclass, field


@dataclass
class ProfilePackageTemplate:
    """Profile Package 模板"""
    matching_id: str
    profile_id: str
    profile_name: str
    iccid: str
    service_provider_name: str = ""
    profile_class: int = 2
    payload: bytes = b''  # UPP (User Profile Package)
    icon: Optional[bytes] = None
    icon_type: int = 0  # 0=none, 1=png, 2=jpg
    notification_address: Optional[str] = None
    notification_events: Optional[List[str]] = None
    ppr_id: Optional[str] = None
    dp_proprietary_data: Optional[bytes] = None


class ProfilePackageStore:
    """Profile Package 内存存储"""
    
    def __init__(self):
        self._packages: Dict[str, ProfilePackageTemplate] = {}
    
    def save(self, template: ProfilePackageTemplate):
        """保存 Profile Package"""
        self._packages[template.matching_id] = template
    
    def get_by_matching_id(self, matching_id: str) -> Optional[ProfilePackageTemplate]:
        """通过 Matching ID 获取"""
        return self._packages.get(matching_id)
    
    def require_by_matching_id(self, matching_id: str) -> ProfilePackageTemplate:
        """获取 Profile Package（不存在则抛出异常）"""
        template = self.get_by_matching_id(matching_id)
        if template is None:
            raise ValueError(f"Profile package not found for matching_id: {matching_id}")
        return template
    
    def delete(self, matching_id: str) -> bool:
        """删除 Profile Package"""
        if matching_id in self._packages:
            del self._packages[matching_id]
            return True
        return False
    
    def list_all(self) -> List[ProfilePackageTemplate]:
        """列出所有 Profile Package"""
        return list(self._packages.values())
    
    def clear(self):
        """清空存储"""
        self._packages.clear()
    
    def __len__(self) -> int:
        return len(self._packages)
