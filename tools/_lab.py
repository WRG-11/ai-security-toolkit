"""labs/vulnllm ağacını bul, yoksa NEDENİNİ söyle.

``tools/`` üç aracın hepsinde lab ağacından import ediyor: saldırı korpusu
(``attacks.*``) ve guard implementasyonları (``defenses.*``). ``labs/`` ise
bilerek paketlenmiyor (gerekçe ``pyproject.toml`` içinde). İkisi birlikte şu
anlama gelir: bu araçlar **repo checkout'u** ister; bir wheel'in içinden tek
başlarına çalışamazlar.

Bu doğru olabilir -- yanlış olan, bunun nasıl söylendiğiydi. 2026-07-29'da
ölçüldü, temiz bir venv'e ``pip install .`` sonrası:

    llm-scanner  --help  -> ModuleNotFoundError: No module named 'attacks'
    llm-firewall --help  -> ModuleNotFoundError: No module named 'defenses'

``--help`` bile çalışmıyordu ve kullanıcıya düşen tek ipucu, kendi kodunda
geçmeyen bir modül adıydı. Bu dosya o hatayı, ne olduğunu ve ne yapılacağını
söyleyen bir mesajla değiştiriyor.

CI'ın bunu görememesinin nedeni ayrıca kayda değer: iş akışı yalnızca
``pip install -e .`` koşuyordu. Editable kurulumda klon diskte kalır, dolayısıyla
``_PROJECT_ROOT / "labs"`` her zaman çözülür -- yani CI'ın denediği kurulum
yolu, kırılması mümkün olmayan yoldu.
"""
from __future__ import annotations

import sys
from pathlib import Path

_TOOLS_DIR = Path(__file__).resolve().parent
_PROJECT_ROOT = _TOOLS_DIR.parent
_VULNLLM_DIR = _PROJECT_ROOT / "labs" / "vulnllm"


class LabTreeMissing(ImportError):
    """Lab ağacı bulunamadı -- araç bir checkout olmadan koşamaz."""


_MESSAGE = """\
{tool}: labs/vulnllm/ bulunamadi -- beklenen konum: {path}

Bu arac saldiri korpusunu ve guard implementasyonlarini labs/vulnllm/
altindan import eder. labs/ bilerek paketlenmez (bkz. pyproject.toml), bu
yuzden arac bir wheel'in icinden tek basina calisamaz; repo checkout'u ister.

Yapilacak:
    git clone https://github.com/WRG-11/ai-security-toolkit.git
    cd ai-security-toolkit
    pip install -e .        # editable: klon diskte kalir, labs/ cozulur

Zaten bir klonunuz varsa, editable-olmayan kurulumu kaldirip
`pip install -e .` ile degistirin."""


def ensure_lab_on_path(tool: str) -> Path:
    """``labs/vulnllm``'i ``sys.path``'e ekle; yoksa açıklayıcı hata fırlat.

    Args:
        tool: Hata mesajında görünecek araç adı.

    Returns:
        Lab ağacının yolu.

    Raises:
        LabTreeMissing: Ağaç yoksa. Mesaj tek satırlık bir modül adı değil,
            ne yapılacağını söyleyen bir talimattır.
    """
    if not _VULNLLM_DIR.is_dir():
        raise LabTreeMissing(_MESSAGE.format(tool=tool, path=_VULNLLM_DIR))

    path = str(_VULNLLM_DIR)
    if path not in sys.path:
        sys.path.insert(0, path)
    return _VULNLLM_DIR


def lab_is_available() -> bool:
    """Ağaç var mı? Fırlatmadan sorabilmek için -- test ve fallback yolları."""
    return _VULNLLM_DIR.is_dir()


__all__ = ["LabTreeMissing", "ensure_lab_on_path", "lab_is_available"]
