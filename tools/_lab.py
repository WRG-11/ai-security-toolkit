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


# Mesaj İNGİLİZCE: bu metin son kullanıcıya gidiyor ve depo (README, CHANGELOG,
# commit'ler) baştan sona İngilizce -- `pip install` yapan biri Türkçe hata
# almamalı. Docstring ve yorumlar Türkçe kalıyor; onlar geliştirici notu.
# Mesajın diakritiksiz olması kasıtlı: dar kod sayfalı Windows konsollarında
# bozulmasın diye (aynı gerekçe `_console.make_output_safe` için de geçerli).
_MESSAGE = """\
{tool}: labs/vulnllm/ not found -- expected at: {path}

This tool imports its attack corpus and guard implementations from
labs/vulnllm/. labs/ is deliberately not packaged (see pyproject.toml), so
the tool cannot run from inside a wheel on its own; it needs the repository
checkout on disk.

To fix:
    git clone https://github.com/WRG-11/ai-security-toolkit.git
    cd ai-security-toolkit
    pip install -e .        # editable: the clone stays on disk, labs/ resolves

If you already have a clone, replace the non-editable install with
`pip install -e .`."""


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


def ensure_lab_or_exit(tool: str) -> Path:
    """``ensure_lab_on_path``, ama bir CLI'ın kullanıcısına göre.

    ``ensure_lab_on_path`` modül seviyesinden çağrılıyor, yani ``main()``
    çalışmadan önce. Oradan fırlayan bir istisna yakalanamaz ve Python onu
    tam traceback'le basar: 2026-07-29'da ölçüldü, açıklayıcı mesaj on
    satırlık bir yığın izinin *altında* çıkıyordu. Kullanıcının gördüğü ilk
    şey ``Traceback (most recent call last)`` ise, mesajı düzeltmek yarım
    iş kalır -- çünkü çıplak traceback "araç çöktü" demektir, oysa durum
    "araç bu kurulum biçiminde çalışamaz, şöyle kur" durumudur.

    Bu sarmalayıcı mesajı stderr'e basar ve ``SystemExit(2)`` ile durur.
    2 bilinçli: 1 "araç koştu ve bulgu buldu" için ayrılmış, bu ise
    yapılandırma hatası.

    Args:
        tool: Hata mesajında görünecek araç adı.

    Returns:
        Lab ağacının yolu.

    Raises:
        SystemExit: Ağaç yoksa, kod 2.
    """
    try:
        return ensure_lab_on_path(tool)
    except LabTreeMissing as exc:
        print(str(exc), file=sys.stderr)
        raise SystemExit(2) from None


def lab_is_available() -> bool:
    """Ağaç var mı? Fırlatmadan sorabilmek için -- test ve fallback yolları."""
    return _VULNLLM_DIR.is_dir()


__all__ = [
    "LabTreeMissing",
    "ensure_lab_on_path",
    "ensure_lab_or_exit",
    "lab_is_available",
]
