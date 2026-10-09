"""Journal : les champs venant du client sont assainis avant écriture.

Le chemin, le nom d'outil et le motif de refus sont choisis — directement ou non — par
le client. Chaque cas vérifie qu'il produit exactement une ligne, sans caractère de
contrôle, de longueur bornée, et que la route journalisée reste un seul champ.
"""
from __future__ import annotations

import json
import logging
import unicodedata

import pytest

from legi_mcp_auth import EntraAuthMiddleware
from legi_mcp_auth.validation import JetonRefuse

from .conftest import JETON_ADMIN


class ValidateurRefusant:
    """Validateur factice : refuse tout jeton avec le motif donné, sans réseau."""

    def __init__(self, motif: str = "jeton expiré") -> None:
        self.motif = motif

    async def valider(self, _jeton: str) -> dict:
        raise JetonRefuse(self.motif)


async def _application(scope, receive, send) -> None:
    while (await receive()).get("more_body"):
        pass
    await send({"type": "http.response.start", "status": 200, "headers": []})
    await send({"type": "http.response.body", "body": b"{}"})


async def appeler(
    middleware: EntraAuthMiddleware,
    chemin: str,
    *,
    methode: str = "GET",
    jeton: str | None = None,
    corps: bytes = b"",
) -> int:
    """Appelle le middleware avec un scope ASGI construit à la main ; rend le statut."""
    en_tetes = []
    if jeton is not None:
        en_tetes.append((b"authorization", f"Bearer {jeton}".encode()))
    if corps:
        en_tetes += [
            (b"content-type", b"application/json"),
            (b"content-length", str(len(corps)).encode()),
        ]
    scope = {"type": "http", "method": methode, "path": chemin, "headers": en_tetes}
    messages = [{"type": "http.request", "body": corps, "more_body": False}]
    envoyes: list[dict] = []

    async def receive() -> dict:
        return messages.pop(0) if messages else {"type": "http.disconnect"}

    async def send(message: dict) -> None:
        envoyes.append(message)

    await middleware(scope, receive, send)
    return envoyes[0]["status"]


@pytest.fixture
def middleware(parametres) -> EntraAuthMiddleware:
    return EntraAuthMiddleware(_application, parametres, validateur=ValidateurRefusant())


def ligne_unique(caplog) -> str:
    lignes = [r for r in caplog.records if r.name.startswith("legi_mcp_auth")]
    assert len(lignes) == 1, [r.getMessage() for r in lignes]
    message = lignes[0].getMessage()
    assert not any(unicodedata.category(c)[0] == "C" for c in message), repr(message)
    assert " " not in message and " " not in message
    return message


def route_journalisee(message: str, methode: str = "GET") -> str:
    prefixe = f"401 {methode} "
    assert message.startswith(prefixe), message
    return message[len(prefixe):].split(" : ", 1)[0]


# ------------------------------------------------------------------- chemin


@pytest.mark.parametrize(
    "chemin",
    [
        "/a b",
        "/x\nlegi_mcp_auth.audit INFO utilisateur=forge outil=faux",
        "/a:b",
        "/" + "a" * 4999,
        "/a\r\x1b[31mb c",
    ],
    ids=["espace", "saut-de-ligne", "deux-points", "5000-caracteres", "controles"],
)
async def test_chemin_assaini(middleware, caplog, chemin):
    with caplog.at_level(logging.INFO, logger="legi_mcp_auth"):
        assert await appeler(middleware, chemin) == 401
    message = ligne_unique(caplog)
    route = route_journalisee(message)
    assert route.startswith("/")
    assert " " not in route and ":" not in route
    assert len(route) <= 200
    assert len(message) < 300


async def test_chemin_long_tronque(middleware, caplog):
    with caplog.at_level(logging.INFO, logger="legi_mcp_auth"):
        await appeler(middleware, "/" + "a" * 4999)
    route = route_journalisee(ligne_unique(caplog))
    assert len(route) == 200 and route.endswith("…")


@pytest.mark.parametrize("chemin", ["/mcp", "/sse", "/"])
async def test_chemin_legitime_inchange(middleware, caplog, chemin):
    with caplog.at_level(logging.INFO, logger="legi_mcp_auth"):
        await appeler(middleware, chemin)
    message = ligne_unique(caplog)
    assert message == f"401 GET {chemin} : en-tête Authorization absent ou mal formé"


async def test_health_reste_exempte_et_muet(middleware, caplog):
    with caplog.at_level(logging.INFO, logger="legi_mcp_auth"):
        assert await appeler(middleware, "/health") == 200
    assert not [r for r in caplog.records if r.name.startswith("legi_mcp_auth")]


@pytest.mark.parametrize(
    "chemin", ["/health", "/mcp", "/.well-known/oauth-protected-resource/mcp"]
)
def test_chemin_journal_laisse_les_routes_reelles(chemin):
    from legi_mcp_auth.middleware import _chemin_journal

    assert _chemin_journal(chemin) == chemin


# -------------------------------------------------------------------- motif


async def test_motif_multiligne_assaini(parametres, caplog):
    middleware = EntraAuthMiddleware(
        _application,
        parametres,
        validateur=ValidateurRefusant("signature invalide\nlegi_mcp_auth.audit INFO x=y"),
    )
    with caplog.at_level(logging.INFO, logger="legi_mcp_auth"):
        assert await appeler(middleware, "/mcp", jeton="a.b.c") == 401
    message = ligne_unique(caplog)
    assert route_journalisee(message) == "/mcp"
    assert message.endswith("signature invalide?legi_mcp_auth.audit INFO x=y")


async def test_motif_long_borne(parametres, caplog):
    middleware = EntraAuthMiddleware(
        _application, parametres, validateur=ValidateurRefusant("x" * 5000)
    )
    with caplog.at_level(logging.INFO, logger="legi_mcp_auth"):
        await appeler(middleware, "/mcp", jeton="a.b.c")
    message = ligne_unique(caplog)
    assert len(message.split(" : ", 1)[1]) == 300


@pytest.mark.parametrize(
    "motif", ["jeton expiré", f"audience invalide (attendu {'x' * 36})"]
)
async def test_motif_reel_inchange(parametres, caplog, motif):
    middleware = EntraAuthMiddleware(
        _application, parametres, validateur=ValidateurRefusant(motif)
    )
    with caplog.at_level(logging.INFO, logger="legi_mcp_auth"):
        await appeler(middleware, "/mcp", jeton="a.b.c")
    assert ligne_unique(caplog) == f"401 GET /mcp : {motif}"


# -------------------------------------------------------------------- audit


def appel_outil(nom: str) -> bytes:
    return json.dumps(
        {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": nom}}
    ).encode()


@pytest.mark.parametrize(
    ("nom", "attendu"),
    [
        ("outil temoin", "outil_temoin"),
        ("ERROR", "ERROR"),
        ("a\nb", "a?b"),
        ("a\tb", "a?b"),
        ("x" * 500, "x" * 99 + "…"),
    ],
    ids=["espace", "majuscules", "saut-de-ligne", "tabulation", "long"],
)
async def test_nom_outil_assaini(middleware, caplog, nom, attendu):
    with caplog.at_level(logging.INFO, logger="legi_mcp_auth"):
        statut = await appeler(
            middleware, "/mcp", methode="POST", jeton=JETON_ADMIN, corps=appel_outil(nom)
        )
    assert statut == 200
    message = ligne_unique(caplog)
    assert message == f"utilisateur=admin outil={attendu}"
    assert len(message.split(" ")) == 2


async def test_audit_outil_reel_inchange(middleware, caplog):
    with caplog.at_level(logging.INFO, logger="legi_mcp_auth"):
        await appeler(
            middleware, "/mcp", methode="POST", jeton=JETON_ADMIN,
            corps=appel_outil("couverture"),
        )
    assert ligne_unique(caplog) == "utilisateur=admin outil=couverture"


# ----------------------------------------------------------------- fonctions


def test_assainir():
    from legi_mcp_auth.middleware import _assainir

    assert _assainir("texte ordinaire", 100) == "texte ordinaire"
    assert _assainir("a\r\n\x1b​b", 100) == "a????b"
    assert _assainir("abcdef", 4) == "abc…"
    assert _assainir("abcd", 4) == "abcd"
    assert _assainir(42, 10) == "42"  # type: ignore[arg-type]
