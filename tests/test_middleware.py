"""Comportement HTTP : exemptions, 401, jeton admin, identité, audit."""
from __future__ import annotations

import json

import pytest

from .conftest import JETON_ADMIN, URL_PUBLIQUE, Autorite

APPEL_OUTIL = {
    "jsonrpc": "2.0",
    "id": 7,
    "method": "tools/call",
    "params": {"name": "rechercher_legislation", "arguments": {"mots_cles": "distribution"}},
}


def entete(jeton: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {jeton}"}


# ------------------------------------------------------------------ exemptions


async def test_health_exempte(client):
    reponse = await client.get("/health")
    assert reponse.status_code == 200
    assert reponse.json()["status"] == "ok"


async def test_well_known_exempte(client):
    reponse = await client.get("/.well-known/oauth-protected-resource")
    assert reponse.status_code == 200


async def test_racine_protegee(client):
    """La racine n'est PAS exemptée : c'est par elle qu'un client découvre le 401."""
    assert (await client.get("/")).status_code == 401


# ------------------------------------------------------------------- refus 401


async def test_sans_jeton(client):
    reponse = await client.post("/mcp", json=APPEL_OUTIL)
    assert reponse.status_code == 401


async def test_forme_exacte_du_401(client, parametres):
    reponse = await client.post("/mcp", json=APPEL_OUTIL)
    assert reponse.status_code == 401

    attendu = (
        f'Bearer resource_metadata="{URL_PUBLIQUE}/.well-known/oauth-protected-resource", '
        f'scope="{parametres.scope_complet}", '
        f'error="invalid_token"'
    )
    assert reponse.headers["www-authenticate"] == attendu
    assert reponse.headers["content-type"].startswith("application/json")
    assert reponse.headers["cache-control"] == "no-store"

    corps = reponse.json()
    assert corps["error"] == "invalid_token"
    assert corps["resource_metadata"] == parametres.url_metadonnees
    assert corps["scope"] == parametres.scope_complet
    assert corps["error_description"]


@pytest.mark.parametrize(
    "en_tetes",
    [
        {},
        {"Authorization": ""},
        {"Authorization": "Bearer"},
        {"Authorization": "Bearer "},
        {"Authorization": "Basic YWRtaW46YWRtaW4="},
        {"Authorization": "bearer"},
        {"Authorization": "Token abc"},
    ],
    ids=["absent", "vide", "sans-jeton", "espace", "basic", "schema-nu", "autre-schema"],
)
async def test_en_tetes_mal_formes(client, en_tetes):
    reponse = await client.post("/mcp", json=APPEL_OUTIL, headers=en_tetes)
    assert reponse.status_code == 401


@pytest.mark.parametrize(
    "fabrique",
    [
        lambda a: a.jeton(expire_dans=-120),
        lambda a: a.jeton(audience="api://autre"),
        lambda a: a.jeton(scope=None),
        lambda a: a.jeton(algorithme="none"),
        lambda a: a.jeton(tenant="99999999-9999-9999-9999-999999999999"),
        lambda a: "n-importe-quoi",
    ],
    ids=["expire", "audience", "scope", "alg-none", "tenant", "illisible"],
)
async def test_jetons_invalides_donnent_401(client, autorite: Autorite, fabrique):
    reponse = await client.post("/mcp", json=APPEL_OUTIL, headers=entete(fabrique(autorite)))
    assert reponse.status_code == 401


async def test_le_401_ne_dit_jamais_pourquoi(client, autorite: Autorite):
    """Deux refus de causes différentes doivent être indiscernables côté client.

    Sinon un attaquant apprend à chaque essai ce qu'il doit corriger.
    """
    refus = [
        await client.post("/mcp", json=APPEL_OUTIL, headers=entete(jeton))
        for jeton in (
            autorite.jeton(expire_dans=-120),
            autorite.jeton(scope=None),
            autorite.jeton(audience="api://autre"),
            autorite.jeton(algorithme="none"),
            "n-importe-quoi",
        )
    ]
    # Réponses rigoureusement identiques, au corps comme à l'en-tête.
    assert len({r.text for r in refus}) == 1
    assert len({r.headers["www-authenticate"] for r in refus}) == 1
    # Et le corps ne nomme aucun contrôle : `scope` n'y figure que comme la portée à
    # DEMANDER, jamais comme le motif du refus.
    for mot in ("expir", "audience", "tid", "tenant", "signature", "groupe", "kid"):
        assert mot not in refus[0].text.lower()


async def test_motif_du_refus_journalise(client, autorite: Autorite, caplog):
    """Le motif doit être dans le journal — c'est là qu'on diagnostique."""
    with caplog.at_level("WARNING", logger="legi_mcp_auth.middleware"):
        await client.post("/mcp", json=APPEL_OUTIL, headers=entete(autorite.jeton(expire_dans=-120)))
    assert "expiré" in caplog.text


async def test_aucun_jeton_dans_les_journaux(client, autorite: Autorite, caplog):
    jeton = autorite.jeton()
    with caplog.at_level("DEBUG"):
        await client.post("/mcp", json=APPEL_OUTIL, headers=entete(jeton))
    assert jeton not in caplog.text
    assert JETON_ADMIN not in caplog.text


# ----------------------------------------------------------------- acceptation


async def test_jeton_valide_passe_et_expose_identite(client, autorite: Autorite):
    reponse = await client.post("/mcp", json=APPEL_OUTIL, headers=entete(autorite.jeton()))
    assert reponse.status_code == 200
    assert reponse.json()["utilisateur"] == {
        "oid": "55555555-5555-5555-5555-555555555555",
        "preferred_username": "avocat@cabinet.example",
        "name": "Maître Test",
    }


async def test_corps_transmis_intact(client, autorite: Autorite):
    """Le tamponnage nécessaire à l'audit ne doit pas amputer la requête."""
    reponse = await client.post("/mcp", json=APPEL_OUTIL, headers=entete(autorite.jeton()))
    assert json.loads(reponse.json()["corps_recu"]) == APPEL_OUTIL


async def test_jeton_admin(client):
    reponse = await client.post("/mcp", json=APPEL_OUTIL, headers=entete(JETON_ADMIN))
    assert reponse.status_code == 200
    assert reponse.json()["utilisateur"] == {"admin": True}


async def test_jeton_admin_approchant_refuse(client):
    """Un jeton admin tronqué ou allongé ne passe pas (comparaison exacte)."""
    for variante in (JETON_ADMIN[:-1], JETON_ADMIN + "x", JETON_ADMIN.upper()):
        reponse = await client.post("/mcp", json=APPEL_OUTIL, headers=entete(variante))
        assert reponse.status_code == 401, variante


# ---------------------------------------------------------------------- audit


async def test_audit_appel_outil(client, autorite: Autorite, caplog):
    with caplog.at_level("INFO", logger="legi_mcp_auth.audit"):
        await client.post("/mcp", json=APPEL_OUTIL, headers=entete(autorite.jeton()))
    assert "utilisateur=avocat@cabinet.example outil=rechercher_legislation" in caplog.text


async def test_audit_jeton_admin(client, caplog):
    with caplog.at_level("INFO", logger="legi_mcp_auth.audit"):
        await client.post("/mcp", json=APPEL_OUTIL, headers=entete(JETON_ADMIN))
    assert "utilisateur=admin outil=rechercher_legislation" in caplog.text


async def test_audit_seulement_sur_les_appels_outil(client, autorite: Autorite, caplog):
    """`initialize`, `tools/list` : pas d'audit d'accès, ce ne sont pas des consultations."""
    with caplog.at_level("INFO", logger="legi_mcp_auth.audit"):
        await client.post(
            "/mcp",
            json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
            headers=entete(autorite.jeton()),
        )
    assert "outil=" not in caplog.text


async def test_audit_lot_jsonrpc(client, autorite: Autorite, caplog):
    lot = [APPEL_OUTIL, {**APPEL_OUTIL, "id": 8, "params": {"name": "texte_acte"}}]
    with caplog.at_level("INFO", logger="legi_mcp_auth.audit"):
        await client.post("/mcp", json=lot, headers=entete(autorite.jeton()))
    assert "outil=rechercher_legislation" in caplog.text
    assert "outil=texte_acte" in caplog.text


async def test_corps_non_json_ne_casse_rien(client, autorite: Autorite):
    reponse = await client.post(
        "/mcp",
        content=b"\x00\x01 ceci n'est pas du JSON",
        headers={**entete(autorite.jeton()), "Content-Type": "application/octet-stream"},
    )
    assert reponse.status_code == 200


async def test_get_sur_mcp(client, autorite: Autorite):
    """Le GET d'ouverture de flux SSE ne porte pas de corps : il doit passer aussi."""
    reponse = await client.get("/mcp", headers=entete(autorite.jeton()))
    assert reponse.status_code == 200
