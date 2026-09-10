"""Validation des jetons : le cas nominal, et chaque motif de refus.

Chaque test de refus vaut un contrôle de sécurité : s'il devient vert par erreur (jeton
accepté), c'est une porte ouverte sur les données du cabinet.
"""
from __future__ import annotations

import base64
import dataclasses
import hashlib
import hmac
import json
from types import SimpleNamespace

import httpx
import jwt
import pytest
import respx
from cryptography.hazmat.primitives import serialization

from legi_mcp_auth.jwks import CacheJWKS, JWKSIndisponible
from legi_mcp_auth.validation import JetonRefuse, ValidateurEntra

from .conftest import CLIENT_ID, GROUPE_AUTORISE, GROUPE_INTERDIT, TENANT, Autorite


def _b64(donnees: bytes) -> str:
    return base64.urlsafe_b64encode(donnees).rstrip(b"=").decode("ascii")


async def test_jeton_valide(validateur, autorite: Autorite):
    revendications = await validateur.valider(autorite.jeton())
    assert revendications["preferred_username"] == "avocat@cabinet.example"
    assert revendications["tid"] == TENANT


async def test_audience_uri_acceptee(validateur, autorite: Autorite):
    """Entra émet `aud` sous la forme `api://<client-id>` selon le manifeste."""
    jeton = autorite.jeton(audience=f"api://{CLIENT_ID}")
    assert await validateur.valider(jeton)


async def test_jeton_expire(validateur, autorite: Autorite):
    # -120 s : au-delà des 60 s de tolérance d'horloge.
    with pytest.raises(JetonRefuse, match="expiré"):
        await validateur.valider(autorite.jeton(expire_dans=-120))


async def test_jeton_expire_dans_la_tolerance(validateur, autorite: Autorite):
    """Une horloge en léger décalage ne doit pas couper le service."""
    assert await validateur.valider(autorite.jeton(expire_dans=-30))


async def test_jeton_pas_encore_valide(validateur, autorite: Autorite):
    with pytest.raises(JetonRefuse, match="nbf"):
        await validateur.valider(autorite.jeton(emis_il_y_a=-600))


async def test_mauvais_tenant(validateur, autorite: Autorite):
    """Un jeton d'un autre annuaire Entra ne passe pas, même bien signé."""
    autre = Autorite(tenant="99999999-9999-9999-9999-999999999999", client_id=CLIENT_ID)
    autre.cles = autorite.cles
    autre.publies = autorite.publies
    with pytest.raises(JetonRefuse, match="émetteur invalide"):
        await validateur.valider(autre.jeton())


async def test_tid_incoherent(validateur, autorite: Autorite):
    """`iss` correct mais `tid` étranger : refusé (contrôle distinct de l'émetteur)."""
    jeton = autorite.jeton(revendications_sup={"tid": "99999999-9999-9999-9999-999999999999"})
    with pytest.raises(JetonRefuse, match="tid="):
        await validateur.valider(jeton)


async def test_mauvaise_audience(validateur, autorite: Autorite):
    jeton = autorite.jeton(audience="api://une-autre-application")
    with pytest.raises(JetonRefuse, match="audience invalide"):
        await validateur.valider(jeton)


async def test_audience_absente(validateur, autorite: Autorite):
    with pytest.raises(JetonRefuse):
        await validateur.valider(autorite.jeton(omettre=("aud",)))


async def test_scope_absent(validateur, autorite: Autorite):
    with pytest.raises(JetonRefuse, match="portée"):
        await validateur.valider(autorite.jeton(scope=None))


async def test_scope_different(validateur, autorite: Autorite):
    with pytest.raises(JetonRefuse, match="portée"):
        await validateur.valider(autorite.jeton(scope="User.Read profile"))


async def test_scope_parmi_plusieurs(validateur, autorite: Autorite):
    """`scp` est une liste séparée par des espaces : la portée requise doit y figurer."""
    assert await validateur.valider(autorite.jeton(scope="profile mcp.access openid"))


async def test_groupe_autorise(parametres, autorite: Autorite, jwks):
    p = dataclasses.replace(parametres, groupes_autorises=(GROUPE_AUTORISE,))
    validateur = ValidateurEntra(p, cache_jwks=CacheJWKS(p.url_jwks, ttl=p.jwks_ttl))
    assert await validateur.valider(autorite.jeton(groupes=[GROUPE_AUTORISE, "autre"]))


async def test_groupe_non_autorise(parametres, autorite: Autorite, jwks):
    p = dataclasses.replace(parametres, groupes_autorises=(GROUPE_AUTORISE,))
    validateur = ValidateurEntra(p, cache_jwks=CacheJWKS(p.url_jwks, ttl=p.jwks_ttl))
    with pytest.raises(JetonRefuse, match="aucun groupe autorisé"):
        await validateur.valider(autorite.jeton(groupes=[GROUPE_INTERDIT]))


async def test_groupes_absents_alors_que_filtrage_actif(parametres, autorite: Autorite, jwks):
    p = dataclasses.replace(parametres, groupes_autorises=(GROUPE_AUTORISE,))
    validateur = ValidateurEntra(p, cache_jwks=CacheJWKS(p.url_jwks, ttl=p.jwks_ttl))
    with pytest.raises(JetonRefuse):
        await validateur.valider(autorite.jeton())


async def test_groupes_deportes_vers_graph(parametres, autorite: Autorite, jwks):
    """Trop de groupes : Entra remplace `groups` par une référence Graph. Refus explicite."""
    p = dataclasses.replace(parametres, groupes_autorises=(GROUPE_AUTORISE,))
    validateur = ValidateurEntra(p, cache_jwks=CacheJWKS(p.url_jwks, ttl=p.jwks_ttl))
    jeton = autorite.jeton(revendications_sup={"_claim_names": {"groups": "src1"}})
    with pytest.raises(JetonRefuse, match="Graph"):
        await validateur.valider(jeton)


async def test_groupes_ignores_si_non_configures(validateur, autorite: Autorite):
    """Sans ENTRA_GROUPES_AUTORISES, la revendication `groups` n'est pas regardée."""
    assert await validateur.valider(autorite.jeton(groupes=[GROUPE_INTERDIT]))


async def test_alg_none_refuse(validateur, autorite: Autorite):
    """L'attaque la plus vieille du monde : un jeton non signé, `alg: none`."""
    with pytest.raises(JetonRefuse, match="algorithme"):
        await validateur.valider(autorite.jeton(algorithme="none"))


async def test_alg_hs256_refuse(validateur, autorite: Autorite):
    """Substitution d'algorithme : signature symétrique avec la clé publique en secret.

    Sans le contrôle d'algorithme, la clé PUBLIQUE du tenant — librement téléchargeable —
    servirait de secret partagé et n'importe qui pourrait forger un jeton.
    """
    pem = autorite.cles["cle-1"].public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    # `jwt.encode` refuse une clé PEM en secret HMAC : on forge le jeton à la main,
    # exactement comme le ferait un attaquant.
    entete = _b64(json.dumps({"alg": "HS256", "typ": "JWT", "kid": "cle-1"}).encode())
    charge = _b64(
        json.dumps(
            {
                "iss": f"https://login.microsoftonline.com/{TENANT}/v2.0",
                "aud": CLIENT_ID,
                "tid": TENANT,
                "exp": 9_999_999_999,
                "scp": "mcp.access",
            }
        ).encode()
    )
    signature = _b64(
        hmac.new(pem, f"{entete}.{charge}".encode("ascii"), hashlib.sha256).digest()
    )
    with pytest.raises(JetonRefuse, match="algorithme"):
        await validateur.valider(f"{entete}.{charge}.{signature}")


async def test_signature_alteree(validateur, autorite: Autorite):
    """Dernier quartet de la signature modifié : la vérification doit échouer."""
    jeton = autorite.jeton()
    entete, charge, signature = jeton.split(".")
    altere = f"{entete}.{charge}.{signature[:-4]}AAAA"
    with pytest.raises(JetonRefuse):
        await validateur.valider(altere)


async def test_jeton_illisible(validateur):
    with pytest.raises(JetonRefuse, match="en-tête JWT illisible"):
        await validateur.valider("ceci-n-est-pas-un-jwt")


async def test_kid_absent(validateur, autorite: Autorite):
    jeton = jwt.encode({"exp": 9_999_999_999}, autorite.cles["cle-1"], algorithm="RS256")
    with pytest.raises(JetonRefuse, match="clé de signature inconnue"):
        await validateur.valider(jeton)


# ------------------------------------------------------------- rotation JWKS


async def test_kid_inconnu_declenche_un_rafraichissement(validateur, autorite: Autorite, jwks):
    """Rotation de clé côté Microsoft : le JWKS est rechargé, le jeton passe."""
    # Premier appel : peuple le cache avec « cle-1 » seule.
    await validateur.valider(autorite.jeton(kid="cle-1"))
    assert jwks.call_count == 1

    # Microsoft publie « cle-2 » et signe désormais avec elle.
    autorite.publies.append("cle-2")
    try:
        assert await validateur.valider(autorite.jeton(kid="cle-2"))
        # Exactement UN rafraîchissement supplémentaire, pas un par requête.
        assert jwks.call_count == 2
        await validateur.valider(autorite.jeton(kid="cle-2"))
        assert jwks.call_count == 2
    finally:
        autorite.publies.remove("cle-2")


async def test_kid_introuvable_apres_rafraichissement(validateur, autorite: Autorite, jwks):
    """`kid` inventé : un seul rechargement, puis refus — pas de martèlement de l'autorité."""
    with pytest.raises(JetonRefuse, match="clé de signature inconnue"):
        await validateur.valider(autorite.jeton(kid="cle-2"))
    appels = jwks.call_count
    with pytest.raises(JetonRefuse):
        await validateur.valider(autorite.jeton(kid="cle-2"))
    assert jwks.call_count == appels, "le rafraîchissement doit être bridé après un échec"


async def test_jwks_injoignable(parametres, autorite: Autorite):
    """Panne de l'autorité : refus (fail closed), et journal distinguant la cause."""
    with respx.mock(assert_all_called=False, assert_all_mocked=False) as mock:
        mock.get(autorite.url_jwks).mock(side_effect=httpx.ConnectError("réseau coupé"))
        validateur = ValidateurEntra(
            parametres, cache_jwks=CacheJWKS(parametres.url_jwks, ttl=parametres.jwks_ttl)
        )
        with pytest.raises(JetonRefuse, match="JWKS indisponible"):
            await validateur.valider(autorite.jeton())


async def test_jwks_vide(parametres, autorite: Autorite):
    with respx.mock(assert_all_called=False, assert_all_mocked=False) as mock:
        mock.get(autorite.url_jwks).mock(return_value=httpx.Response(200, json={"keys": []}))
        cache = CacheJWKS(parametres.url_jwks, ttl=parametres.jwks_ttl)
        with pytest.raises(JWKSIndisponible):
            await cache.cle("cle-1")


async def test_rotation_juste_apres_un_demarrage(parametres, autorite: Autorite, jwks, monkeypatch):
    """Régression : une rotation de clé dans les 5 min suivant le démarrage doit passer.

    `time.monotonic()` part de zéro au démarrage de la machine. Avec un sentinelle
    d'échec à 0.0, toute rotation survenant pendant les cinq premières minutes d'uptime
    était bridée — et c'est justement le moment le plus probable, puisque redémarrer un
    serveur repart d'un cache JWKS vide.
    """
    # Machine fraîchement démarrée : `monotonic()` vaut une poignée de secondes. On
    # remplace le module `time` VU PAR jwks.py, et non `time.monotonic` lui-même, qui
    # est global au processus (asyncio s'en sert à chaque tour de boucle).
    monkeypatch.setattr(
        "legi_mcp_auth.jwks.time", SimpleNamespace(monotonic=lambda: 2.0)
    )
    cache = CacheJWKS(parametres.url_jwks, ttl=parametres.jwks_ttl)
    validateur = ValidateurEntra(parametres, cache_jwks=cache)

    await validateur.valider(autorite.jeton(kid="cle-1"))
    autorite.publies.append("cle-2")
    try:
        assert await validateur.valider(autorite.jeton(kid="cle-2"))
    finally:
        autorite.publies.remove("cle-2")


async def test_bridage_leve_apres_une_rotation_reussie(parametres, autorite: Autorite, jwks):
    """Un échec puis une vraie rotation : le second `kid` inconnu doit être rechargé."""
    cache = CacheJWKS(parametres.url_jwks, ttl=parametres.jwks_ttl)
    validateur = ValidateurEntra(parametres, cache_jwks=cache)

    with pytest.raises(JetonRefuse):  # kid inventé -> échec, bridage armé
        await validateur.valider(autorite.jeton(kid="cle-2"))

    autorite.publies.append("cle-2")
    try:
        # Le bridage empêche encore le rechargement...
        with pytest.raises(JetonRefuse, match="bridé"):
            await validateur.valider(autorite.jeton(kid="cle-2"))
        # ... jusqu'à expiration du délai, simulée en remontant l'horodatage.
        cache._dernier_echec -= 301.0
        assert await validateur.valider(autorite.jeton(kid="cle-2"))
        # Rotation réussie : le bridage est desarmé.
        assert cache._dernier_echec is None
    finally:
        autorite.publies.remove("cle-2")
